/*
Copyright (C) 2026 Riff contributors

This file is part of Riff, based on Ostinato 1.3.0 (GPLv3).

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#include "wirelessmanager.h"

#include "childjob.h"
#include "settings.h"

#include <QApplication>
#include <QWidget>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTextCodec>
#include <QTextStream>
#include <QThread>
#include <QTimer>

#ifdef Q_OS_WIN32
#include <windows.h>
#include <shellapi.h>
#endif

const char *WirelessManager::kDistro = "RiffWireless";

WirelessManager::WirelessManager(QObject *parent)
    : QObject(parent), state_(Idle), keepAlive_(0), captureKeepAlive_(0), agent_(0),
      usbIdsLoaded_(false)
{
}

WirelessManager::~WirelessManager()
{
    if (state_ != Idle)
        stop();
    // registered dongles stay registered (Riff only) - see registerDongle();
    // dongles kept in WSL after live captures go back to the usbipd driver
    releaseKeptDongles();
}

// ---- Windows driver handover (usbipd bind --force) ------------------------

#ifdef Q_OS_WIN32
// Same mutex as the extcap (usbip.AttachLock): dongles are handed between
// Windows and WSL one at a time
class HandoverLock
{
public:
    HandoverLock() {
        h_ = CreateMutexW(NULL, FALSE, L"Local\\RiffWifiUsbHandover");
        if (h_ && WaitForSingleObject(h_, 180000) == WAIT_TIMEOUT) {
            CloseHandle(h_);
            h_ = NULL;
        }
    }
    ~HandoverLock() {
        if (h_) {
            ReleaseMutex(h_);
            CloseHandle(h_);
        }
    }
private:
    HANDLE h_;
};
#else
class HandoverLock {};
#endif

QHash<QString, bool> WirelessManager::forcedState(QSet<QString> *attached,
                                                  QSet<QString> *phantoms)
{
    QHash<QString, bool> forced;
    QProcess p;
    p.start(usbipdPath(), {"state"});
    if (!p.waitForFinished(20000))
        return forced;
    QJsonArray devs = QJsonDocument::fromJson(p.readAllStandardOutput())
                          .object().value("Devices").toArray();
    // A shared device runs on a usbipd stub device. When two dongles have
    // the same serial number, Windows can give that stub the instance ID
    // another (registered) dongle had - usbipd then lists the stub as an
    // extra device on the same bus id. It is not a real dongle: skip it.
    QSet<QString> stubs;    // "<bus>|<stub instance id>"
    foreach (const QJsonValue &v, devs) {
        QJsonObject o = v.toObject();
        QString stub = o.value("StubInstanceId").toString();
        if (!stub.isEmpty())
            stubs.insert(o.value("BusId").toString() + "|" + stub.toUpper());
    }
    foreach (const QJsonValue &v, devs) {
        QJsonObject o = v.toObject();
        QString bus = o.value("BusId").toString();
        if (bus.isEmpty())
            continue;
        if (stubs.contains(bus + "|" + o.value("InstanceId").toString().toUpper())
                && o.value("ClientIPAddress").toString().isEmpty()) {
            if (phantoms)
                phantoms->insert(bus + "|" + o.value("Description").toString());
            continue;
        }
        forced.insert(bus, o.value("IsForced").toBool());
        if (attached && !o.value("ClientIPAddress").toString().isEmpty())
            attached->insert(bus);
    }
    return forced;
}

// Runs "cmd.exe /c <cmdLine>" through one UAC prompt and waits for it
bool WirelessManager::runElevatedCmd(const QString &cmdLine)
{
#ifdef Q_OS_WIN32
    QString params = QString("/c \"%1\"").arg(cmdLine);
    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    // owner window: the UAC prompt comes to the front instead of only
    // flashing in the taskbar when Riff is not the foreground app
    if (QWidget *w = QApplication::activeWindow())
        sei.hwnd = reinterpret_cast<HWND>(w->winId());
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = reinterpret_cast<LPCWSTR>(params.utf16());
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess)
        return false;   // UAC declined
    WaitForSingleObject(sei.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return code == 0;
#else
    Q_UNUSED(cmdLine);
    return false;
#endif
}

// Starting with dongles that are not registered yet: register them now.
bool WirelessManager::ensureRegistered(const QStringList &busIds,
                                       QString *error)
{
    return registerDongles(busIds, error);
}

bool WirelessManager::registerDongle(const QString &busId, QString *error)
{
    return registerDongles(QStringList() << busId, error);
}

// Takes the dongles off their Windows Wi-Fi driver for good (usbipd bind
// --force), all with one administrator prompt. Older Realtek rtwlanu6
// drivers crash Windows when two of their adapters stop one after the
// other; the dialog asks to update those (windowsDriverWarning()).
bool WirelessManager::registerDongles(const QStringList &busIds,
                                      QString *error)
{
    QList<UsbDevice> devs = listUsbDevices();
    QStringList need, missing;
    foreach (const QString &id, busIds) {
        bool found = false;
        foreach (const UsbDevice &d, devs)
            if (d.busId == id) {
                found = true;
                if (!d.registered)
                    need << id;
            }
        if (!found)
            missing << id;
    }
    if (!missing.isEmpty()) {
        if (error)
            *error = tr("USB %1 is not connected.").arg(missing.join(", "));
        return false;
    }
    if (need.isEmpty())
        return true;
    QString ids = need.join(", ");
    emit message(tr("Registering USB %1 for Riff: the Windows Wi-Fi driver is "
                    "taken off it - please allow the administrator prompt.")
                    .arg(ids), false);
    QString exe = QDir::toNativeSeparators(usbipdPath());
    QStringList cmds;
    foreach (const QString &id, need)
        cmds << QString("\"%1\" bind --busid %2 --force").arg(exe, id);
    bool ok;
    {
        HandoverLock lock;
        ok = runElevatedCmd(cmds.join(" & "));
        QThread::msleep(2000);  // the devices restart on the usbipd driver
    }
    QHash<QString, bool> forced = forcedState();
    foreach (const QString &id, need)
        ok = ok && forced.value(id, false);
    emit registrationChanged();
    if (!ok) {
        if (error)
            *error = tr("USB %1 could not be registered (the administrator "
                        "prompt was declined or failed).").arg(ids);
        return false;
    }
    QStringList ports;
    foreach (const UsbDevice &d, devs)
        if (need.contains(d.busId))
            ports << portKey(d);
    setRemembered(ports, true);
    emit message(tr("USB %1 is registered for Riff. It stays with Riff until "
                    "you give it back to Windows.").arg(ids), false);
    return true;

}

bool WirelessManager::unregisterDongle(const QString &busId, QString *error)
{
    if (attached_.contains(busId) && state_ != Idle) {
        if (error)
            *error = tr("Stop the transmit agent first.");
        return false;
    }
    if (isCaptureRunning()) {
        if (error)
            *error = tr("Stop the Wireshark live capture first.");
        return false;
    }
    if (preps_.contains(busId)) {
        preps_.value(busId).job->kill();
        finishPrep(busId);
    }
    QString port;
    foreach (const UsbDevice &d, listUsbDevices())
        if (d.busId == busId)
            port = portKey(d);
    emit message(tr("Giving USB %1 back to Windows - please allow the "
                    "administrator prompt.").arg(busId), false);
    QString exe = QDir::toNativeSeparators(usbipdPath());
    bool ok;
    {
        HandoverLock lock;
        // bind first so that unbind also clears a forced flag left without
        // a share record (seen after a dongle moved to another port)
        runElevatedCmd(QString("\"%1\" detach --busid %2 >nul 2>&1 & "
                               "\"%1\" bind --busid %2 >nul 2>&1 & "
                               "\"%1\" unbind --busid %2").arg(exe, busId));
        QThread::msleep(2000);
        ok = !forcedState().value(busId, true);
    }
    // forget the port first: the refresh below must not register it again
    if (ok && !port.isEmpty())
        setRemembered(QStringList() << port, false);
    emit registrationChanged();
    if (!ok) {
        if (error)
            *error = tr("USB %1 could not be given back to Windows (the "
                        "administrator prompt was declined or failed).")
                        .arg(busId);
        return false;
    }
    emit message(tr("USB %1 is used by Windows again.").arg(busId), false);
    return true;
}

// ---- Wireshark live capture (extcap) -------------------------------------

QString WirelessManager::wiresharkPath() const
{
    QString p = appSettings->value(kWiresharkPathKey,
                                   kWiresharkPathDefaultValue).toString();
    return QFile::exists(p) ? p : QString();
}

QString WirelessManager::extcapSource() const
{
    return QCoreApplication::applicationDirPath()
            + "/wireless/riff-wifi-extcap.exe";
}

QString WirelessManager::extcapTarget() const
{
    // Wireshark's personal extcap folder: no administrator rights needed
    QString appData = qEnvironmentVariable("APPDATA");
    return QDir(appData).filePath("Wireshark/extcap/riff-wifi-extcap.exe");
}

static QByteArray fileHash(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    QCryptographicHash h(QCryptographicHash::Sha256);
    h.addData(&f);
    return h.result();
}

bool WirelessManager::isExtcapCurrent() const
{
    QByteArray src = fileHash(extcapSource());
    return !src.isEmpty() && src == fileHash(extcapTarget());
}

bool WirelessManager::installExtcap(QString *error)
{
    if (!QFile::exists(extcapSource())) {
        if (error)
            *error = tr("The Wireshark plugin file was not found: %1")
                        .arg(QDir::toNativeSeparators(extcapSource()));
        return false;
    }
    if (isExtcapCurrent())
        return true;
    QDir().mkpath(QFileInfo(extcapTarget()).absolutePath());
    QFile::remove(extcapTarget());
    if (!QFile::copy(extcapSource(), extcapTarget())) {
        if (error)
            *error = tr("Could not copy the Wireshark plugin to %1 (is a "
                        "capture running in Wireshark?)")
                        .arg(QDir::toNativeSeparators(extcapTarget()));
        return false;
    }
    emit message(tr("Installed the Wireshark plugin (Riff Wi-Fi capture)."),
                 false);
    return true;
}

// the extcap names its interfaces riffwifi_<vid>_<pid>_<bus>_<port>
QString WirelessManager::captureInterface(const UsbDevice &dev)
{
    return QString("riffwifi_%1_%2")
            .arg(QString(dev.vidPid).replace(':', '_'),
                 QString(dev.busId).replace('-', '_').replace('.', '_'));
}

// Realtek rtwlanu6 (RTL8852AU/8832AU, e.g. ASUS USB-AX56) before
// 5001.0.15.110 keeps a per-adapter buffer in a global variable: once two
// dongles ran, stopping them frees it twice and Windows crashes
// (BAD_POOL_HEADER). 5001.0.15.110 does not crash (tested on two PCs).
static quint64 fileVersion(const QString &path)
{
    std::wstring p = QDir::toNativeSeparators(path).toStdWString();
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(p.c_str(), &dummy);
    if (!size)
        return 0;
    QByteArray buf(int(size), 0);
    if (!GetFileVersionInfoW(p.c_str(), 0, size, buf.data()))
        return 0;
    VS_FIXEDFILEINFO *info = 0;
    UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", (void **)&info, &len) || !info)
        return 0;
    return (quint64(info->dwFileVersionMS) << 32) | info->dwFileVersionLS;
}

QString WirelessManager::windowsDriverWarning(const QList<UsbDevice> &list) const
{
    bool realtek = false;
    foreach (const UsbDevice &d, list)
        if (d.driver.startsWith("rtw89_"))
            realtek = true;
    if (!realtek)
        return QString();
    QString sysRoot = QString::fromLocal8Bit(qgetenv("SystemRoot"));
    if (sysRoot.isEmpty())
        sysRoot = "C:/Windows";
    quint64 v = fileVersion(sysRoot + "/System32/drivers/rtwlanu6.sys");
    const quint64 fixed = (quint64(5001) << 48) | (quint64(0) << 32)
                        | (quint64(15) << 16) | 110;
    if (!v || v >= fixed)
        return QString();
    QString ver = QString("%1.%2.%3.%4").arg(v >> 48).arg((v >> 32) & 0xffff)
                    .arg((v >> 16) & 0xffff).arg(v & 0xffff);
    return tr("The Realtek Wi-Fi driver on this PC (rtwlanu6 %1) is outdated. "
              "With two of its dongles plugged in, Windows can crash (blue "
              "screen) when they stop - unplugging, disabling, registering "
              "for Riff or shutting down. Install version 5001.0.15.110 or "
              "later from the maker of your dongle (for the ASUS USB-AX56: "
              "ASUS support site, USB-AX56 > Driver & Tools).").arg(ver);
}

bool WirelessManager::startLiveCapture(const QList<CaptureTarget> &targets,
                                       const QString &country, bool oneWindow,
                                       QString *error)
{
    QString ws = wiresharkPath();
    if (ws.isEmpty()) {
        if (error)
            *error = tr("Wireshark was not found. Install Wireshark, or set "
                        "its location in Edit > Preferences.");
        return false;
    }
    if (!ensureUsbipdService()) {
        if (error)
            *error = tr("The usbipd-win service is not running.");
        return false;
    }
    if (targets.isEmpty()) {
        if (error)
            *error = tr("Check at least one dongle to capture from.");
        return false;
    }
    if (!installExtcap(error))
        return false;

    // the dongles must be registered for Riff (no Windows driver on them)
    QStringList ids;
    foreach (const CaptureTarget &t, targets)
        ids << t.dev.busId;
    if (!ensureRegistered(ids, error))
        return false;

    // one-shot settings for each interface, read by the extcap when the
    // capture starts (see riffRequest() in wireless/extcap)
    QDir reqDir(QDir(qEnvironmentVariable("LOCALAPPDATA"))
                    .filePath("Riff/capture-requests"));
    reqDir.mkpath(".");
    QStringList ifaces;
    foreach (const CaptureTarget &t, targets) {
        QString iface = captureInterface(t.dev);
        QFile f(reqDir.filePath(iface + ".txt"));
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            QTextStream ts(&f);
            ts << "freq=" << t.freq << "\nwidth=" << t.width
               << "\ncountry=" << country << "\n";
        }
        ifaces << iface;
        emit message(tr("Live capture: USB %1 (%2) on %3 MHz, %4 MHz wide.")
                        .arg(t.dev.busId, t.dev.name).arg(t.freq).arg(t.width),
                     false);
    }

    QList<QStringList> launches;
    if (oneWindow) {
        QStringList args;
        foreach (const QString &i, ifaces)
            args << "-i" << i;
        launches << (args << "-k");
    }
    else {
        foreach (const QString &i, ifaces)
            launches << QStringList({"-i", i, "-k"});
    }
    waitPrepared(90000);
    ensureCaptureKeepAlive();
    foreach (const QStringList &args, launches) {
        if (!startOutsideJob(ws, args)) {
            if (error)
                *error = tr("Could not start Wireshark.");
            return false;
        }
    }
    emit message(oneWindow
        ? tr("Started Wireshark with %n dongle(s) in one window.", "",
             targets.size())
        : tr("Started %n Wireshark window(s), one per dongle.", "",
             targets.size()), false);
    return true;
}

bool WirelessManager::isCaptureRunning()
{
    QString out;
    return runWsl({"-d", kDistro, "-u", "root", "--", "pgrep", "-x",
                   "tcpdump"}, &out, 10000) == 0;
}

// Run a program and wait. Output decoding: wsl.exe prints UTF-8 with
// WSL_UTF8=1 (set below), usbipd prints in the console code page.
int WirelessManager::run(const QString &program, const QStringList &args,
                         QString *out, int timeoutMs)
{
    QProcess p;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("WSL_UTF8", "1");
    p.setProcessEnvironment(env);
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(program, args);
    if (!p.waitForStarted(5000)) {
        if (out)
            *out = p.errorString();
        return -1;
    }
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(2000);
        if (out)
            *out = tr("timed out");
        return -2;
    }
    if (out) {
        QByteArray b = p.readAll();
        bool wsl = QFileInfo(program).baseName().compare("wsl",
                                        Qt::CaseInsensitive) == 0;
        // wsl.exe's own messages can still be UTF-16 on older WSL
        if (wsl && b.size() > 1 && b.at(1) == '\0')
            *out = QString::fromUtf16(
                        reinterpret_cast<const char16_t*>(b.constData()),
                        b.size()/2);
        else if (wsl)
            *out = QString::fromUtf8(b);
        else {
            // usbipd (.NET) writes UTF-8 when redirected; older tools use
            // the console code page - take UTF-8 only if it decodes cleanly
            QTextCodec::ConverterState st;
            QString u = QTextCodec::codecForName("UTF-8")->toUnicode(
                            b.constData(), b.size(), &st);
            *out = st.invalidChars == 0 ? u : QString::fromLocal8Bit(b);
        }
        out->remove(QChar('\r'));
    }
    return p.exitCode();
}

// usbipd detach --busid. usbipd (5.3) fails with "Sequence contains more
// than one matching element" when two devices share the bus id (the stub of
// an attached dongle listed under an old registration, see forcedState()):
// then detach every device of that vendor/product id.
void WirelessManager::detachDongle(const QString &busId)
{
    QString usbipd = usbipdPath(), out;
    if (run(usbipd, {"detach", "--busid", busId}, &out, 20000) == 0
            || !out.contains("more than one"))
        return;
    QProcess p;
    p.start(usbipd, {"state"});
    if (!p.waitForFinished(20000))
        return;
    QRegularExpression re("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})");
    foreach (const QJsonValue &v, QJsonDocument::fromJson(
                 p.readAllStandardOutput()).object().value("Devices").toArray()) {
        QJsonObject o = v.toObject();
        if (o.value("BusId").toString() != busId)
            continue;
        QRegularExpressionMatch m = re.match(o.value("InstanceId").toString());
        if (m.hasMatch()) {
            run(usbipd, {"detach", "--hardware-id",
                         (m.captured(1) + ":" + m.captured(2)).toLower()},
                0, 20000);
            return;
        }
    }
}

int WirelessManager::runWsl(const QStringList &args, QString *out,
                            int timeoutMs)
{
    return run("wsl.exe", args, out, timeoutMs);
}

bool WirelessManager::isWslAvailable(QString *detail)
{
    QString out;
    int rc = runWsl({"--status"}, &out, 15000);
    if (detail)
        *detail = out.trimmed();
    return rc == 0;
}

QString WirelessManager::usbipdPath()
{
    QString p = QStandardPaths::findExecutable("usbipd");
    if (!p.isEmpty())
        return p;
    QString pf = qEnvironmentVariable("ProgramFiles", "C:/Program Files");
    p = QDir(pf).filePath("usbipd-win/usbipd.exe");
    return QFile::exists(p) ? p : QString();
}

bool WirelessManager::isDistroInstalled()
{
    QString out;
    if (runWsl({"--list", "--quiet"}, &out, 15000) != 0)
        return false;
    foreach (QString l, out.split('\n'))
        if (l.trimmed() == kDistro)
            return true;
    return false;
}

QString WirelessManager::rootfsPath() const
{
    return QCoreApplication::applicationDirPath()
            + "/wireless/riffwireless-rootfs.tar.gz";
}

QString WirelessManager::distroDir() const
{
    QString base = qEnvironmentVariable("LOCALAPPDATA");
    if (base.isEmpty())
        base = QDir::homePath();
    return QDir(base).filePath("Riff/wsl/RiffWireless");
}

QString WirelessManager::bundledVersion() const
{
    QFile f(QCoreApplication::applicationDirPath()
            + "/wireless/riffwireless-version.txt");
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    return QString::fromLatin1(f.readAll()).trimmed();
}

QString WirelessManager::installedVersion()
{
    QString out;
    if (runWsl({"-d", kDistro, "-u", "root", "--", "cat", "/opt/riff/VERSION"},
               &out, 20000) != 0)
        return QString();
    return out.trimmed();
}

void WirelessManager::installDistro()
{
    if (!QFile::exists(rootfsPath())) {
        emit message(tr("The wireless environment file was not found: %1")
                        .arg(QDir::toNativeSeparators(rootfsPath())), true);
        emit installFinished(false);
        return;
    }
    if (isDistroInstalled()) {
        // update: replace Riff's own distribution with the bundled one
        emit message(tr("Removing the old wireless environment ..."), false);
        QString out;
        runWsl({"--unregister", kDistro}, &out, 60000);
    }
    QDir().mkpath(distroDir());
    emit message(tr("Installing the Riff wireless environment "
                    "(WSL distribution \"%1\") ...").arg(kDistro), false);
    // a separate distribution: the user's own distributions and .wslconfig
    // are not changed
    QProcess *p = new QProcess(this);
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("WSL_UTF8", "1");
    p->setProcessEnvironment(env);
    p->setProcessChannelMode(QProcess::MergedChannels);
    connect(p, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(
                &QProcess::finished), this,
            [this, p](int code, QProcess::ExitStatus) {
        QString out = QString::fromUtf8(p->readAll()).trimmed();
        p->deleteLater();
        bool ok = code == 0 && isDistroInstalled();
        if (ok)
            emit message(tr("The wireless environment is installed."), false);
        else
            emit message(tr("Installing the wireless environment failed: %1")
                            .arg(out), true);
        emit installFinished(ok);
    });
    p->start("wsl.exe", {"--import", kDistro,
                QDir::toNativeSeparators(distroDir()),
                QDir::toNativeSeparators(rootfsPath()), "--version", "2"});
}

void WirelessManager::uninstallDistro()
{
    if (state_ != Idle)
        stop();
    QString out;
    int rc = runWsl({"--unregister", kDistro}, &out, 60000);
    emit message(rc == 0 ? tr("The wireless environment was removed.")
                         : tr("Removing the wireless environment failed: %1")
                                .arg(out.trimmed()), rc != 0);
}

void WirelessManager::loadUsbIds()
{
    if (usbIdsLoaded_)
        return;
    usbIdsLoaded_ = true;
    QFile f(QCoreApplication::applicationDirPath()
            + "/wireless/riff-wifi-usbids.txt");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    QTextStream ts(&f);
    while (!ts.atEnd()) {
        QStringList w = ts.readLine().split(' ', Qt::SkipEmptyParts);
        if (w.size() >= 2)
            usbIds_.insert(w.at(0).toUpper(), w.at(1));
    }
}

QList<WirelessManager::UsbDevice> WirelessManager::listUsbDevices(
        QString *error)
{
    QList<UsbDevice> list;
    QString usbipd = usbipdPath();
    if (usbipd.isEmpty()) {
        if (error)
            *error = tr("usbipd-win is not installed");
        return list;
    }
    loadUsbIds();
    QString out;
    if (run(usbipd, {"list"}, &out, 20000) != 0) {
        if (error)
            *error = out.trimmed();
        return list;
    }
    // Connected:
    // BUSID  VID:PID    DEVICE                       STATE
    // 5-4    0b05:1997  ASUS USB-AX56 Wireless ...   Shared
    QRegularExpression re("^(\\d+-[\\d.]+)\\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{4})"
                          "\\s+(.*?)\\s{2,}(\\S.*)$");
    bool inConnected = false;
    foreach (QString line, out.split('\n')) {
        if (line.startsWith("Connected"))
            inConnected = true;
        else if (line.startsWith("Persisted"))
            inConnected = false;
        if (!inConnected)
            continue;
        QRegularExpressionMatch m = re.match(line.trimmed());
        if (!m.hasMatch())
            continue;
        UsbDevice d;
        d.busId = m.captured(1);
        d.vidPid = m.captured(2).toLower();
        d.name = m.captured(3).trimmed();
        d.state = m.captured(4).trimmed();
        d.driver = usbIds_.value(d.vidPid.toUpper());
        list.append(d);
    }
    // registered = usbipd forced bind (not shown by "usbipd list")
    QSet<QString> phantoms;
    QHash<QString, bool> forced = forcedState(0, &phantoms);
    for (int i = list.size() - 1; i >= 0; i--)
        if (phantoms.contains(list.at(i).busId + "|" + list.at(i).name))
            list.removeAt(i);
    for (int i = 0; i < list.size(); i++)
        list[i].registered = forced.value(list.at(i).busId, false);
    // ports registered for Riff: remember them (also registrations made
    // before Riff kept this list), and flag dongles there that lost it
    QStringList known = rememberedPorts(), seen;
    for (int i = 0; i < list.size(); i++) {
        if (list.at(i).driver.isEmpty())
            continue;
        if (list.at(i).registered)
            seen << portKey(list.at(i));
        else if (known.contains(portKey(list.at(i))))
            list[i].remembered = true;
    }
    setRemembered(seen, true);
    return list;
}

// "usbipd bind" (share a device with WSL) needs administrator rights once
// per device; ask through the normal Windows UAC prompt.
bool WirelessManager::bindElevated(const QString &busId)
{
#ifdef Q_OS_WIN32
    QString exe = QDir::toNativeSeparators(usbipdPath());
    QString params = QString("bind --busid %1").arg(busId);
    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = reinterpret_cast<LPCWSTR>(exe.utf16());
    sei.lpParameters = reinterpret_cast<LPCWSTR>(params.utf16());
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess)
        return false;   // UAC declined
    WaitForSingleObject(sei.hProcess, 60000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return code == 0;
#else
    Q_UNUSED(busId);
    return false;
#endif
}

void WirelessManager::setState(State s)
{
    if (state_ == s)
        return;
    state_ = s;
    emit stateChanged(s);
}

void WirelessManager::start(QStringList busIds, QString country, int channel)
{
    if (state_ != Idle)
        return;
    autoSuppressed_ = false;
    if (busIds.isEmpty()) {
        emit message(tr("Select a dongle first."), true);
        return;
    }
    if (!ensureUsbipdService())
        return;
    // a dongle being prepared for capture must be ready before the agent
    // takes it
    waitPrepared(90000);
    setState(Starting);
    emit portStatus(tr("starting the wireless agent ..."), 0);
    agentAddr_.clear();
    agentHost_.clear();
    attached_.clear();
    ownAttached_.clear();

    // keep the distro running while usbipd attaches (it attaches through a
    // running WSL 2 distribution)
    keepAlive_ = new QProcess(this);
    keepAlive_->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                                  "sleep", "2147483647"});
    keepAlive_->waitForStarted(5000);

    QString usbipd = usbipdPath();
    // the dongles must be registered for Riff (no Windows driver on them)
    QString regError;
    if (!ensureRegistered(busIds, &regError)) {
        emit message(regError, true);
        cleanup();
        return;
    }
    QList<UsbDevice> devs = listUsbDevices();
    HandoverLock lock;      // one dongle at a time
    bool first = true;
    foreach (QString id, busIds) {
        QString state;
        foreach (const UsbDevice &d, devs)
            if (d.busId == id)
                state = d.state;
        if (!first)
            QThread::msleep(2000);
        first = false;
        if (!state.startsWith("Attached", Qt::CaseInsensitive)) {
            QString out;
            emit message(tr("Connecting USB device %1 to WSL ...").arg(id),
                         false);
            if (run(usbipd, {"attach", "--wsl", "--busid", id}, &out, 60000)
                    != 0) {
                emit message(tr("Connecting USB device %1 failed: %2")
                                .arg(id, out.trimmed()), true);
                cleanup();
                return;
            }
            ownAttached_.append(id);
        }
        attached_.append(id);
    }

    emit message(tr("Loading the dongle drivers and starting the agent ..."),
                 false);
    agent_ = new QProcess(this);
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("WSL_UTF8", "1");
    agent_->setProcessEnvironment(env);
    agent_->setProcessChannelMode(QProcess::MergedChannels);
    connect(agent_, &QProcess::readyRead,
            this, &WirelessManager::onAgentOutput);
    connect(agent_, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(
                &QProcess::finished),
            this, &WirelessManager::onAgentFinished);
    agent_->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                  "/opt/riff/riff-start.sh", country,
                  channel > 0 ? QString::number(channel) : QString("-"),
                  QString::number(kAgentPort)});
}

void WirelessManager::onAgentOutput()
{
    while (agent_ && agent_->canReadLine())
        handleAgentLine(QString::fromUtf8(agent_->readLine()).trimmed());
}

void WirelessManager::handleAgentLine(const QString &line)
{
    if (line.isEmpty())
        return;
    QStringList w = line.split(' ', Qt::SkipEmptyParts);
    const QString tag = w.value(0);
    if (tag == "RIFF_WIFI_LOADED") {
        emit message(tr("Drivers loaded (%1).").arg(w.mid(1).join(' ')),
                     false);
    } else if (tag == "RIFF_WIFI_BUILTIN") {
        emit message(tr("This WSL kernel (%1) already contains Wi-Fi drivers; "
                        "using them.").arg(line.section("kernel=", 1)), false);
    } else if (tag == "RIFF_DONGLE") {
        emit message(tr("Dongle ready: %1 (driver %2, MAC %3), monitor mode")
                        .arg(w.value(1), w.value(2), w.value(3)), false);
    } else if (tag == "RIFF_ADDR") {
        agentAddr_ = w.value(1);
    } else if (tag == "RIFF_NEED_REBUILD") {
        noDriversFor(line.section("kernel=", 1));
    } else if (tag == "RIFF_NO_DONGLE") {
        emit message(tr("No Wi-Fi interface appeared. The dongle may not be "
                        "supported, or it needs to be re-plugged."), true);
    } else if (tag == "RIFF_WARN") {
        emit message(line.mid(tag.size() + 1), true);
    } else if (tag.startsWith("RIFF_WIFI_ERROR") || tag == "RIFF_ERROR") {
        emit message(tr("Error: %1").arg(line.mid(tag.size() + 1)), true);
    } else if (tag == "RIFF_WIFI_KERNEL_MISMATCH") {
        noDriversFor(line.section("running=", 1).section(' ', 0, 0));
    } else if (line.startsWith("Ready to send traffic")) {
        connectWhenReachable(0);
    }
}

// The RiffWireless distro has no driver pack for the kernel WSL runs (WSL
// was updated to a kernel this Riff does not know yet). Tell the user once
// per kernel - queued, never from inside the agent's output handler: a modal
// box there spins an event loop in which the agent process is deleted - and
// stop starting the agent automatically, which would only fail again.
void WirelessManager::noDriversFor(const QString &kernel)
{
    emit message(tr("No dongle drivers could be found or downloaded for the "
                    "WSL kernel %1.").arg(kernel), true);
    if (noDriversKernel_ == kernel)
        return;
    noDriversKernel_ = kernel;
    emit portStatus(tr("no dongle drivers for this WSL kernel (%1) yet")
                    .arg(kernel), 1);
    QTimer::singleShot(0, this, [this, kernel]() { emit needRebuild(kernel); });
}

void WirelessManager::buildDrivers()
{
    if (build_)
        return;
    emit message(tr("Building the dongle drivers for this WSL kernel on this "
                    "PC. This takes about 10 minutes (about an hour if the quick "
                    "way does not work); keep Riff open."), false);
    emit portStatus(tr("building the dongle drivers ..."), 0);
    build_ = new QProcess(this);
    build_->setProcessChannelMode(QProcess::MergedChannels);
    connect(build_, &QProcess::readyRead, this, [this]() {
        while (build_ && build_->canReadLine()) {
            QString l = QString::fromUtf8(build_->readLine()).trimmed();
            if (l.startsWith("RIFF_BUILD_STEP")) {
                QString step = l.mid(16);
                emit message(tr("Building the drivers: %1").arg(step), false);
                emit portStatus(tr("building the dongle drivers: %1").arg(step), 0);
            } else if (l.startsWith("RIFF_BUILD_ERROR")) {
                emit message(tr("Building the drivers failed: %1").arg(l.mid(17)),
                             true);
            } else if (l.startsWith("RIFF_PACK_") || l.startsWith("RIFF_BUILD_DONE")) {
                emit message(l, false);
            }
        }
    });
    connect(build_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this](int code, QProcess::ExitStatus st) {
        bool ok = st == QProcess::NormalExit && code == 0;
        build_->deleteLater();
        build_ = nullptr;
        if (ok) {
            emit message(tr("The dongle drivers are ready."), false);
            noDriversKernel_.clear();
            emit portStatus("", 2);
            QTimer::singleShot(0, this, &WirelessManager::prepareRegistered);
        } else {
            emit portStatus(tr("the dongle drivers could not be built"), 1);
        }
        emit driversBuilt(ok);
    });
    build_->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                              "sh", "/opt/riff/riff-buildpack.sh"});
}

// Prefer localhost (WSL forwards it in most setups); fall back to the VM's
// own address, which always works in NAT mode.
void WirelessManager::connectWhenReachable(int attempt)
{
    QStringList hosts;
    hosts << "127.0.0.1";
    if (!agentAddr_.isEmpty())
        hosts << agentAddr_;
    foreach (QString h, hosts) {
        QTcpSocket s;
        s.connectToHost(h, kAgentPort);
        if (s.waitForConnected(1500)) {
            s.disconnectFromHost();
            agentHost_ = h;
            setState(Running);
            emit message(tr("The wireless agent is running (%1:%2).")
                            .arg(h).arg(kAgentPort), false);
            emit agentReady(h, kAgentPort);
            return;
        }
    }
    if (attempt < 5 && state_ == Starting) {
        QTimer::singleShot(1000, this, [this, attempt]() {
            connectWhenReachable(attempt + 1);
        });
        return;
    }
    emit message(tr("Riff could not connect to the wireless agent "
                    "(port %1).").arg(kAgentPort), true);
    emit portStatus(tr("could not connect to the wireless agent"), 1);
}

void WirelessManager::onAgentFinished(int exitCode, QProcess::ExitStatus)
{
    if (agent_)
        onAgentOutput();
    bool wasRunning = state_ == Running;
    if (state_ != Stopping && exitCode != 0 && exitCode != 3)
        emit message(tr("The wireless agent stopped (exit code %1).")
                        .arg(exitCode), true);
    if (state_ != Stopping) {
        cleanup();
        if (wasRunning)
            emit agentStopped();
    }
}

void WirelessManager::setChannel(int channel)
{
    if (state_ != Running)
        return;
    QString out;
    runWsl({"-d", kDistro, "-u", "root", "--", "/opt/riff/riff-channel.sh",
            QString::number(channel)}, &out, 15000);
    foreach (QString l, out.split('\n')) {
        l = l.trimmed();
        if (l.startsWith("RIFF_CHANNEL"))
            emit message(tr("Channel set to %1.").arg(channel), false);
        else if (l.startsWith("RIFF_WARN"))
            emit message(tr("Channel %1 was refused by the dongle or the "
                            "country setting.").arg(channel), true);
    }
}

// Prepared dongles become ports of the transmit agent without the user
// pressing Start; their channel stays as prepared (set per port later).
void WirelessManager::autoStartAgent()
{
    if (state_ != Idle || autoSuppressed_ || !preps_.isEmpty()
            || !noDriversKernel_.isEmpty())
        return;
    QStringList ids;
    foreach (const UsbDevice &d, listUsbDevices())
        if (!d.driver.isEmpty() && d.registered
                && d.state.startsWith("Attached", Qt::CaseInsensitive))
            ids << d.busId;
    if (ids.isEmpty())
        return;
    // an agent left behind by a killed Riff holds the port
    runWsl({"-d", kDistro, "-u", "root", "--", "killall", "-q", "riff-agent"},
           0, 10000);
    emit message(tr("Starting the wireless agent for the prepared dongle(s): "
                    "they appear as ports in the main window."), false);
    start(ids, appSettings->value("Wireless/Country", "JP").toString(), 0);
}

int WirelessManager::centerFreq(int freq, int width)
{
    if (width == 20)
        return freq;
    if (freq < 2500) {                       // 2.4 GHz: HT40+ / HT40-
        int num = freq == 2484 ? 14 : (freq - 2407) / 5;
        if (width != 40 || num >= 14)
            return 0;
        return num <= 7 ? freq + 10 : freq - 10;
    }
    int n = width / 20;
    if (freq < 5950) {                       // 5 GHz
        if (width > 160)
            return 0;
        int num = (freq - 5000) / 5;
        int base = num >= 149 ? 149 : 36;
        int center = base + (num - base) / (4 * n) * 4 * n + 2 * (n - 1);
        static const QList<int> ok40 = {38, 46, 54, 62, 102, 110, 118, 126,
                                        134, 142, 151, 159, 167, 175};
        static const QList<int> ok80 = {42, 58, 106, 122, 138, 155, 171};
        static const QList<int> ok160 = {50, 114, 163};
        const QList<int> &ok = width == 40 ? ok40 : width == 80 ? ok80 : ok160;
        return ok.contains(center) ? 5000 + 5 * center : 0;
    }
    int num = (freq - 5950) / 5;             // 6 GHz
    int center = 1 + (num - 1) / (4 * n) * 4 * n + 2 * (n - 1);
    if (center + 2 * (n - 1) > 233)
        return 0;
    return 5950 + 5 * center;
}

bool WirelessManager::setChannel(const QString &iface, int freq, int width,
                                 QString *error)
{
    int center = centerFreq(freq, width);
    if (!center) {
        if (error)
            *error = tr("%1 MHz has no %2 MHz wide channel.").arg(freq)
                        .arg(width);
        return false;
    }
    QString out;
    runWsl({"-d", kDistro, "-u", "root", "--", "/opt/riff/riff-channel.sh",
            "-f", QString::number(freq), QString::number(width),
            QString::number(center), iface}, &out, 20000);
    if (out.contains("RIFF_CHANNEL")) {
        emit message(tr("%1: channel set to %2 MHz, %3 MHz wide.")
                        .arg(iface).arg(freq).arg(width), false);
        return true;
    }
    if (error)
        *error = tr("The dongle (%1) refused %2 MHz / %3 MHz: the dongle or "
                    "the country setting does not allow it.")
                    .arg(iface).arg(freq).arg(width);
    return false;
}

void WirelessManager::stop()
{
    if (state_ == Idle)
        return;
    autoSuppressed_ = true;     // until the user starts it again
    bool wasRunning = state_ == Running;
    setState(Stopping);
    emit message(tr("Stopping the wireless agent ..."), false);
    runWsl({"-d", kDistro, "-u", "root", "--", "killall", "riff-agent"},
           0, 10000);
    cleanup();
    if (wasRunning)
        emit agentStopped();
    emit message(tr("Stopped."), false);
}

// ---- registered ports / preparing dongles ahead of the first capture -------

static const char *kRegisteredPortsKey = "Wireless/RegisteredPorts";

QString WirelessManager::portKey(const UsbDevice &d)
{
    return d.vidPid + "@" + d.busId;
}

QStringList WirelessManager::rememberedPorts() const
{
    return appSettings->value(kRegisteredPortsKey).toStringList();
}

void WirelessManager::setRemembered(const QStringList &ports, bool add)
{
    QStringList cur = rememberedPorts();
    bool changed = false;
    foreach (const QString &p, ports) {
        if (add && !cur.contains(p)) {
            cur << p;
            changed = true;
        }
        else if (!add && cur.removeAll(p))
            changed = true;
    }
    if (changed)
        appSettings->setValue(kRegisteredPortsKey, cur);
}

bool WirelessManager::reRegisterRemembered(QString *error)
{
    QStringList need;
    foreach (const UsbDevice &d, listUsbDevices())
        if (d.remembered)
            need << d.busId;
    if (need.isEmpty())
        return true;
    emit message(tr("USB %1 was registered for Riff, but Windows gave it "
                    "another device ID (two dongles with the same serial "
                    "number swap IDs). Registering it again - this is needed "
                    "only once per ID.").arg(need.join(", ")), false);
    return registerDongles(need, error);
}

// The usbipd-win service does the actual USB hand-over. It can crash (seen
// with usbipd 5.3: "'overlapped' has already been freed") and is then not
// restarted by Windows: start it again through one administrator prompt.
bool WirelessManager::ensureUsbipdService()
{
#ifdef Q_OS_WIN32
    if (usbipdPath().isEmpty())
        return false;
    QString out;
    run("sc.exe", {"query", "usbipd"}, &out, 10000);
    if (out.contains("RUNNING") || !out.contains("STOPPED"))
        return true;
    emit message(tr("The usbipd-win service is not running (it may have "
                    "crashed). Starting it again - please allow the "
                    "administrator prompt."), true);
    runElevatedCmd("sc start usbipd");
    for (int i = 0; i < 20; i++) {
        run("sc.exe", {"query", "usbipd"}, &out, 10000);
        if (out.contains("RUNNING")) {
            emit message(tr("The usbipd-win service is running again."),
                         false);
            return true;
        }
        QThread::msleep(500);
    }
    emit message(tr("The usbipd-win service could not be started. Restart "
                    "Windows, then start Riff again."), true);
    emit portStatus(tr("the usbipd-win service is not running"), 1);
    return false;
#else
    return true;
#endif
}

void WirelessManager::prepareRegistered()
{
    if (state_ != Idle)
        return;     // the transmit agent owns the dongles
    if (!noDriversKernel_.isEmpty())
        return;     // no drivers for this WSL kernel: it would only fail
    if (!ensureUsbipdService())
        return;
    QList<UsbDevice> todo;
    foreach (const UsbDevice &d, listUsbDevices())
        if (!d.driver.isEmpty() && d.registered && !preps_.contains(d.busId)
                && !d.state.startsWith("Attached", Qt::CaseInsensitive))
            todo << d;
    if (todo.isEmpty()) {
        autoStartAgent();   // e.g. already prepared by an earlier Riff
        return;
    }
    if (!isDistroInstalled())
        return;
    emit portStatus(tr("readying the dongle(s) ..."), 0);
    ensureCaptureKeepAlive();
    QString usbipd = usbipdPath();
    QString country = appSettings->value("Wireless/Country", "JP").toString();
    foreach (const UsbDevice &d, todo) {
        // the channel the capture list has for this dongle (20 MHz here;
        // a wider capture re-tunes when it starts)
        QStringList s = appSettings->value("Wireless/Capture/"
                + captureInterface(d), "0,5180,20").toString().split(',');
        int freq = s.size() > 1 && s.at(1).toInt() > 0 ? s.at(1).toInt() : 5180;
        Prep p;
        // the dongle may drop off the bus once while its firmware uploads:
        // keep re-attaching until it is ready
        p.attach = new QProcess(this);
        p.attach->start(usbipd, {"attach", "--wsl", "--busid", d.busId,
                                 "--auto-attach"});
        p.job = new QProcess(this);
        // riff-capture reports the driver loader's lines (e.g. no pack for
        // this WSL kernel) on stderr
        p.job->setProcessChannelMode(QProcess::MergedChannels);
        QString busId = d.busId;
        connect(p.job, QOverload<int, QProcess::ExitStatus>::of(
                    &QProcess::finished), this,
                [this, busId](int code, QProcess::ExitStatus st) {
            bool ok = st == QProcess::NormalExit && code == 0;
            if (QProcess *job = preps_.value(busId).job) {
                foreach (QString l, QString::fromUtf8(job->readAll()).split('\n')) {
                    l = l.trimmed();
                    if (l.startsWith("RIFF_NEED_REBUILD")
                            || l.startsWith("RIFF_WIFI_KERNEL_MISMATCH"))
                        handleAgentLine(l);
                }
            }
            finishPrep(busId);
            emit message(ok ? tr("USB %1 is ready: a live capture starts in "
                                 "a few seconds.").arg(busId)
                            : tr("USB %1 could not be prepared ahead; it is "
                                 "prepared when a capture starts.")
                                 .arg(busId), !ok);
            emit prepared(busId, ok);
            if (!ok)
                prepFailed_ = true;
            if (preps_.isEmpty()) {
                autoStartAgent();
                if (state_ == Idle && !noDriversKernel_.isEmpty())
                    emit portStatus(tr("no dongle drivers for this WSL "
                            "kernel (%1) yet").arg(noDriversKernel_), 1);
                else if (state_ == Idle)    // no agent started after all
                    emit portStatus(prepFailed_
                            ? tr("the dongle(s) could not be readied") : "",
                            prepFailed_ ? 1 : 2);
                prepFailed_ = false;
            }
        });
        p.job->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                "/opt/riff/riff-capture", country, QString::number(freq),
                "20", QString::number(freq), d.busId + "@" + d.vidPid,
                "prepare"});
        preps_.insert(busId, p);
        // never hang around for good
        QTimer::singleShot(120000, this, [this, busId]() {
            if (preps_.contains(busId))
                preps_.value(busId).job->kill();
        });
        emit message(tr("Preparing USB %1 for capture in the background ...")
                        .arg(busId), false);
    }
}

void WirelessManager::finishPrep(const QString &busId)
{
    if (!preps_.contains(busId))
        return;
    Prep p = preps_.take(busId);
    // the dongle stays attached; only the re-attach loop stops
    p.attach->kill();
    p.attach->waitForFinished(3000);
    p.attach->deleteLater();
    p.job->deleteLater();
}

void WirelessManager::waitPrepared(int timeoutMs)
{
    if (preps_.isEmpty())
        return;
    emit message(tr("Waiting for the dongle(s) being prepared ..."), false);
    QElapsedTimer t;
    t.start();
    while (!preps_.isEmpty() && t.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
        QThread::msleep(50);
    }
}

void WirelessManager::ensureCaptureKeepAlive()
{
    if (captureKeepAlive_ && captureKeepAlive_->state() != QProcess::NotRunning)
        return;
    delete captureKeepAlive_;
    captureKeepAlive_ = new QProcess(this);
    captureKeepAlive_->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                                         "sleep", "2147483647"});
    captureKeepAlive_->waitForStarted(5000);
}

// On exit: hand dongles kept in WSL after live captures back to the usbipd
// driver (they stay registered) - unless a capture is still running.
void WirelessManager::releaseKeptDongles()
{
    foreach (const QString &id, preps_.keys()) {
        preps_.value(id).job->kill();
        finishPrep(id);
    }
    // Not only what this run kept: after Riff was killed (or crashed) the
    // dongles stay in WSL, and the next Riff finds them already attached.
    QString usbipd = usbipdPath();
    QStringList kept;
    if (!usbipd.isEmpty()) {
        QSet<QString> attached;
        QHash<QString, bool> forced = forcedState(&attached);
        foreach (const QString &id, attached)
            if (forced.value(id, false))
                kept << id;
    }
    if ((!kept.isEmpty() || captureKeepAlive_) && !isCaptureRunning()) {
        foreach (const QString &id, kept)
            detachDongle(id);
        // also ends a keep-alive left behind by a killed Riff
        runWsl({"--terminate", kDistro}, 0, 20000);
    }
    if (captureKeepAlive_) {
        captureKeepAlive_->kill();
        captureKeepAlive_->waitForFinished(3000);
        delete captureKeepAlive_;
        captureKeepAlive_ = 0;
    }
}

// Release everything started by start(): agent, USB attachments, keep-alive.
void WirelessManager::cleanup()
{
    if (state_ == Starting)     // failed before the agent was reachable
        emit portStatus(noDriversKernel_.isEmpty()
                ? tr("the wireless agent could not start")
                : tr("no dongle drivers for this WSL kernel (%1) yet")
                      .arg(noDriversKernel_), 1);
    else if (state_ == Stopping)
        emit portStatus("", 2);
    if (agent_) {
        agent_->disconnect(this);
        if (agent_->state() != QProcess::NotRunning) {
            agent_->kill();
            agent_->waitForFinished(3000);
        }
        agent_->deleteLater();
        agent_ = 0;
    }
    // A Wireshark live capture may still be using the dongle: then leave it
    // in WSL (the capture hands it back to Windows when it stops)
    bool capturing = isCaptureRunning();
    QString usbipd = usbipdPath();
    if (!capturing) {
        // only what start() attached: dongles Riff prepared stay in WSL
        foreach (QString id, ownAttached_)
            detachDongle(id);
    }
    else {
        emit message(tr("A Wireshark live capture is running: the dongle "
                        "stays connected to WSL for it."), false);
    }
    ownAttached_.clear();
    attached_.clear();
    if (keepAlive_) {
        keepAlive_->kill();
        keepAlive_->waitForFinished(3000);
        keepAlive_->deleteLater();
        keepAlive_ = 0;
    }
    // stops only Riff's own distribution (not while it holds dongles kept
    // from live captures)
    if (!capturing && !captureKeepAlive_)
        runWsl({"--terminate", kDistro}, 0, 20000);
    agentHost_.clear();
    setState(Idle);
}
