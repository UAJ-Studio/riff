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

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTextCodec>
#include <QTextStream>
#include <QTimer>

#ifdef Q_OS_WIN32
#include <windows.h>
#include <shellapi.h>
#endif

const char *WirelessManager::kDistro = "RiffWireless";

WirelessManager::WirelessManager(QObject *parent)
    : QObject(parent), state_(Idle), keepAlive_(0), agent_(0),
      usbIdsLoaded_(false)
{
}

WirelessManager::~WirelessManager()
{
    if (state_ != Idle)
        stop();
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
    if (busIds.isEmpty()) {
        emit message(tr("Select a dongle first."), true);
        return;
    }
    setState(Starting);
    agentAddr_.clear();
    agentHost_.clear();
    attached_.clear();

    // keep the distro running while usbipd attaches (it attaches through a
    // running WSL 2 distribution)
    keepAlive_ = new QProcess(this);
    keepAlive_->start("wsl.exe", {"-d", kDistro, "-u", "root", "--",
                                  "sleep", "2147483647"});
    keepAlive_->waitForStarted(5000);

    QString usbipd = usbipdPath();
    QList<UsbDevice> devs = listUsbDevices();
    foreach (QString id, busIds) {
        QString state;
        foreach (const UsbDevice &d, devs)
            if (d.busId == id)
                state = d.state;
        if (state.startsWith("Not shared", Qt::CaseInsensitive)) {
            emit message(tr("Sharing USB device %1 with WSL - please allow "
                            "the administrator prompt (only needed once).")
                            .arg(id), false);
            if (!bindElevated(id)) {
                emit message(tr("USB device %1 could not be shared "
                                "(the administrator prompt was declined or "
                                "failed).").arg(id), true);
                cleanup();
                return;
            }
        }
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
                  "/opt/riff/riff-start.sh", country, QString::number(channel),
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
        emit needRebuild(line.section("kernel=", 1));
    } else if (tag == "RIFF_NO_DONGLE") {
        emit message(tr("No Wi-Fi interface appeared. The dongle may not be "
                        "supported, or it needs to be re-plugged."), true);
    } else if (tag == "RIFF_WARN") {
        emit message(line.mid(tag.size() + 1), true);
    } else if (tag.startsWith("RIFF_WIFI_ERROR") || tag == "RIFF_ERROR") {
        emit message(tr("Error: %1").arg(line.mid(tag.size() + 1)), true);
    } else if (tag == "RIFF_WIFI_KERNEL_MISMATCH") {
        emit needRebuild(line.section("running=", 1).section(' ', 0, 0));
    } else if (line.startsWith("Ready to send traffic")) {
        connectWhenReachable(0);
    }
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

void WirelessManager::stop()
{
    if (state_ == Idle)
        return;
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

// Release everything started by start(): agent, USB attachments, keep-alive.
void WirelessManager::cleanup()
{
    if (agent_) {
        agent_->disconnect(this);
        if (agent_->state() != QProcess::NotRunning) {
            agent_->kill();
            agent_->waitForFinished(3000);
        }
        agent_->deleteLater();
        agent_ = 0;
    }
    QString usbipd = usbipdPath();
    foreach (QString id, attached_)
        run(usbipd, {"detach", "--busid", id}, 0, 20000);
    attached_.clear();
    if (keepAlive_) {
        keepAlive_->kill();
        keepAlive_->waitForFinished(3000);
        keepAlive_->deleteLater();
        keepAlive_ = 0;
    }
    // stops only Riff's own distribution
    runWsl({"--terminate", kDistro}, 0, 20000);
    agentHost_.clear();
    setState(Idle);
}
