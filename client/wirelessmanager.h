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

#ifndef _WIRELESS_MANAGER_H
#define _WIRELESS_MANAGER_H

#include <QHash>
#include <QObject>
#include <QProcess>
#include <QSet>
#include <QStringList>

class QTimer;

/*
 * USB Wi-Fi dongles through WSL (see wireless/README.md):
 * Riff's own WSL distro "RiffWireless" runs a Linux riff-agent; usbipd-win
 * passes the dongle into WSL; the agent shows up as an extra port group.
 * Microsoft's stock WSL kernel is used - the user's .wslconfig and other
 * distros are never touched.
 */
class WirelessManager : public QObject
{
    Q_OBJECT
public:
    struct UsbDevice {
        QString busId;
        QString vidPid;     // "0b05:1997"
        QString name;
        QString state;      // usbipd: "Not shared", "Shared", "Attached"
        QString driver;     // supported driver, empty if not supported
        bool registered = false; // "Riff only": usbipd forced bind, no
                                 // Windows driver on it
    };
    enum State { Idle, Starting, Running, Stopping };

    static const char *kDistro;
    static const quint16 kAgentPort = 7879;

    explicit WirelessManager(QObject *parent = 0);
    ~WirelessManager();

    // environment checks (synchronous, quick)
    bool isWslAvailable(QString *detail = 0);
    QString usbipdPath();
    bool isDistroInstalled();
    // content version of the bundled rootfs and of the installed distro;
    // different = the installed one is from an older Riff
    QString bundledVersion() const;
    QString installedVersion();
    QString rootfsPath() const;
    QString distroDir() const;

    QList<UsbDevice> listUsbDevices(QString *error = 0);

    // Wireshark live capture: the Riff Wi-Fi extcap (wireless/riff-wifi-
    // extcap.exe) goes to Wireshark's personal extcap folder
    QString wiresharkPath() const;
    QString extcapSource() const;
    QString extcapTarget() const;
    bool isExtcapCurrent() const;
    bool installExtcap(QString *error = 0);
    // one dongle to capture from, with the channel (control frequency in
    // MHz) and width it should use
    struct CaptureTarget {
        UsbDevice dev;
        int freq;
        int width;
    };
    static QString captureInterface(const UsbDevice &dev);
    // Non-empty when a Windows Wi-Fi driver with a known multi-dongle
    // crash bug is installed for one of the listed dongles (Realtek
    // rtwlanu6 older than 5001.0.15.110): a warning with the fix.
    QString windowsDriverWarning(const QList<UsbDevice> &list) const;
    // opens Wireshark capturing live from the dongles - all in one window
    // (interfaces merged) or one window per dongle
    bool startLiveCapture(const QList<CaptureTarget> &targets,
                          const QString &country, bool oneWindow,
                          QString *error = 0);
    bool isCaptureRunning();

    State state() const { return state_; }
    QString agentHost() const { return agentHost_; }

public slots:
    void installDistro();
    void uninstallDistro();
    void start(QStringList busIds, QString country, int channel);
    void stop();
    void setChannel(int channel);

    // Dongles used with Riff stay "registered" (usbipd bind --force): the
    // Windows Wi-Fi driver never runs on them, so it is never torn down.
    // Several vendor drivers crash Windows when two of their adapters stop
    // (e.g. Realtek rtwlanu6 keeps one buffer in a global for all
    // adapters and frees it twice). Register one dongle at a time.
    bool registerDongle(const QString &busId, QString *error = 0);
    bool registerDongles(const QStringList &busIds, QString *error = 0);
    bool unregisterDongle(const QString &busId, QString *error = 0);

signals:
    void message(QString text, bool isError);
    void installFinished(bool ok);
    void stateChanged(int state);
    void agentReady(QString host, quint16 port);
    void agentStopped();
    void needRebuild(QString kernel);
    void registrationChanged();

private slots:
    void onAgentOutput();
    void onAgentFinished(int exitCode, QProcess::ExitStatus status);

private:
    int run(const QString &program, const QStringList &args,
            QString *out = 0, int timeoutMs = 30000);
    int runWsl(const QStringList &args, QString *out = 0,
            int timeoutMs = 30000);
    bool bindElevated(const QString &busId);
    // While WSL uses a dongle it is bound in "forced" mode, so the Windows
    // Wi-Fi driver is unloaded once, cleanly, instead of being torn down
    // on attach (the Realtek rtwlanu6 driver can crash Windows there).
    // Riff gives the dongles back to Windows when it is done with them.
    QHash<QString, bool> forcedState(QSet<QString> *attached = 0);
    bool ensureRegistered(const QStringList &busIds, QString *error);
    bool runElevatedCmd(const QString &cmdLine);
    void loadUsbIds();
    void setState(State s);
    void handleAgentLine(const QString &line);
    void connectWhenReachable(int attempt);
    void cleanup();

    State state_;
    QProcess *keepAlive_;
    QProcess *agent_;
    QStringList attached_;
    QString agentAddr_;     // VM address reported by riff-start.sh
    QString agentHost_;
    QHash<QString, QString> usbIds_; // "0B05:1997" -> driver
    bool usbIdsLoaded_;
};

#endif
