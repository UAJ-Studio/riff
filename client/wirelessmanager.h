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
#include <QStringList>

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

    State state() const { return state_; }
    QString agentHost() const { return agentHost_; }

public slots:
    void installDistro();
    void uninstallDistro();
    void start(QStringList busIds, QString country, int channel);
    void stop();
    void setChannel(int channel);

signals:
    void message(QString text, bool isError);
    void installFinished(bool ok);
    void stateChanged(int state);
    void agentReady(QString host, quint16 port);
    void agentStopped();
    void needRebuild(QString kernel);

private slots:
    void onAgentOutput();
    void onAgentFinished(int exitCode, QProcess::ExitStatus status);

private:
    int run(const QString &program, const QStringList &args,
            QString *out = 0, int timeoutMs = 30000);
    int runWsl(const QStringList &args, QString *out = 0,
            int timeoutMs = 30000);
    bool bindElevated(const QString &busId);
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
