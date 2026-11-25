/*
Copyright (C) 2010 Srivats P.

This file is part of "Ostinato"

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

#include "mainwindow.h"

#if 0
#include "dbgthread.h"
#endif

#include "clipboardhelper.h"
#include "jumpurl.h"
#include "riffurls.h"
#include "logsmodel.h"
#include "logswindow.h"
#include "params.h"
#include "portgrouplist.h"
#include "portstatswindow.h"
#include "portswindow.h"
#include "preferences.h"
#include "sessionfileformat.h"
#include "settings.h"
#include "ui_about.h"
#include "riffupdater.h"
#include "updater.h"
#include "wirelessdialog.h"
#include "wirelessmanager.h"

#include "fileformat.pb.h"

#include <QApplication>
#include <QComboBox>
#include <QDate>
#include <QDateTime>
#include <QHBoxLayout>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDockWidget>
#include <QFormLayout>
#include <QLabel>
#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QProcess>
#include <QProgressDialog>
#include <QTimer>
#include <QUrl>

#ifdef Q_OS_WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#endif

extern const char* version;
extern const char* revision;

PortGroupList    *pgl;
LogsModel        *appLogs;
ClipboardHelper  *clipboardHelper;

MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow (parent), wireless_(NULL), wirelessDialog_(NULL),
      wirelessPortGroup_(NULL), updater_(NULL), updateBar_(NULL),
      updateProgress_(NULL), manualUpdateCheck_(false)
{
    if (appParams.optLocalDrone()) {
        QString serverApp = QCoreApplication::applicationDirPath();
#ifdef Q_OS_MAC
        // applicationDirPath() does not return bundle,
        // but executable inside bundle
        serverApp.replace("Ostinato.app", "drone.app");
#endif
#ifdef Q_OS_WIN32
        serverApp.append("/riff-agent.exe");
#else
        serverApp.append("/drone");
#endif

        qDebug("staring local server - %s", qPrintable(serverApp));
        localServer_ = new QProcess(this);
        connect(localServer_, SIGNAL(finished(int, QProcess::ExitStatus)),
                SLOT(onLocalServerFinished(int, QProcess::ExitStatus)));

#if QT_VERSION >= 0x050600
        connect(localServer_, SIGNAL(errorOccurred(QProcess::ProcessError)),
                SLOT(onLocalServerError(QProcess::ProcessError)));
#else
        connect(localServer_, SIGNAL(error(QProcess::ProcessError)),
                SLOT(onLocalServerError(QProcess::ProcessError)));
#endif
        localServer_->setProcessChannelMode(QProcess::ForwardedChannels);
#ifdef Q_OS_WIN32
        {
            // Npcap installed without "WinPcap API-compatible mode" puts
            // wpcap.dll/Packet.dll only in System32\Npcap, which is not on
            // the DLL search path - add it so that riff-agent.exe can start
            wchar_t sysDir[MAX_PATH];
            UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
            if (len > 0 && len < MAX_PATH) {
                QString npcapDir = QString::fromWCharArray(sysDir, int(len))
                                    + "\\Npcap";
                QProcessEnvironment env =
                    QProcessEnvironment::systemEnvironment();
                env.insert("PATH", npcapDir + ";" + env.value("PATH"));
                localServer_->setProcessEnvironment(env);
            }
        }
#endif
        localServer_->start(serverApp, QStringList());
        QTimer::singleShot(5000, this, SLOT(stopLocalServerMonitor()));
    }
    else
        localServer_ = NULL;

#ifdef Q_OS_WIN32
    // dongles registered for Riff: ready them for capture in the background
    // (does nothing without usbipd or registered dongles)
    QTimer::singleShot(4000, this, [this]() {
        ensureWireless();
        wireless_->prepareRegistered();
    });
#endif

    pgl = new PortGroupList;
    appLogs = new LogsModel(this);
    clipboardHelper = new ClipboardHelper(this);

    portsWindow = new PortsWindow(pgl, this);
    connect(portsWindow, &PortsWindow::wifiChannelRequested,
            this, &MainWindow::onWifiChannelRequested);
    statsWindow = new PortStatsWindow(pgl, this);

    portsDock = new QDockWidget(tr("Ports and Streams"), this);
    portsDock->setObjectName("portsDock");
    portsDock->setFeatures(
                portsDock->features() & ~QDockWidget::DockWidgetClosable);

    statsDock = new QDockWidget(tr("Port Statistics"), this);
    statsDock->setObjectName("statsDock");
    statsDock->setFeatures(
                statsDock->features() & ~QDockWidget::DockWidgetClosable);

    logsDock_ = new QDockWidget(tr("Logs"), this);
    logsDock_->setObjectName("logsDock");
    logsDock_->setFeatures(
                logsDock_->features() & ~QDockWidget::DockWidgetClosable);
    logsWindow_ = new LogsWindow(appLogs, logsDock_);

    setupUi(this);

    menuFile->insertActions(menuFile->actions().at(3),
                            portsWindow->portActions());
    menuEdit->addActions(clipboardHelper->actions());
    menuStreams->addActions(portsWindow->streamActions());
    menuDevices->addActions(portsWindow->deviceActions());

    statsDock->setWidget(statsWindow);
    addDockWidget(Qt::BottomDockWidgetArea, statsDock);
    logsDock_->setWidget(logsWindow_);
    addDockWidget(Qt::BottomDockWidgetArea, logsDock_);
    tabifyDockWidget(statsDock, logsDock_);
    statsDock->show();
    statsDock->raise();

    portsDock->setWidget(portsWindow);
    addDockWidget(Qt::TopDockWidgetArea, portsDock);

#if QT_VERSION >= 0x050600
    // Set top and bottom docks to equal height
    resizeDocks({portsDock, statsDock}, {height()/2, height()/2}, Qt::Vertical);
#endif

    portsWindow->setFocus();

    // Save the default window geometry and layout ...
    defaultGeometry_ = geometry();
    defaultLayout_ = saveState(0);

    // ... before restoring the last used settings
    QRect geom = appSettings->value(kApplicationWindowGeometryKey).toRect();
    if (!geom.isNull())
        setGeometry(geom);
    QByteArray layout = appSettings->value(kApplicationWindowLayout)
                            .toByteArray();
    if (layout.size())
        restoreState(layout, 0);

    connect(actionFileExit, SIGNAL(triggered()), this, SLOT(close()));
    connect(actionAboutQt, SIGNAL(triggered()), qApp, SLOT(aboutQt()));

    connect(actionViewShowMyReservedPortsOnly, SIGNAL(toggled(bool)),
            portsWindow, SLOT(showMyReservedPortsOnly(bool)));
    connect(actionViewShowMyReservedPortsOnly, SIGNAL(toggled(bool)),
            statsWindow, SLOT(showMyReservedPortsOnly(bool)));

    // Riff update check: once a day, a while after start (Help menu turns
    // it off); upstream's ostinato.org check is a different product line
    actionCheckAtStart->setChecked(
            appSettings->value(kRiffUpdateCheckAtStart, true).toBool());
    QTimer::singleShot(8000, this, [this]() { autoUpdateCheck(); });
    QTimer *updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, [this]() { autoUpdateCheck(); });
    updateTimer->start(6 * 60 * 60 * 1000);

    // TODO: If session file specified (and valid?), don't add local drone PG
    // Add the "Local" Port Group
    if (appParams.optLocalDrone()) {
        PortGroup *pg = new PortGroup;
        pgl->addPortGroup(*pg);
    }

    if (appParams.argumentCount()) {
        QString fileName = appParams.argument(0);
        if (QFile::exists(fileName))
            openSession(fileName);
        else
            QMessageBox::information(NULL, qApp->applicationName(),
                    QString("File not found: " + fileName));
    }

#if 0
    {
        DbgThread *dbg = new DbgThread(pgl);
        dbg->start();
    }
#endif
}

MainWindow::~MainWindow()
{
    // stop the WSL wireless agent and give the dongle back to Windows
    if (wireless_)
        wireless_->stop();
    stopLocalServerMonitor();
    if (localServer_) {
#ifdef Q_OS_WIN32
        //! \todo - find a way to terminate cleanly
        localServer_->kill();
#else    
        localServer_->terminate();
#endif
    }

    delete pgl;

    // We don't want to save state for Stream Stats Docks - so delete them
    QList<QDockWidget*> streamStatsDocks
            = findChildren<QDockWidget*>("streamStatsDock");
    foreach(QDockWidget *dock, streamStatsDocks)
        delete dock;
    Q_ASSERT(findChildren<QDockWidget*>("streamStatsDock").size() == 0);

    QByteArray layout = saveState(0);
    appSettings->setValue(kApplicationWindowLayout, layout);
    appSettings->setValue(kApplicationWindowGeometryKey, geometry());

    if (localServer_) {
        localServer_->waitForFinished();
        delete localServer_;
    }
}

void MainWindow::openSession(QString fileName)
{
    qDebug("Open Session Action (%s)", qPrintable(fileName));

    static QString dirName;
    QStringList fileTypes = SessionFileFormat::supportedFileTypes(
                                                SessionFileFormat::kOpenFile);
    QString fileType;
    QString errorStr;
    bool ret;

    if (!fileName.isEmpty())
        goto _skip_prompt;

    if (portsWindow->portGroupCount()) {
        if (QMessageBox::question(this,
                tr("Open Session"),
                tr("Existing session will be lost. Proceed?"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) == QMessageBox::No)
            goto _exit;
    }

    if (fileTypes.size())
        fileType = fileTypes.at(0);

    fileName = QFileDialog::getOpenFileName(this, tr("Open Session"),
            dirName, fileTypes.join(";;"), &fileType);
    if (fileName.isEmpty())
        goto _exit;

_skip_prompt:
    ret = openSession(fileName, errorStr);
    if (!ret || !errorStr.isEmpty()) {
        QMessageBox msgBox(this);
        QStringList str = errorStr.split("\n\n\n\n");

        msgBox.setIcon(ret ? QMessageBox::Warning : QMessageBox::Critical);
        msgBox.setWindowTitle(qApp->applicationName());
        msgBox.setText(str.at(0));
        if (str.size() > 1)
            msgBox.setDetailedText(str.at(1));
        msgBox.setStandardButtons(QMessageBox::Ok);

        msgBox.exec();
    }
    dirName = QFileInfo(fileName).absolutePath();

_exit:
    return;
}

void MainWindow::on_actionOpenSession_triggered()
{
    openSession();
}

void MainWindow::on_actionSaveSession_triggered()
{
    qDebug("Save Session Action");

    static QString fileName;
    QStringList fileTypes = SessionFileFormat::supportedFileTypes(
                                                SessionFileFormat::kSaveFile);
    QString fileType;
    QString errorStr;
    QFileDialog::Options options;

    if (portsWindow->reservedPortCount()) {
        QString myself = appSettings->value(kUserKey, kUserDefaultValue)
                            .toString();
        if (QMessageBox::question(this,
                tr("Save Session"),
                QString("Some ports are reserved!\n\nOnly ports reserved by %1 will be saved. Proceed?").arg(myself),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) == QMessageBox::No)
            goto _exit;
    }

    // On Mac OS with Native Dialog, getSaveFileName() ignores fileType.
    // Although currently there's only one supported file type, we may
    // have more in the future
#if defined(Q_OS_MAC)
    options |= QFileDialog::DontUseNativeDialog;
#endif

    if (fileTypes.size())
        fileType = fileTypes.at(0);

_retry:
    fileName = QFileDialog::getSaveFileName(this, tr("Save Session"),
            fileName, fileTypes.join(";;"), &fileType, options);
    if (fileName.isEmpty())
        goto _exit;

    if (QFileInfo(fileName).suffix().isEmpty()) {
        QString fileExt = fileType.section(QRegExp("[\\*\\)]"), 1, 1);
        qDebug("Adding extension '%s' to '%s'",
                qPrintable(fileExt), qPrintable(fileName));
        fileName.append(fileExt);
        if (QFileInfo(fileName).exists()) {
            if (QMessageBox::warning(this, tr("Overwrite File?"), 
                QString("The file \"%1\" already exists.\n\n"
                    "Do you wish to overwrite it?")
                    .arg(QFileInfo(fileName).fileName()),
                QMessageBox::Yes|QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes)
                goto _retry;
        }
    }

    if (!saveSession(fileName, fileType, errorStr))
        QMessageBox::critical(this, qApp->applicationName(), errorStr);
    else if (!errorStr.isEmpty())
        QMessageBox::warning(this, qApp->applicationName(), errorStr);

    fileName = QFileInfo(fileName).absolutePath();
_exit:
    return;
}

void MainWindow::on_actionPreferences_triggered()
{
    Preferences *preferences = new Preferences();

    preferences->exec();

    delete preferences;
}

void MainWindow::on_actionViewRestoreDefaults_triggered()
{
    // Use the saved default geometry/layout, however keep the
    // window location same
    defaultGeometry_.moveTo(geometry().topLeft());
    setGeometry(defaultGeometry_);
    restoreState(defaultLayout_, 0);

    // Add streamStats as tabs
    QList<QDockWidget*> streamStatsDocks
            = findChildren<QDockWidget*>("streamStatsDock");
    foreach(QDockWidget *dock, streamStatsDocks) {
        dock->setFloating(false);
        tabifyDockWidget(statsDock, dock);
    }
    statsDock->show();
    statsDock->raise();

    actionViewShowMyReservedPortsOnly->setChecked(false);

    portsWindow->clearCurrentSelection();
    statsWindow->clearCurrentSelection();
    logsWindow_->clearCurrentSelection();
}

void MainWindow::on_actionHelpOnline_triggered()
{
    // the user manual in the UI's language (the Japanese translation of
    // this URL is the Japanese manual)
    QDesktopServices::openUrl(QUrl(tr("https://github.com/UAJ-Studio/riff/blob/main/docs/manual-en.md")));
}

void MainWindow::on_actionDonate_triggered()
{
    QDesktopServices::openUrl(QUrl(RIFF_SPONSORS_URL));
}

void MainWindow::on_actionCheckForUpdates_triggered()
{
    manualUpdateCheck_ = true;
    if (!updater_) {
        updater_ = new RiffUpdater(this);
        connect(updater_, &RiffUpdater::checked,
                this, &MainWindow::onUpdateChecked);
        connect(updater_, &RiffUpdater::checkFailed,
                this, &MainWindow::onUpdateCheckFailed);
    }
    updater_->check();
}

void MainWindow::on_actionCheckAtStart_toggled(bool on)
{
    appSettings->setValue(kRiffUpdateCheckAtStart, on);
}

// asks GitHub for the latest release at most once in 20 hours
void MainWindow::autoUpdateCheck()
{
    if (!appSettings->value(kRiffUpdateCheckAtStart, true).toBool())
        return;
    if (updateProgress_)
        return;
    QDateTime last = appSettings->value(kRiffUpdateLastCheck).toDateTime();
    if (last.isValid() && last.secsTo(QDateTime::currentDateTime()) < 20*3600)
        return;
    on_actionCheckForUpdates_triggered();
    manualUpdateCheck_ = false;
}

void MainWindow::onUpdateChecked(bool newer, QString latest)
{
    const bool manual = manualUpdateCheck_;
    manualUpdateCheck_ = false;
    appSettings->setValue(kRiffUpdateLastCheck, QDateTime::currentDateTime());

    if (!newer) {
        if (manual)
            QMessageBox::information(this, tr("Riff Update"),
                tr("This Riff (%1) is the latest version.").arg(version));
        return;
    }

    showUpdateBar(latest);

    // the dialog once per version; the status bar keeps the Update button
    if (!manual && appSettings->value(kRiffUpdateNotified).toString() == latest)
        return;
    appSettings->setValue(kRiffUpdateNotified, latest);

    QMessageBox *box = new QMessageBox(QMessageBox::Information,
        tr("Riff Update"),
        tr("<p><b>Riff %1 is available</b> (you have %2). "
           "<a href='%3'>What's new</a></p>"
           "<p><b>Update</b> downloads it, closes Riff, updates it and "
           "starts Riff again. Your settings are kept.</p>")
            .arg(latest).arg(version)
            .arg(updater_->notesUrl().toString()),
        QMessageBox::NoButton, this);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setTextFormat(Qt::RichText);
    box->setTextInteractionFlags(Qt::TextBrowserInteraction);
    QPushButton *update = box->addButton(tr("Update"), QMessageBox::AcceptRole);
    box->addButton(tr("Later"), QMessageBox::RejectRole);
    box->setDefaultButton(update);
    connect(update, &QPushButton::clicked, this, [this]() { startUpdate(); });
    box->open();
}

void MainWindow::onUpdateCheckFailed(QString error)
{
    const bool manual = manualUpdateCheck_;
    manualUpdateCheck_ = false;
    if (manual)
        QMessageBox::warning(this, tr("Riff Update"),
            tr("Could not check for updates: %1").arg(error));
}

void MainWindow::showUpdateBar(QString ver)
{
    if (updateBar_) {
        statusBar()->removeWidget(updateBar_);
        updateBar_->deleteLater();
    }
    updateBar_ = new QWidget(this);
    QHBoxLayout *layout = new QHBoxLayout(updateBar_);
    layout->setContentsMargins(0, 0, 0, 0);
    QLabel *label = new QLabel(tr("Riff %1 is available").arg(ver), updateBar_);
    QPushButton *button = new QPushButton(tr("Update"), updateBar_);
    connect(button, &QPushButton::clicked, this, [this]() { startUpdate(); });
    layout->addWidget(label);
    layout->addWidget(button);
    statusBar()->addPermanentWidget(updateBar_);
}

void MainWindow::startUpdate()
{
    if (!updater_ || updateProgress_)
        return;

    updateProgress_ = new QProgressDialog(
            tr("Downloading Riff %1...").arg(updater_->latestVersion()),
            tr("Cancel"), 0, 100, this);
    updateProgress_->setWindowTitle(tr("Riff Update"));
    updateProgress_->setWindowModality(Qt::WindowModal);
    updateProgress_->setMinimumDuration(0);
    updateProgress_->setAutoClose(false);
    updateProgress_->setAutoReset(false);
    updateProgress_->setValue(0);

    auto done = [this]() {
        disconnect(updater_, &RiffUpdater::progress, this, nullptr);
        disconnect(updater_, &RiffUpdater::downloaded, this, nullptr);
        disconnect(updater_, &RiffUpdater::downloadFailed, this, nullptr);
        if (updateProgress_) {
            updateProgress_->deleteLater();
            updateProgress_ = NULL;
        }
    };
    connect(updateProgress_, &QProgressDialog::canceled, this, [this, done]() {
        updater_->cancelDownload();
        done();
    });
    connect(updater_, &RiffUpdater::progress, this,
            [this](qint64 got, qint64 total) {
        if (updateProgress_ && total > 0)
            updateProgress_->setValue(int(got * 100 / total));
    });
    connect(updater_, &RiffUpdater::downloadFailed, this,
            [this, done](QString error) {
        done();
        if (!error.isEmpty())
            QMessageBox::warning(this, tr("Riff Update"),
                tr("The update could not be downloaded: %1").arg(error));
    });
    connect(updater_, &RiffUpdater::downloaded, this, [this, done]() {
        updateProgress_->setLabelText(tr("Closing Riff and updating..."));
        updateProgress_->setCancelButton(NULL);
        QString error;
        if (!updater_->runInstaller(&error)) {
            done();
            QMessageBox::warning(this, tr("Riff Update"), error);
            return;
        }
        done();
        // the setup waits for Riff to close, then starts it again
        qApp->quit();
    });
    updater_->download();
}

void MainWindow::on_actionHelpAbout_triggered()
{
    QDialog *aboutDialog = new QDialog;

    Ui::About about;
    about.setupUi(aboutDialog);
    about.versionLabel->setText(
            QString("Version: %1 Revision: %2").arg(version).arg(revision));

    aboutDialog->exec();

    delete aboutDialog;
}

void MainWindow::stopLocalServerMonitor()
{
    // We are only interested in startup errors
#if QT_VERSION >= 0x050600
    disconnect(localServer_, SIGNAL(errorOccurred(QProcess::ProcessError)),
            this, SLOT(onLocalServerError(QProcess::ProcessError)));
#else
    disconnect(localServer_, SIGNAL(error(QProcess::ProcessError)),
            this, SLOT(onLocalServerError(QProcess::ProcessError)));
#endif
    disconnect(localServer_, SIGNAL(finished(int, QProcess::ExitStatus)),
            this, SLOT(onLocalServerFinished(int, QProcess::ExitStatus)));
}

void MainWindow::onLocalServerFinished(int exitCode,
                                       QProcess::ExitStatus /*exitStatus*/)
{
    if (exitCode)
        reportLocalServerError();
}

void MainWindow::onLocalServerError(QProcess::ProcessError /*error*/)
{
    reportLocalServerError();
}

void MainWindow::reportLocalServerError()
{
    QMessageBox msgBox(this);
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setTextFormat(Qt::RichText);
    msgBox.setStyleSheet("messagebox-text-interaction-flags: 5"); // mouse copy
    QString errorStr = tr("<p>Failed to start the local Riff agent (riff-agent) - "
                          "error 0x%1, exit status 0x%2 exit code 0x%3.</p>")
            .arg(localServer_->error(), 0, 16)
            .arg(localServer_->exitStatus(), 0, 16)
            .arg(localServer_->exitCode(), 0, 16);
    if (localServer_->error() == QProcess::FailedToStart)
        errorStr.append(tr("<p>The riff-agent program does not exist at %1 or you "
                           "don't have sufficient permissions to execute it."
                           "</p>")
                        .arg(QCoreApplication::applicationDirPath()));
    if (localServer_->exitCode() == 1)
        errorStr.append(tr("<p>The riff-agent program was not able to bind to "
                           "TCP port 7878 - maybe another agent process is already "
                           "running?</p>"));
#ifdef Q_OS_WIN32
    if (localServer_->exitCode() == STATUS_DLL_NOT_FOUND)
        errorStr.append(tr("<p>This is most likely because Packet.dll "
                           "was not found - make sure you have "
                           "<a href='%1'>npcap installed and accessible</a>."
                           "</p>")
                                .arg(jumpUrl("winpcap")));
#endif
    msgBox.setText(errorStr);
    msgBox.setInformativeText(tr("Try running riff-agent.exe directly."));
    msgBox.exec();

    QMessageBox::information(this, QString(),
        tr("<p>If you have remote agents running, you can still add "
           "and connect to them.</p>"
           "<p>If you don't want to start the local Riff agent (riff-agent) at startup, "
           "provide the <b>-c</b> option to Riff on the command line.</p>"
           "<p>Learn about the (upstream Ostinato) <a href='%1'>Controller-Agent "
           "architecture</a></p>").arg(jumpUrl("arch")));
}

void MainWindow::onNewVersion(QString newVersion)
{
    QDate today = QDate::currentDate();
    QDate lastChecked = QDate::fromString(
                            appSettings->value(kLastUpdateCheck).toString(),
                            Qt::ISODate);
    if (lastChecked.daysTo(today) >= 5) {
        QMessageBox::information(this, tr("Update check"),
            tr("<p><b>Ostinato version %1 is now available</b> (you have %2). "
                "See <a href='%3'>change log</a>.</p>"
                "<p>Visit <a href='%4'>ostinato.org</a> to download.</p>")
                .arg(newVersion)
                .arg(version)
                .arg(jumpUrl("changelog", "app", "status", "update"))
                .arg(jumpUrl("download", "app", "status", "update")));
    }
    else {
        QLabel *msg = new QLabel(tr("New Ostinato version %1 available. Visit "
                    "<a href='%2'>ostinato.org</a> to download")
                .arg(newVersion)
                .arg(jumpUrl("download", "app", "status", "update")));
        msg->setOpenExternalLinks(true);
        statusBar()->addPermanentWidget(msg);
    }

    appSettings->setValue(kLastUpdateCheck, today.toString(Qt::ISODate));
    sender()->deleteLater();
}

void MainWindow::onLatestVersion(QString latestVersion)
{
    if (version != latestVersion) {
        QMessageBox::information(this, tr("Update check"),
            tr("<p><b>Ostinato version %1 is now available</b> (you have %2). "
                "See <a href='%3'>change log</a>.</p>"
                "<p>Visit <a href='%4'>ostinato.org</a> to download.</p>")
                .arg(latestVersion)
                .arg(version)
                .arg(jumpUrl("changelog", "app", "status", "update"))
                .arg(jumpUrl("download", "app", "status", "update")));
    }
    else {
        QMessageBox::information(this, tr("Update check"),
            tr("You are already running the latest Ostinato version - %1")
                .arg(version));
    }

    sender()->deleteLater();
}

//! Returns true on success (or user cancel) and false on failure
bool MainWindow::openSession(QString fileName, QString &error)
{
    bool ret = false;
    QDialog *optDialog;
    QProgressDialog progress("Opening Session", "Cancel", 0, 0, this);
    OstProto::SessionContent session;
    SessionFileFormat *fmt = SessionFileFormat::fileFormatFromFile(fileName);

    if (fmt == NULL) {
        error = tr("Unknown session file format");
        goto _fail;
    }

    if ((optDialog = fmt->openOptionsDialog()))
    {
        int ret;
        optDialog->setParent(this, Qt::Dialog);
        ret = optDialog->exec();
        optDialog->setParent(0, Qt::Dialog);
        if (ret == QDialog::Rejected)
            goto _user_opt_cancel;
    }

    progress.setAutoReset(false);
    progress.setAutoClose(false);
    progress.setMinimumDuration(0);
    progress.show();

    setDisabled(true);
    progress.setEnabled(true); // to override the mainWindow disable

    connect(fmt, SIGNAL(status(QString)),&progress,SLOT(setLabelText(QString)));
    connect(fmt, SIGNAL(target(int)), &progress, SLOT(setMaximum(int)));
    connect(fmt, SIGNAL(progress(int)), &progress, SLOT(setValue(int)));
    connect(&progress, SIGNAL(canceled()), fmt, SLOT(cancel()));

    fmt->openAsync(fileName, session, error);
    qDebug("after open async");

    while (!fmt->isFinished())
        qApp->processEvents();
    qDebug("wait over for async operation");

    if (!fmt->result())
        goto _fail;

    // process any remaining events posted from the thread
    for (int i = 0; i < 10; i++)
        qApp->processEvents();

    // XXX: user can't cancel operation from here on!
    progress.close();

    portsWindow->openSession(&session, error);

_user_opt_cancel:
    ret = true;

_fail:
    progress.close();
    setEnabled(true);
    return ret;
}

bool MainWindow::saveSession(QString fileName, QString fileType, QString &error)
{
    bool ret = false;
    QProgressDialog progress("Saving Session", "Cancel", 0, 0, this);
    SessionFileFormat *fmt = SessionFileFormat::fileFormatFromType(fileType);
    OstProto::SessionContent session;

    if (fmt == NULL)
        goto _fail;

    progress.setAutoReset(false);
    progress.setAutoClose(false);
    progress.setMinimumDuration(0);
    progress.show();

    setDisabled(true);
    progress.setEnabled(true); // to override the mainWindow disable

    // Fill in session
    ret = portsWindow->saveSession(&session, error, &progress);
    if (!ret)
        goto _user_cancel;

    connect(fmt, SIGNAL(status(QString)),&progress,SLOT(setLabelText(QString)));
    connect(fmt, SIGNAL(target(int)), &progress, SLOT(setMaximum(int)));
    connect(fmt, SIGNAL(progress(int)), &progress, SLOT(setValue(int)));
    connect(&progress, SIGNAL(canceled()), fmt, SLOT(cancel()));

    fmt->saveAsync(session, fileName, error);
    qDebug("after save async");

    while (!fmt->isFinished())
        qApp->processEvents();
    qDebug("wait over for async operation");

    ret = fmt->result();
    goto _exit;

_user_cancel:
   goto _exit;

_fail:
    error = QString("Unsupported File Type - %1").arg(fileType);
    goto _exit;

_exit:
    progress.close();
    setEnabled(true);
    return ret;
}


void MainWindow::ensureWireless()
{
    if (!wireless_) {
        wireless_ = new WirelessManager(this);
        connect(wireless_, &WirelessManager::agentReady,
                this, &MainWindow::onWirelessAgentReady);
        connect(wireless_, &WirelessManager::agentStopped,
                this, &MainWindow::onWirelessAgentStopped);
        connect(wireless_, &WirelessManager::portStatus,
                this, &MainWindow::onWirelessPortStatus);
        connect(wireless_, &WirelessManager::needRebuild,
                this, &MainWindow::onWirelessNoDrivers);
    }
}

// WSL runs a kernel no dongle drivers could be found or downloaded for (the
// manager tells once per kernel). Not modal: Riff keeps working with its
// wired ports. Offers to build the drivers on this PC.
void MainWindow::onWirelessNoDrivers(QString kernel)
{
    QMessageBox *box = new QMessageBox(QMessageBox::Information,
        tr("USB Wi-Fi dongles"),
        tr("<p><b>The dongle drivers for this WSL version could not be "
           "downloaded.</b></p>"
           "<p>WSL on this PC runs the kernel %1. Riff downloads the drivers "
           "for a new WSL kernel by itself, but they are not published yet "
           "(that normally happens automatically within a day) or this PC "
           "is not connected to the Internet. Riff tries again the next "
           "time it starts.</p>"
           "<p>You can also build the drivers on this PC now. It needs an "
           "Internet connection and takes about 10 minutes (about an hour "
           "if the quick way does not work); keep Riff open until it is "
           "done.</p>"
           "<p>The wired Ethernet ports work as usual.</p>")
           .arg(kernel.toHtmlEscaped()),
        QMessageBox::NoButton, this);
    QPushButton *build = box->addButton(tr("Build on This PC"),
                                        QMessageBox::AcceptRole);
    box->addButton(QMessageBox::Close);
    box->setTextFormat(Qt::RichText);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setModal(false);
    connect(box, &QMessageBox::buttonClicked, this,
            [this, build](QAbstractButton *b) {
        if (b == build && wireless_)
            wireless_->buildDrivers();
    });
    box->show();
}

// Until the wireless agent is reachable its port group is shown with what
// Riff is doing (readying the dongles, starting the agent) or what failed
void MainWindow::onWirelessPortStatus(QString text, int kind)
{
    if (kind == 2) {
        if (wirelessPortGroup_ && wirelessPortGroup_->isPending()) {
            pgl->removePortGroup(*wirelessPortGroup_);  // deletes it
            wirelessPortGroup_ = NULL;
        }
        return;
    }
    if (!wirelessPortGroup_) {
        wirelessPortGroup_ = new PortGroup("127.0.0.1", 7879);
        wirelessPortGroup_->setUserAlias(tr("USB Wi-Fi dongles"));
        wirelessPortGroup_->setPending(text, kind == 1);
        pgl->addPortGroup(*wirelessPortGroup_);
    }
    else if (wirelessPortGroup_->isPending())
        wirelessPortGroup_->setPending(text, kind == 1);
}

void MainWindow::on_actionWirelessDongle_triggered()
{
    ensureWireless();
    if (!wirelessDialog_)
        wirelessDialog_ = new WirelessDialog(wireless_, this);
    wirelessDialog_->show();
    wirelessDialog_->raise();
    wirelessDialog_->activateWindow();
    // environment checks spawn wsl.exe/usbipd: run after the dialog is shown
    QTimer::singleShot(0, wirelessDialog_, &WirelessDialog::refresh);
}

// The Linux agent in the RiffWireless distro is an extra port group; its
// ports are the dongle's monitor-mode interface(s)
void MainWindow::onWirelessAgentReady(QString host, quint16 port)
{
    if (wirelessPortGroup_) {
        if (wirelessPortGroup_->isPending())
            wirelessPortGroup_->connectToHost(host, port);
        return;
    }
    wirelessPortGroup_ = new PortGroup(host, port);
    wirelessPortGroup_->setUserAlias(tr("USB Wi-Fi dongles"));
    pgl->addPortGroup(*wirelessPortGroup_);
}

// Port context menu "Wi-Fi Channel...": pick channel + width for one dongle
void MainWindow::onWifiChannelRequested(QString iface, QString description)
{
    if (!wireless_)
        return;
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Wi-Fi Channel"));
    QFormLayout *form = new QFormLayout(&dlg);
    form->addRow(new QLabel(QString("<b>%1</b> &nbsp; %2")
                            .arg(iface, description.toHtmlEscaped())));
    QComboBox *channel = new QComboBox;
    WirelessDialog::fillChannels(channel);
    QComboBox *width = new QComboBox;
    for (int mhz : {20, 40, 80, 160, 320})
        width->addItem(QString("%1 MHz").arg(mhz), mhz);
    // last choice for this interface
    QStringList last = appSettings->value("Wireless/TxChannel/" + iface,
                                          "5180,20").toString().split(',');
    int ci = channel->findData(last.value(0).toInt());
    channel->setCurrentIndex(ci < 0 ? channel->findData(5180) : ci);
    int wi = width->findData(last.value(1).toInt());
    width->setCurrentIndex(wi < 0 ? 0 : wi);
    form->addRow(tr("Channel:"), channel);
    form->addRow(tr("Width:"), width);
    QLabel *note = new QLabel(tr("Frames are sent on this channel. A live "
            "capture on the same dongle follows it."));
    note->setWordWrap(true);
    form->addRow(note);
    QDialogButtonBox *buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(buttons);
    if (dlg.exec() != QDialog::Accepted)
        return;

    int freq = channel->currentData().toInt();
    int mhz = width->currentData().toInt();
    QString error;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    bool ok = wireless_->setChannel(iface, freq, mhz, &error);
    QApplication::restoreOverrideCursor();
    if (!ok) {
        QMessageBox::warning(this, tr("Wi-Fi Channel"), error);
        return;
    }
    appSettings->setValue("Wireless/TxChannel/" + iface,
                          QString("%1,%2").arg(freq).arg(mhz));
    statusBar()->showMessage(tr("%1: %2, %3 MHz wide")
            .arg(iface, channel->currentText()).arg(mhz), 5000);
}

void MainWindow::onWirelessAgentStopped()
{
    if (!wirelessPortGroup_)
        return;
    pgl->removePortGroup(*wirelessPortGroup_);  // deletes it
    wirelessPortGroup_ = NULL;
}
