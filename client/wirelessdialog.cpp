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

#include "wirelessdialog.h"

#include "settings.h"
#include "thememanager.h"
#include "wirelessmanager.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

static const char *kWirelessCountryKey = "Wireless/Country";
static const char *kWirelessChannelKey = "Wireless/Channel";
static const char *kWirelessBusIdsKey = "Wireless/BusIds";
static const char *kWirelessOneWindowKey = "Wireless/CaptureOneWindow";
// per dongle: "Wireless/Capture/<vid_pid_bus>" = "checked,freq,width"
static const char *kWirelessCapturePrefix = "Wireless/Capture/";

WirelessDialog::WirelessDialog(WirelessManager *manager, QWidget *parent)
    : QDialog(parent), manager_(manager),
      wslOk_(false), usbipdOk_(false), distroOk_(false), distroUpdate_(false),
      wiresharkOk_(false), driverWarned_(false), reRegisterTried_(false)
{
    setWindowTitle(tr("Wireless Dongle"));
    resize(760, 780);

    QVBoxLayout *top = new QVBoxLayout(this);

    QLabel *intro = new QLabel(tr(
        "Send and capture raw 802.11 frames through a USB Wi-Fi dongle, "
        "without connecting to an access point. The dongle is passed to "
        "Riff's own WSL environment; your other WSL distributions and "
        "settings are not changed."));
    intro->setWordWrap(true);
    top->addWidget(intro);

    // 1. prerequisites
    QGroupBox *prereq = new QGroupBox(tr("1. Preparation"));
    QFormLayout *pf = new QFormLayout(prereq);
    wslStatus_ = new QLabel;
    wslStatus_->setWordWrap(true);
    wslStatus_->setTextInteractionFlags(Qt::TextBrowserInteraction);
    wslStatus_->setOpenExternalLinks(true);
    usbipdStatus_ = new QLabel;
    usbipdStatus_->setWordWrap(true);
    usbipdStatus_->setTextInteractionFlags(Qt::TextBrowserInteraction);
    usbipdStatus_->setOpenExternalLinks(true);
    distroStatus_ = new QLabel;
    distroStatus_->setWordWrap(true);
    installButton_ = new QPushButton(tr("Set up"));
    QHBoxLayout *dl = new QHBoxLayout;
    dl->addWidget(distroStatus_, 1);
    dl->addWidget(installButton_);
    pf->addRow(tr("WSL:"), wslStatus_);
    pf->addRow(tr("usbipd-win:"), usbipdStatus_);
    pf->addRow(tr("Riff wireless environment:"), dl);
    top->addWidget(prereq);

    // 2. dongle
    QGroupBox *dg = new QGroupBox(tr("2. Dongle"));
    QVBoxLayout *dv = new QVBoxLayout(dg);
    devices_ = new QTreeWidget;
    devices_->setRootIsDecorated(false);
    devices_->setHeaderLabels({tr("Use"), tr("Bus ID"), tr("Device"),
                               tr("Support"), tr("State")});
    devices_->header()->setStretchLastSection(false);
    devices_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    devices_->setMinimumHeight(120);
    dv->addWidget(devices_);
    QHBoxLayout *dh = new QHBoxLayout;
    QLabel *hint = new QLabel(tr("Check the dongle(s) to use. \"Supported\" "
            "dongles have a driver in Riff. A dongle is registered for Riff "
            "the first time it is used and stays with Riff until you give it "
            "back to Windows."));
    hint->setWordWrap(true);
    registerButton_ = new QPushButton(tr("Register for Riff"));
    registerButton_->setToolTip(tr("Take the selected dongle away from its "
            "Windows Wi-Fi driver for good (until you give it back)."));
    returnButton_ = new QPushButton(tr("Give back to Windows"));
    returnButton_->setToolTip(tr("Let Windows use the selected dongle as a "
            "normal Wi-Fi adapter again."));
    refreshButton_ = new QPushButton(tr("Refresh"));
    dh->addWidget(hint, 1);
    dh->addWidget(registerButton_);
    dh->addWidget(returnButton_);
    dh->addWidget(refreshButton_);
    dv->addLayout(dh);
    top->addWidget(dg);

    // 3. radio settings + start
    QGroupBox *rg = new QGroupBox(tr("3. Transmit (use the dongle as a "
                                     "Riff port)"));
    QHBoxLayout *rh = new QHBoxLayout(rg);
    country_ = new QComboBox;
    const char *countries[][2] = {
        {"JP", QT_TR_NOOP("Japan")}, {"US", QT_TR_NOOP("United States")},
        {"GB", QT_TR_NOOP("United Kingdom")}, {"DE", QT_TR_NOOP("Germany")},
        {"FR", QT_TR_NOOP("France")}, {"KR", QT_TR_NOOP("Korea")},
        {"TW", QT_TR_NOOP("Taiwan")}, {"CN", QT_TR_NOOP("China")},
        {"AU", QT_TR_NOOP("Australia")}, {"CA", QT_TR_NOOP("Canada")},
    };
    for (auto &c : countries)
        country_->addItem(QString("%1 (%2)").arg(tr(c[1]), c[0]), c[0]);
    country_->setToolTip(tr("Transmission follows this country's radio "
                            "rules (allowed channels and power)."));
    channel_ = new QComboBox;
    QList<int> chans;
    for (int c = 1; c <= 13; c++)
        chans << c;
    chans << 36 << 40 << 44 << 48 << 52 << 56 << 60 << 64 << 100 << 104
          << 108 << 112 << 116 << 120 << 124 << 128 << 132 << 136 << 140
          << 144 << 149 << 153 << 157 << 161 << 165;
    foreach (int c, chans)
        channel_->addItem(QString("%1  (%2 GHz)").arg(c)
                            .arg(c <= 14 ? "2.4" : "5"), c);
    startButton_ = new QPushButton;
    startButton_->setDefault(true);
    rh->addWidget(new QLabel(tr("Country:")));
    rh->addWidget(country_);
    rh->addSpacing(12);
    rh->addWidget(new QLabel(tr("Channel:")));
    rh->addWidget(channel_);
    rh->addStretch(1);
    rh->addWidget(startButton_);
    top->addWidget(rg);

    // 4. live capture in Wireshark (extcap)
    QGroupBox *cg = new QGroupBox(tr("4. Live capture (Wireshark)"));
    QVBoxLayout *cv = new QVBoxLayout(cg);
    capList_ = new QTreeWidget;
    capList_->setRootIsDecorated(false);
    capList_->setHeaderLabels({tr("Capture"), tr("Bus ID"), tr("Device"),
                               tr("Channel"), tr("Width")});
    capList_->header()->setStretchLastSection(false);
    capList_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    capList_->setMinimumHeight(70);
    capList_->setToolTip(tr("Each supported dongle can capture a different "
            "channel at the same time. A dongle that is also transmitting "
            "is retuned to the capture channel."));
    cv->addWidget(capList_);
    QHBoxLayout *ch4 = new QHBoxLayout;
    captureStatus_ = new QLabel;
    captureStatus_->setWordWrap(true);
    oneWindow_ = new QCheckBox(tr("Show in one Wireshark window"));
    oneWindow_->setToolTip(tr("On: all checked dongles in one Wireshark "
            "window (frames merged; the interface column tells them apart). "
            "Off: one Wireshark window per dongle."));
    oneWindow_->setChecked(appSettings->value(kWirelessOneWindowKey,
                                              true).toBool());
    captureButton_ = new QPushButton(tr("Live Capture in Wireshark"));
    captureButton_->setToolTip(tr("Opens Wireshark capturing live from the "
            "checked dongles on the chosen channels. In Wireshark each "
            "dongle is also listed as \"Wi-Fi monitor: ...\" (channel: the "
            "gear icon next to it). Works with or without the transmit "
            "agent."));
    ch4->addWidget(captureStatus_, 1);
    ch4->addWidget(oneWindow_);
    ch4->addWidget(captureButton_);
    cv->addLayout(ch4);
    top->addWidget(cg);

    log_ = new QPlainTextEdit;
    log_->setReadOnly(true);
    log_->setMaximumBlockCount(500);
    top->addWidget(log_, 1);

    QDialogButtonBox *bb = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    top->addWidget(bb);

    // restore settings
    int ci = country_->findData(appSettings->value(kWirelessCountryKey,
                                                   "JP").toString());
    country_->setCurrentIndex(ci < 0 ? 0 : ci);
    int ch = channel_->findData(appSettings->value(kWirelessChannelKey,
                                                   1).toInt());
    channel_->setCurrentIndex(ch < 0 ? 0 : ch);

    connect(refreshButton_, &QPushButton::clicked, this, &WirelessDialog::refresh);
    connect(installButton_, &QPushButton::clicked, this, &WirelessDialog::onInstall);
    connect(startButton_, &QPushButton::clicked, this, &WirelessDialog::onStartStop);
    connect(captureButton_, &QPushButton::clicked, this, &WirelessDialog::onLiveCapture);
    connect(oneWindow_, &QCheckBox::toggled, this, &WirelessDialog::saveCaptureSettings);
    connect(capList_, &QTreeWidget::itemChanged, this, &WirelessDialog::saveCaptureSettings);
    connect(channel_, static_cast<void (QComboBox::*)(int)>(
                &QComboBox::currentIndexChanged),
            this, &WirelessDialog::onChannelChanged);
    connect(country_, static_cast<void (QComboBox::*)(int)>(
                &QComboBox::currentIndexChanged), this, [this]() {
        appSettings->setValue(kWirelessCountryKey,
                              country_->currentData().toString());
    });
    connect(manager_, &WirelessManager::message, this, &WirelessDialog::onMessage);
    connect(manager_, &WirelessManager::stateChanged,
            this, &WirelessDialog::onStateChanged);
    connect(registerButton_, &QPushButton::clicked, this, &WirelessDialog::onRegister);
    connect(returnButton_, &QPushButton::clicked, this, &WirelessDialog::onGiveBack);
    connect(devices_, &QTreeWidget::currentItemChanged, this, [this]() { updateButtons(); });
    connect(manager_, &WirelessManager::registrationChanged, this, &WirelessDialog::refresh);
    connect(manager_, &WirelessManager::prepared, this, &WirelessDialog::refresh);
    connect(manager_, &WirelessManager::installFinished, this, [this]() {
        refresh();
    });

    updateButtons();
}

void WirelessDialog::setCheck(QLabel *label, bool ok, const QString &text)
{
    QString color = ok ? ThemeManager::instance()->successColor()
                       : ThemeManager::instance()->warningColor();
    label->setText(QString("<span style='color:%1'><b>%2</b></span> %3")
                   .arg(color, ok ? QString::fromUtf8("✓")
                                  : QString::fromUtf8("✗"), text));
}

void WirelessDialog::refresh()
{
    QApplication::setOverrideCursor(Qt::WaitCursor);

    QString detail;
    wslOk_ = manager_->isWslAvailable(&detail);
    setCheck(wslStatus_, wslOk_, wslOk_ ? tr("Available")
        : tr("Not available. Install WSL from an administrator terminal "
             "with <code>wsl --install</code> and restart Windows."));

    usbipdOk_ = !manager_->usbipdPath().isEmpty();
    setCheck(usbipdStatus_, usbipdOk_, usbipdOk_ ? tr("Installed")
        : tr("Not installed. Install it with the Riff installer's "
             "\"Wireless dongle\" option, or from "
             "<a href='https://github.com/dorssel/usbipd-win/releases'>"
             "github.com/dorssel/usbipd-win</a>."));

    distroOk_ = wslOk_ && manager_->isDistroInstalled();
    QString bundled = manager_->bundledVersion();
    distroUpdate_ = distroOk_ && !bundled.isEmpty()
                    && manager_->installedVersion() != bundled;
    if (distroUpdate_)
        setCheck(distroStatus_, true, tr("Installed - an update is available "
                                         "(click Update)."));
    else
        setCheck(distroStatus_, distroOk_, distroOk_ ? tr("Installed")
            : tr("Not set up yet (about 70 MB, takes a minute)."));

    // keep the user's checks across refreshes
    QStringList checked = appSettings->value(kWirelessBusIdsKey).toStringList();
    for (int i = 0; i < devices_->topLevelItemCount(); i++) {
        QTreeWidgetItem *it = devices_->topLevelItem(i);
        QString id = it->text(1);
        checked.removeAll(id);
        if (it->checkState(0) == Qt::Checked)
            checked << id;
    }
    devices_->clear();
    if (usbipdOk_) {
        QString err;
        QList<WirelessManager::UsbDevice> list = manager_->listUsbDevices(&err);
        if (!err.isEmpty())
            onMessage(err, true);
        // supported dongles first
        std::stable_sort(list.begin(), list.end(),
            [](const WirelessManager::UsbDevice &a,
               const WirelessManager::UsbDevice &b) {
                return !a.driver.isEmpty() && b.driver.isEmpty();
            });
        // nothing chosen before (or none of it plugged in): the dongles
        // already registered for Riff - never every supported device
        bool savedPresent = false;
        foreach (const WirelessManager::UsbDevice &d, list)
            if (checked.contains(d.busId))
                savedPresent = true;
        foreach (const WirelessManager::UsbDevice &d, list) {
            QTreeWidgetItem *it = new QTreeWidgetItem(devices_);
            bool sup = !d.driver.isEmpty();
            it->setCheckState(0, sup && (checked.contains(d.busId) ||
                    (!savedPresent && d.registered)) ? Qt::Checked : Qt::Unchecked);
            if (d.windowsCapture)   // AirPcap: a Windows port, never a dongle
                it->setFlags(it->flags() & ~Qt::ItemIsUserCheckable);
            it->setText(1, d.busId);
            it->setText(2, d.name);
            it->setText(3, d.windowsCapture
                    ? (d.registered
                       ? tr("Windows capture adapter - give it back to Windows")
                       : tr("Windows capture adapter (an AirPcap port in Riff)"))
                    : !sup ? tr("Not supported")
                    : d.registered ? tr("Riff only (%1)").arg(d.driver)
                    : d.remembered ? tr("Riff only - register again (%1)")
                                         .arg(d.driver)
                                   : tr("Supported (%1)").arg(d.driver));
            it->setData(3, Qt::UserRole, d.registered);
            it->setData(3, Qt::UserRole + 1, d.remembered);
            it->setData(3, Qt::UserRole + 2, sup);     // a Riff dongle
            it->setData(3, Qt::UserRole + 3, d.windowsCapture);
            it->setText(4, d.state);
            it->setToolTip(2, d.vidPid);
            if (!sup)
                it->setForeground(3, palette().color(QPalette::Disabled,
                                                     QPalette::Text));
        }
        for (int c = 0; c < devices_->columnCount(); c++)
            if (c != 2)
                devices_->resizeColumnToContents(c);
        // known-buggy Windows driver installed: say once how to fix it
        if (!driverWarned_) {
            QString w = manager_->windowsDriverWarning(list);
            if (!w.isEmpty()) {
                onMessage(w, true);
                driverWarned_ = true;
            }
        }
        fillCaptureList(list);
    }
    else {
        fillCaptureList(QList<WirelessManager::UsbDevice>());
    }
    // registered dongles: re-register those that swapped device IDs (once
    // per dialog), then ready them for capture in the background
    if (usbipdOk_ && distroOk_ && !distroUpdate_) {
        bool again = false;
        for (int i = 0; i < devices_->topLevelItemCount(); i++)
            if (devices_->topLevelItem(i)->data(3, Qt::UserRole + 1).toBool())
                again = true;
        if (again && !reRegisterTried_) {
            reRegisterTried_ = true;
            QTimer::singleShot(0, this, [this]() {
                QString err;
                if (!manager_->reRegisterRemembered(&err))
                    onMessage(err, true);
            });
        }
        else if (!again) {
            QTimer::singleShot(0, manager_, &WirelessManager::prepareRegistered);
        }
    }
    // Wireshark + the Riff Wi-Fi extcap (installed/updated automatically)
    wiresharkOk_ = !manager_->wiresharkPath().isEmpty();
    if (!wiresharkOk_) {
        setCheck(captureStatus_, false, tr("Wireshark was not found. Install "
            "it (or set its location in Edit > Preferences) to capture live."));
    }
    else {
        QString err;
        bool ok = manager_->installExtcap(&err);
        setCheck(captureStatus_, ok, ok
            ? tr("Ready. In Wireshark the dongle is listed as \"Wi-Fi "
                 "monitor: ...\" too.")
            : err);
    }

    QApplication::restoreOverrideCursor();
    updateButtons();
}

void WirelessDialog::updateButtons()
{
    int st = manager_->state();
    installButton_->setVisible(wslOk_ && (!distroOk_ || distroUpdate_));
    installButton_->setText(distroOk_ ? tr("Update") : tr("Set up"));
    installButton_->setEnabled(st == WirelessManager::Idle);
    bool ready = wslOk_ && usbipdOk_ && distroOk_;
    switch (st) {
    case WirelessManager::Idle:
        startButton_->setText(tr("Start"));
        startButton_->setEnabled(ready);
        break;
    case WirelessManager::Starting:
        startButton_->setText(tr("Starting..."));
        startButton_->setEnabled(false);
        break;
    case WirelessManager::Running:
        startButton_->setText(tr("Stop"));
        startButton_->setEnabled(true);
        break;
    case WirelessManager::Stopping:
        startButton_->setText(tr("Stopping..."));
        startButton_->setEnabled(false);
        break;
    }
    bool idle = st == WirelessManager::Idle;
    QTreeWidgetItem *cur = devices_->currentItem();
    bool curSupported = cur && cur->data(3, Qt::UserRole + 2).toBool();
    bool curRegistered = cur && cur->data(3, Qt::UserRole).toBool();
    bool envOk = wslOk_ && usbipdOk_;
    registerButton_->setEnabled(envOk && idle && curSupported && !curRegistered);
    returnButton_->setEnabled(envOk && idle && curRegistered);
    // the checks stay as they are while the agent runs, but the list can
    // still be scrolled and read (a disabled list does not scroll)
    for (int i = 0; i < devices_->topLevelItemCount(); i++) {
        QTreeWidgetItem *it = devices_->topLevelItem(i);
        const bool checkable = idle
                && !it->data(3, Qt::UserRole + 3).toBool();
        Qt::ItemFlags f = it->flags();
        f = checkable ? (f | Qt::ItemIsUserCheckable)
                      : (f & ~Qt::ItemIsUserCheckable);
        if (f != it->flags())
            it->setFlags(f);
    }
    refreshButton_->setEnabled(idle);
    country_->setEnabled(idle);
    captureButton_->setEnabled(wslOk_ && usbipdOk_ && distroOk_
                               && wiresharkOk_);
    capList_->setEnabled(wslOk_ && usbipdOk_ && distroOk_);
}

void WirelessDialog::onInstall()
{
    installButton_->setEnabled(false);
    manager_->installDistro();
}

void WirelessDialog::onStartStop()
{
    if (manager_->state() == WirelessManager::Running) {
        manager_->stop();
        return;
    }
    QStringList ids;
    bool unsupported = false;
    for (int i = 0; i < devices_->topLevelItemCount(); i++) {
        QTreeWidgetItem *it = devices_->topLevelItem(i);
        if (it->checkState(0) != Qt::Checked)
            continue;
        ids << it->text(1);
        if (!it->data(3, Qt::UserRole + 2).toBool())
            unsupported = true;
    }
    if (ids.isEmpty()) {
        QMessageBox::information(this, windowTitle(),
                tr("Check the dongle to use in the list."));
        return;
    }
    if (unsupported && QMessageBox::question(this, windowTitle(),
            tr("A checked device is not a supported Wi-Fi dongle. While it "
               "is used by Riff, Windows cannot use it (for example a "
               "keyboard or camera would stop working). Continue?"))
            != QMessageBox::Yes)
        return;
    appSettings->setValue(kWirelessBusIdsKey, ids);
    appSettings->setValue(kWirelessChannelKey, channel_->currentData().toInt());
    log_->clear();
    manager_->start(ids, country_->currentData().toString(),
                    channel_->currentData().toInt());
}

void WirelessDialog::onChannelChanged(int /*index*/)
{
    appSettings->setValue(kWirelessChannelKey, channel_->currentData().toInt());
    if (manager_->state() == WirelessManager::Running)
        manager_->setChannel(channel_->currentData().toInt());
}

void WirelessDialog::onMessage(QString text, bool isError)
{
    QString t = QTime::currentTime().toString("HH:mm:ss");
    QString color = isError ? ThemeManager::instance()->errorColor()
                            : palette().color(QPalette::Text).name();
    log_->appendHtml(QString("<span style='color:%1'>%2&nbsp;&nbsp;%3</span>")
                     .arg(color, t, text.toHtmlEscaped()));
    // always show the latest line
    log_->verticalScrollBar()->setValue(log_->verticalScrollBar()->maximum());
}

void WirelessDialog::onStateChanged(int /*state*/)
{
    updateButtons();
    if (manager_->state() == WirelessManager::Idle)
        refresh();
}


// Channel list for capture: 2.4, 5 and 6 GHz control channels (the dongle
// and the country decide what actually works; the extcap reports it)
void WirelessDialog::fillChannels(QComboBox *box)
{
    for (int c = 1; c <= 14; c++)
        box->addItem(QString("2.4 GHz  ch %1  (%2 MHz)").arg(c)
                     .arg(c == 14 ? 2484 : 2407 + 5 * c),
                     c == 14 ? 2484 : 2407 + 5 * c);
    const int ch5[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                       116, 120, 124, 128, 132, 136, 140, 144, 149, 153,
                       157, 161, 165, 169, 173, 177};
    for (int c : ch5)
        box->addItem(QString("5 GHz  ch %1  (%2 MHz)").arg(c).arg(5000 + 5 * c),
                     5000 + 5 * c);
    for (int c = 1; c <= 233; c += 4)
        box->addItem(QString("6 GHz  ch %1  (%2 MHz)").arg(c).arg(5950 + 5 * c),
                     5950 + 5 * c);
}

static QString captureKey(const WirelessManager::UsbDevice &d)
{
    return QString(kWirelessCapturePrefix)
            + WirelessManager::captureInterface(d);
}

void WirelessDialog::fillCaptureList(
        const QList<WirelessManager::UsbDevice> &list)
{
    capList_->clear();
    int row = 0;
    foreach (const WirelessManager::UsbDevice &d, list) {
        if (d.driver.isEmpty())
            continue;   // supported dongles only
        // "checked,freq,width" - default: first dongle on, 5 GHz ch 36
        QStringList s = appSettings->value(captureKey(d),
                QString("%1,5180,20").arg(row == 0 ? 1 : 0)).toString()
                .split(',');
        QTreeWidgetItem *it = new QTreeWidgetItem(capList_);
        it->setCheckState(0, s.value(0) == "1" ? Qt::Checked : Qt::Unchecked);
        it->setText(1, d.busId);
        it->setText(2, d.name);
        it->setToolTip(2, d.vidPid);
        it->setData(0, Qt::UserRole, d.driver);

        QComboBox *ch = new QComboBox;
        fillChannels(ch);
        int ci = ch->findData(s.value(1).toInt());
        ch->setCurrentIndex(ci < 0 ? ch->findData(5180) : ci);
        QComboBox *w = new QComboBox;
        for (int mhz : {20, 40, 80, 160, 320})
            w->addItem(QString("%1 MHz").arg(mhz), mhz);
        int wi = w->findData(s.value(2).toInt());
        w->setCurrentIndex(wi < 0 ? 0 : wi);
        capList_->setItemWidget(it, 3, ch);
        capList_->setItemWidget(it, 4, w);
        connect(ch, static_cast<void (QComboBox::*)(int)>(
                    &QComboBox::currentIndexChanged),
                this, &WirelessDialog::saveCaptureSettings);
        connect(w, static_cast<void (QComboBox::*)(int)>(
                    &QComboBox::currentIndexChanged),
                this, &WirelessDialog::saveCaptureSettings);
        row++;
    }
    for (int c : {0, 1, 3, 4})
        capList_->resizeColumnToContents(c);
}

void WirelessDialog::saveCaptureSettings()
{
    for (int i = 0; i < capList_->topLevelItemCount(); i++) {
        QTreeWidgetItem *it = capList_->topLevelItem(i);
        WirelessManager::UsbDevice d;
        d.busId = it->text(1);
        d.vidPid = it->toolTip(2);
        QComboBox *ch = qobject_cast<QComboBox*>(capList_->itemWidget(it, 3));
        QComboBox *w = qobject_cast<QComboBox*>(capList_->itemWidget(it, 4));
        if (!ch || !w)
            continue;
        appSettings->setValue(captureKey(d), QString("%1,%2,%3")
                .arg(it->checkState(0) == Qt::Checked ? 1 : 0)
                .arg(ch->currentData().toInt())
                .arg(w->currentData().toInt()));
    }
    appSettings->setValue(kWirelessOneWindowKey, oneWindow_->isChecked());
}

void WirelessDialog::onLiveCapture()
{
    QList<WirelessManager::CaptureTarget> targets;
    for (int i = 0; i < capList_->topLevelItemCount(); i++) {
        QTreeWidgetItem *it = capList_->topLevelItem(i);
        if (it->checkState(0) != Qt::Checked)
            continue;
        QComboBox *ch = qobject_cast<QComboBox*>(capList_->itemWidget(it, 3));
        QComboBox *w = qobject_cast<QComboBox*>(capList_->itemWidget(it, 4));
        WirelessManager::CaptureTarget t;
        t.dev.busId = it->text(1);
        t.dev.name = it->text(2);
        t.dev.vidPid = it->toolTip(2);
        t.freq = ch ? ch->currentData().toInt() : 5180;
        t.width = w ? w->currentData().toInt() : 20;
        targets << t;
    }
    if (targets.isEmpty()) {
        QMessageBox::information(this, windowTitle(),
                tr("Check at least one dongle in the capture list."));
        return;
    }
    saveCaptureSettings();
    QString err;
    if (!manager_->startLiveCapture(targets,
                                    country_->currentData().toString(),
                                    oneWindow_->isChecked(), &err))
        QMessageBox::warning(this, windowTitle(), err);
}

void WirelessDialog::onRegister()
{
    QTreeWidgetItem *cur = devices_->currentItem();
    if (!cur)
        return;
    QString err;
    if (!manager_->registerDongle(cur->text(1), &err)) {
        onMessage(err, true);
        QMessageBox::warning(this, windowTitle(), err);
    }
}

void WirelessDialog::onGiveBack()
{
    QTreeWidgetItem *cur = devices_->currentItem();
    if (!cur)
        return;
    QString text = tr("Give USB %1 back to Windows? It can then be used as a "
                      "normal Wi-Fi adapter, and Riff registers it again "
                      "when you use it next time.").arg(cur->text(1));
    if (QMessageBox::question(this, windowTitle(), text) != QMessageBox::Yes)
        return;
    QString err;
    if (!manager_->unregisterDongle(cur->text(1), &err)) {
        onMessage(err, true);
        QMessageBox::warning(this, windowTitle(), err);
    }
}
