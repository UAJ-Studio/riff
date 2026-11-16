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
#include <QTreeWidget>
#include <QVBoxLayout>

static const char *kWirelessCountryKey = "Wireless/Country";
static const char *kWirelessChannelKey = "Wireless/Channel";
static const char *kWirelessBusIdsKey = "Wireless/BusIds";

WirelessDialog::WirelessDialog(WirelessManager *manager, QWidget *parent)
    : QDialog(parent), manager_(manager),
      wslOk_(false), usbipdOk_(false), distroOk_(false), distroUpdate_(false)
{
    setWindowTitle(tr("Wireless Dongle"));
    resize(720, 640);

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
    QLabel *hint = new QLabel(tr("Check the dongle(s) to use. Devices marked "
                                 "\"Supported\" have a driver in Riff."));
    hint->setWordWrap(true);
    refreshButton_ = new QPushButton(tr("Refresh"));
    dh->addWidget(hint, 1);
    dh->addWidget(refreshButton_);
    dv->addLayout(dh);
    top->addWidget(dg);

    // 3. radio settings + start
    QGroupBox *rg = new QGroupBox(tr("3. Radio"));
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
    connect(manager_, &WirelessManager::needRebuild,
            this, &WirelessDialog::onNeedRebuild);
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
        foreach (const WirelessManager::UsbDevice &d, list) {
            QTreeWidgetItem *it = new QTreeWidgetItem(devices_);
            bool sup = !d.driver.isEmpty();
            it->setCheckState(0, (checked.contains(d.busId) ||
                    (checked.isEmpty() && sup)) ? Qt::Checked : Qt::Unchecked);
            it->setText(1, d.busId);
            it->setText(2, d.name);
            it->setText(3, sup ? tr("Supported (%1)").arg(d.driver)
                               : tr("Not supported"));
            it->setText(4, d.state);
            it->setToolTip(2, d.vidPid);
            if (!sup)
                it->setForeground(3, palette().color(QPalette::Disabled,
                                                     QPalette::Text));
        }
        for (int c = 0; c < devices_->columnCount(); c++)
            if (c != 2)
                devices_->resizeColumnToContents(c);
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
    devices_->setEnabled(idle);
    refreshButton_->setEnabled(idle);
    country_->setEnabled(idle);
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
        if (it->text(3) == tr("Not supported"))
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

void WirelessDialog::onNeedRebuild(QString kernel)
{
    onMessage(tr("WSL has been updated (kernel %1): the dongle drivers have "
                 "to be rebuilt for it.").arg(kernel), true);
    QMessageBox::information(this, windowTitle(),
        tr("<p><b>WSL has been updated, so the dongle drivers need to be "
           "rebuilt.</b></p>"
           "<p>Windows updated the WSL kernel to %1. The dongle drivers "
           "included with Riff are built for a specific kernel, so they "
           "have to be rebuilt once for the new one.</p>"
           "<p>Rebuilding takes about an hour and needs an Internet "
           "connection. Your other WSL distributions are not affected.</p>")
           .arg(kernel));
}
