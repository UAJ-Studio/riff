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

#ifndef _WIRELESS_DIALOG_H
#define _WIRELESS_DIALOG_H

#include <QDialog>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTreeWidget;
class WirelessManager;

// Tools > Wireless dongle: set up and run USB Wi-Fi dongles through WSL
class WirelessDialog : public QDialog
{
    Q_OBJECT
public:
    WirelessDialog(WirelessManager *manager, QWidget *parent = 0);

public slots:
    void refresh();

private slots:
    void onStartStop();
    void onInstall();
    void onMessage(QString text, bool isError);
    void onStateChanged(int state);
    void onNeedRebuild(QString kernel);
    void onChannelChanged(int index);

private:
    void setCheck(QLabel *label, bool ok, const QString &text);
    void updateButtons();

    WirelessManager *manager_;
    QLabel *wslStatus_;
    QLabel *usbipdStatus_;
    QLabel *distroStatus_;
    QPushButton *installButton_;
    QTreeWidget *devices_;
    QComboBox *country_;
    QComboBox *channel_;
    QPushButton *startButton_;
    QPushButton *refreshButton_;
    QPlainTextEdit *log_;
    bool wslOk_, usbipdOk_, distroOk_;
};

#endif
