/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff"

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

#ifndef _CAPWAP_CONFIG_H
#define _CAPWAP_CONFIG_H

#include "abstractprotocolconfig.h"

class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QRadioButton;
class QSpinBox;

class CapwapConfigForm : public AbstractProtocolConfigForm
{
    Q_OBJECT
public:
    CapwapConfigForm(QWidget *parent = 0);
    virtual ~CapwapConfigForm();

    static CapwapConfigForm* createInstance();

    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);

private slots:
    void updateEnabled();

private:
    QRadioButton *dataChannel_;
    QRadioButton *controlChannel_;
    QSpinBox *version_;
    QSpinBox *type_;
    QCheckBox *overrideHlen_;
    QSpinBox *hlen_;
    QSpinBox *rid_;
    QComboBox *wbid_;
    QCheckBox *flag_[6];
    QSpinBox *fragmentId_;
    QSpinBox *fragmentOffset_;

    QGroupBox *controlBox_;
    QComboBox *messageType_;
    QSpinBox *seqNum_;
    QCheckBox *overrideMsgLen_;
    QSpinBox *msgLen_;
    QSpinBox *msgFlags_;

    QLabel *hint_;
};

#endif
