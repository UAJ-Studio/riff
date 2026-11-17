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

#ifndef _DOT11_CONFIG_H
#define _DOT11_CONFIG_H

#include "abstractprotocolconfig.h"

class QCheckBox;
class QComboBox;
class QFormLayout;
class QLabel;
class QLineEdit;
class QSpinBox;
class QStackedWidget;

// The 802.11 forms read and write the protocol's protobuf message directly
// (protoDataCopyInto / protoDataCopyFrom)

class Dot11RadiotapConfigForm : public AbstractProtocolConfigForm
{
    Q_OBJECT
public:
    Dot11RadiotapConfigForm(QWidget *parent = 0);
    static Dot11RadiotapConfigForm* createInstance();
    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);

private slots:
    void updateEnabled();

private:
    QCheckBox *hasRate_;
    QComboBox *rate_;
    QCheckBox *hasTxFlags_;
    QCheckBox *noAck_;
    QCheckBox *noSeq_;
    QCheckBox *hasRetries_;
    QSpinBox *retries_;
    QCheckBox *hasMcs_;
    QSpinBox *mcsIndex_;
    QComboBox *mcsBw_;
    QCheckBox *mcsSgi_;
};

class Dot11ConfigForm : public AbstractProtocolConfigForm
{
    Q_OBJECT
public:
    Dot11ConfigForm(QWidget *parent = 0);
    static Dot11ConfigForm* createInstance();
    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);

private slots:
    void fillSubtypes();
    void updateEnabled();

private:
    QCheckBox *autoType_;
    QComboBox *type_;
    QComboBox *subtype_;
    QSpinBox *version_;
    QCheckBox *flag_[8];
    QSpinBox *duration_;
    QLineEdit *addr_[4];
    QComboBox *addrMode_[4];
    QSpinBox *addrCount_[4];
    QSpinBox *addrStep_[4];
    QSpinBox *seqNum_;
    QCheckBox *seqIncrement_;
    QSpinBox *fragNum_;
    QSpinBox *qos_;
    QLabel *hint_;
};

class Dot11MgmtConfigForm : public AbstractProtocolConfigForm
{
    Q_OBJECT
public:
    Dot11MgmtConfigForm(QWidget *parent = 0);
    static Dot11MgmtConfigForm* createInstance();
    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);

private slots:
    void updateVisible();

private:
    void showRow(QWidget *field, bool show);

    QFormLayout *form_;
    QComboBox *kind_;
    QLineEdit *timestamp_;
    QSpinBox *beaconInterval_;
    QSpinBox *capability_;
    QSpinBox *listenInterval_;
    QLineEdit *currentAp_;
    QSpinBox *status_;
    QSpinBox *aid_;
    QComboBox *authAlg_;
    QSpinBox *authSeq_;
    QComboBox *reason_;
    QSpinBox *category_;
    QLineEdit *actionData_;
    QLabel *hint_;
};

class Dot11IeConfigForm : public AbstractProtocolConfigForm
{
    Q_OBJECT
public:
    Dot11IeConfigForm(QWidget *parent = 0);
    static Dot11IeConfigForm* createInstance();
    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);

private slots:
    void updateEnabled();
    void applyPreset(int index);

private:
    QComboBox *kind_;
    QStackedWidget *pages_;
    QLineEdit *ssid_;
    QCheckBox *ssidNumbered_;
    QSpinBox *ssidCount_;
    QLineEdit *rates_;
    QSpinBox *channel_;
    QComboBox *preset_;
    QSpinBox *elementId_;
    QLineEdit *data_;
    QCheckBox *overrideLength_;
    QSpinBox *length_;
};

#endif
