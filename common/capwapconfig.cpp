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

#include "capwapconfig.h"

#include "capwap.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QRadioButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

const int kFlagFields[6] = {
    CapwapProtocol::capwap_flagT, CapwapProtocol::capwap_flagF,
    CapwapProtocol::capwap_flagL, CapwapProtocol::capwap_flagW,
    CapwapProtocol::capwap_flagM, CapwapProtocol::capwap_flagK,
};

// A spin box + "auto" check box pair: when not overridden the value is
// computed by the protocol and the spin box is disabled
QWidget* overrideRow(QWidget *parent, QCheckBox **check, QSpinBox **spin,
                     int max)
{
    QWidget *w = new QWidget(parent);
    QHBoxLayout *h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    *spin = new QSpinBox(w);
    (*spin)->setRange(0, max);
    *check = new QCheckBox(QObject::tr("Override"), w);
    (*check)->setToolTip(QObject::tr("Unchecked: calculated automatically"));
    h->addWidget(*spin, 1);
    h->addWidget(*check);
    return w;
}

} // namespace

CapwapConfigForm::CapwapConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    // Channel
    QGroupBox *channel = new QGroupBox(tr("Channel"), this);
    QHBoxLayout *ch = new QHBoxLayout(channel);
    dataChannel_ = new QRadioButton(tr("Data (UDP 5247)"), channel);
    controlChannel_ = new QRadioButton(tr("Control (UDP 5246)"), channel);
    dataChannel_->setToolTip(tr("Carries client frames between the WTP "
                                "(access point) and the AC (controller)"));
    controlChannel_->setToolTip(tr("Adds the control message header "
                                   "(message type, sequence number ...)"));
    ch->addWidget(dataChannel_);
    ch->addWidget(controlChannel_);
    ch->addStretch();
    layout->addWidget(channel);

    // Header
    QGroupBox *header = new QGroupBox(tr("CAPWAP header"), this);
    QFormLayout *form = new QFormLayout(header);

    version_ = new QSpinBox(header);
    version_->setRange(0, 15);
    form->addRow(tr("Version"), version_);

    type_ = new QSpinBox(header);
    type_->setRange(0, 15);
    type_->setToolTip(tr("0 = CAPWAP header follows, 1 = DTLS"));
    form->addRow(tr("Type"), type_);

    form->addRow(tr("Header length (HLEN, 4-byte words)"),
                 overrideRow(header, &overrideHlen_, &hlen_, 31));

    rid_ = new QSpinBox(header);
    rid_->setRange(0, 31);
    form->addRow(tr("Radio ID"), rid_);

    wbid_ = new QComboBox(header);
    wbid_->setEditable(true);
    wbid_->addItem(tr("1 - IEEE 802.11"), 1);
    wbid_->addItem(tr("3 - EPCGlobal"), 3);
    wbid_->setToolTip(tr("Wireless binding ID (0 - 31)"));
    form->addRow(tr("Wireless binding ID"), wbid_);

    QWidget *flags = new QWidget(header);
    QGridLayout *fg = new QGridLayout(flags);
    fg->setContentsMargins(0, 0, 0, 0);
    const QString flagText[6] = {
        tr("T: native frame"), tr("F: fragment"),
        tr("L: not last fragment"), tr("W: wireless info"),
        tr("M: radio MAC"), tr("K: keep-alive")};
    const QString flagTip[6] = {
        tr("Off: the payload is an IEEE 802.3 (Ethernet) frame. On: the "
           "payload uses the binding's native format (e.g. IEEE 802.11)."),
        tr("This packet is a fragment"),
        tr("More fragments follow"),
        tr("Wireless specific information is present (set HLEN to "
           "include it, and add the bytes yourself)"),
        tr("Radio MAC address is present (set HLEN to include it, and add "
           "the bytes yourself)"),
        tr("Data channel keep-alive packet")};
    for (int i = 0; i < 6; i++) {
        flag_[i] = new QCheckBox(flagText[i], flags);
        flag_[i]->setToolTip(flagTip[i]);
        fg->addWidget(flag_[i], i / 3, i % 3);
    }
    form->addRow(tr("Flags"), flags);

    fragmentId_ = new QSpinBox(header);
    fragmentId_->setRange(0, 0xFFFF);
    form->addRow(tr("Fragment ID"), fragmentId_);

    fragmentOffset_ = new QSpinBox(header);
    fragmentOffset_->setRange(0, 0x1FFF);
    fragmentOffset_->setToolTip(tr("In units of 8 bytes"));
    form->addRow(tr("Fragment offset"), fragmentOffset_);
    layout->addWidget(header);

    // Control message header
    controlBox_ = new QGroupBox(tr("Control message header"), this);
    QFormLayout *cf = new QFormLayout(controlBox_);
    messageType_ = new QComboBox(controlBox_);
    messageType_->setEditable(true);
    for (quint32 t = 1; t <= 26; t++)
        messageType_->addItem(QString("%1 - %2").arg(t)
                .arg(CapwapProtocol::messageTypeName(t)), t);
    messageType_->setToolTip(tr("Pick a message, or type a number"));
    cf->addRow(tr("Message type"), messageType_);

    seqNum_ = new QSpinBox(controlBox_);
    seqNum_->setRange(0, 255);
    cf->addRow(tr("Sequence number"), seqNum_);

    cf->addRow(tr("Message element length"),
               overrideRow(controlBox_, &overrideMsgLen_, &msgLen_, 0xFFFF));

    msgFlags_ = new QSpinBox(controlBox_);
    msgFlags_->setRange(0, 255);
    cf->addRow(tr("Message flags"), msgFlags_);
    layout->addWidget(controlBox_);

    hint_ = new QLabel(this);
    hint_->setWordWrap(true);
    hint_->setEnabled(false); // secondary text
    layout->addWidget(hint_);
    layout->addStretch();

    connect(dataChannel_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(overrideHlen_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(overrideMsgLen_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(flag_[0], SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    dataChannel_->setChecked(true);
    updateEnabled();
}

CapwapConfigForm::~CapwapConfigForm()
{
}

CapwapConfigForm* CapwapConfigForm::createInstance()
{
    return new CapwapConfigForm;
}

void CapwapConfigForm::updateEnabled()
{
    bool control = controlChannel_->isChecked();
    controlBox_->setEnabled(control);
    hlen_->setEnabled(overrideHlen_->isChecked());
    msgLen_->setEnabled(control && overrideMsgLen_->isChecked());

    if (control)
        hint_->setText(tr("The UDP port is set to 5246 automatically. To "
            "add message elements, put a <i>Hex Dump</i> after CAPWAP in "
            "<b>Protocol Selection &gt; Advanced</b> (each element: type "
            "2 bytes, length 2 bytes, value)."));
    else if (!flag_[0]->isChecked())
        hint_->setText(tr("The UDP port is set to 5247 automatically. With "
            "T off, the payload is an Ethernet frame: in <b>Protocol "
            "Selection &gt; Advanced</b> add it after CAPWAP - e.g. "
            "<i>MAC, Ethernet II, IPv4, UDP</i>."));
    else
        hint_->setText(tr("The UDP port is set to 5247 automatically. With "
            "T on, add the native frame (e.g. IEEE 802.11) after CAPWAP as "
            "a <i>Hex Dump</i>."));
}

void CapwapConfigForm::loadWidget(AbstractProtocol *proto)
{
    auto value = [proto](int field) {
        return proto->fieldData(field, AbstractProtocol::FieldValue).toUInt();
    };

    bool control = proto->fieldData(CapwapProtocol::capwap_isControl,
            AbstractProtocol::FieldValue).toBool();
    controlChannel_->setChecked(control);
    dataChannel_->setChecked(!control);

    version_->setValue(int(value(CapwapProtocol::capwap_version)));
    type_->setValue(int(value(CapwapProtocol::capwap_type)));
    overrideHlen_->setChecked(proto->fieldData(
            CapwapProtocol::capwap_isOverrideHlen,
            AbstractProtocol::FieldValue).toBool());
    hlen_->setValue(int(value(CapwapProtocol::capwap_hlen)));
    rid_->setValue(int(value(CapwapProtocol::capwap_rid)));

    uint wbid = value(CapwapProtocol::capwap_wbid);
    int idx = wbid_->findData(wbid);
    if (idx >= 0)
        wbid_->setCurrentIndex(idx);
    else
        wbid_->setEditText(QString::number(wbid));

    for (int i = 0; i < 6; i++)
        flag_[i]->setChecked(value(kFlagFields[i]) != 0);
    fragmentId_->setValue(int(value(CapwapProtocol::capwap_fragmentId)));
    fragmentOffset_->setValue(
            int(value(CapwapProtocol::capwap_fragmentOffset)));

    // Control header values are kept even while on the data channel
    {
        uint type = value(CapwapProtocol::capwap_messageType);
        idx = messageType_->findData(type);
        if (idx >= 0)
            messageType_->setCurrentIndex(idx);
        else
            messageType_->setEditText(QString::number(type));
        seqNum_->setValue(int(value(CapwapProtocol::capwap_seqNum)));
        msgLen_->setValue(int(value(CapwapProtocol::capwap_msgElemLen)));
        msgFlags_->setValue(int(value(CapwapProtocol::capwap_msgFlags)));
    }
    overrideMsgLen_->setChecked(proto->fieldData(
            CapwapProtocol::capwap_isOverrideMsgElemLen,
            AbstractProtocol::FieldValue).toBool());
    updateEnabled();
}

void CapwapConfigForm::storeWidget(AbstractProtocol *proto)
{
    // "1 - IEEE 802.11" or a typed number: take the leading number
    auto leadingNumber = [](QComboBox *combo, uint fallback) {
        int idx = combo->findText(combo->currentText());
        if (idx >= 0 && combo->itemData(idx).isValid())
            return combo->itemData(idx).toUInt();
        bool ok = false;
        uint v = combo->currentText().section(' ', 0, 0).toUInt(&ok);
        return ok ? v : fallback;
    };

    proto->setFieldData(CapwapProtocol::capwap_isControl,
                        controlChannel_->isChecked());
    proto->setFieldData(CapwapProtocol::capwap_version, version_->value());
    proto->setFieldData(CapwapProtocol::capwap_type, type_->value());
    proto->setFieldData(CapwapProtocol::capwap_isOverrideHlen,
                        overrideHlen_->isChecked());
    proto->setFieldData(CapwapProtocol::capwap_hlen, hlen_->value());
    proto->setFieldData(CapwapProtocol::capwap_rid, rid_->value());
    proto->setFieldData(CapwapProtocol::capwap_wbid,
                        leadingNumber(wbid_, 1) & 0x1F);
    for (int i = 0; i < 6; i++)
        proto->setFieldData(kFlagFields[i], flag_[i]->isChecked() ? 1 : 0);
    proto->setFieldData(CapwapProtocol::capwap_fragmentId,
                        fragmentId_->value());
    proto->setFieldData(CapwapProtocol::capwap_fragmentOffset,
                        fragmentOffset_->value());

    proto->setFieldData(CapwapProtocol::capwap_messageType,
                        leadingNumber(messageType_, 13));
    proto->setFieldData(CapwapProtocol::capwap_seqNum, seqNum_->value());
    proto->setFieldData(CapwapProtocol::capwap_isOverrideMsgElemLen,
                        overrideMsgLen_->isChecked());
    proto->setFieldData(CapwapProtocol::capwap_msgElemLen, msgLen_->value());
    proto->setFieldData(CapwapProtocol::capwap_msgFlags, msgFlags_->value());
}
