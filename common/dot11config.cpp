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

#include "dot11config.h"

#include "dot11.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QStackedWidget>
#include <QVBoxLayout>

namespace {

QLabel* hintLabel(QWidget *parent)
{
    QLabel *l = new QLabel(parent);
    l->setWordWrap(true);
    l->setEnabled(false);   // secondary text
    return l;
}

QSpinBox* spin(QWidget *parent, int max, bool hex = false)
{
    QSpinBox *s = new QSpinBox(parent);
    s->setRange(0, max);
    if (hex) {
        s->setDisplayIntegerBase(16);
        s->setPrefix("0x");
    }
    return s;
}

QLineEdit* macEdit(QWidget *parent)
{
    QLineEdit *e = new QLineEdit(parent);
    e->setInputMask("HH:HH:HH:HH:HH:HH;0");
    e->setMinimumWidth(e->fontMetrics().width("00:00:00:00:00:00") + 16);
    return e;
}

void setMac(QLineEdit *e, quint64 mac)
{
    e->setText(Dot11ProtocolBase::macText(mac));
}

quint64 mac(const QLineEdit *e)
{
    // displayText(): with the blank character "0" of the input mask, text()
    // drops every 0 digit (02:00:00:00:02:00 would read as 0x22)
    QString hex = e->displayText().remove(QLatin1Char(':'));
    return hex.toULongLong(nullptr, 16) & 0xFFFFFFFFFFFFULL;
}

// "3 - SAE" or a typed number: the leading number
uint leadingNumber(const QComboBox *combo, uint fallback)
{
    int idx = combo->findText(combo->currentText());
    if (idx >= 0 && combo->itemData(idx).isValid())
        return combo->itemData(idx).toUInt();
    bool ok = false;
    uint v = combo->currentText().section(' ', 0, 0).toUInt(&ok);
    return ok ? v : fallback;
}

void setNumber(QComboBox *combo, uint value)
{
    int idx = combo->findData(value);
    if (idx >= 0)
        combo->setCurrentIndex(idx);
    else
        combo->setEditText(QString::number(value));
}

QString hexText(const std::string &bytes)
{
    return QString(QByteArray(bytes.data(), int(bytes.size())).toHex(' '));
}

std::string hexBytes(const QString &text)
{
    QByteArray b = QByteArray::fromHex(text.toLatin1());
    return std::string(b.constData(), size_t(b.size()));
}

} // namespace

// ---- Radiotap (TX) -------------------------------------------------------

Dot11RadiotapConfigForm::Dot11RadiotapConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    QGroupBox *box = new QGroupBox(tr("Radiotap header (transmit settings)"),
                                   this);
    QGridLayout *g = new QGridLayout(box);
    int row = 0;

    hasRate_ = new QCheckBox(tr("Rate"), box);
    rate_ = new QComboBox(box);
    rate_->setEditable(true);
    const double rates[] = {1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54};
    for (double r : rates)
        rate_->addItem(QString("%1 Mb/s").arg(r), int(r * 2));
    rate_->setToolTip(tr("Legacy rate. 1, 2, 5.5 and 11 Mb/s (CCK) are only "
                         "valid on 2.4 GHz"));
    g->addWidget(hasRate_, row, 0);
    g->addWidget(rate_, row++, 1, 1, 3);

    hasTxFlags_ = new QCheckBox(tr("TX flags"), box);
    noAck_ = new QCheckBox(tr("No ACK expected"), box);
    noAck_->setToolTip(tr("Send unicast frames once, without waiting for "
                          "an ACK or retrying"));
    noSeq_ = new QCheckBox(tr("Keep my sequence number"), box);
    noSeq_->setToolTip(tr("Ask the driver not to overwrite the 802.11 "
                          "sequence number"));
    g->addWidget(hasTxFlags_, row, 0);
    g->addWidget(noAck_, row, 1);
    g->addWidget(noSeq_, row++, 2, 1, 2);

    hasRetries_ = new QCheckBox(tr("Data retries"), box);
    retries_ = spin(box, 15);
    g->addWidget(hasRetries_, row, 0);
    g->addWidget(retries_, row++, 1);

    hasMcs_ = new QCheckBox(tr("MCS (HT)"), box);
    mcsIndex_ = spin(box, 31);
    mcsIndex_->setPrefix(tr("MCS "));
    mcsBw_ = new QComboBox(box);
    mcsBw_->addItem(tr("20 MHz"), 0);
    mcsBw_->addItem(tr("40 MHz"), 1);
    mcsSgi_ = new QCheckBox(tr("Short GI"), box);
    hasMcs_->setToolTip(tr("Send with an HT (802.11n) rate instead of the "
                           "legacy rate"));
    g->addWidget(hasMcs_, row, 0);
    g->addWidget(mcsIndex_, row, 1);
    g->addWidget(mcsBw_, row, 2);
    g->addWidget(mcsSgi_, row++, 3);
    g->setColumnStretch(4, 1);
    layout->addWidget(box);

    QLabel *hint = hintLabel(this);
    hint->setText(tr("The radiotap header tells the wireless dongle how to "
        "send the frame; it is not sent over the air. Put it first, then "
        "<i>802.11</i> and the frame body (<i>802.11 Mgmt</i> + <i>802.11 "
        "IE</i>, or <i>LLC</i> + <i>SNAP</i> + IPv4 ...). Frames starting with "
        "Radiotap TX are sent exactly as built: the frame length setting is "
        "not used, except to size a <i>Payload</i>."));
    layout->addWidget(hint);
    layout->addStretch();

    connect(hasRate_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(hasTxFlags_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(hasRetries_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(hasMcs_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    updateEnabled();
}

Dot11RadiotapConfigForm* Dot11RadiotapConfigForm::createInstance()
{
    return new Dot11RadiotapConfigForm;
}

void Dot11RadiotapConfigForm::updateEnabled()
{
    rate_->setEnabled(hasRate_->isChecked());
    noAck_->setEnabled(hasTxFlags_->isChecked());
    noSeq_->setEnabled(hasTxFlags_->isChecked());
    retries_->setEnabled(hasRetries_->isChecked());
    mcsIndex_->setEnabled(hasMcs_->isChecked());
    mcsBw_->setEnabled(hasMcs_->isChecked());
    mcsSgi_->setEnabled(hasMcs_->isChecked());
}

void Dot11RadiotapConfigForm::loadWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    const OstProto::Dot11Radiotap &d = p.GetExtension(OstProto::dot11_radiotap);

    hasRate_->setChecked(d.use_rate());
    int idx = rate_->findData(int(d.rate()));
    if (idx >= 0)
        rate_->setCurrentIndex(idx);
    else
        rate_->setEditText(QString("%1 Mb/s").arg(d.rate() / 2.0));
    hasTxFlags_->setChecked(d.use_tx_flags());
    noAck_->setChecked(d.tx_flags() & DOT11_TXF_NOACK);
    noSeq_->setChecked(d.tx_flags() & DOT11_TXF_NOSEQ);
    hasRetries_->setChecked(d.use_retries());
    retries_->setValue(int(d.retries()));
    hasMcs_->setChecked(d.use_mcs());
    mcsIndex_->setValue(int(d.mcs_index()));
    mcsBw_->setCurrentIndex(d.mcs_bw() == 1 ? 1 : 0);
    mcsSgi_->setChecked(d.mcs_sgi());
    updateEnabled();
}

void Dot11RadiotapConfigForm::storeWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    OstProto::Dot11Radiotap *d = p.MutableExtension(OstProto::dot11_radiotap);

    d->set_use_rate(hasRate_->isChecked());
    int idx = rate_->findText(rate_->currentText());
    if (idx >= 0) {
        d->set_rate(rate_->itemData(idx).toUInt());
    }
    else {
        bool ok = false;
        double mbps = rate_->currentText().section(' ', 0, 0).toDouble(&ok);
        if (ok && mbps > 0 && mbps < 128)
            d->set_rate(uint(mbps * 2 + 0.5));
    }
    d->set_use_tx_flags(hasTxFlags_->isChecked());
    uint txf = d->tx_flags() & ~uint(DOT11_TXF_NOACK | DOT11_TXF_NOSEQ);
    if (noAck_->isChecked())
        txf |= DOT11_TXF_NOACK;
    if (noSeq_->isChecked())
        txf |= DOT11_TXF_NOSEQ;
    d->set_tx_flags(txf);
    d->set_use_retries(hasRetries_->isChecked());
    d->set_retries(uint(retries_->value()));
    d->set_use_mcs(hasMcs_->isChecked());
    d->set_mcs_index(uint(mcsIndex_->value()));
    d->set_mcs_bw(uint(mcsBw_->currentData().toUInt()));
    d->set_mcs_sgi(mcsSgi_->isChecked());
    proto->protoDataCopyFrom(p);
}

// ---- 802.11 header -------------------------------------------------------

Dot11ConfigForm::Dot11ConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    // Frame control
    QGroupBox *fcBox = new QGroupBox(tr("Frame control"), this);
    QGridLayout *fc = new QGridLayout(fcBox);
    autoType_ = new QCheckBox(tr("Auto type/subtype"), fcBox);
    autoType_->setToolTip(tr("Followed by 802.11 Mgmt: management frame "
        "of that body's kind. Followed by LLC or SNAP: data frame. "
        "Otherwise the type and subtype below."));
    type_ = new QComboBox(fcBox);
    type_->addItem(tr("0 - Management"), 0);
    type_->addItem(tr("1 - Control"), 1);
    type_->addItem(tr("2 - Data"), 2);
    type_->addItem(tr("3 - Extension"), 3);
    subtype_ = new QComboBox(fcBox);
    version_ = spin(fcBox, 3);
    fc->addWidget(autoType_, 0, 0, 1, 2);
    fc->addWidget(new QLabel(tr("Type"), fcBox), 1, 0);
    fc->addWidget(type_, 1, 1);
    fc->addWidget(new QLabel(tr("Subtype"), fcBox), 1, 2);
    fc->addWidget(subtype_, 1, 3);
    fc->addWidget(new QLabel(tr("Version"), fcBox), 1, 4);
    fc->addWidget(version_, 1, 5);

    const QString flagText[8] = {
        tr("To DS"), tr("From DS"), tr("More fragments"), tr("Retry"),
        tr("Power management"), tr("More data"), tr("Protected"),
        tr("+HTC / Order")};
    QWidget *flags = new QWidget(fcBox);
    QGridLayout *fg = new QGridLayout(flags);
    fg->setContentsMargins(0, 0, 0, 0);
    for (int i = 0; i < 8; i++) {
        flag_[i] = new QCheckBox(flagText[i], flags);
        fg->addWidget(flag_[i], i / 4, i % 4);
    }
    flag_[6]->setToolTip(tr("Only sets the bit: the body is not "
                            "encrypted"));
    fc->addWidget(new QLabel(tr("Flags"), fcBox), 2, 0);
    fc->addWidget(flags, 2, 1, 1, 5);
    fc->setColumnStretch(6, 1);
    layout->addWidget(fcBox);

    // Addresses
    QGroupBox *addrBox = new QGroupBox(tr("Addresses"), this);
    QGridLayout *ag = new QGridLayout(addrBox);
    const QString addrName[4] = {
        tr("Address 1 (receiver / destination)"),
        tr("Address 2 (transmitter / source)"),
        tr("Address 3 (BSSID)"),
        tr("Address 4 (To DS + From DS only)")};
    ag->addWidget(new QLabel(tr("Mode"), addrBox), 0, 2);
    ag->addWidget(new QLabel(tr("Count"), addrBox), 0, 3);
    ag->addWidget(new QLabel(tr("Step"), addrBox), 0, 4);
    for (int i = 0; i < 4; i++) {
        addr_[i] = macEdit(addrBox);
        addrMode_[i] = new QComboBox(addrBox);
        addrMode_[i]->addItem(tr("Fixed"), OstProto::Dot11Vary::kFixed);
        addrMode_[i]->addItem(tr("Increment"),
                              OstProto::Dot11Vary::kIncrement);
        addrMode_[i]->addItem(tr("Decrement"),
                              OstProto::Dot11Vary::kDecrement);
        addrMode_[i]->addItem(tr("Random"), OstProto::Dot11Vary::kRandom);
        addrMode_[i]->setToolTip(tr("Random: a different locally "
            "administered unicast address per packet (repeats after Count "
            "packets)"));
        addrCount_[i] = spin(addrBox, 65535);
        addrCount_[i]->setMinimum(1);
        addrStep_[i] = spin(addrBox, 65535);
        addrStep_[i]->setMinimum(1);
        ag->addWidget(new QLabel(addrName[i], addrBox), i + 1, 0);
        ag->addWidget(addr_[i], i + 1, 1);
        ag->addWidget(addrMode_[i], i + 1, 2);
        ag->addWidget(addrCount_[i], i + 1, 3);
        ag->addWidget(addrStep_[i], i + 1, 4);
        connect(addrMode_[i], SIGNAL(currentIndexChanged(int)),
                SLOT(updateEnabled()));
    }
    ag->setColumnStretch(5, 1);
    layout->addWidget(addrBox);

    // Other fields
    QGroupBox *other = new QGroupBox(tr("Other fields"), this);
    QGridLayout *og = new QGridLayout(other);
    duration_ = spin(other, 65535);
    seqNum_ = spin(other, 4095);
    seqIncrement_ = new QCheckBox(tr("Increment per packet"), other);
    seqIncrement_->setToolTip(tr("Sequence number + 1 for every packet "
                                 "(wraps after 4095)"));
    fragNum_ = spin(other, 15);
    qos_ = spin(other, 65535, true);
    qos_->setToolTip(tr("QoS data frames only. Bits 0-3: TID"));
    og->addWidget(new QLabel(tr("Duration / ID"), other), 0, 0);
    og->addWidget(duration_, 0, 1);
    og->addWidget(new QLabel(tr("Sequence number"), other), 1, 0);
    og->addWidget(seqNum_, 1, 1);
    og->addWidget(seqIncrement_, 1, 2);
    og->addWidget(new QLabel(tr("Fragment number"), other), 2, 0);
    og->addWidget(fragNum_, 2, 1);
    og->addWidget(new QLabel(tr("QoS control"), other), 3, 0);
    og->addWidget(qos_, 3, 1);
    og->setColumnStretch(3, 1);
    layout->addWidget(other);

    hint_ = hintLabel(this);
    hint_->setText(tr("Header length follows the frame type: control "
        "frames have no Address 3 / sequence control (CTS and ACK only "
        "Address 1), Address 4 is added for data frames with To DS and "
        "From DS, QoS control for QoS data subtypes."));
    layout->addWidget(hint_);
    layout->addStretch();

    connect(type_, SIGNAL(currentIndexChanged(int)), SLOT(fillSubtypes()));
    connect(autoType_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(seqIncrement_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    fillSubtypes();
    updateEnabled();
}

Dot11ConfigForm* Dot11ConfigForm::createInstance()
{
    return new Dot11ConfigForm;
}

void Dot11ConfigForm::fillSubtypes()
{
    uint keep = subtype_->count() ? subtype_->currentData().toUInt() : 0;
    uint type = type_->currentData().toUInt();
    subtype_->clear();
    for (uint s = 0; s < 16; s++) {
        QString n = Dot11Protocol::typeName(type, s);
        subtype_->addItem(QString("%1 - %2").arg(s)
                .arg(n.isEmpty() ? tr("Reserved") : n), s);
    }
    subtype_->setCurrentIndex(int(keep));
}

void Dot11ConfigForm::updateEnabled()
{
    bool manual = !autoType_->isChecked();
    type_->setEnabled(manual);
    subtype_->setEnabled(manual);
    for (int i = 0; i < 4; i++) {
        bool vary = addrMode_[i]->currentData().toInt()
                        != OstProto::Dot11Vary::kFixed;
        bool step = vary && addrMode_[i]->currentData().toInt()
                        != OstProto::Dot11Vary::kRandom;
        addrCount_[i]->setEnabled(vary);
        addrStep_[i]->setEnabled(step);
    }
}

void Dot11ConfigForm::loadWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    const OstProto::Dot11 &d = p.GetExtension(OstProto::dot11);

    autoType_->setChecked(d.is_auto_type());
    type_->setCurrentIndex(int(d.type() & 3));
    fillSubtypes();
    subtype_->setCurrentIndex(int(d.subtype() & 0xF));
    version_->setValue(int(d.version() & 3));
    for (int i = 0; i < 8; i++)
        flag_[i]->setChecked(d.flags() & (1u << i));
    duration_->setValue(int(d.duration() & 0xFFFF));

    const quint64 a[4] = {d.addr1(), d.addr2(), d.addr3(), d.addr4()};
    const OstProto::Dot11Vary *v[4] = {&d.addr1_vary(), &d.addr2_vary(),
                                       &d.addr3_vary(), &d.addr4_vary()};
    for (int i = 0; i < 4; i++) {
        setMac(addr_[i], a[i]);
        addrMode_[i]->setCurrentIndex(addrMode_[i]->findData(
                int(v[i]->mode())));
        addrCount_[i]->setValue(int(v[i]->count()));
        addrStep_[i]->setValue(int(v[i]->step()));
    }
    seqNum_->setValue(int(d.seq_num() & 0xFFF));
    seqIncrement_->setChecked(d.seq_increment());
    fragNum_->setValue(int(d.frag_num() & 0xF));
    qos_->setValue(int(d.qos_control() & 0xFFFF));
    updateEnabled();
}

void Dot11ConfigForm::storeWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    OstProto::Dot11 *d = p.MutableExtension(OstProto::dot11);

    d->set_is_auto_type(autoType_->isChecked());
    d->set_type(type_->currentData().toUInt());
    d->set_subtype(subtype_->currentData().toUInt());
    d->set_version(uint(version_->value()));
    uint flags = 0;
    for (int i = 0; i < 8; i++)
        if (flag_[i]->isChecked())
            flags |= 1u << i;
    d->set_flags(flags);
    d->set_duration(uint(duration_->value()));

    d->set_addr1(mac(addr_[0]));
    d->set_addr2(mac(addr_[1]));
    d->set_addr3(mac(addr_[2]));
    d->set_addr4(mac(addr_[3]));
    OstProto::Dot11Vary *v[4] = {d->mutable_addr1_vary(),
                                 d->mutable_addr2_vary(),
                                 d->mutable_addr3_vary(),
                                 d->mutable_addr4_vary()};
    for (int i = 0; i < 4; i++) {
        v[i]->set_mode(OstProto::Dot11Vary::Mode(
                addrMode_[i]->currentData().toInt()));
        v[i]->set_count(uint(addrCount_[i]->value()));
        v[i]->set_step(uint(addrStep_[i]->value()));
    }
    d->set_seq_num(uint(seqNum_->value()));
    d->set_seq_increment(seqIncrement_->isChecked());
    d->set_frag_num(uint(fragNum_->value()));
    d->set_qos_control(uint(qos_->value()));
    proto->protoDataCopyFrom(p);
}

// ---- Management body -----------------------------------------------------

Dot11MgmtConfigForm::Dot11MgmtConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    QGroupBox *box = new QGroupBox(tr("Management frame body"), this);
    form_ = new QFormLayout(box);

    kind_ = new QComboBox(box);
    const int kinds[] = {
        OstProto::Dot11Mgmt::kProbeRequest, OstProto::Dot11Mgmt::kProbeResponse,
        OstProto::Dot11Mgmt::kBeacon, OstProto::Dot11Mgmt::kAuth,
        OstProto::Dot11Mgmt::kDeauth, OstProto::Dot11Mgmt::kAssocRequest,
        OstProto::Dot11Mgmt::kAssocResponse,
        OstProto::Dot11Mgmt::kReassocRequest,
        OstProto::Dot11Mgmt::kReassocResponse,
        OstProto::Dot11Mgmt::kDisassoc, OstProto::Dot11Mgmt::kAction,
        OstProto::Dot11Mgmt::kAtim};
    for (int k : kinds)
        kind_->addItem(QString("%1 (%2)").arg(Dot11MgmtProtocol::kindName(
                quint32(k))).arg(k), k);
    kind_->setToolTip(tr("The number is the subtype; with Auto type/subtype "
                         "the 802.11 header uses it"));
    form_->addRow(tr("Frame"), kind_);

    timestamp_ = new QLineEdit(box);
    timestamp_->setToolTip(tr("Microseconds (decimal, or hex with 0x)"));
    form_->addRow(tr("Timestamp"), timestamp_);
    beaconInterval_ = spin(box, 65535);
    beaconInterval_->setSuffix(tr(" TU"));
    beaconInterval_->setToolTip(tr("1 TU = 1.024 ms"));
    form_->addRow(tr("Beacon interval"), beaconInterval_);
    capability_ = spin(box, 65535, true);
    capability_->setToolTip(tr("0x0001 ESS, 0x0002 IBSS, 0x0010 Privacy, "
        "0x0020 Short preamble, 0x0400 Short slot time"));
    form_->addRow(tr("Capability information"), capability_);
    listenInterval_ = spin(box, 65535);
    form_->addRow(tr("Listen interval"), listenInterval_);
    currentAp_ = macEdit(box);
    form_->addRow(tr("Current AP address"), currentAp_);
    status_ = spin(box, 65535);
    status_->setToolTip(tr("0 = success"));
    form_->addRow(tr("Status code"), status_);
    aid_ = spin(box, 65535, true);
    aid_->setToolTip(tr("Association ID with the two top bits set "
                        "(0xC001 = AID 1)"));
    form_->addRow(tr("Association ID"), aid_);
    authAlg_ = new QComboBox(box);
    authAlg_->setEditable(true);
    authAlg_->addItem(tr("0 - Open System"), 0);
    authAlg_->addItem(tr("1 - Shared Key"), 1);
    authAlg_->addItem(tr("2 - Fast BSS Transition"), 2);
    authAlg_->addItem(tr("3 - SAE"), 3);
    form_->addRow(tr("Authentication algorithm"), authAlg_);
    authSeq_ = spin(box, 65535);
    form_->addRow(tr("Authentication sequence"), authSeq_);
    reason_ = new QComboBox(box);
    reason_->setEditable(true);
    reason_->addItem(tr("1 - Unspecified"), 1);
    reason_->addItem(tr("2 - Previous authentication no longer valid"), 2);
    reason_->addItem(tr("3 - Leaving (deauthenticated)"), 3);
    reason_->addItem(tr("4 - Inactivity"), 4);
    reason_->addItem(tr("6 - Class 2 frame from non-authenticated STA"), 6);
    reason_->addItem(tr("7 - Class 3 frame from non-associated STA"), 7);
    reason_->addItem(tr("8 - Leaving (disassociated)"), 8);
    form_->addRow(tr("Reason code"), reason_);
    category_ = spin(box, 255);
    category_->setToolTip(tr("e.g. 0 Spectrum management, 3 Block Ack, "
                             "4 Public, 127 Vendor specific"));
    form_->addRow(tr("Action category"), category_);
    actionData_ = new QLineEdit(box);
    actionData_->setPlaceholderText(tr("hex bytes, e.g. 00 50 f2 01"));
    form_->addRow(tr("Action details"), actionData_);
    layout->addWidget(box);

    hint_ = hintLabel(this);
    hint_->setText(tr("Add information elements (<i>802.11 IE</i>: SSID, "
        "rates, channel ...) after this body in <b>Protocol Selection &gt; "
        "Advanced</b>. A Probe Request has no fixed fields, only "
        "elements."));
    layout->addWidget(hint_);
    layout->addStretch();

    connect(kind_, SIGNAL(currentIndexChanged(int)), SLOT(updateVisible()));
    updateVisible();
}

Dot11MgmtConfigForm* Dot11MgmtConfigForm::createInstance()
{
    return new Dot11MgmtConfigForm;
}

void Dot11MgmtConfigForm::showRow(QWidget *field, bool show)
{
    field->setVisible(show);
    if (QWidget *label = form_->labelForField(field))
        label->setVisible(show);
}

void Dot11MgmtConfigForm::updateVisible()
{
    const int k = kind_->currentData().toInt();
    const bool beacon = k == OstProto::Dot11Mgmt::kBeacon
                     || k == OstProto::Dot11Mgmt::kProbeResponse;
    const bool assocReq = k == OstProto::Dot11Mgmt::kAssocRequest
                       || k == OstProto::Dot11Mgmt::kReassocRequest;
    const bool assocResp = k == OstProto::Dot11Mgmt::kAssocResponse
                        || k == OstProto::Dot11Mgmt::kReassocResponse;
    const bool auth = k == OstProto::Dot11Mgmt::kAuth;
    showRow(timestamp_, beacon);
    showRow(beaconInterval_, beacon);
    showRow(capability_, beacon || assocReq || assocResp);
    showRow(listenInterval_, assocReq);
    showRow(currentAp_, k == OstProto::Dot11Mgmt::kReassocRequest);
    showRow(status_, assocResp || auth);
    showRow(aid_, assocResp);
    showRow(authAlg_, auth);
    showRow(authSeq_, auth);
    showRow(reason_, k == OstProto::Dot11Mgmt::kDisassoc
                     || k == OstProto::Dot11Mgmt::kDeauth);
    showRow(category_, k == OstProto::Dot11Mgmt::kAction);
    showRow(actionData_, k == OstProto::Dot11Mgmt::kAction);
}

void Dot11MgmtConfigForm::loadWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    const OstProto::Dot11Mgmt &d = p.GetExtension(OstProto::dot11_mgmt);

    int idx = kind_->findData(int(d.kind()));
    kind_->setCurrentIndex(idx >= 0 ? idx : 0);
    timestamp_->setText(QString::number(d.timestamp()));
    beaconInterval_->setValue(int(d.beacon_interval() & 0xFFFF));
    capability_->setValue(int(d.capability() & 0xFFFF));
    listenInterval_->setValue(int(d.listen_interval() & 0xFFFF));
    setMac(currentAp_, d.current_ap());
    status_->setValue(int(d.status() & 0xFFFF));
    aid_->setValue(int(d.aid() & 0xFFFF));
    setNumber(authAlg_, d.auth_alg());
    authSeq_->setValue(int(d.auth_seq() & 0xFFFF));
    setNumber(reason_, d.reason());
    category_->setValue(int(d.action_category() & 0xFF));
    actionData_->setText(hexText(d.action_data()));
    updateVisible();
}

void Dot11MgmtConfigForm::storeWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    OstProto::Dot11Mgmt *d = p.MutableExtension(OstProto::dot11_mgmt);

    d->set_kind(OstProto::Dot11Mgmt::Kind(kind_->currentData().toInt()));
    bool ok = false;
    quint64 ts = timestamp_->text().trimmed().toULongLong(&ok, 0);
    d->set_timestamp(ok ? ts : 0);
    d->set_beacon_interval(uint(beaconInterval_->value()));
    d->set_capability(uint(capability_->value()));
    d->set_listen_interval(uint(listenInterval_->value()));
    d->set_current_ap(mac(currentAp_));
    d->set_status(uint(status_->value()));
    d->set_aid(uint(aid_->value()));
    d->set_auth_alg(leadingNumber(authAlg_, 0) & 0xFFFF);
    d->set_auth_seq(uint(authSeq_->value()));
    d->set_reason(leadingNumber(reason_, 7) & 0xFFFF);
    d->set_action_category(uint(category_->value()));
    d->set_action_data(hexBytes(actionData_->text()));
    proto->protoDataCopyFrom(p);
}

// ---- Information element -------------------------------------------------

namespace {

struct IePreset {
    const char *name;
    int id;
    const char *hex;
};

// Ready-made element bodies for the Generic page
const IePreset kPresets[] = {
    {"TIM (DTIM period 1)", 5, "00 01 00 00"},
    {"Country JP (2.4 GHz 1-13, 5 GHz 36-48)", 7,
     "4a 50 20 01 0d 14 24 04 17 00"},
    {"RSN WPA2-PSK CCMP", 48,
     "01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 00 00"},
    {"HT Capabilities (MCS 0-15)", 45,
     "2c 01 03 ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
     "00 00 00"},
    {"Extended Capabilities", 127, "00 00 00 00 00 00 00 40"},
    {"WMM information (vendor 00:50:f2)", 221, "00 50 f2 02 00 01 00"},
};

} // namespace

Dot11IeConfigForm::Dot11IeConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    QGroupBox *box = new QGroupBox(tr("Information element"), this);
    QVBoxLayout *bl = new QVBoxLayout(box);

    QFormLayout *top = new QFormLayout;
    kind_ = new QComboBox(box);
    kind_->addItem(tr("SSID (0)"), OstProto::Dot11Ie::kSsid);
    kind_->addItem(tr("Supported Rates (1)"), OstProto::Dot11Ie::kRates);
    kind_->addItem(tr("DS Parameter Set - channel (3)"),
                   OstProto::Dot11Ie::kDsParam);
    kind_->addItem(tr("Other element (ID + hex data)"),
                   OstProto::Dot11Ie::kGeneric);
    top->addRow(tr("Element"), kind_);
    bl->addLayout(top);

    pages_ = new QStackedWidget(box);

    // SSID
    QWidget *ssidPage = new QWidget(pages_);
    QFormLayout *sf = new QFormLayout(ssidPage);
    sf->setContentsMargins(0, 0, 0, 0);
    ssid_ = new QLineEdit(ssidPage);
    ssid_->setToolTip(tr("Empty: wildcard SSID (Probe Request) / hidden "
                         "network (Beacon)"));
    sf->addRow(tr("SSID"), ssid_);
    QWidget *num = new QWidget(ssidPage);
    QHBoxLayout *nl = new QHBoxLayout(num);
    nl->setContentsMargins(0, 0, 0, 0);
    ssidNumbered_ = new QCheckBox(tr("Append a number 1 ... N per packet"),
                                  num);
    ssidCount_ = spin(num, 65535);
    ssidCount_->setMinimum(1);
    ssidCount_->setPrefix(tr("N = "));
    nl->addWidget(ssidNumbered_);
    nl->addWidget(ssidCount_);
    nl->addStretch();
    sf->addRow(QString(), num);
    pages_->addWidget(ssidPage);

    // Rates
    QWidget *ratesPage = new QWidget(pages_);
    QFormLayout *rf = new QFormLayout(ratesPage);
    rf->setContentsMargins(0, 0, 0, 0);
    rates_ = new QLineEdit(ratesPage);
    rf->addRow(tr("Rates (Mb/s)"), rates_);
    QLabel *rh = hintLabel(ratesPage);
    rh->setText(tr("Comma separated, * marks a basic rate, e.g. "
        "<tt>1*,2*,5.5*,11*,6,9,12,18</tt> (2.4 GHz) or "
        "<tt>6*,9,12*,18,24*,36,48,54</tt> (5 GHz). Rates beyond the "
        "eighth go into an Extended Supported Rates element."));
    rf->addRow(QString(), rh);
    pages_->addWidget(ratesPage);

    // DS parameter
    QWidget *dsPage = new QWidget(pages_);
    QFormLayout *df = new QFormLayout(dsPage);
    df->setContentsMargins(0, 0, 0, 0);
    channel_ = spin(dsPage, 255);
    df->addRow(tr("Channel"), channel_);
    pages_->addWidget(dsPage);

    // Generic
    QWidget *genPage = new QWidget(pages_);
    QFormLayout *gf = new QFormLayout(genPage);
    gf->setContentsMargins(0, 0, 0, 0);
    preset_ = new QComboBox(genPage);
    preset_->addItem(tr("(choose to fill in)"));
    for (const IePreset &p : kPresets)
        preset_->addItem(QString("%1 - %2").arg(p.id).arg(p.name));
    gf->addRow(tr("Template"), preset_);
    elementId_ = spin(genPage, 255);
    gf->addRow(tr("Element ID"), elementId_);
    data_ = new QLineEdit(genPage);
    data_->setPlaceholderText(tr("hex bytes, e.g. 00 50 f2 02"));
    gf->addRow(tr("Data"), data_);
    pages_->addWidget(genPage);

    bl->addWidget(pages_);

    QWidget *lenRow = new QWidget(box);
    QHBoxLayout *ll = new QHBoxLayout(lenRow);
    ll->setContentsMargins(0, 0, 0, 0);
    ll->addWidget(new QLabel(tr("Length"), lenRow));
    length_ = spin(lenRow, 255);
    overrideLength_ = new QCheckBox(tr("Override"), lenRow);
    overrideLength_->setToolTip(tr("Unchecked: calculated automatically. "
        "Checked: send this (possibly wrong) length for robustness "
        "tests"));
    ll->addWidget(length_);
    ll->addWidget(overrideLength_);
    ll->addStretch();
    bl->addWidget(lenRow);
    layout->addWidget(box);

    QLabel *hint = hintLabel(this);
    hint->setText(tr("One element per protocol: add <i>802.11 IE</i> "
        "several times in <b>Protocol Selection &gt; Advanced</b>, in the "
        "order they should appear (SSID, Supported Rates, DS Parameter "
        "Set ...)."));
    layout->addWidget(hint);
    layout->addStretch();

    connect(kind_, SIGNAL(currentIndexChanged(int)), SLOT(updateEnabled()));
    connect(ssidNumbered_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(overrideLength_, SIGNAL(toggled(bool)), SLOT(updateEnabled()));
    connect(preset_, SIGNAL(activated(int)), SLOT(applyPreset(int)));
    updateEnabled();
}

Dot11IeConfigForm* Dot11IeConfigForm::createInstance()
{
    return new Dot11IeConfigForm;
}

void Dot11IeConfigForm::updateEnabled()
{
    pages_->setCurrentIndex(kind_->currentIndex());
    ssidCount_->setEnabled(ssidNumbered_->isChecked());
    length_->setEnabled(overrideLength_->isChecked());
}

void Dot11IeConfigForm::applyPreset(int index)
{
    if (index <= 0)
        return;
    const IePreset &p = kPresets[index - 1];
    elementId_->setValue(p.id);
    data_->setText(QString(p.hex));
    preset_->setCurrentIndex(0);
}

void Dot11IeConfigForm::loadWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    const OstProto::Dot11Ie &d = p.GetExtension(OstProto::dot11_ie);

    int idx = kind_->findData(int(d.kind()));
    kind_->setCurrentIndex(idx >= 0 ? idx : 0);
    ssid_->setText(QString::fromUtf8(d.ssid().c_str()));
    ssidNumbered_->setChecked(d.ssid_numbered());
    ssidCount_->setValue(int(d.ssid_count()));
    rates_->setText(QString::fromUtf8(d.rates().c_str()));
    channel_->setValue(int(d.channel() & 0xFF));
    elementId_->setValue(int(d.element_id() & 0xFF));
    data_->setText(hexText(d.data()));
    overrideLength_->setChecked(d.is_override_length());
    length_->setValue(int(proto->fieldData(Dot11IeProtocol::ie_length,
            AbstractProtocol::FieldValue).toUInt()));
    updateEnabled();
}

void Dot11IeConfigForm::storeWidget(AbstractProtocol *proto)
{
    OstProto::Protocol p;
    proto->protoDataCopyInto(p);
    OstProto::Dot11Ie *d = p.MutableExtension(OstProto::dot11_ie);

    d->set_kind(OstProto::Dot11Ie::Kind(kind_->currentData().toInt()));
    d->set_ssid(ssid_->text().toUtf8().constData());
    d->set_ssid_numbered(ssidNumbered_->isChecked());
    d->set_ssid_count(uint(ssidCount_->value()));
    d->set_rates(rates_->text().toUtf8().constData());
    d->set_channel(uint(channel_->value()));
    d->set_element_id(uint(elementId_->value()));
    d->set_data(hexBytes(data_->text()));
    d->set_is_override_length(overrideLength_->isChecked());
    d->set_length(uint(length_->value()));
    proto->protoDataCopyFrom(p);
}
