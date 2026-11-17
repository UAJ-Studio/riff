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

#include "dot11.h"

#include "variablefields.h"

#include <QObject>
#include <QRegExp>
#include <QStringList>

namespace {

QString hex(quint64 value, int digits)
{
    return QString("0x%1").arg(value, digits, BASE_HEX, QChar('0'));
}

Dot11Field numField(const QString &name, quint64 value, int bits,
                    const QString &text = QString())
{
    Dot11Field f;
    f.name = name;
    f.bits = bits;
    f.value = value;
    f.text = text.isEmpty() ? QString::number(value) : text;
    return f;
}

// Little-endian multi-byte field
Dot11Field leField(const QString &name, quint64 value, int bytes,
                   const QString &text = QString())
{
    Dot11Field f = numField(name, value, bytes * 8, text);
    f.bytes = Dot11ProtocolBase::le(value, bytes);
    return f;
}

Dot11Field bytesField(const QString &name, const QByteArray &bytes,
                      const QString &text = QString())
{
    Dot11Field f;
    f.name = name;
    f.bits = bytes.size() * 8;
    f.bytes = bytes;
    f.text = text.isEmpty() ? QString(bytes.toHex(' ')) : text;
    return f;
}

Dot11Field macField(const QString &name, quint64 mac)
{
    Dot11Field f = bytesField(name, Dot11ProtocolBase::macBytes(mac),
                              Dot11ProtocolBase::macText(mac));
    f.value = mac;
    return f;
}

Dot11Field absent(const QString &name, quint64 value = 0)
{
    Dot11Field f;
    f.name = name;
    f.value = value;
    return f;
}

// Packs the fields MSB first (whole-byte fields use their bytes)
QByteArray pack(const Dot11Fields &fields)
{
    QByteArray out;
    quint32 acc = 0;
    int accBits = 0;
    for (const Dot11Field &f : fields) {
        if (f.bits <= 0)
            continue;
        if (accBits == 0 && (f.bits % 8) == 0) {
            if (!f.bytes.isEmpty())
                out += f.bytes;
            else
                for (int i = f.bits / 8 - 1; i >= 0; i--)
                    out.append(char((f.value >> (8 * i)) & 0xFF));
            continue;
        }
        for (int i = f.bits - 1; i >= 0; i--) {
            acc = (acc << 1) | ((f.value >> i) & 1);
            if (++accBits == 8) {
                out.append(char(acc & 0xFF));
                acc = 0;
                accBits = 0;
            }
        }
    }
    if (accBits)
        out.append(char((acc << (8 - accBits)) & 0xFF));
    return out;
}

int fieldsSize(const Dot11Fields &fields)
{
    int bits = 0;
    for (const Dot11Field &f : fields)
        bits += qMax(f.bits, 0);
    return (bits + 7) / 8;
}

quint64 splitmix64(quint64 x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

quint64 boundedLcm(quint64 a, quint64 b, quint64 bound)
{
    quint64 l = AbstractProtocol::lcm(a, b);
    return l > bound ? bound : l;
}

const char *kFlagNames[8] = {
    "To DS", "From DS", "More Fragments", "Retry", "Power Management",
    "More Data", "Protected", "Order"
};

} // namespace

// ---- Dot11ProtocolBase ---------------------------------------------------

Dot11ProtocolBase::Dot11ProtocolBase(StreamBase *stream,
        AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

QByteArray Dot11ProtocolBase::le(quint64 value, int bytes)
{
    QByteArray b(bytes, 0);
    for (int i = 0; i < bytes; i++)
        b[i] = char((value >> (8 * i)) & 0xFF);
    return b;
}

QByteArray Dot11ProtocolBase::macBytes(quint64 mac)
{
    QByteArray b(6, 0);
    for (int i = 0; i < 6; i++)
        b[i] = char((mac >> (8 * (5 - i))) & 0xFF);
    return b;
}

QString Dot11ProtocolBase::macText(quint64 mac)
{
    QStringList parts;
    for (int i = 5; i >= 0; i--)
        parts << QString("%1").arg((mac >> (8 * i)) & 0xFF, 2, BASE_HEX,
                                   QChar('0'));
    return parts.join(':');
}

QVariant Dot11ProtocolBase::fieldData(int index, FieldAttrib attrib,
        int streamIndex) const
{
    Dot11Fields fields = frameFields(streamIndex);
    if (index < 0 || index >= fields.size())
        return AbstractProtocol::fieldData(index, attrib, streamIndex);

    const Dot11Field &f = fields.at(index);
    switch (attrib) {
    case FieldName:
        return f.name;
    case FieldValue:
        return QVariant(qulonglong(f.value));
    case FieldTextValue:
        return f.bits > 0 ? f.text : QObject::tr("<not-included>");
    case FieldFrameValue: {
        if (f.bits <= 0)
            return QByteArray();
        if (!f.bytes.isEmpty())
            return f.bytes;
        Dot11Fields one;
        one.append(f);
        return pack(one);
    }
    case FieldBitSize:
        return qMax(f.bits, 0);
    default:
        break;
    }
    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

int Dot11ProtocolBase::protocolFrameSize(int streamIndex) const
{
    return fieldsSize(frameFields(streamIndex));
}

QByteArray Dot11ProtocolBase::protocolFrameValue(int streamIndex,
        bool /*forCksum*/, FrameValueAttrib* /*attrib*/) const
{
    QByteArray fv = pack(frameFields(streamIndex));
    VariableFields::apply(this, fv, streamIndex);
    return fv;
}

// ---- Radiotap (TX) -------------------------------------------------------

Dot11RadiotapProtocol::Dot11RadiotapProtocol(StreamBase *stream,
        AbstractProtocol *parent)
    : Dot11ProtocolBase(stream, parent)
{
}

AbstractProtocol* Dot11RadiotapProtocol::createInstance(StreamBase *stream,
        AbstractProtocol *parent)
{
    return new Dot11RadiotapProtocol(stream, parent);
}

quint32 Dot11RadiotapProtocol::protocolNumber() const
{
    return OstProto::Protocol::kDot11RadiotapFieldNumber;
}

void Dot11RadiotapProtocol::protoDataCopyInto(
        OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::dot11_radiotap)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void Dot11RadiotapProtocol::protoDataCopyFrom(
        const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::dot11_radiotap))
        data.MergeFrom(protocol.GetExtension(OstProto::dot11_radiotap));
}

QString Dot11RadiotapProtocol::name() const
{
    return QString("Radiotap header for frame injection (TX)");
}

QString Dot11RadiotapProtocol::shortName() const
{
    return QString("Radiotap TX");
}

int Dot11RadiotapProtocol::fieldCount() const
{
    return rt_fieldCount;
}

Dot11Fields Dot11RadiotapProtocol::frameFields(int /*streamIndex*/) const
{
    Dot11Fields f(rt_fieldCount);

    // Fields in bit order; each aligned to its natural size relative to
    // the start of the header
    quint32 present = 0;
    int len = 8;
    if (data.use_rate()) {
        present |= 1u << 2;
        len += 1;
    }
    bool txPad = false;
    if (data.use_tx_flags()) {
        present |= 1u << 15;
        txPad = (len % 2) != 0;     // u16, 2-byte aligned
        len += (txPad ? 1 : 0) + 2;
    }
    if (data.use_retries()) {
        present |= 1u << 17;
        len += 1;
    }
    if (data.use_mcs()) {
        present |= 1u << 19;
        len += 3;
    }

    f[rt_version] = numField("Version", 0, 8);
    f[rt_pad] = numField("Pad", 0, 8);
    f[rt_length] = leField("Length", quint32(len), 2);

    QStringList names;
    if (present & (1u << 2)) names << "Rate";
    if (present & (1u << 15)) names << "TX flags";
    if (present & (1u << 17)) names << "Data retries";
    if (present & (1u << 19)) names << "MCS";
    f[rt_present] = leField("Present flags", present, 4,
            QString("%1 (%2)").arg(hex(present, 8), names.join(", ")));

    const quint32 rate = data.rate() & 0xFF;
    f[rt_rate] = data.use_rate()
        ? numField("Rate", rate, 8, QString("%1 Mb/s").arg(rate / 2.0))
        : absent("Rate", rate);

    f[rt_txFlagsPad] = txPad ? numField("Alignment pad", 0, 8)
                             : absent("Alignment pad");
    const quint32 txf = data.tx_flags() & 0xFFFF;
    QStringList tf;
    if (txf & DOT11_TXF_NOACK) tf << "No ACK";
    if (txf & DOT11_TXF_NOSEQ) tf << "No sequence number";
    f[rt_txFlags] = data.use_tx_flags()
        ? leField("TX flags", txf, 2, tf.isEmpty() ? hex(txf, 4)
                  : QString("%1 (%2)").arg(hex(txf, 4), tf.join(", ")))
        : absent("TX flags", txf);

    f[rt_retries] = data.use_retries()
        ? numField("Data retries", data.retries() & 0xFF, 8)
        : absent("Data retries", data.retries() & 0xFF);

    // MCS: known (bandwidth, index, guard interval), flags, index
    const quint32 mcsFlags = (data.mcs_bw() & 0x3)
                           | (data.mcs_sgi() ? 0x04 : 0);
    if (data.use_mcs()) {
        f[rt_mcsKnown] = numField("MCS known", 0x07, 8,
                "0x07 (bandwidth, MCS index, guard interval)");
        f[rt_mcsFlags] = numField("MCS flags", mcsFlags, 8,
                QString("%1 (%2 MHz, %3 GI)").arg(hex(mcsFlags, 2))
                    .arg((data.mcs_bw() & 0x3) == 1 ? 40 : 20)
                    .arg(data.mcs_sgi() ? "short" : "long"));
        f[rt_mcsIndex] = numField("MCS index", data.mcs_index() & 0xFF, 8);
    }
    else {
        f[rt_mcsKnown] = absent("MCS known");
        f[rt_mcsFlags] = absent("MCS flags", mcsFlags);
        f[rt_mcsIndex] = absent("MCS index", data.mcs_index() & 0xFF);
    }
    return f;
}

bool Dot11RadiotapProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    if (attrib != FieldValue)
        return false;
    bool ok = false;
    uint v = value.toUInt(&ok);
    if (!ok)
        return false;
    switch (index) {
    case rt_rate: data.set_rate(v & 0xFF); break;
    case rt_txFlags: data.set_tx_flags(v & 0xFFFF); break;
    case rt_retries: data.set_retries(v & 0xFF); break;
    case rt_mcsIndex: data.set_mcs_index(v & 0xFF); break;
    default: return false;
    }
    return true;
}

// ---- 802.11 header -------------------------------------------------------

Dot11Protocol::Dot11Protocol(StreamBase *stream, AbstractProtocol *parent)
    : Dot11ProtocolBase(stream, parent)
{
}

AbstractProtocol* Dot11Protocol::createInstance(StreamBase *stream,
        AbstractProtocol *parent)
{
    return new Dot11Protocol(stream, parent);
}

quint32 Dot11Protocol::protocolNumber() const
{
    return OstProto::Protocol::kDot11FieldNumber;
}

void Dot11Protocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::dot11)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void Dot11Protocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::dot11))
        data.MergeFrom(protocol.GetExtension(OstProto::dot11));
}

QString Dot11Protocol::name() const
{
    return QString("IEEE 802.11 MAC header");
}

QString Dot11Protocol::shortName() const
{
    return QString("802.11");
}

int Dot11Protocol::fieldCount() const
{
    return d11_fieldCount;
}

QString Dot11Protocol::typeName(quint32 type, quint32 subtype)
{
    static const char *mgmt[16] = {
        "Association Request", "Association Response",
        "Reassociation Request", "Reassociation Response",
        "Probe Request", "Probe Response", "Timing Advertisement", nullptr,
        "Beacon", "ATIM", "Disassociation", "Authentication",
        "Deauthentication", "Action", "Action No Ack", nullptr};
    static const char *ctrl[16] = {
        nullptr, nullptr, "Trigger", "TACK", "Beamforming Report Poll",
        "VHT/HE NDP Announcement", "Control Frame Extension",
        "Control Wrapper", "Block Ack Request", "Block Ack", "PS-Poll",
        "RTS", "CTS", "ACK", "CF-End", "CF-End + CF-Ack"};
    static const char *dataNames[16] = {
        "Data", nullptr, nullptr, nullptr, "Null (no data)", nullptr,
        nullptr, nullptr, "QoS Data", "QoS Data + CF-Ack",
        "QoS Data + CF-Poll", "QoS Data + CF-Ack + CF-Poll", "QoS Null",
        nullptr, "QoS CF-Poll", "QoS CF-Ack + CF-Poll"};
    const char *n = nullptr;
    subtype &= 0xF;
    switch (type & 0x3) {
    case 0: n = mgmt[subtype]; break;
    case 1: n = ctrl[subtype]; break;
    case 2: n = dataNames[subtype]; break;
    default: break;
    }
    return n ? QString(n) : QString();
}

void Dot11Protocol::effectiveType(quint32 *type, quint32 *subtype) const
{
    *type = data.type() & 0x3;
    *subtype = data.subtype() & 0xF;
    if (!data.is_auto_type() || !next)
        return;

    switch (next->protocolNumber()) {
    case OstProto::Protocol::kDot11MgmtFieldNumber:
        *type = 0;
        *subtype = static_cast<const Dot11MgmtProtocol*>(next)->kind() & 0xF;
        break;
    case OstProto::Protocol::kLlcFieldNumber:
    case OstProto::Protocol::kDot2LlcFieldNumber:
    case OstProto::Protocol::kSnapFieldNumber:
    case OstProto::Protocol::kDot2SnapFieldNumber:
        if (*type != 2) {   // keep a data subtype chosen by the user
            *type = 2;
            *subtype = 0;
        }
        break;
    default:
        break;
    }
}

quint64 Dot11Protocol::address(int which, int streamIndex) const
{
    const quint64 kMask = 0xFFFFFFFFFFFFULL;
    quint64 base = 0;
    const OstProto::Dot11Vary *vary = nullptr;
    switch (which) {
    case 1: base = data.addr1(); vary = &data.addr1_vary(); break;
    case 2: base = data.addr2(); vary = &data.addr2_vary(); break;
    case 3: base = data.addr3(); vary = &data.addr3_vary(); break;
    default: base = data.addr4(); vary = &data.addr4_vary(); break;
    }
    base &= kMask;

    const quint64 count = qMax(vary->count(), 1u);
    const quint64 n = quint64(qMax(streamIndex, 0)) % count;
    switch (vary->mode()) {
    case OstProto::Dot11Vary::kIncrement:
        return (base + n * vary->step()) & kMask;
    case OstProto::Dot11Vary::kDecrement:
        return (base - n * vary->step()) & kMask;
    case OstProto::Dot11Vary::kRandom: {
        // deterministic per frame index; locally administered unicast
        quint64 r = splitmix64(base ^ (quint64(which) << 52)
                               ^ (n * 0xD6E8FEB86659FD93ULL));
        r &= kMask;
        quint64 b0 = ((r >> 40) & 0xFC) | 0x02;
        return (b0 << 40) | (r & 0xFFFFFFFFFFULL);
    }
    default:
        return base;
    }
}

quint32 Dot11Protocol::sequence(int streamIndex) const
{
    quint32 seq = data.seq_num() & 0xFFF;
    if (data.seq_increment())
        seq = (seq + quint32(qMax(streamIndex, 0))) % 4096;
    return seq;
}

int Dot11Protocol::protocolFrameVariableCount() const
{
    quint64 count = quint64(AbstractProtocol::protocolFrameVariableCount());
    const OstProto::Dot11Vary *v[4] = {&data.addr1_vary(), &data.addr2_vary(),
                                       &data.addr3_vary(), &data.addr4_vary()};
    quint32 type, subtype;
    effectiveType(&type, &subtype);
    const bool hasAddr4 = type == 2
        && (data.flags() & (DOT11_FLAG_TODS | DOT11_FLAG_FROMDS))
               == (DOT11_FLAG_TODS | DOT11_FLAG_FROMDS);
    for (int i = 0; i < 4; i++) {
        if (i == 3 && !hasAddr4)
            continue;
        if (v[i]->mode() != OstProto::Dot11Vary::kFixed)
            count = boundedLcm(count, qMax(v[i]->count(), 1u),
                               kMaxVariableCount);
    }
    if (data.seq_increment() && type != 1)
        count = boundedLcm(count, 4096, kMaxVariableCount);
    return int(count);
}

Dot11Fields Dot11Protocol::frameFields(int streamIndex) const
{
    Dot11Fields f(d11_fieldCount);
    quint32 type, subtype;
    effectiveType(&type, &subtype);
    const quint32 flags = data.flags() & 0xFF;

    QString tn = typeName(type, subtype);
    f[d11_subtype] = numField("Subtype", subtype, 4,
            tn.isEmpty() ? QString::number(subtype)
                         : QString("%1 (%2)").arg(subtype).arg(tn));
    static const char *typeNames[4] = {"Management", "Control", "Data",
                                       "Extension"};
    f[d11_type] = numField("Type", type, 2,
            QString("%1 (%2)").arg(type).arg(typeNames[type & 3]));
    f[d11_version] = numField("Protocol version", data.version() & 0x3, 2);

    QStringList fl;
    for (int i = 0; i < 8; i++)
        if (flags & (1u << i))
            fl << kFlagNames[i];
    f[d11_flags] = numField("Flags", flags, 8, fl.isEmpty() ? hex(flags, 2)
            : QString("%1 (%2)").arg(hex(flags, 2), fl.join(", ")));

    f[d11_duration] = leField(type == 1 && subtype == 10 ? "AID"
                              : "Duration", data.duration() & 0xFFFF, 2);

    // Address names by frame type and DS bits
    const bool toDs = flags & DOT11_FLAG_TODS;
    const bool fromDs = flags & DOT11_FLAG_FROMDS;
    QString n1 = "Receiver address", n2 = "Transmitter address",
            n3 = "BSSID";
    if (type == 0 || (type == 2 && !toDs && !fromDs)) {
        n1 = "Destination address";
        n2 = "Source address";
    }
    else if (type == 2 && toDs && !fromDs) {
        n1 = "BSSID (receiver)";
        n2 = "Source address";
        n3 = "Destination address";
    }
    else if (type == 2 && !toDs && fromDs) {
        n1 = "Destination address";
        n2 = "BSSID (transmitter)";
        n3 = "Source address";
    }
    else if (type == 2) {
        n3 = "Destination address";
    }

    // Control frames: RTS, PS-Poll, BA ... 16 bytes; CTS and ACK 10 bytes
    const bool ctrl = type == 1;
    const bool shortCtrl = ctrl && (subtype == 12 || subtype == 13);
    f[d11_addr1] = macField(n1, address(1, streamIndex));
    f[d11_addr2] = shortCtrl ? absent(n2, address(2, streamIndex))
                             : macField(n2, address(2, streamIndex));
    f[d11_addr3] = ctrl ? absent(n3, address(3, streamIndex))
                        : macField(n3, address(3, streamIndex));

    const quint32 seq = sequence(streamIndex);
    const quint32 frag = data.frag_num() & 0xF;
    const quint32 sc = (seq << 4) | frag;
    f[d11_seqCtl] = ctrl ? absent("Sequence control", sc)
        : leField("Sequence control", sc, 2,
                  QString("Sequence %1, fragment %2").arg(seq).arg(frag));

    const bool hasAddr4 = type == 2 && toDs && fromDs;
    f[d11_addr4] = hasAddr4 ? macField("Source address",
                                       address(4, streamIndex))
                            : absent("Address 4", address(4, streamIndex));

    const bool qos = type == 2 && (subtype & 0x8);
    const quint32 qc = data.qos_control() & 0xFFFF;
    f[d11_qos] = qos ? leField("QoS control", qc, 2,
                               QString("%1 (TID %2)").arg(hex(qc, 4))
                                   .arg(qc & 0xF))
                     : absent("QoS control", qc);
    return f;
}

bool Dot11Protocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    if (attrib != FieldValue)
        return false;
    bool ok = false;
    qulonglong v = value.toULongLong(&ok);
    if (!ok)
        return false;
    switch (index) {
    case d11_subtype: data.set_subtype(v & 0xF); break;
    case d11_type: data.set_type(v & 0x3); break;
    case d11_version: data.set_version(v & 0x3); break;
    case d11_flags: data.set_flags(v & 0xFF); break;
    case d11_duration: data.set_duration(v & 0xFFFF); break;
    case d11_addr1: data.set_addr1(v & 0xFFFFFFFFFFFFULL); break;
    case d11_addr2: data.set_addr2(v & 0xFFFFFFFFFFFFULL); break;
    case d11_addr3: data.set_addr3(v & 0xFFFFFFFFFFFFULL); break;
    case d11_addr4: data.set_addr4(v & 0xFFFFFFFFFFFFULL); break;
    case d11_seqCtl:
        data.set_frag_num(v & 0xF);
        data.set_seq_num((v >> 4) & 0xFFF);
        break;
    case d11_qos: data.set_qos_control(v & 0xFFFF); break;
    default: return false;
    }
    return true;
}

// ---- Management body -----------------------------------------------------

Dot11MgmtProtocol::Dot11MgmtProtocol(StreamBase *stream,
        AbstractProtocol *parent)
    : Dot11ProtocolBase(stream, parent)
{
}

AbstractProtocol* Dot11MgmtProtocol::createInstance(StreamBase *stream,
        AbstractProtocol *parent)
{
    return new Dot11MgmtProtocol(stream, parent);
}

quint32 Dot11MgmtProtocol::protocolNumber() const
{
    return OstProto::Protocol::kDot11MgmtFieldNumber;
}

void Dot11MgmtProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::dot11_mgmt)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void Dot11MgmtProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::dot11_mgmt))
        data.MergeFrom(protocol.GetExtension(OstProto::dot11_mgmt));
}

QString Dot11MgmtProtocol::name() const
{
    return QString("IEEE 802.11 management frame body");
}

QString Dot11MgmtProtocol::shortName() const
{
    return QString("802.11 Mgmt");
}

int Dot11MgmtProtocol::fieldCount() const
{
    return mg_fieldCount;
}

QString Dot11MgmtProtocol::kindName(quint32 kind)
{
    return Dot11Protocol::typeName(0, kind);
}

Dot11Fields Dot11MgmtProtocol::frameFields(int /*streamIndex*/) const
{
    Dot11Fields f(mg_fieldCount);
    const quint32 k = kind();
    const bool beacon = k == OstProto::Dot11Mgmt::kBeacon
                     || k == OstProto::Dot11Mgmt::kProbeResponse;
    const bool assocReq = k == OstProto::Dot11Mgmt::kAssocRequest
                       || k == OstProto::Dot11Mgmt::kReassocRequest;
    const bool assocResp = k == OstProto::Dot11Mgmt::kAssocResponse
                        || k == OstProto::Dot11Mgmt::kReassocResponse;
    const bool auth = k == OstProto::Dot11Mgmt::kAuth;
    const bool reason = k == OstProto::Dot11Mgmt::kDisassoc
                     || k == OstProto::Dot11Mgmt::kDeauth;
    const bool action = k == OstProto::Dot11Mgmt::kAction;

    auto opt = [](bool on, const Dot11Field &field) {
        return on ? field : absent(field.name, field.value);
    };

    const quint64 ts = data.timestamp();
    f[mg_timestamp] = opt(beacon, leField("Timestamp", ts, 8));
    const quint32 bi = data.beacon_interval() & 0xFFFF;
    f[mg_beaconInterval] = opt(beacon, leField("Beacon interval", bi, 2,
            QString("%1 TU (%2 ms)").arg(bi).arg(bi * 1.024)));

    const quint32 cap = data.capability() & 0xFFFF;
    QStringList cn;
    static const struct { quint32 bit; const char *name; } capBits[] = {
        {0x0001, "ESS"}, {0x0002, "IBSS"}, {0x0010, "Privacy"},
        {0x0020, "Short preamble"}, {0x0100, "Spectrum management"},
        {0x0200, "QoS"}, {0x0400, "Short slot time"},
        {0x1000, "Radio measurement"}};
    for (const auto &c : capBits)
        if (cap & c.bit)
            cn << c.name;
    f[mg_capability] = opt(beacon || assocReq || assocResp,
            leField("Capability information", cap, 2, cn.isEmpty()
                    ? hex(cap, 4)
                    : QString("%1 (%2)").arg(hex(cap, 4), cn.join(", "))));
    f[mg_listenInterval] = opt(assocReq, leField("Listen interval",
            data.listen_interval() & 0xFFFF, 2));
    f[mg_currentAp] = opt(k == OstProto::Dot11Mgmt::kReassocRequest,
            macField("Current AP address", data.current_ap()));

    const quint32 st = data.status() & 0xFFFF;
    f[mg_status] = opt(assocResp, leField("Status code", st, 2,
            st == 0 ? QString("0 (Success)") : QString::number(st)));
    const quint32 aid = data.aid() & 0xFFFF;
    f[mg_aid] = opt(assocResp, leField("Association ID", aid, 2,
            QString("%1 (AID %2)").arg(hex(aid, 4)).arg(aid & 0x3FFF)));

    const quint32 alg = data.auth_alg() & 0xFFFF;
    static const char *algNames[] = {"Open System", "Shared Key",
                                     "Fast BSS Transition", "SAE"};
    f[mg_authAlg] = opt(auth, leField("Authentication algorithm", alg, 2,
            alg < 4 ? QString("%1 (%2)").arg(alg).arg(algNames[alg])
                    : QString::number(alg)));
    f[mg_authSeq] = opt(auth, leField("Authentication sequence",
            data.auth_seq() & 0xFFFF, 2));
    f[mg_authStatus] = opt(auth, leField("Status code", st, 2,
            st == 0 ? QString("0 (Success)") : QString::number(st)));

    const quint32 rc = data.reason() & 0xFFFF;
    static const char *reasons[] = {
        nullptr, "Unspecified", "Previous authentication no longer valid",
        "Leaving (deauthenticated)", "Inactivity", "AP busy",
        "Class 2 frame from non-authenticated STA",
        "Class 3 frame from non-associated STA",
        "Leaving (disassociated)", "Not authenticated"};
    f[mg_reason] = opt(reason, leField("Reason code", rc, 2,
            rc >= 1 && rc <= 9 ? QString("%1 (%2)").arg(rc).arg(reasons[rc])
                               : QString::number(rc)));

    f[mg_category] = opt(action, numField("Category",
            data.action_category() & 0xFF, 8));
    const QByteArray ad(data.action_data().data(),
                        int(data.action_data().size()));
    if (action && !ad.isEmpty())
        f[mg_actionData] = bytesField("Action details", ad);
    else
        f[mg_actionData] = absent("Action details");
    return f;
}

bool Dot11MgmtProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    if (attrib != FieldValue)
        return false;
    bool ok = false;
    qulonglong v = value.toULongLong(&ok);
    if (!ok)
        return false;
    switch (index) {
    case mg_timestamp: data.set_timestamp(v); break;
    case mg_beaconInterval: data.set_beacon_interval(v & 0xFFFF); break;
    case mg_capability: data.set_capability(v & 0xFFFF); break;
    case mg_listenInterval: data.set_listen_interval(v & 0xFFFF); break;
    case mg_currentAp: data.set_current_ap(v & 0xFFFFFFFFFFFFULL); break;
    case mg_status:
    case mg_authStatus: data.set_status(v & 0xFFFF); break;
    case mg_aid: data.set_aid(v & 0xFFFF); break;
    case mg_authAlg: data.set_auth_alg(v & 0xFFFF); break;
    case mg_authSeq: data.set_auth_seq(v & 0xFFFF); break;
    case mg_reason: data.set_reason(v & 0xFFFF); break;
    case mg_category: data.set_action_category(v & 0xFF); break;
    default: return false;
    }
    return true;
}

// ---- Information element -------------------------------------------------

Dot11IeProtocol::Dot11IeProtocol(StreamBase *stream, AbstractProtocol *parent)
    : Dot11ProtocolBase(stream, parent)
{
}

AbstractProtocol* Dot11IeProtocol::createInstance(StreamBase *stream,
        AbstractProtocol *parent)
{
    return new Dot11IeProtocol(stream, parent);
}

quint32 Dot11IeProtocol::protocolNumber() const
{
    return OstProto::Protocol::kDot11IeFieldNumber;
}

void Dot11IeProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::dot11_ie)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void Dot11IeProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::dot11_ie))
        data.MergeFrom(protocol.GetExtension(OstProto::dot11_ie));
}

QString Dot11IeProtocol::name() const
{
    return QString("IEEE 802.11 information element");
}

QString Dot11IeProtocol::shortName() const
{
    return QString("802.11 IE");
}

int Dot11IeProtocol::fieldCount() const
{
    return ie_fieldCount;
}

bool Dot11IeProtocol::parseRates(const QString &text, QByteArray *rates)
{
    bool allOk = true;
    rates->clear();
    const QStringList items = text.split(QRegExp("[,;\\s]+"),
                                         QString::SkipEmptyParts);
    for (QString item : items) {
        bool basic = false;
        if (item.endsWith('*') || item.endsWith('B')
                || item.endsWith('b')) {
            basic = true;
            item.chop(1);
        }
        bool ok = false;
        double mbps = item.toDouble(&ok);
        int units = int(mbps * 2 + 0.5);
        if (!ok || units < 1 || units > 127
                || qAbs(units - mbps * 2) > 0.01) {
            allOk = false;
            continue;
        }
        rates->append(char(units | (basic ? 0x80 : 0)));
    }
    return allOk;
}

QString Dot11IeProtocol::elementName(quint32 id)
{
    switch (id) {
    case 0: return "SSID";
    case 1: return "Supported Rates";
    case 3: return "DS Parameter Set";
    case 5: return "TIM";
    case 7: return "Country";
    case 45: return "HT Capabilities";
    case 48: return "RSN";
    case 50: return "Extended Supported Rates";
    case 61: return "HT Operation";
    case 127: return "Extended Capabilities";
    case 191: return "VHT Capabilities";
    case 221: return "Vendor Specific";
    case 255: return "Element ID Extension";
    default: return QString();
    }
}

QByteArray Dot11IeProtocol::ssid(int streamIndex) const
{
    QString s = QString::fromUtf8(data.ssid().c_str());
    if (data.ssid_numbered()) {
        quint32 count = qMax(data.ssid_count(), 1u);
        s += QString::number(quint32(qMax(streamIndex, 0)) % count + 1);
    }
    return s.toUtf8().left(255);
}

bool Dot11IeProtocol::isProtocolFrameSizeVariable() const
{
    return data.kind() == OstProto::Dot11Ie::kSsid && data.ssid_numbered()
        && data.ssid_count() > 1;
}

int Dot11IeProtocol::protocolFrameVariableCount() const
{
    quint64 count = quint64(AbstractProtocol::protocolFrameVariableCount());
    if (isProtocolFrameSizeVariable())
        count = boundedLcm(count, data.ssid_count(),
                           Dot11Protocol::kMaxVariableCount);
    return int(count);
}

Dot11Fields Dot11IeProtocol::frameFields(int streamIndex) const
{
    Dot11Fields f(ie_fieldCount);
    quint32 id = 0;
    QByteArray info, ext;
    QString infoText;

    switch (data.kind()) {
    case OstProto::Dot11Ie::kSsid:
        id = 0;
        info = ssid(streamIndex);
        infoText = info.isEmpty() ? QString("(wildcard / hidden)")
                                  : QString("\"%1\"")
                                        .arg(QString::fromUtf8(info));
        break;
    case OstProto::Dot11Ie::kRates: {
        id = 1;
        QByteArray all;
        parseRates(QString::fromUtf8(data.rates().c_str()), &all);
        info = all.left(8);
        ext = all.mid(8, 255);  // beyond 8: Extended Supported Rates
        break;
    }
    case OstProto::Dot11Ie::kDsParam:
        id = 3;
        info.append(char(data.channel() & 0xFF));
        infoText = QString("Channel %1").arg(data.channel() & 0xFF);
        break;
    default:
        id = data.element_id() & 0xFF;
        info = QByteArray(data.data().data(), int(data.data().size()));
        break;
    }
    info = info.left(255);

    auto ratesText = [](const QByteArray &r) {
        QStringList l;
        for (char c : r)
            l << QString("%1%2").arg((uchar(c) & 0x7F) / 2.0)
                     .arg((uchar(c) & 0x80) ? "(B)" : "");
        return l.join(' ') + " Mb/s";
    };
    if (data.kind() == OstProto::Dot11Ie::kRates)
        infoText = ratesText(info);

    const QString en = elementName(id);
    const QString infoName = en.isEmpty() ? QString("Information") : en;
    f[ie_id] = numField("Element ID", id, 8,
            en.isEmpty() ? QString::number(id)
                         : QString("%1 (%2)").arg(id).arg(en));
    const quint32 len = data.is_override_length() ? (data.length() & 0xFF)
                                                  : quint32(info.size());
    f[ie_length] = numField("Length", len, 8);
    if (info.isEmpty()) {
        f[ie_info] = absent(infoName);
    }
    else {
        f[ie_info] = bytesField(infoName, info, infoText);
    }

    if (!ext.isEmpty()) {
        f[ie_extId] = numField("Element ID", 50, 8,
                               "50 (Extended Supported Rates)");
        f[ie_extLength] = numField("Length", quint32(ext.size()), 8);
        f[ie_extInfo] = bytesField("Extended Supported Rates", ext,
                                   ratesText(ext));
    }
    else {
        f[ie_extId] = absent("Element ID");
        f[ie_extLength] = absent("Length");
        f[ie_extInfo] = absent("Extended Supported Rates");
    }
    return f;
}

bool Dot11IeProtocol::hasErrors(QStringList *errors) const
{
    if (data.kind() != OstProto::Dot11Ie::kRates)
        return false;
    QByteArray rates;
    if (parseRates(QString::fromUtf8(data.rates().c_str()), &rates)
            && !rates.isEmpty())
        return false;
    if (errors)
        *errors << QObject::tr("802.11 Supported Rates: invalid rate list "
                               "\"%1\"").arg(QString::fromUtf8(
                                       data.rates().c_str()));
    return true;
}

bool Dot11IeProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    if (attrib != FieldValue)
        return false;
    bool ok = false;
    uint v = value.toUInt(&ok);
    if (!ok)
        return false;
    switch (index) {
    case ie_id:
        data.set_kind(OstProto::Dot11Ie::kGeneric);
        data.set_element_id(v & 0xFF);
        break;
    case ie_length:
        data.set_is_override_length(true);
        data.set_length(v & 0xFF);
        break;
    default:
        return false;
    }
    return true;
}
