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

#include "capwap.h"

#include <QtEndian>

namespace {

const int kHeaderLen = 8;           // without optional fields
const int kControlHeaderLen = 8;

QByteArray bigEndianBytes(quint32 value, int bits)
{
    int n = (bits + 7) / 8;
    QByteArray fv(n, 0);
    for (int i = n - 1; i >= 0; i--) {
        fv[i] = char(value & 0xFF);
        value >>= 8;
    }
    return fv;
}

struct FlagInfo {
    const char *name;
    quint32 bit;
};

// indexed by field - capwap_flagT
const FlagInfo kFlags[] = {
    {"T (Native Frame)", CAPWAP_FLAG_T},
    {"F (Fragment)", CAPWAP_FLAG_F},
    {"L (Not Last Fragment)", CAPWAP_FLAG_L},
    {"W (Wireless Info)", CAPWAP_FLAG_W},
    {"M (Radio MAC)", CAPWAP_FLAG_M},
    {"K (Keep-alive)", CAPWAP_FLAG_K},
};

} // namespace

CapwapProtocol::CapwapProtocol(StreamBase *stream, AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

CapwapProtocol::~CapwapProtocol()
{
}

AbstractProtocol* CapwapProtocol::createInstance(StreamBase *stream,
    AbstractProtocol *parent)
{
    return new CapwapProtocol(stream, parent);
}

quint32 CapwapProtocol::protocolNumber() const
{
    return OstProto::Protocol::kCapwapFieldNumber;
}

void CapwapProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::capwap)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void CapwapProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::capwap))
        data.MergeFrom(protocol.GetExtension(OstProto::capwap));
}

QString CapwapProtocol::name() const
{
    return QString("CAPWAP - Control And Provisioning of Wireless Access "
                   "Points (RFC 5415)");
}

QString CapwapProtocol::shortName() const
{
    return QString("CAPWAP");
}

quint32 CapwapProtocol::protocolId(ProtocolIdType type) const
{
    switch (type) {
    case ProtocolIdTcpUdp:
        // lets UDP pick the port automatically
        return data.is_control() ? 5246 : 5247;
    default:
        break;
    }
    return AbstractProtocol::protocolId(type);
}

QString CapwapProtocol::messageTypeName(quint32 type)
{
    static const char *names[] = {
        nullptr,
        "Discovery Request", "Discovery Response",
        "Join Request", "Join Response",
        "Configuration Status Request", "Configuration Status Response",
        "Configuration Update Request", "Configuration Update Response",
        "WTP Event Request", "WTP Event Response",
        "Change State Event Request", "Change State Event Response",
        "Echo Request", "Echo Response",
        "Image Data Request", "Image Data Response",
        "Reset Request", "Reset Response",
        "Primary Discovery Request", "Primary Discovery Response",
        "Data Transfer Request", "Data Transfer Response",
        "Clear Configuration Request", "Clear Configuration Response",
        "Station Configuration Request", "Station Configuration Response",
    };
    if (type >= 1 && type < sizeof(names) / sizeof(names[0]))
        return QString(names[type]);
    return QString();
}

quint32 CapwapProtocol::hlen() const
{
    return data.is_override_hlen() ? (data.hlen() & 0x1F)
                                   : quint32(kHeaderLen / 4);
}

quint32 CapwapProtocol::msgElemLen(int streamIndex) const
{
    if (data.is_override_msg_elem_len())
        return data.msg_elem_len() & 0xFFFF;
    // RFC 5415: counts the bytes after the Sequence Number field - the
    // length field itself, the flags and the message elements (= payload)
    return quint32(3 + protocolFramePayloadSize(streamIndex)) & 0xFFFF;
}

int CapwapProtocol::fieldCount() const
{
    return capwap_fieldCount;
}

AbstractProtocol::FieldFlags CapwapProtocol::fieldFlags(int index) const
{
    AbstractProtocol::FieldFlags flags = AbstractProtocol::fieldFlags(index);

    switch (index) {
    case capwap_isControl:
    case capwap_isOverrideHlen:
    case capwap_isOverrideMsgElemLen:
    case capwap_flags:
        flags &= ~FrameField;
        flags |= MetaField;
        break;
    default:
        break;
    }
    return flags;
}

QVariant CapwapProtocol::fieldData(int index, FieldAttrib attrib,
        int streamIndex) const
{
    // Generic numeric frame field
    auto numeric = [attrib](const QString &name, quint32 value, int bits,
                            bool hex, const QString &meaning) -> QVariant {
        switch (attrib) {
        case FieldName:
            return name;
        case FieldValue:
            return value;
        case FieldTextValue: {
            QString text = hex ? QString("0x%1").arg(value, (bits + 3) / 4,
                                                     BASE_HEX, QChar('0'))
                               : QString::number(value);
            if (!meaning.isEmpty())
                text += QString(" (%1)").arg(meaning);
            return text;
        }
        case FieldFrameValue:
            return bigEndianBytes(value, bits);
        case FieldBitSize:
            return bits;
        default:
            return QVariant();
        }
    };

    // Control message header fields exist only on the control channel
    auto controlOnly = [attrib](const QString &name, quint32 value)
            -> QVariant {
        if (attrib == FieldName)
            return name;
        if (attrib == FieldValue)  // kept so that it survives switching
            return value;          // channels in the config form
        if (attrib == FieldTextValue)
            return QObject::tr("<not-included>");
        return QVariant();
    };

    switch (index) {
    case capwap_version:
        return numeric("Version", data.version() & 0xF, 4, false, QString());
    case capwap_type:
        return numeric("Type", data.type() & 0xF, 4, false,
                       (data.type() & 0xF) == 0 ? "CAPWAP Header"
                       : (data.type() & 0xF) == 1 ? "DTLS" : QString());
    case capwap_hlen:
        return numeric("HLEN", hlen(), 5, false,
                       QString("%1 bytes").arg(hlen() * 4));
    case capwap_rid:
        return numeric("Radio ID", data.rid() & 0x1F, 5, false, QString());
    case capwap_wbid:
        return numeric("Wireless Binding ID", data.wbid() & 0x1F, 5, false,
                       (data.wbid() & 0x1F) == 1 ? "IEEE 802.11"
                       : (data.wbid() & 0x1F) == 3 ? "EPCGlobal" : QString());
    case capwap_flagT:
    case capwap_flagF:
    case capwap_flagL:
    case capwap_flagW:
    case capwap_flagM:
    case capwap_flagK: {
        const FlagInfo &f = kFlags[index - capwap_flagT];
        quint32 set = (data.flags() & f.bit) ? 1 : 0;
        QString meaning;
        if (index == capwap_flagT)
            meaning = set ? "Native frame" : "IEEE 802.3 frame";
        return numeric(f.name, set, 1, false, meaning);
    }
    case capwap_rsvdFlags:
        return numeric("Flags (Reserved)", data.rsvd_flags() & 0x7, 3, false,
                       QString());
    case capwap_fragmentId:
        return numeric("Fragment ID", data.fragment_id() & 0xFFFF, 16, false,
                       QString());
    case capwap_fragmentOffset:
        return numeric("Fragment Offset", data.fragment_offset() & 0x1FFF,
                       13, false, QString());
    case capwap_rsvd2:
        return numeric("Reserved", data.rsvd2() & 0x7, 3, false, QString());

    case capwap_messageType:
        if (!data.is_control())
            return controlOnly("Message Type", data.message_type());
        return numeric("Message Type", data.message_type(), 32, false,
                       messageTypeName(data.message_type()));
    case capwap_seqNum:
        if (!data.is_control())
            return controlOnly("Sequence Number", data.seq_num() & 0xFF);
        return numeric("Sequence Number", data.seq_num() & 0xFF, 8, false,
                       QString());
    case capwap_msgElemLen:
        if (!data.is_control())
            return controlOnly("Msg Element Length", msgElemLen(streamIndex));
        return numeric("Msg Element Length", msgElemLen(streamIndex), 16,
                       false, QString());
    case capwap_msgFlags:
        if (!data.is_control())
            return controlOnly("Message Flags", data.msg_flags() & 0xFF);
        return numeric("Message Flags", data.msg_flags() & 0xFF, 8, true,
                       QString());

    // Meta fields
    case capwap_isControl:
        return attrib == FieldValue ? QVariant(data.is_control())
                                    : QVariant();
    case capwap_isOverrideHlen:
        return attrib == FieldValue ? QVariant(data.is_override_hlen())
                                    : QVariant();
    case capwap_isOverrideMsgElemLen:
        return attrib == FieldValue
                   ? QVariant(data.is_override_msg_elem_len()) : QVariant();
    case capwap_flags:
        return attrib == FieldValue ? QVariant(data.flags() & 0x3F)
                                    : QVariant();

    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
               index);
        break;
    }

    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

bool CapwapProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    if (attrib != FieldValue)
        return false;

    bool ok = true;
    uint v = 0;
    switch (index) {
    case capwap_isControl:
    case capwap_isOverrideHlen:
    case capwap_isOverrideMsgElemLen:
        break;
    default:
        v = value.toUInt(&ok);
        if (!ok)
            return false;
        break;
    }

    switch (index) {
    case capwap_version: data.set_version(v & 0xF); break;
    case capwap_type: data.set_type(v & 0xF); break;
    case capwap_hlen: data.set_hlen(v & 0x1F); break;
    case capwap_rid: data.set_rid(v & 0x1F); break;
    case capwap_wbid: data.set_wbid(v & 0x1F); break;
    case capwap_flagT:
    case capwap_flagF:
    case capwap_flagL:
    case capwap_flagW:
    case capwap_flagM:
    case capwap_flagK: {
        quint32 bit = kFlags[index - capwap_flagT].bit;
        data.set_flags(v ? (data.flags() | bit) : (data.flags() & ~bit));
        break;
    }
    case capwap_flags: data.set_flags(v & 0x3F); break;
    case capwap_rsvdFlags: data.set_rsvd_flags(v & 0x7); break;
    case capwap_fragmentId: data.set_fragment_id(v & 0xFFFF); break;
    case capwap_fragmentOffset: data.set_fragment_offset(v & 0x1FFF); break;
    case capwap_rsvd2: data.set_rsvd2(v & 0x7); break;
    case capwap_messageType: data.set_message_type(v); break;
    case capwap_seqNum: data.set_seq_num(v & 0xFF); break;
    case capwap_msgElemLen: data.set_msg_elem_len(v & 0xFFFF); break;
    case capwap_msgFlags: data.set_msg_flags(v & 0xFF); break;
    case capwap_isControl: data.set_is_control(value.toBool()); break;
    case capwap_isOverrideHlen:
        data.set_is_override_hlen(value.toBool());
        break;
    case capwap_isOverrideMsgElemLen:
        data.set_is_override_msg_elem_len(value.toBool());
        break;
    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
               index);
        return false;
    }
    return true;
}

QByteArray CapwapProtocol::protocolFrameValue(int streamIndex,
        bool /*forCksum*/, FrameValueAttrib* /*attrib*/) const
{
    QByteArray fv(protocolFrameSize(streamIndex), 0);
    uchar *p = reinterpret_cast<uchar*>(fv.data());

    quint32 w0 = ((data.version() & 0xF) << 28)
               | ((data.type() & 0xF) << 24)
               | ((hlen() & 0x1F) << 19)
               | ((data.rid() & 0x1F) << 14)
               | ((data.wbid() & 0x1F) << 9)
               | ((data.flags() & 0x3F) << 3)
               | (data.rsvd_flags() & 0x7);
    quint32 w1 = ((data.fragment_id() & 0xFFFF) << 16)
               | ((data.fragment_offset() & 0x1FFF) << 3)
               | (data.rsvd2() & 0x7);
    qToBigEndian(w0, p);
    qToBigEndian(w1, p + 4);

    if (data.is_control()) {
        qToBigEndian(quint32(data.message_type()), p + 8);
        p[12] = uchar(data.seq_num() & 0xFF);
        qToBigEndian(quint16(msgElemLen(streamIndex)), p + 13);
        p[15] = uchar(data.msg_flags() & 0xFF);
    }
    return fv;
}

int CapwapProtocol::protocolFrameSize(int /*streamIndex*/) const
{
    return kHeaderLen + (data.is_control() ? kControlHeaderLen : 0);
}
