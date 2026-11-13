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

#include "etherip.h"

#include <QtEndian>

EtherIpProtocol::EtherIpProtocol(StreamBase *stream, AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

EtherIpProtocol::~EtherIpProtocol()
{
}

AbstractProtocol* EtherIpProtocol::createInstance(StreamBase *stream,
    AbstractProtocol *parent)
{
    return new EtherIpProtocol(stream, parent);
}

quint32 EtherIpProtocol::protocolNumber() const
{
    return OstProto::Protocol::kEtherIpFieldNumber;
}

void EtherIpProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::etherip)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void EtherIpProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::etherip))
        data.MergeFrom(protocol.GetExtension(OstProto::etherip));
}

QString EtherIpProtocol::name() const
{
    return QString("EtherIP - Ethernet over IP (RFC 3378)");
}

QString EtherIpProtocol::shortName() const
{
    return QString("EtherIP");
}

quint32 EtherIpProtocol::protocolId(ProtocolIdType type) const
{
    switch (type) {
    case ProtocolIdIp:
        return 97;
    default:
        break;
    }
    return AbstractProtocol::protocolId(type);
}

int EtherIpProtocol::fieldCount() const
{
    return etherip_fieldCount;
}

QVariant EtherIpProtocol::fieldData(int index, FieldAttrib attrib,
        int streamIndex) const
{
    switch (index) {
    case etherip_version:
        switch (attrib) {
        case FieldName:
            return QString("Version");
        case FieldValue:
            return data.version() & 0xF;
        case FieldTextValue:
            return QString::number(data.version() & 0xF);
        case FieldFrameValue:
            return QByteArray(1, char(data.version() & 0xF));
        case FieldBitSize:
            return 4;
        default:
            break;
        }
        break;

    case etherip_reserved:
        switch (attrib) {
        case FieldName:
            return QString("Reserved");
        case FieldValue:
            return data.reserved() & 0xFFF;
        case FieldTextValue:
            return QString("0x%1").arg(data.reserved() & 0xFFF, 3, BASE_HEX,
                                       QChar('0'));
        case FieldFrameValue: {
            QByteArray fv(2, 0);
            qToBigEndian(quint16(data.reserved() & 0xFFF),
                         reinterpret_cast<uchar*>(fv.data()));
            return fv;
        }
        case FieldBitSize:
            return 12;
        default:
            break;
        }
        break;

    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
               index);
        break;
    }

    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

bool EtherIpProtocol::setFieldData(int index, const QVariant &value,
        FieldAttrib attrib)
{
    bool ok = false;
    if (attrib != FieldValue)
        return false;

    uint v = value.toUInt(&ok);
    if (!ok)
        return false;

    switch (index) {
    case etherip_version:
        data.set_version(v & 0xF);
        break;
    case etherip_reserved:
        data.set_reserved(v & 0xFFF);
        break;
    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
               index);
        return false;
    }
    return true;
}

QByteArray EtherIpProtocol::protocolFrameValue(int /*streamIndex*/,
        bool /*forCksum*/, FrameValueAttrib* /*attrib*/) const
{
    QByteArray fv(2, 0);
    quint16 word = quint16(((data.version() & 0xF) << 12)
                           | (data.reserved() & 0xFFF));
    qToBigEndian(word, reinterpret_cast<uchar*>(fv.data()));
    return fv;
}

int EtherIpProtocol::protocolFrameSize(int /*streamIndex*/) const
{
    return 2;
}
