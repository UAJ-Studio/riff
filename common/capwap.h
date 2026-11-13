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

#ifndef _CAPWAP_H
#define _CAPWAP_H

#include "abstractprotocol.h"
#include "capwap.pb.h"

/*
CAPWAP header (RFC 5415, section 4.3)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  |  HLEN   |   RID   | WBID    |T|F|L|W|M|K|Flags|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Fragment ID          |     Frag Offset         |Rsvd |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Control message header (control channel only, section 4.5.1)
   |                       Message Type                            |
   |    Seq Num    |        Msg Element Length     |     Flags     |
*/

// Bits of OstProto::Capwap::flags
#define CAPWAP_FLAG_T 0x20  // native frame format (else IEEE 802.3)
#define CAPWAP_FLAG_F 0x10  // fragment
#define CAPWAP_FLAG_L 0x08  // not last fragment
#define CAPWAP_FLAG_W 0x04  // wireless specific info present
#define CAPWAP_FLAG_M 0x02  // radio MAC address present
#define CAPWAP_FLAG_K 0x01  // keep-alive

class CapwapProtocol : public AbstractProtocol
{
public:
    enum capwapfield
    {
        // Frame fields
        capwap_version = 0,
        capwap_type,
        capwap_hlen,
        capwap_rid,
        capwap_wbid,
        capwap_flagT,
        capwap_flagF,
        capwap_flagL,
        capwap_flagW,
        capwap_flagM,
        capwap_flagK,
        capwap_rsvdFlags,
        capwap_fragmentId,
        capwap_fragmentOffset,
        capwap_rsvd2,
        // control channel only
        capwap_messageType,
        capwap_seqNum,
        capwap_msgElemLen,
        capwap_msgFlags,

        // Meta fields
        capwap_isControl,
        capwap_isOverrideHlen,
        capwap_isOverrideMsgElemLen,
        capwap_flags,

        capwap_fieldCount
    };

    CapwapProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    virtual ~CapwapProtocol();

    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;

    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);

    virtual quint32 protocolId(ProtocolIdType type) const;

    virtual QString name() const;
    virtual QString shortName() const;

    virtual int fieldCount() const;

    virtual AbstractProtocol::FieldFlags fieldFlags(int index) const;
    virtual QVariant fieldData(int index, FieldAttrib attrib,
               int streamIndex = 0) const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);

    virtual QByteArray protocolFrameValue(int streamIndex = 0,
            bool forCksum = false, FrameValueAttrib *attrib = nullptr) const;
    virtual int protocolFrameSize(int streamIndex = 0) const;

    static QString messageTypeName(quint32 type);

private:
    quint32 hlen() const;
    quint32 msgElemLen(int streamIndex) const;

    OstProto::Capwap data;
};

#endif
