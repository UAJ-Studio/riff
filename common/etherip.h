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

#ifndef _ETHERIP_H
#define _ETHERIP_H

#include "abstractprotocol.h"
#include "etherip.pb.h"

/*
EtherIP header (RFC 3378) - followed by the tunnelled Ethernet frame
    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |VERSION|       RESERVED        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
class EtherIpProtocol : public AbstractProtocol
{
public:
    enum etheripfield
    {
        etherip_version = 0,
        etherip_reserved,

        etherip_fieldCount
    };

    EtherIpProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    virtual ~EtherIpProtocol();

    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;

    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);

    virtual quint32 protocolId(ProtocolIdType type) const;

    virtual QString name() const;
    virtual QString shortName() const;

    virtual int fieldCount() const;

    virtual QVariant fieldData(int index, FieldAttrib attrib,
               int streamIndex = 0) const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);

    virtual int protocolFrameSize(int streamIndex = 0) const;

private:
    OstProto::EtherIp data;
};

#endif
