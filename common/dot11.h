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

#ifndef _DOT11_H
#define _DOT11_H

#include "abstractprotocol.h"
#include "dot11.pb.h"

#include <QVector>

/*
IEEE 802.11 frames for a USB Wi-Fi dongle in monitor mode. A stream is
built as

    Radiotap (TX) | IEEE 802.11 header | [802.11 management body
    | 802.11 information element ...] or [LLC | SNAP | IPv4 ...]

and sent exactly as built: StreamBase does not pad/truncate a stream whose
first protocol is Radiotap (TX), and the dongle appends the FCS.

All four protocols describe their frame as a list of fields (name, bit
size, value or bytes); the same list gives the packet view and the frame
bytes, so the two can not disagree.
*/

// Frame control flags (second byte)
#define DOT11_FLAG_TODS     0x01
#define DOT11_FLAG_FROMDS   0x02
#define DOT11_FLAG_MOREFRAG 0x04
#define DOT11_FLAG_RETRY    0x08
#define DOT11_FLAG_PWRMGT   0x10
#define DOT11_FLAG_MOREDATA 0x20
#define DOT11_FLAG_PROTECT  0x40
#define DOT11_FLAG_ORDER    0x80

// Radiotap TX flags
#define DOT11_TXF_NOACK     0x0008
#define DOT11_TXF_NOSEQ     0x0010

struct Dot11Field
{
    QString name;
    int bits = 0;           // 0: not in this frame
    quint64 value = 0;      // used when bytes is empty
    QByteArray bytes;       // frame bytes of a whole-byte field
    QString text;           // shown in the packet view
};
typedef QVector<Dot11Field> Dot11Fields;

// Common field handling of the 802.11 protocols
class Dot11ProtocolBase : public AbstractProtocol
{
public:
    Dot11ProtocolBase(StreamBase *stream, AbstractProtocol *parent);

    virtual QVariant fieldData(int index, FieldAttrib attrib,
               int streamIndex = 0) const;
    virtual QByteArray protocolFrameValue(int streamIndex = 0,
            bool forCksum = false, FrameValueAttrib *attrib = nullptr) const;
    virtual int protocolFrameSize(int streamIndex = 0) const;

    // little-endian helpers
    static QByteArray le(quint64 value, int bytes);
    static QByteArray macBytes(quint64 mac);
    static QString macText(quint64 mac);

protected:
    // One entry per field index (fieldCount() entries)
    virtual Dot11Fields frameFields(int streamIndex) const = 0;
};

class Dot11RadiotapProtocol : public Dot11ProtocolBase
{
public:
    enum field {
        rt_version = 0,
        rt_pad,
        rt_length,
        rt_present,
        rt_rate,
        rt_txFlagsPad,
        rt_txFlags,
        rt_retries,
        rt_mcsKnown,
        rt_mcsFlags,
        rt_mcsIndex,
        rt_fieldCount
    };

    Dot11RadiotapProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;
    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);
    virtual QString name() const;
    virtual QString shortName() const;
    virtual int fieldCount() const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);

protected:
    virtual Dot11Fields frameFields(int streamIndex) const;

private:
    OstProto::Dot11Radiotap data;
};

class Dot11Protocol : public Dot11ProtocolBase
{
public:
    enum field {
        d11_subtype = 0,
        d11_type,
        d11_version,
        d11_flags,
        d11_duration,
        d11_addr1,
        d11_addr2,
        d11_addr3,
        d11_seqCtl,         // fragment (low 4 bits) + sequence
        d11_addr4,
        d11_qos,
        d11_fieldCount
    };

    Dot11Protocol(StreamBase *stream, AbstractProtocol *parent = 0);
    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;
    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);
    virtual QString name() const;
    virtual QString shortName() const;
    virtual int fieldCount() const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);
    virtual int protocolFrameVariableCount() const;

    // type/subtype actually used (auto: from the next protocol)
    void effectiveType(quint32 *type, quint32 *subtype) const;
    quint64 address(int which, int streamIndex) const;   // which: 1..4
    quint32 sequence(int streamIndex) const;

    static QString typeName(quint32 type, quint32 subtype);

    // Bound for the number of distinct frames reported to the stream
    static const int kMaxVariableCount = 65536;

protected:
    virtual Dot11Fields frameFields(int streamIndex) const;

private:
    OstProto::Dot11 data;
};

class Dot11MgmtProtocol : public Dot11ProtocolBase
{
public:
    enum field {
        mg_timestamp = 0,
        mg_beaconInterval,
        mg_capability,
        mg_listenInterval,
        mg_currentAp,
        mg_status,
        mg_aid,
        mg_authAlg,
        mg_authSeq,
        mg_authStatus,
        mg_reason,
        mg_category,
        mg_actionData,
        mg_fieldCount
    };

    Dot11MgmtProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;
    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);
    virtual QString name() const;
    virtual QString shortName() const;
    virtual int fieldCount() const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);

    quint32 kind() const { return quint32(data.kind()); }
    static QString kindName(quint32 kind);

protected:
    virtual Dot11Fields frameFields(int streamIndex) const;

private:
    OstProto::Dot11Mgmt data;
};

class Dot11IeProtocol : public Dot11ProtocolBase
{
public:
    enum field {
        ie_id = 0,
        ie_length,
        ie_info,
        ie_extId,       // Extended Supported Rates (rates beyond 8)
        ie_extLength,
        ie_extInfo,
        ie_fieldCount
    };

    Dot11IeProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;
    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);
    virtual QString name() const;
    virtual QString shortName() const;
    virtual int fieldCount() const;
    virtual bool setFieldData(int index, const QVariant &value,
            FieldAttrib attrib = FieldValue);
    virtual bool isProtocolFrameSizeVariable() const;
    virtual int protocolFrameVariableCount() const;
    virtual bool hasErrors(QStringList *errors = nullptr) const;

    // "1*,2*,5.5,11" -> rate bytes (500 kb/s units, 0x80 = basic);
    // false if an entry is not a valid rate
    static bool parseRates(const QString &text, QByteArray *rates);
    static QString elementName(quint32 id);

protected:
    virtual Dot11Fields frameFields(int streamIndex) const;

private:
    QByteArray ssid(int streamIndex) const;
    OstProto::Dot11Ie data;
};

#endif
