/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#include "templatestream.h"

#include "packettemplates.h"
#include "stream.h"

#include "../common/dot11.pb.h"
#include "../common/hexdump.pb.h"
#include "../common/ip4.pb.h"
#include "../common/llc.pb.h"
#include "../common/pcapfileformat.h"
#include "../common/snap.pb.h"
#include "../common/udp.pb.h"
#include "../common/protocol.pb.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include <algorithm>
#include <vector>
#include <iterator>

namespace {

const quint64 kApMac = 0x020000000100ULL;
const quint64 kStaMac = 0x020000000200ULL;
const quint64 kDstMac = 0x001122334455ULL;
const quint64 kBroadcast = 0xffffffffffffULL;
const quint32 kSrcIp = 0xc0a8000a;     // 192.168.0.10
const quint32 kDstIp = 0xc0a80014;     // 192.168.0.20

OstProto::Protocol* add(OstProto::Stream *s, int id)
{
    OstProto::Protocol *p = s->add_protocol();
    p->mutable_protocol_id()->set_id(id);
    return p;
}

void radiotap(OstProto::Stream *s)
{
    // 6 Mb/s, TX flags 0 - as in the hex template
    OstProto::Dot11Radiotap *r = add(s, OstProto::Protocol::kDot11RadiotapFieldNumber)
            ->MutableExtension(OstProto::dot11_radiotap);
    r->set_rate(12);
    r->set_tx_flags(0);
}

OstProto::Dot11* header(OstProto::Stream *s, int type, int subtype,
                        int flags, quint64 a1, quint64 a2, quint64 a3)
{
    OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
            ->MutableExtension(OstProto::dot11);
    h->set_is_auto_type(false);
    h->set_type(type);
    h->set_subtype(subtype);
    h->set_flags(flags);
    h->set_addr1(a1);
    h->set_addr2(a2);
    h->set_addr3(a3);
    return h;
}

OstProto::Dot11Ie* ie(OstProto::Stream *s, OstProto::Dot11Ie::Kind kind)
{
    OstProto::Dot11Ie *e = add(s, OstProto::Protocol::kDot11IeFieldNumber)
            ->MutableExtension(OstProto::dot11_ie);
    e->set_kind(kind);
    return e;
}

// the hex templates advertise the OFDM rates (6, 12, 24 basic)
const char *kRates = "6*,9,12*,18,24*,36,48,54";

// LLC/SNAP + IPv4 + UDP + payload
void ipv4Udp(OstProto::Stream *s)
{
    add(s, OstProto::Protocol::kLlcFieldNumber);
    add(s, OstProto::Protocol::kSnapFieldNumber);
    OstProto::Ip4 *ip = add(s, OstProto::Protocol::kIp4FieldNumber)
            ->MutableExtension(OstProto::ip4);
    ip->set_ttl(64);
    ip->set_src_ip(kSrcIp);
    ip->set_dst_ip(kDstIp);
    OstProto::Udp *udp = add(s, OstProto::Protocol::kUdpFieldNumber)
            ->MutableExtension(OstProto::udp);
    udp->set_is_override_src_port(true);
    udp->set_is_override_dst_port(true);
    udp->set_src_port(49152);
    udp->set_dst_port(5000);
    add(s, OstProto::Protocol::kPayloadFieldNumber);
}

// frame length without the FCS the driver adds
bool wifi(int index, OstProto::Stream *s)
{
    int first = 0;
    while (first < PacketTemplates::count() && !PacketTemplates::isWifi(first))
        first++;
    int kind = index - first;
    switch (kind) {
    case 0: {   // Beacon
        radiotap(s);
        header(s, 0, 8, 0, kBroadcast, kApMac, kApMac);
        OstProto::Dot11Mgmt *m = add(s, OstProto::Protocol::kDot11MgmtFieldNumber)
                ->MutableExtension(OstProto::dot11_mgmt);
        m->set_kind(OstProto::Dot11Mgmt::kBeacon);
        ie(s, OstProto::Dot11Ie::kSsid)->set_ssid("Riff-Test");
        ie(s, OstProto::Dot11Ie::kRates)->set_rates(kRates);
        ie(s, OstProto::Dot11Ie::kDsParam)->set_channel(1);
        return true;
    }
    case 1: {   // Probe Request, wildcard SSID
        radiotap(s);
        header(s, 0, 4, 0, kBroadcast, kStaMac, kBroadcast);
        add(s, OstProto::Protocol::kDot11MgmtFieldNumber)
                ->MutableExtension(OstProto::dot11_mgmt)
                ->set_kind(OstProto::Dot11Mgmt::kProbeRequest);
        ie(s, OstProto::Dot11Ie::kSsid)->set_ssid("");
        ie(s, OstProto::Dot11Ie::kRates)->set_rates(kRates);
        return true;
    }
    case 2:     // Data to the AP (To DS)
        radiotap(s);
        header(s, 2, 0, 0x01, kApMac, kStaMac, kDstMac);
        ipv4Udp(s);
        return true;
    case 3:     // QoS Data to the AP
        radiotap(s);
        header(s, 2, 8, 0x01, kApMac, kStaMac, kDstMac);
        ipv4Udp(s);
        return true;
    case 4:     // Null data (To DS)
        radiotap(s);
        header(s, 2, 4, 0x01, kApMac, kStaMac, kApMac);
        return true;
    case 5:     // RTS
        radiotap(s);
        header(s, 1, 11, 0, kApMac, kStaMac, 0)->set_duration(300);
        return true;
    case 6:     // CTS
        radiotap(s);
        header(s, 1, 12, 0, kStaMac, 0, 0);
        return true;
    case 7:     // ACK
        radiotap(s);
        header(s, 1, 13, 0, kStaMac, 0, 0);
        return true;
    }
    return false;
}

QByteArray le32(quint32 v)
{
    QByteArray b(4, 0);
    for (int i = 0; i < 4; i++)
        b[i] = char((v >> (8 * i)) & 0xff);
    return b;
}

// the packet as a one-packet Ethernet PCAP file, decoded through tshark
bool decode(const QByteArray &pkt, OstProto::Stream *s, QString *error)
{
    QTemporaryFile pcap(QDir::tempPath() + "/riff-template-XXXXXX.pcap");
    if (!pcap.open())
        return false;
    QByteArray file = QByteArray::fromHex("d4c3b2a1" "0200" "0400")
            + le32(0) + le32(0) + le32(65535) + le32(1)       // Ethernet
            + le32(0) + le32(0) + le32(pkt.size()) + le32(pkt.size()) + pkt;
    pcap.write(file);
    pcap.close();

    PcapFileFormat fmt;     // own instance: import via PDML, with diff
    OstProto::StreamConfigList list;
    QString err;
    if (!fmt.open(pcap.fileName(), list, err) || list.stream_size() < 1) {
        if (error)
            *error = err;
        return false;
    }
    const OstProto::Stream &d = list.stream(0);
    for (int i = 0; i < d.protocol_size(); i++)
        s->add_protocol()->CopyFrom(d.protocol(i));
    return s->protocol_size() > 0;
}

// ---- 802.11 bytes -> protocols ------------------------------------------

quint32 le(const QByteArray &b, int pos, int n)
{
    quint32 v = 0;
    for (int i = n - 1; i >= 0; i--)
        v = (v << 8) | uchar(b.at(pos + i));
    return v;
}

quint64 macAt(const QByteArray &b, int pos)
{
    quint64 v = 0;
    for (int i = 0; i < 6; i++)
        v = (v << 8) | uchar(b.at(pos + i));
    return v;
}

void hexDumpOf(OstProto::Stream *s, const QByteArray &bytes)
{
    if (bytes.isEmpty())
        return;
    OstProto::HexDump *h = add(s, OstProto::Protocol::kHexDumpFieldNumber)
            ->MutableExtension(OstProto::hexDump);
    h->set_content(bytes.constData(), size_t(bytes.size()));
    h->set_pad_until_end(false);
}

// radiotap TX header: only the fields the Radiotap TX protocol knows
bool parseRadiotap(const QByteArray &b, int *len, OstProto::Stream *s)
{
    if (b.size() < 8 || b.at(0) != 0)
        return false;
    *len = int(le(b, 2, 2));
    quint32 present = le(b, 4, 4);
    const quint32 known = (1u << 2) | (1u << 15) | (1u << 17) | (1u << 19);
    if (*len < 8 || *len > b.size() || (present & ~known))
        return false;
    OstProto::Dot11Radiotap *r = add(s, OstProto::Protocol::kDot11RadiotapFieldNumber)
            ->MutableExtension(OstProto::dot11_radiotap);
    int pos = 8;
    r->set_use_rate(present & (1u << 2));
    if (r->use_rate())
        r->set_rate(uchar(b.at(pos++)));
    r->set_use_tx_flags(present & (1u << 15));
    if (r->use_tx_flags()) {
        pos += pos % 2;
        r->set_tx_flags(le(b, pos, 2));
        pos += 2;
    }
    r->set_use_retries(present & (1u << 17));
    if (r->use_retries())
        r->set_retries(uchar(b.at(pos++)));
    r->set_use_mcs(present & (1u << 19));
    if (r->use_mcs()) {
        uchar flags = uchar(b.at(pos + 1));
        r->set_mcs_bw(flags & 0x03);
        r->set_mcs_sgi(flags & 0x04);
        r->set_mcs_index(uchar(b.at(pos + 2)));
        pos += 3;
    }
    return pos <= *len;
}

QString ratesText(const QByteArray &rates)
{
    QStringList l;
    for (char c : rates)
        l << QString::number((uchar(c) & 0x7F) / 2.0)
                + ((uchar(c) & 0x80) ? "*" : "");
    return l.join(',');
}

// information elements up to the end of the frame
void parseIes(const QByteArray &b, int pos, OstProto::Stream *s)
{
    while (pos + 2 <= b.size()) {
        int id = uchar(b.at(pos)), n = uchar(b.at(pos + 1));
        if (pos + 2 + n > b.size())
            break;
        QByteArray info = b.mid(pos + 2, n);
        pos += 2 + n;
        if (id == 0 && QString::fromUtf8(info).toUtf8() == info) {
            ie(s, OstProto::Dot11Ie::kSsid)->set_ssid(info.toStdString());
        }
        else if (id == 1 && n >= 1 && n <= 8) {
            // the Rates element writes an Extended Supported Rates element
            // itself for more than 8 rates
            if (n == 8 && pos + 2 <= b.size() && uchar(b.at(pos)) == 50
                    && pos + 2 + uchar(b.at(pos + 1)) <= b.size()) {
                info += b.mid(pos + 2, uchar(b.at(pos + 1)));
                pos += 2 + uchar(b.at(pos + 1));
            }
            ie(s, OstProto::Dot11Ie::kRates)
                ->set_rates(ratesText(info).toStdString());
        }
        else if (id == 3 && n == 1) {
            ie(s, OstProto::Dot11Ie::kDsParam)->set_channel(uchar(info.at(0)));
        }
        else {
            OstProto::Dot11Ie *e = ie(s, OstProto::Dot11Ie::kGeneric);
            e->set_element_id(id);
            e->set_data(info.constData(), size_t(info.size()));
        }
    }
    hexDumpOf(s, b.mid(pos));       // trailing bytes that are no element
}

bool decodeEthernet(const QByteArray &pkt, OstProto::Stream *s,
                    QString *error);

bool decodeWifi(const QByteArray &b, OstProto::Stream *s)
{
    int pos = 0;
    if (!parseRadiotap(b, &pos, s) || pos + 10 > b.size())
        return false;
    const int fc0 = uchar(b.at(pos)), flags = uchar(b.at(pos + 1));
    const int type = (fc0 >> 2) & 3, subtype = fc0 >> 4;
    if (type == 3)
        return false;
    OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
            ->MutableExtension(OstProto::dot11);
    h->set_is_auto_type(false);
    h->set_version(fc0 & 3);
    h->set_type(type);
    h->set_subtype(subtype);
    h->set_flags(flags);
    h->set_duration(le(b, pos + 2, 2));
    h->set_addr1(macAt(b, pos + 4));
    h->set_seq_increment(false);    // exactly the bytes that were edited
    if (type == 1) {                // control
        bool shortCtrl = subtype == 12 || subtype == 13;
        if (!shortCtrl) {
            if (pos + 16 > b.size())
                return false;
            h->set_addr2(macAt(b, pos + 10));
        }
        hexDumpOf(s, b.mid(pos + (shortCtrl ? 10 : 16)));
        return true;
    }
    if (pos + 24 > b.size())
        return false;
    h->set_addr2(macAt(b, pos + 10));
    h->set_addr3(macAt(b, pos + 16));
    quint32 sc = le(b, pos + 22, 2);
    h->set_frag_num(sc & 0xF);
    h->set_seq_num(sc >> 4);
    pos += 24;
    if (type == 2 && (flags & 3) == 3) {
        if (pos + 6 > b.size())
            return false;
        h->set_addr4(macAt(b, pos));
        pos += 6;
    }
    if (type == 2 && (subtype & 8)) {
        if (pos + 2 > b.size())
            return false;
        h->set_qos_control(le(b, pos, 2));
        pos += 2;
    }
    if (flags & 0x40) {             // protected: the body is encrypted
        hexDumpOf(s, b.mid(pos));
        return true;
    }

    if (type == 0) {                // management body + elements
        static const int kinds[] = {0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13};
        if (std::find(std::begin(kinds), std::end(kinds), subtype)
                == std::end(kinds)) {
            hexDumpOf(s, b.mid(pos));
            return true;
        }
        OstProto::Dot11Mgmt *m = add(s, OstProto::Protocol::kDot11MgmtFieldNumber)
                ->MutableExtension(OstProto::dot11_mgmt);
        m->set_kind(OstProto::Dot11Mgmt::Kind(subtype));
        auto need = [&](int n) { return pos + n <= b.size(); };
        switch (subtype) {
        case 0: case 2:             // (re)association request
            if (!need(subtype == 2 ? 10 : 4))
                return false;
            m->set_capability(le(b, pos, 2));
            m->set_listen_interval(le(b, pos + 2, 2));
            pos += 4;
            if (subtype == 2) {
                m->set_current_ap(macAt(b, pos));
                pos += 6;
            }
            break;
        case 1: case 3:             // (re)association response
            if (!need(6))
                return false;
            m->set_capability(le(b, pos, 2));
            m->set_status(le(b, pos + 2, 2));
            m->set_aid(le(b, pos + 4, 2));
            pos += 6;
            break;
        case 5: case 8:             // probe response, beacon
            if (!need(12))
                return false;
            m->set_timestamp(quint64(le(b, pos, 4))
                             | (quint64(le(b, pos + 4, 4)) << 32));
            m->set_beacon_interval(le(b, pos + 8, 2));
            m->set_capability(le(b, pos + 10, 2));
            pos += 12;
            break;
        case 10: case 12:           // disassociation, deauthentication
            if (!need(2))
                return false;
            m->set_reason(le(b, pos, 2));
            pos += 2;
            break;
        case 11:                    // authentication
            if (!need(6))
                return false;
            m->set_auth_alg(le(b, pos, 2));
            m->set_auth_seq(le(b, pos + 2, 2));
            m->set_status(le(b, pos + 4, 2));
            pos += 6;
            break;
        case 13:                    // action: category + details, no IEs
            if (!need(1))
                return false;
            m->set_action_category(uchar(b.at(pos)));
            m->set_action_data(b.constData() + pos + 1,
                               size_t(b.size() - pos - 1));
            return true;
        default:
            break;
        }
        parseIes(b, pos, s);
        return true;
    }

    // data: LLC/SNAP + whatever follows, decoded like an Ethernet payload
    QByteArray body = b.mid(pos);
    if (body.size() >= 8 && body.startsWith(QByteArray::fromHex("aaaa03000000"))) {
        quint32 etype = le(body, 7, 1) | (le(body, 6, 1) << 8);
        add(s, OstProto::Protocol::kLlcFieldNumber);
        OstProto::Snap *snap = add(s, OstProto::Protocol::kSnapFieldNumber)
                ->MutableExtension(OstProto::snap);
        snap->set_is_override_type(true);
        snap->set_type(etype);
        QByteArray eth = QByteArray::fromHex("020000000001020000000002")
                + body.mid(6, 2) + body.mid(8);
        OstProto::Stream inner;
        if (body.size() > 8 && decodeEthernet(eth, &inner, nullptr)) {
            // drop the made-up Ethernet header (MAC + Ethernet II)
            int i = 0;
            while (i < inner.protocol_size()
                    && (inner.protocol(i).protocol_id().id()
                            == OstProto::Protocol::kMacFieldNumber
                        || inner.protocol(i).protocol_id().id()
                            == OstProto::Protocol::kEth2FieldNumber))
                i++;
            for (; i < inner.protocol_size(); i++)
                s->add_protocol()->CopyFrom(inner.protocol(i));
        }
        else {
            hexDumpOf(s, body.mid(8));
        }
        return true;
    }
    hexDumpOf(s, body);
    return true;
}

// rebuilds the packet from the protocols: true if it is the same bytes
bool sameBytes(const OstProto::Stream &s, const QByteArray &pkt, bool wifi)
{
    Stream tmp;
    tmp.protoDataCopyFrom(s);
    QByteArray buf(qMax(pkt.size(), 60) + 64, 0);
    int n = tmp.frameValue(reinterpret_cast<uchar*>(buf.data()),
                           buf.size(), 0);
    if (n < pkt.size())
        return false;
    if (buf.left(pkt.size()) != pkt)
        return false;
    // Ethernet: anything beyond the original bytes is only zero padding
    if (!wifi)
        for (int i = pkt.size(); i < n; i++)
            if (buf.at(i))
                return false;
    return wifi ? n == pkt.size() : true;
}

void setFixedLength(OstProto::Stream *s, int bytes, bool wifi)
{
    // the bytes + 4 byte FCS (added by the NIC / driver)
    s->mutable_core()->set_len_mode(OstProto::StreamCore::e_fl_fixed);
    s->mutable_core()->set_frame_len(
            quint32((wifi ? bytes : qMax(bytes, 60)) + 4));
}

bool decodeEthernet(const QByteArray &pkt, OstProto::Stream *s,
                    QString *error)
{
    return decode(pkt, s, error);
}

// A PCAP/PDML import fixes lengths, checksums and next-protocol numbers
// ("is_override_*"). Let every such value be calculated again where that
// gives the same bytes - so a checksum follows a later edit of an address.
void relaxOverrides(OstProto::Stream *s, const QByteArray &pkt, bool wifi)
{
    using google::protobuf::FieldDescriptor;
    using google::protobuf::Message;
    for (int i = 0; i < s->protocol_size(); i++) {
        OstProto::Protocol *proto = s->mutable_protocol(i);
        const google::protobuf::Reflection *pr = proto->GetReflection();
        std::vector<const FieldDescriptor*> fields;
        pr->ListFields(*proto, &fields);
        for (const FieldDescriptor *fd : fields) {
            if (!fd->is_extension()
                    || fd->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE
                    || fd->is_repeated())
                continue;
            Message *m = pr->MutableMessage(proto, fd);
            const google::protobuf::Reflection *mr = m->GetReflection();
            const google::protobuf::Descriptor *d = m->GetDescriptor();
            for (int f = 0; f < d->field_count(); f++) {
                const FieldDescriptor *bf = d->field(f);
                if (bf->cpp_type() != FieldDescriptor::CPPTYPE_BOOL
                        || bf->is_repeated()
                        || bf->name().rfind("is_override_", 0) != 0
                        || !mr->GetBool(*m, bf))
                    continue;
                mr->SetBool(m, bf, false);
                if (!sameBytes(*s, pkt, wifi))
                    mr->SetBool(m, bf, true);
            }
        }
    }
}

} // namespace

bool TemplateStream::fromBytes(const QByteArray &pkt, bool wifi,
                               OstProto::Stream *stream, QString *error)
{
    OstProto::Stream s;
    s.CopyFrom(*stream);
    s.clear_protocol();
    setFixedLength(&s, pkt.size(), wifi);
    bool ok = wifi ? decodeWifi(pkt, &s) : decode(pkt, &s, error);
    if (!ok || s.protocol_size() == 0)
        return false;
    if (!sameBytes(s, pkt, wifi)) {
        if (error)
            *error = QCoreApplication::translate("TemplateStream",
                    "The protocols would not give the same bytes.");
        return false;
    }
    relaxOverrides(&s, pkt, wifi);
    stream->CopyFrom(s);
    return true;
}

bool TemplateStream::apply(int index, OstProto::Stream *stream,
                           QString *error)
{
    if (index < 0 || index >= PacketTemplates::count())
        return false;
    QByteArray pkt = PacketTemplates::build(index);
    stream->clear_protocol();
    bool ok;
    if (PacketTemplates::isWifi(index)) {
        ok = wifi(index, stream);
    }
    else {
        ok = fromBytes(pkt, false, stream, error);
        if (!ok) {
            // no tshark (Wireshark): keep the bytes as one hex dump
            stream->clear_protocol();
            add(stream, OstProto::Protocol::kHexDumpFieldNumber)
                ->MutableExtension(OstProto::hexDump)
                ->set_content(pkt.constData(), pkt.size());
            ok = true;
        }
    }
    // fixed length: the bytes + 4 byte FCS (added by the NIC / driver)
    bool wifiPkt = PacketTemplates::isWifi(index);
    stream->mutable_core()->set_len_mode(OstProto::StreamCore::e_fl_fixed);
    stream->mutable_core()->set_frame_len(
            quint32((wifiPkt ? pkt.size() : qMax(pkt.size(), 60)) + 4));
    return ok;
}

bool TemplateStream::selfTest(const QString &reportFile)
{
    QFile f(reportFile);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    bool all = true;
    for (int i = 0; i < PacketTemplates::count(); i++) {
        QByteArray pkt = PacketTemplates::build(i);
        bool wifi = PacketTemplates::isWifi(i);
        OstProto::Stream s;
        QString error;
        bool ok = fromBytes(pkt, wifi, &s, &error);
        all = all && ok;
        QStringList protos;
        int overrides = 0;
        for (int p = 0; p < s.protocol_size(); p++) {
            protos << QString::number(s.protocol(p).protocol_id().id());
            std::string dbg = s.protocol(p).DebugString();
            for (size_t pos = dbg.find("is_override_"); pos != std::string::npos;
                    pos = dbg.find("is_override_", pos + 1))
                if (dbg.compare(dbg.find(':', pos) + 2, 4, "true") == 0)
                    overrides++;
        }
        f.write(QString("%1 %2 [%3] %4 protos=%5 fixed=%6 %7\n")
                .arg(ok ? "OK  " : "FAIL").arg(i)
                .arg(PacketTemplates::group(i)).arg(PacketTemplates::name(i))
                .arg(protos.join(',')).arg(overrides).arg(error).toUtf8());
    }
    // extra 802.11 frames beyond the templates
    const QByteArray rt = QByteArray::fromHex("00000c0004800000" "0c000000");
    const QByteArray ap = QByteArray::fromHex("020000000100");
    const QByteArray sta = QByteArray::fromHex("020000000200");
    const QByteArray bc = QByteArray::fromHex("ffffffffffff");
    struct { const char *name; QByteArray pkt; } extra[] = {
        {"Beacon, 12 rates + HT caps", rt + QByteArray::fromHex("80000000") + bc
            + ap + ap + QByteArray::fromHex("1000")
            + QByteArray::fromHex("0000000000000000" "6400" "0104")
            + QByteArray::fromHex("0004") + QByteArray("Test")
            + QByteArray::fromHex("010882848b960c121824" "3204303648 6c")
            + QByteArray::fromHex("2d1a" "ef0117ffff0000000000000000000000"
                                  "000000000000000000000000")},
        {"QoS Data, 4 addresses", rt + QByteArray::fromHex("88030000") + ap
            + sta + ap + QByteArray::fromHex("2000") + sta
            + QByteArray::fromHex("0500") + QByteArray::fromHex("aaaa030000000800")
            + QByteArray::fromHex("4500001c0001000040110000c0a8000ac0a80014"
                                  "c000138800080000")},
        {"Authentication", rt + QByteArray::fromHex("b0003a01") + ap + sta + ap
            + QByteArray::fromHex("3000" "000001000000")},
        {"Action", rt + QByteArray::fromHex("d0000000") + ap + sta + ap
            + QByteArray::fromHex("4000" "7f0050f2" "0102")},
        {"Protected data", rt + QByteArray::fromHex("08410000") + ap + sta + ap
            + QByteArray::fromHex("5000" "0102030405060708090a0b0c0d0e")},
        {"Block Ack Request", rt + QByteArray::fromHex("84000000") + ap + sta
            + QByteArray::fromHex("04001000")},
    };
    for (const auto &e : extra) {
        OstProto::Stream s;
        QString error;
        bool ok = fromBytes(e.pkt, true, &s, &error);
        all = all && ok;
        QStringList protos;
        for (int p = 0; p < s.protocol_size(); p++)
            protos << QString::number(s.protocol(p).protocol_id().id());
        f.write(QString("%1 extra %2 protos=%3 %4\n").arg(ok ? "OK  " : "FAIL")
                .arg(e.name).arg(protos.join(',')).arg(error).toUtf8());
    }
    return all;
}
