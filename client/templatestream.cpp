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
#include <QTemporaryFile>

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

} // namespace

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
        ok = decode(pkt, stream, error);
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
