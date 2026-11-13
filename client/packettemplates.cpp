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

#include "packettemplates.h"

#include "packetdecoder.h"

#include <QCoreApplication>

namespace {

// ---- template builders ----

QByteArray mac(const char *text)
{
    return QByteArray::fromHex(QByteArray(text).replace(":", ""));
}

QByteArray be16(int v)
{
    QByteArray b(2, 0);
    b[0] = char((v >> 8) & 0xFF);
    b[1] = char(v & 0xFF);
    return b;
}

QByteArray be32(quint32 v)
{
    return be16(int(v >> 16)) + be16(int(v & 0xFFFF));
}

QByteArray ip4(int a, int b, int c, int d)
{
    QByteArray r;
    r.append(char(a)).append(char(b)).append(char(c)).append(char(d));
    return r;
}

QByteArray ethernet(const QByteArray &dst, const QByteArray &src, int type)
{
    return dst + src + be16(type);
}

QByteArray ipv4Header(int proto, const QByteArray &src, const QByteArray &dst,
                      int payloadLen, int ttl = 64)
{
    QByteArray h;
    h.append(char(0x45)).append(char(0));           // ver/ihl, dscp/ecn
    h.append(be16(20 + payloadLen));                // total length
    h.append(be16(0x1234));                         // identification
    h.append(be16(0x4000));                         // DF
    h.append(char(ttl)).append(char(proto));        // ttl, protocol
    h.append(be16(0));                              // checksum (fixed later)
    h.append(src).append(dst);
    return h;
}

QByteArray ipv4(int proto, const QByteArray &src, const QByteArray &dst,
                const QByteArray &payload, int ttl = 64)
{
    return ipv4Header(proto, src, dst, payload.size(), ttl) + payload;
}

// UDP checksum 0 = "not used" over IPv4 (common for tunnels); a non-zero
// placeholder gets the correct value from fixChecksums()
QByteArray udp(int sport, int dport, const QByteArray &payload,
               bool checksum = false)
{
    return be16(sport) + be16(dport) + be16(8 + payload.size())
           + be16(checksum ? 0xFFFF : 0) + payload;
}

QByteArray icmpEcho(int seq = 1)
{
    return QByteArray::fromHex("0800") + be16(0) + be16(1) + be16(seq)
           + QByteArray("abcdefghijklmnopqrstuvwabcdefghi");
}

QByteArray padTo60(QByteArray frame)
{
    if (frame.size() < 60)
        frame.append(QByteArray(60 - frame.size(), 0));
    return frame;
}

const QByteArray kDstMac = mac("00:11:22:33:44:55");
const QByteArray kSrcMac = mac("00:aa:bb:cc:dd:ee");
const QByteArray kSrcIp = ip4(192, 168, 0, 10);
const QByteArray kDstIp = ip4(192, 168, 0, 20);

// Inner frame used by the L2 tunnel templates: a ping between two hosts
QByteArray innerPingFrame()
{
    return ethernet(mac("02:00:00:00:00:02"), mac("02:00:00:00:00:01"),
                    0x0800)
           + ipv4(1, ip4(10, 0, 0, 1), ip4(10, 0, 0, 2), icmpEcho());
}

QByteArray innerPingPacket()
{
    return ipv4(1, ip4(10, 0, 0, 1), ip4(10, 0, 0, 2), icmpEcho());
}

QByteArray outerIpv4(int proto, const QByteArray &payload)
{
    return ethernet(kDstMac, kSrcMac, 0x0800)
           + ipv4(proto, kSrcIp, kDstIp, payload);
}

struct Template {
    const char *group;
    const char *name;
};

const Template kTemplates[] = {
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "Ethernet + IPv4 + UDP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "Ethernet + IPv4 + TCP SYN")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "ICMP Echo Request (ping)")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "ARP Request")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "Ethernet + IPv6 + UDP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "802.1Q VLAN + IPv4 + UDP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Basic"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "Empty Ethernet frame (60 bytes)")},

    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "CAPWAP Data (802.3 frame)")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "CAPWAP Control (Echo Request)")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "EtherIP (Ethernet over IP)")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "VXLAN")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "Geneve")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "GRE (IPv4 in GRE)")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "IP-in-IP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "MPLS + IPv4 + UDP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "PPPoE Session + IPv4")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Tunnels / encapsulation"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "GTP-U")},

    {QT_TRANSLATE_NOOP("HexPacketEditor", "Control / applications"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "DNS Query")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Control / applications"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "DHCP Discover")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Control / applications"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "LLDP")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Control / applications"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "STP BPDU")},
    {QT_TRANSLATE_NOOP("HexPacketEditor", "Control / applications"),
     QT_TRANSLATE_NOOP("HexPacketEditor", "IGMPv2 Membership Report")},
};
const int kTemplateCount = int(sizeof(kTemplates) / sizeof(kTemplates[0]));

QByteArray lldpTlv(int type, const QByteArray &value)
{
    return be16((type << 9) | value.size()) + value;
}

QByteArray buildTemplate(int index)
{
    switch (index) {
    case 0: // IPv4 + UDP
        return outerIpv4(17, udp(49152, 5000, "Hello from Riff!..", true));
    case 1: { // IPv4 + TCP SYN
        QByteArray tcp = be16(49152) + be16(80) + be32(1) + be32(0)
            + QByteArray::fromHex("5002") + be16(64240) + be16(0) + be16(0);
        return outerIpv4(6, tcp);
    }
    case 2: // ICMP echo request
        return ethernet(kDstMac, kSrcMac, 0x0800)
               + ipv4(1, kSrcIp, ip4(192, 168, 0, 1), icmpEcho());
    case 3: { // ARP request
        QByteArray arp = be16(1) + be16(0x0800)
            + QByteArray::fromHex("0604") + be16(1)
            + kSrcMac + kSrcIp + QByteArray(6, 0) + ip4(192, 168, 0, 1);
        return padTo60(ethernet(QByteArray(6, char(0xFF)), kSrcMac, 0x0806)
                       + arp);
    }
    case 4: { // IPv6 + UDP
        QByteArray u = udp(49152, 5000, "Hello from Riff!", true);
        QByteArray ip6 = QByteArray::fromHex("60000000") + be16(u.size())
            + QByteArray::fromHex("1140")      // next header UDP, hop limit 64
            + QByteArray::fromHex("20010db8000000000000000000000010")
            + QByteArray::fromHex("20010db8000000000000000000000020");
        return ethernet(mac("33:33:00:00:00:01"), kSrcMac, 0x86DD) + ip6 + u;
    }
    case 5: // VLAN 100
        return ethernet(kDstMac, kSrcMac, 0x8100) + be16(100) + be16(0x0800)
               + ipv4(17, kSrcIp, kDstIp,
                      udp(49152, 5000, "Hello VLAN 100", true));
    case 6: // empty frame with the IEEE "local experimental" EtherType
        return ethernet(kDstMac, kSrcMac, 0x88B5) + QByteArray(46, 0);

    case 7: { // CAPWAP data: HLEN 2 (8 bytes), RID 1, WBID 1, T=0 (802.3)
        QByteArray cw = be32(0x00104200) + be32(0) + innerPingFrame();
        return outerIpv4(17, udp(12222, 5247, cw));
    }
    case 8: { // CAPWAP control: Echo Request, no message elements
        QByteArray cw = be32(0x00100200) + be32(0)
            + be32(13)                    // enterprise 0 + message type 13
            + QByteArray(1, char(1))      // sequence number
            + be16(3)                     // length: itself + flags
            + QByteArray(1, char(0));     // flags
        return outerIpv4(17, udp(12223, 5246, cw));
    }
    case 9: // EtherIP: version 3
        return outerIpv4(97, be16(0x3000) + innerPingFrame());
    case 10: // VXLAN VNI 100
        return outerIpv4(17, udp(49152, 4789,
                be32(0x08000000) + be32(100 << 8) + innerPingFrame()));
    case 11: // Geneve VNI 100, Ethernet payload
        return outerIpv4(17, udp(49152, 6081,
                be16(0x0000) + be16(0x6558) + be32(100 << 8)
                + innerPingFrame()));
    case 12: // GRE carrying IPv4
        return outerIpv4(47, be16(0x0000) + be16(0x0800) + innerPingPacket());
    case 13: // IP-in-IP
        return outerIpv4(4, innerPingPacket());
    case 14: // MPLS label 100, bottom of stack, TTL 64
        return ethernet(kDstMac, kSrcMac, 0x8847)
               + be32((100u << 12) | 0x100 | 64)
               + ipv4(17, kSrcIp, kDstIp, udp(49152, 5000, "Hello MPLS", true));
    case 15: { // PPPoE session 0x1234 + IPv4
        QByteArray ppp = be16(0x0021)
            + ipv4(17, kSrcIp, kDstIp, udp(49152, 5000, "Hello PPPoE", true));
        return ethernet(kDstMac, kSrcMac, 0x8864)
               + QByteArray::fromHex("1100") + be16(0x1234)
               + be16(ppp.size()) + ppp;
    }
    case 16: { // GTP-U G-PDU, TEID 1
        QByteArray inner = innerPingPacket();
        QByteArray gtp = QByteArray::fromHex("30ff") + be16(inner.size())
                         + be32(1) + inner;
        return outerIpv4(17, udp(2152, 2152, gtp));
    }

    case 17: { // DNS query example.com A
        QByteArray q = QByteArray::fromHex("1234" "0100" "0001" "0000"
                                           "0000" "0000")
            + QByteArray("\x07" "example" "\x03" "com", 12)  // no NUL
            + QByteArray(1, 0) + be16(1) + be16(1);        // root, A, IN
        return ethernet(kDstMac, kSrcMac, 0x0800)
               + ipv4(17, kSrcIp, ip4(192, 168, 0, 1),
                      udp(53000, 53, q, true));
    }
    case 18: { // DHCP Discover
        QByteArray bootp = QByteArray::fromHex("01010600") + be32(0x3903F326)
            + be16(0) + be16(0x8000)
            + QByteArray(16, 0)                       // ci/yi/si/gi addr
            + kSrcMac + QByteArray(10, 0)             // chaddr
            + QByteArray(64 + 128, 0)                 // sname, file
            + be32(0x63825363)
            + QByteArray::fromHex("350101"            // msg type DISCOVER
                                  "3703010306"        // param request list
                                  "ff");
        return ethernet(QByteArray(6, char(0xFF)), kSrcMac, 0x0800)
               + ipv4(17, ip4(0, 0, 0, 0), ip4(255, 255, 255, 255),
                      udp(68, 67, bootp, true));
    }
    case 19: { // LLDP
        QByteArray tlvs = lldpTlv(1, QByteArray(1, char(4)) + kSrcMac)
            + lldpTlv(2, QByteArray(1, char(5)) + QByteArray("port1"))
            + lldpTlv(3, be16(120))
            + lldpTlv(5, QByteArray("riff-host"))
            + lldpTlv(0, QByteArray());
        return padTo60(ethernet(mac("01:80:c2:00:00:0e"), kSrcMac, 0x88CC)
                       + tlvs);
    }
    case 20: { // STP configuration BPDU over 802.3/LLC
        QByteArray bpdu = QByteArray::fromHex("0000" "00" "00" "00")
            + be16(0x8000) + kSrcMac + be32(0)        // root id, cost
            + be16(0x8000) + kSrcMac + be16(0x8001)   // bridge id, port
            + be16(0) + be16(20 * 256) + be16(2 * 256) + be16(15 * 256);
        QByteArray llc = QByteArray::fromHex("424203") + bpdu;
        return padTo60(ethernet(mac("01:80:c2:00:00:00"), kSrcMac,
                                llc.size()) + llc);
    }
    default: { // IGMPv2 report for 239.1.1.1
        QByteArray igmp = QByteArray::fromHex("1600") + be16(0)
                          + ip4(239, 1, 1, 1);
        return padTo60(ethernet(mac("01:00:5e:01:01:01"), kSrcMac, 0x0800)
                       + ipv4(2, kSrcIp, ip4(239, 1, 1, 1), igmp, 1));
    }
    }
}

} // namespace

namespace PacketTemplates {

int count()
{
    return kTemplateCount;
}

const char* name(int index)
{
    return (index >= 0 && index < kTemplateCount) ? kTemplates[index].name
                                                  : "";
}

const char* group(int index)
{
    return (index >= 0 && index < kTemplateCount) ? kTemplates[index].group
                                                  : "";
}

QByteArray build(int index)
{
    QByteArray pkt = buildTemplate(index);
    PacketDecoder::fixChecksums(pkt);
    return pkt;
}

} // namespace PacketTemplates
