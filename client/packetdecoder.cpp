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

#include "packetdecoder.h"

#include <QHostAddress>
#include <QRegularExpression>
#include <QStringList>

namespace {

const QString kArrow = QString::fromUtf8(" \xE2\x86\x92 "); // " → "

QString hex(quint64 v, int digits)
{
    return QString("0x%1").arg(v, digits, 16, QChar('0')).toUpper()
                .replace("0X", "0x");
}

QString macText(const QByteArray &pkt, int off)
{
    QStringList parts;
    for (int i = 0; i < 6; i++)
        parts << QString("%1").arg(quint8(pkt.at(off + i)), 2, 16, QChar('0'));
    return parts.join(':');
}

QString ipv4Text(const QByteArray &pkt, int off)
{
    return QString("%1.%2.%3.%4").arg(quint8(pkt.at(off)))
            .arg(quint8(pkt.at(off + 1))).arg(quint8(pkt.at(off + 2)))
            .arg(quint8(pkt.at(off + 3)));
}

QString ipv6Text(const QByteArray &pkt, int off)
{
    Q_IPV6ADDR addr;
    for (int i = 0; i < 16; i++)
        addr[i] = quint8(pkt.at(off + i));
    return QHostAddress(addr).toString();
}

} // namespace

quint16 internetChecksum(const QByteArray &data, quint32 sum)
{
    const int n = data.size();
    for (int i = 0; i + 1 < n; i += 2)
        sum += (quint32(quint8(data.at(i))) << 8) | quint8(data.at(i + 1));
    if (n & 1)
        sum += quint32(quint8(data.at(n - 1))) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return quint16(~sum & 0xFFFF);
}

// ------------------------------------------------------------------------

PacketDecoder::PacketDecoder(const QByteArray &packet)
    : pkt_(packet)
{
    if (!pkt_.isEmpty())
        decodeEthernet(0, fields_);
}

DecodedField PacketDecoder::uintField(const QString &name, int off, int len,
        quint64 mask, int shift, const QString &meaning, bool hexStyle)
{
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::UInt;
    f.offset = off;
    f.length = len;
    f.mask = mask;
    f.shift = shift;
    f.hexStyle = hexStyle;

    quint64 v = readUInt(pkt_, f);
    if (hexStyle) {
        int bits = 0;
        for (quint64 m = maxValue(f); m; m >>= 1)
            bits++;
        f.value = hex(v, (bits + 3) / 4);
    }
    else {
        f.value = QString::number(v);
    }
    if (!meaning.isEmpty())
        f.value += QString(" (%1)").arg(meaning);
    return f;
}

DecodedField PacketDecoder::macField(const QString &name, int off)
{
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Mac;
    f.offset = off;
    f.length = 6;
    f.value = macText(pkt_, off);
    if (u8(off) & 0x01)
        f.value += (pkt_.mid(off, 6) == QByteArray(6, char(0xFF)))
            ? tr(" (broadcast)") : tr(" (multicast)");
    return f;
}

DecodedField PacketDecoder::ipv4Field(const QString &name, int off)
{
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Ipv4;
    f.offset = off;
    f.length = 4;
    f.value = ipv4Text(pkt_, off);
    return f;
}

DecodedField PacketDecoder::ipv6Field(const QString &name, int off)
{
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Ipv6;
    f.offset = off;
    f.length = 16;
    f.value = ipv6Text(pkt_, off);
    return f;
}

DecodedField PacketDecoder::checksumField(const QString &name, int off,
                                          quint16 correct)
{
    DecodedField f = uintField(name, off, 2, 0, 0, QString(), true);
    quint16 cur = quint16(u16(off));
    if (cur == correct) {
        f.value += tr(" (correct)");
    }
    else {
        f.value += tr(" (wrong - should be %1)").arg(hex(correct, 4));
        f.error = true;
    }
    checksums_.append(ChecksumSpot{off, correct});
    return f;
}

void PacketDecoder::addData(int off, int len, const QString &name,
                            QList<DecodedField> &out)
{
    if (len <= 0 || !has(off, len))
        return;
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Bytes;
    f.offset = off;
    f.length = len;
    f.value = tr("%n byte(s)", "", len);
    out.append(f);
}

// ---- Ethernet / VLAN / LLC ---------------------------------------------

static QString etherTypeName(quint32 type)
{
    switch (type) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86DD: return "IPv6";
    case 0x8100: return "802.1Q VLAN";
    case 0x88A8: return "802.1ad QinQ";
    case 0x9100: return "QinQ";
    case 0x8847: return "MPLS";
    case 0x8863: return "PPPoE Discovery";
    case 0x8864: return "PPPoE Session";
    case 0x88CC: return "LLDP";
    case 0x88F7: return "PTP";
    default: return QString();
    }
}

static bool isVlanTpid(quint32 type)
{
    return type == 0x8100 || type == 0x88A8 || type == 0x9100;
}

int PacketDecoder::decodeEthernet(int off, QList<DecodedField> &out)
{
    if (!has(off, 14)) {
        addData(off, pkt_.size() - off,
                tr("Data (too short for an Ethernet header)"), out);
        return pkt_.size();
    }

    DecodedField eth;
    eth.name = tr("Ethernet");
    eth.kind = DecodedField::Header;
    eth.offset = off;
    eth.length = 14;
    eth.value = macText(pkt_, off + 6) + kArrow + macText(pkt_, off);
    eth.children << macField(tr("Destination"), off)
                 << macField(tr("Source"), off + 6);

    int type = int(u16(off + 12));
    if (type <= 1500) {
        eth.children << uintField(tr("Length"), off + 12, 2);
        out << eth;
        off += 14;
        // 802.3 + LLC
        if (has(off, 3)) {
            DecodedField llc;
            llc.name = tr("LLC");
            llc.kind = DecodedField::Header;
            llc.offset = off;
            llc.length = 3;
            llc.children << uintField("DSAP", off, 1, 0, 0, QString(), true)
                         << uintField("SSAP", off + 1, 1, 0, 0, QString(), true)
                         << uintField(tr("Control"), off + 2, 1, 0, 0,
                                      QString(), true);
            out << llc;
            off += 3;
        }
        addData(off, qMin(pkt_.size(), 14 + type) - off, tr("Data"), out);
        return pkt_.size();
    }

    eth.children << uintField(tr("Type"), off + 12, 2, 0, 0,
                              etherTypeName(quint32(type)), true);
    out << eth;
    off += 14;

    while (isVlanTpid(quint32(type)) && has(off, 4))
        off = decodeVlan(off, type, out, &type);

    switch (type) {
    case 0x0800: off = decodeIpv4(off, out); break;
    case 0x86DD: off = decodeIpv6(off, out); break;
    case 0x0806: off = decodeArp(off, out); break;
    default: break;
    }

    addData(off, pkt_.size() - off,
            (type == 0x0800 || type == 0x86DD || type == 0x0806)
                ? tr("Trailer / padding") : tr("Data"), out);
    return pkt_.size();
}

int PacketDecoder::decodeVlan(int off, int tpid, QList<DecodedField> &out,
                              int *type)
{
    DecodedField vlan;
    vlan.name = (tpid == 0x8100) ? tr("VLAN (802.1Q)") : tr("VLAN (QinQ)");
    vlan.kind = DecodedField::Header;
    vlan.offset = off;
    vlan.length = 4;
    vlan.value = tr("VLAN %1").arg(u16(off) & 0x0FFF);
    vlan.children
        << uintField(tr("Priority (PCP)"), off, 2, 0xE000, 13)
        << uintField(tr("Drop eligible (DEI)"), off, 2, 0x1000, 12)
        << uintField(tr("VLAN ID"), off, 2, 0x0FFF, 0)
        << uintField(tr("Type"), off + 2, 2, 0, 0,
                     etherTypeName(u16(off + 2)), true);
    out << vlan;
    *type = int(u16(off + 2));
    return off + 4;
}

// ---- ARP ---------------------------------------------------------------

int PacketDecoder::decodeArp(int off, QList<DecodedField> &out)
{
    if (!has(off, 8))
        return off;

    quint32 op = u16(off + 6);
    QString opName = (op == 1) ? tr("Request") : (op == 2) ? tr("Reply")
                                                         : QString();
    DecodedField arp;
    arp.name = "ARP";
    arp.kind = DecodedField::Header;
    arp.offset = off;
    arp.length = 8;
    arp.children
        << uintField(tr("Hardware type"), off, 2, 0, 0,
                     u16(off) == 1 ? "Ethernet" : QString())
        << uintField(tr("Protocol type"), off + 2, 2, 0, 0,
                     etherTypeName(u16(off + 2)), true)
        << uintField(tr("Hardware size"), off + 4, 1)
        << uintField(tr("Protocol size"), off + 5, 1)
        << uintField(tr("Operation"), off + 6, 2, 0, 0, opName);

    if (u8(off + 4) == 6 && u8(off + 5) == 4 && has(off, 28)) {
        arp.length = 28;
        arp.children << macField(tr("Sender MAC"), off + 8)
                     << ipv4Field(tr("Sender IP"), off + 14)
                     << macField(tr("Target MAC"), off + 18)
                     << ipv4Field(tr("Target IP"), off + 24);
        if (op == 1)
            arp.value = tr("Who has %1? Tell %2")
                .arg(ipv4Text(pkt_, off + 24), ipv4Text(pkt_, off + 14));
        else if (op == 2)
            arp.value = tr("%1 is at %2")
                .arg(ipv4Text(pkt_, off + 14), macText(pkt_, off + 8));
    }
    out << arp;
    return off + arp.length;
}

// ---- IPv4 / IPv6 -------------------------------------------------------

static QString ipProtoName(quint32 p)
{
    switch (p) {
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 47: return "GRE";
    case 50: return "ESP";
    case 58: return "ICMPv6";
    case 89: return "OSPF";
    case 132: return "SCTP";
    default: return QString();
    }
}

int PacketDecoder::decodeIpv4(int off, QList<DecodedField> &out)
{
    if (!has(off, 20))
        return off;

    int ihl = int(u8(off) & 0x0F);
    int hlen = ihl * 4;
    int avail = pkt_.size() - off;
    int total = int(u16(off + 2));

    DecodedField ip;
    ip.name = tr("IPv4");
    ip.kind = DecodedField::Header;
    ip.offset = off;
    ip.length = qMin(qMax(hlen, 20), avail);
    ip.value = ipv4Text(pkt_, off + 12) + kArrow + ipv4Text(pkt_, off + 16);

    DecodedField ver = uintField(tr("Version"), off, 1, 0xF0, 4);
    ver.error = (u8(off) >> 4) != 4;
    DecodedField hl = uintField(tr("Header length"), off, 1, 0x0F, 0,
                                tr("%1 bytes").arg(hlen));
    hl.error = hlen < 20 || hlen > avail;
    DecodedField tl = uintField(tr("Total length"), off + 2, 2);
    tl.error = total < hlen || total > avail;
    if (tl.error)
        tl.value += tr(" (bytes available: %1)").arg(avail);

    ip.children << ver << hl
        << uintField("DSCP", off + 1, 1, 0xFC, 2)
        << uintField("ECN", off + 1, 1, 0x03, 0)
        << tl
        << uintField(tr("Identification"), off + 4, 2, 0, 0, QString(), true)
        << uintField(tr("Don't fragment"), off + 6, 2, 0x4000, 14)
        << uintField(tr("More fragments"), off + 6, 2, 0x2000, 13)
        << uintField(tr("Fragment offset"), off + 6, 2, 0x1FFF, 0)
        << uintField("TTL", off + 8, 1)
        << uintField(tr("Protocol"), off + 9, 1, 0, 0,
                     ipProtoName(u8(off + 9)));

    if (hlen >= 20 && hlen <= avail) {
        QByteArray hdr = pkt_.mid(off, hlen);
        hdr[10] = 0;
        hdr[11] = 0;
        ip.children << checksumField(tr("Header checksum"), off + 10,
                                     internetChecksum(hdr));
    }
    else {
        ip.children << uintField(tr("Header checksum"), off + 10, 2, 0, 0,
                                 QString(), true);
    }
    ip.children << ipv4Field(tr("Source"), off + 12)
                << ipv4Field(tr("Destination"), off + 16);
    if (hlen > 20 && hlen <= avail)
        addData(off + 20, hlen - 20, tr("Options"), ip.children);
    out << ip;

    if (hlen < 20 || hlen > avail)
        return off + ip.length;

    // Fragments other than the first carry no L4 header
    bool firstFragment = (u16(off + 6) & 0x1FFF) == 0;
    int end = off + qMin(qMax(total, hlen), avail);
    int l4off = off + hlen;
    int l4len = end - l4off;

    QByteArray pseudo = pkt_.mid(off + 12, 8);
    pseudo.append(char(0));
    pseudo.append(char(u8(off + 9)));
    pseudo.append(char((l4len >> 8) & 0xFF));
    pseudo.append(char(l4len & 0xFF));

    int proto = int(u8(off + 9));
    int done = l4off;
    if (firstFragment) {
        switch (proto) {
        case 6: done = decodeTcp(l4off, l4len, pseudo, out); break;
        case 17: done = decodeUdp(l4off, l4len, pseudo, out); break;
        case 1: done = decodeIcmp(l4off, l4len, out); break;
        default: break;
        }
    }
    addData(done, end - done, tr("Data"), out);
    return end;
}

int PacketDecoder::decodeIpv6(int off, QList<DecodedField> &out)
{
    if (!has(off, 40))
        return off;

    int avail = pkt_.size() - off - 40;
    int plen = int(u16(off + 4));
    int nh = int(u8(off + 6));

    DecodedField ip;
    ip.name = tr("IPv6");
    ip.kind = DecodedField::Header;
    ip.offset = off;
    ip.length = 40;
    ip.value = ipv6Text(pkt_, off + 8) + kArrow + ipv6Text(pkt_, off + 24);

    DecodedField ver = uintField(tr("Version"), off, 1, 0xF0, 4);
    ver.error = (u8(off) >> 4) != 6;
    DecodedField pl = uintField(tr("Payload length"), off + 4, 2);
    pl.error = plen > avail;
    if (pl.error)
        pl.value += tr(" (bytes available: %1)").arg(avail);

    ip.children << ver
        << uintField(tr("Traffic class"), off, 4, 0x0FF00000, 20,
                     QString(), true)
        << uintField(tr("Flow label"), off, 4, 0x000FFFFF, 0,
                     QString(), true)
        << pl
        << uintField(tr("Next header"), off + 6, 1, 0, 0, ipProtoName(nh))
        << uintField(tr("Hop limit"), off + 7, 1)
        << ipv6Field(tr("Source"), off + 8)
        << ipv6Field(tr("Destination"), off + 24);
    out << ip;

    int l4off = off + 40;
    int l4len = qMin(plen, avail);
    int end = l4off + l4len;

    QByteArray pseudo = pkt_.mid(off + 8, 32);
    pseudo.append(char((l4len >> 24) & 0xFF));
    pseudo.append(char((l4len >> 16) & 0xFF));
    pseudo.append(char((l4len >> 8) & 0xFF));
    pseudo.append(char(l4len & 0xFF));
    pseudo.append(QByteArray(3, char(0)));
    pseudo.append(char(nh));

    int done = l4off;
    switch (nh) {
    case 6: done = decodeTcp(l4off, l4len, pseudo, out); break;
    case 17: done = decodeUdp(l4off, l4len, pseudo, out); break;
    case 58: done = decodeIcmp6(l4off, l4len, pseudo, out); break;
    default: break;
    }
    addData(done, end - done, tr("Data"), out);
    return end;
}

// ---- TCP / UDP / ICMP --------------------------------------------------

static quint16 l4Checksum(const QByteArray &pkt, int off, int len,
                          int csumOff, const QByteArray &pseudo)
{
    QByteArray seg = pkt.mid(off, len);
    seg[csumOff] = 0;
    seg[csumOff + 1] = 0;
    return internetChecksum(pseudo + seg);
}

int PacketDecoder::decodeTcp(int off, int len, const QByteArray &pseudo,
                             QList<DecodedField> &out)
{
    if (len < 20 || !has(off, 20))
        return off;

    int doff = int(u8(off + 12) >> 4) * 4;
    quint32 flags = u16(off + 12) & 0x01FF;
    static const char *flagNames[] = {"FIN", "SYN", "RST", "PSH", "ACK",
                                      "URG", "ECE", "CWR", "NS"};
    QStringList set;
    for (int i = 0; i < 9; i++)
        if (flags & (1u << i))
            set << flagNames[i];

    DecodedField tcp;
    tcp.name = "TCP";
    tcp.kind = DecodedField::Header;
    tcp.offset = off;
    tcp.length = qBound(20, doff, len);
    tcp.value = QString("%1%2%3").arg(u16(off)).arg(kArrow).arg(u16(off + 2));
    if (!set.isEmpty())
        tcp.value += QString(" [%1]").arg(set.join(", "));

    DecodedField hl = uintField(tr("Header length"), off + 12, 1, 0xF0, 4,
                                tr("%1 bytes").arg(doff));
    hl.error = doff < 20 || doff > len;

    tcp.children
        << uintField(tr("Source port"), off, 2)
        << uintField(tr("Destination port"), off + 2, 2)
        << uintField(tr("Sequence number"), off + 4, 4)
        << uintField(tr("Acknowledgment number"), off + 8, 4)
        << hl
        << uintField(tr("Flags"), off + 12, 2, 0x01FF, 0,
                     set.join(", "), true)
        << uintField(tr("Window"), off + 14, 2)
        << checksumField(tr("Checksum"), off + 16,
                         l4Checksum(pkt_, off, len, 16, pseudo))
        << uintField(tr("Urgent pointer"), off + 18, 2);
    if (doff > 20 && doff <= len)
        addData(off + 20, doff - 20, tr("Options"), tcp.children);
    out << tcp;

    int hdr = tcp.length;
    addData(off + hdr, len - hdr, tr("Payload"), out);
    return off + len;
}

int PacketDecoder::decodeUdp(int off, int len, const QByteArray &pseudo,
                             QList<DecodedField> &out)
{
    if (len < 8 || !has(off, 8))
        return off;

    DecodedField udp;
    udp.name = "UDP";
    udp.kind = DecodedField::Header;
    udp.offset = off;
    udp.length = 8;
    udp.value = QString("%1%2%3").arg(u16(off)).arg(kArrow).arg(u16(off + 2));

    DecodedField ulen = uintField(tr("Length"), off + 4, 2);
    ulen.error = int(u16(off + 4)) != len;
    if (ulen.error)
        ulen.value += tr(" (should be %1)").arg(len);

    udp.children << uintField(tr("Source port"), off, 2)
                 << uintField(tr("Destination port"), off + 2, 2)
                 << ulen;

    bool ipv4 = pseudo.size() == 12;
    if (ipv4 && u16(off + 6) == 0) {
        // Checksum is optional for UDP over IPv4; zero means "not used"
        udp.children << uintField(tr("Checksum"), off + 6, 2, 0, 0,
                                  tr("not used"), true);
    }
    else {
        quint16 c = l4Checksum(pkt_, off, len, 6, pseudo);
        udp.children << checksumField(tr("Checksum"), off + 6,
                                      c ? c : 0xFFFF);
    }
    out << udp;
    addData(off + 8, len - 8, tr("Payload"), out);
    return off + len;
}

int PacketDecoder::decodeIcmp(int off, int len, QList<DecodedField> &out)
{
    if (len < 4 || !has(off, 4))
        return off;

    quint32 type = u8(off);
    QString name;
    switch (type) {
    case 0: name = tr("Echo Reply"); break;
    case 3: name = tr("Destination Unreachable"); break;
    case 5: name = tr("Redirect"); break;
    case 8: name = tr("Echo Request"); break;
    case 11: name = tr("Time Exceeded"); break;
    default: break;
    }

    DecodedField icmp;
    icmp.name = "ICMP";
    icmp.kind = DecodedField::Header;
    icmp.offset = off;
    icmp.length = qMin(8, len);
    icmp.value = name;

    QByteArray msg = pkt_.mid(off, len);
    msg[2] = 0;
    msg[3] = 0;
    icmp.children << uintField(tr("Type"), off, 1, 0, 0, name)
                  << uintField(tr("Code"), off + 1, 1)
                  << checksumField(tr("Checksum"), off + 2,
                                   internetChecksum(msg));
    if ((type == 0 || type == 8) && len >= 8) {
        icmp.children << uintField(tr("Identifier"), off + 4, 2)
                      << uintField(tr("Sequence number"), off + 6, 2);
    }
    else if (len >= 8) {
        addData(off + 4, 4, tr("Rest of header"), icmp.children);
    }
    out << icmp;
    addData(off + icmp.length, len - icmp.length, tr("Data"), out);
    return off + len;
}

int PacketDecoder::decodeIcmp6(int off, int len, const QByteArray &pseudo,
                               QList<DecodedField> &out)
{
    if (len < 4 || !has(off, 4))
        return off;

    quint32 type = u8(off);
    QString name;
    switch (type) {
    case 1: name = tr("Destination Unreachable"); break;
    case 3: name = tr("Time Exceeded"); break;
    case 128: name = tr("Echo Request"); break;
    case 129: name = tr("Echo Reply"); break;
    case 133: name = tr("Router Solicitation"); break;
    case 134: name = tr("Router Advertisement"); break;
    case 135: name = tr("Neighbor Solicitation"); break;
    case 136: name = tr("Neighbor Advertisement"); break;
    default: break;
    }

    DecodedField icmp;
    icmp.name = "ICMPv6";
    icmp.kind = DecodedField::Header;
    icmp.offset = off;
    icmp.length = 4;
    icmp.value = name;
    icmp.children << uintField(tr("Type"), off, 1, 0, 0, name)
                  << uintField(tr("Code"), off + 1, 1)
                  << checksumField(tr("Checksum"), off + 2,
                                   l4Checksum(pkt_, off, len, 2, pseudo));
    if ((type == 128 || type == 129) && len >= 8) {
        icmp.length = 8;
        icmp.children << uintField(tr("Identifier"), off + 4, 2)
                      << uintField(tr("Sequence number"), off + 6, 2);
    }
    out << icmp;
    addData(off + icmp.length, len - icmp.length, tr("Data"), out);
    return off + len;
}

// ---- Reading / writing values ------------------------------------------

quint64 PacketDecoder::maxValue(const DecodedField &f)
{
    quint64 full = (f.length >= 8) ? ~quint64(0)
                                   : ((quint64(1) << (8 * f.length)) - 1);
    if (!f.mask)
        return full;
    return (f.mask & full) >> f.shift;
}

quint64 PacketDecoder::readUInt(const QByteArray &pkt, const DecodedField &f)
{
    quint64 raw = 0;
    for (int i = 0; i < f.length && f.offset + i < pkt.size(); i++)
        raw = (raw << 8) | quint8(pkt.at(f.offset + i));
    if (f.mask)
        raw = (raw & f.mask) >> f.shift;
    return raw;
}

void PacketDecoder::writeUInt(QByteArray &pkt, const DecodedField &f,
                              quint64 v)
{
    if (f.offset + f.length > pkt.size())
        return;
    quint64 raw = 0;
    for (int i = 0; i < f.length; i++)
        raw = (raw << 8) | quint8(pkt.at(f.offset + i));
    if (f.mask)
        raw = (raw & ~f.mask) | ((v << f.shift) & f.mask);
    else
        raw = v;
    for (int i = f.length - 1; i >= 0; i--) {
        pkt[f.offset + i] = char(raw & 0xFF);
        raw >>= 8;
    }
}

QString PacketDecoder::editText(const QByteArray &pkt, const DecodedField &f)
{
    switch (f.kind) {
    case DecodedField::UInt: {
        quint64 v = readUInt(pkt, f);
        if (f.hexStyle)
            return QString("0x%1").arg(v, 0, 16).toUpper().replace("0X", "0x");
        return QString::number(v);
    }
    case DecodedField::Mac:
        return macText(pkt, f.offset);
    case DecodedField::Ipv4:
        return ipv4Text(pkt, f.offset);
    case DecodedField::Ipv6:
        return ipv6Text(pkt, f.offset);
    default:
        return QString();
    }
}

bool PacketDecoder::writeText(QByteArray &pkt, const DecodedField &f,
                              const QString &input, QString *error)
{
    QString text = input.trimmed();
    if (f.offset + f.length > pkt.size()) {
        *error = tr("The field is outside the packet.");
        return false;
    }

    switch (f.kind) {
    case DecodedField::UInt: {
        bool ok = false;
        quint64 v = text.startsWith("0x", Qt::CaseInsensitive)
                        ? text.mid(2).toULongLong(&ok, 16)
                        : text.toULongLong(&ok, 10);
        if (!ok) {
            *error = tr("Enter a number - decimal (e.g. 80) or "
                        "hexadecimal with 0x (e.g. 0x50).");
            return false;
        }
        if (v > maxValue(f)) {
            *error = tr("The value must be between 0 and %1.")
                         .arg(maxValue(f));
            return false;
        }
        writeUInt(pkt, f, v);
        return true;
    }
    case DecodedField::Mac: {
        QString digits = text;
        digits.remove(QRegularExpression("[:\\-\\.\\s]"));
        bool ok = digits.size() == 12;
        QByteArray bytes = QByteArray::fromHex(digits.toLatin1());
        ok = ok && bytes.size() == 6
                && QRegularExpression("^[0-9A-Fa-f]{12}$")
                       .match(digits).hasMatch();
        if (!ok) {
            *error = tr("Enter a MAC address such as 00:11:22:33:44:55.");
            return false;
        }
        pkt.replace(f.offset, 6, bytes);
        return true;
    }
    case DecodedField::Ipv4: {
        QHostAddress addr;
        if (!addr.setAddress(text)
                || addr.protocol() != QAbstractSocket::IPv4Protocol) {
            *error = tr("Enter an IPv4 address such as 192.168.0.1.");
            return false;
        }
        quint32 v = addr.toIPv4Address();
        for (int i = 0; i < 4; i++)
            pkt[f.offset + i] = char((v >> (24 - 8 * i)) & 0xFF);
        return true;
    }
    case DecodedField::Ipv6: {
        QHostAddress addr;
        if (!addr.setAddress(text)
                || addr.protocol() != QAbstractSocket::IPv6Protocol) {
            *error = tr("Enter an IPv6 address such as 2001:db8::1.");
            return false;
        }
        Q_IPV6ADDR v = addr.toIPv6Address();
        for (int i = 0; i < 16; i++)
            pkt[f.offset + i] = char(v[i]);
        return true;
    }
    default:
        *error = tr("Edit these bytes directly in the hex pane.");
        return false;
    }
}

int PacketDecoder::fixChecksums(QByteArray &pkt)
{
    int changed = 0;
    // Checksums of different layers don't cover each other, but run a
    // couple of passes anyway in case decoding changes after a fix
    for (int pass = 0; pass < 3; pass++) {
        PacketDecoder dec(pkt);
        int n = 0;
        for (const ChecksumSpot &spot : dec.checksums()) {
            quint16 cur = quint16((quint8(pkt.at(spot.offset)) << 8)
                                  | quint8(pkt.at(spot.offset + 1)));
            if (cur != spot.correct) {
                pkt[spot.offset] = char(spot.correct >> 8);
                pkt[spot.offset + 1] = char(spot.correct & 0xFF);
                n++;
            }
        }
        changed += n;
        if (!n)
            break;
    }
    return changed;
}
