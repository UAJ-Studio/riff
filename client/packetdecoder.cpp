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
#include <QMap>
#include <QRegularExpression>
#include <QSet>
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

// Printable preview of a byte range, or empty if it doesn't look like text
QString textPreview(const QByteArray &pkt, int off, int len)
{
    if (len < 4)
        return QString();
    int n = qMin(len, 32), printable = 0;
    QString s;
    for (int i = 0; i < n; i++) {
        uchar c = uchar(pkt.at(off + i));
        if (c >= 0x20 && c < 0x7F) {
            printable++;
            s.append(QChar(c));
        }
        else {
            s.append('.');
        }
    }
    if (printable * 10 < n * 8)
        return QString();
    return QString("  \"%1%2\"").arg(s, len > n ? QString::fromUtf8("\xE2\x80\xA6")
                                                : QString());
}

QString etherTypeName(quint32 type)
{
    switch (type) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86DD: return "IPv6";
    case 0x8100: return "802.1Q VLAN";
    case 0x88A8: return "802.1ad QinQ";
    case 0x9100: return "QinQ";
    case 0x8847: return "MPLS";
    case 0x8848: return "MPLS multicast";
    case 0x8863: return "PPPoE Discovery";
    case 0x8864: return "PPPoE Session";
    case 0x88CC: return "LLDP";
    case 0x88F7: return "PTP";
    case 0x6558: return "Transparent Ethernet Bridging";
    case 0x88BE: return "ERSPAN Type II";
    case 0x22EB: return "ERSPAN Type III";
    case 0x8809: return "Slow Protocols (LACP)";
    case 0x88E5: return "MACsec";
    case 0x8906: return "FCoE";
    case 0x88B5: return "Local Experimental";
    default: return QString();
    }
}

bool isVlanTpid(quint32 type)
{
    return type == 0x8100 || type == 0x88A8 || type == 0x9100;
}

QString ipProtoName(quint32 p)
{
    switch (p) {
    case 0: return "IPv6 Hop-by-Hop";
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 4: return "IPv4 (IP-in-IP)";
    case 6: return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 43: return "IPv6 Routing";
    case 44: return "IPv6 Fragment";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    case 58: return "ICMPv6";
    case 59: return "No Next Header";
    case 60: return "IPv6 Destination Options";
    case 89: return "OSPF";
    case 97: return "EtherIP";
    case 103: return "PIM";
    case 112: return "VRRP";
    case 115: return "L2TPv3";
    case 132: return "SCTP";
    default: return QString();
    }
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
        decodeEthernet(0, pkt_.size(), fields_, 0);
}

DecodedField PacketDecoder::header(const QString &name, int off, int len,
                                   const QString &value)
{
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Header;
    f.offset = off;
    f.length = len;
    f.value = value;
    return f;
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

void PacketDecoder::addData(int off, int len, const QString &name, Out &out)
{
    if (len <= 0 || !has(off, len))
        return;
    DecodedField f;
    f.name = name;
    f.kind = DecodedField::Bytes;
    f.offset = off;
    f.length = len;
    f.value = tr("%n byte(s)", "", len) + textPreview(pkt_, off, len);
    out.append(f);
}

// ---- Layer 2 -----------------------------------------------------------

int PacketDecoder::decodeEthernet(int off, int end, Out &out, int depth)
{
    if (end - off < 14) {
        addData(off, end - off,
                tr("Data (too short for an Ethernet header)"), out);
        return end;
    }

    DecodedField eth = header(depth ? tr("Inner Ethernet") : tr("Ethernet"),
            off, 14, macText(pkt_, off + 6) + kArrow + macText(pkt_, off));
    eth.children << macField(tr("Destination"), off)
                 << macField(tr("Source"), off + 6);

    int type = int(u16(off + 12));
    if (type <= 1500) {
        // IEEE 802.3 length field + LLC
        DecodedField len = uintField(tr("Length"), off + 12, 2);
        len.error = off + 14 + type > end;
        eth.children << len;
        out << eth;
        int llcEnd = qMin(end, off + 14 + type);
        int done = decodeLlc(off + 14, llcEnd, out, depth);
        addData(done, llcEnd - done, tr("Data"), out);
        addData(llcEnd, end - llcEnd, tr("Trailer / padding"), out);
        return end;
    }

    eth.children << uintField(tr("Type"), off + 12, 2, 0, 0,
                              etherTypeName(quint32(type)), true);
    out << eth;
    off += 14;

    while (isVlanTpid(quint32(type)) && off + 4 <= end)
        off = decodeVlan(off, type, out, &type);

    int done = dispatchEtherType(type, off, end, out, depth);
    addData(done, end - done,
            done > off ? tr("Trailer / padding") : tr("Data"), out);
    return end;
}

int PacketDecoder::decodeVlan(int off, int tpid, Out &out, int *type)
{
    DecodedField vlan = header(
            (tpid == 0x8100) ? tr("VLAN (802.1Q)") : tr("VLAN (QinQ)"),
            off, 4, tr("VLAN %1").arg(u16(off) & 0x0FFF));
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

int PacketDecoder::dispatchEtherType(int type, int off, int end, Out &out,
                                     int depth)
{
    if (depth > kMaxDepth)
        return off;
    switch (type) {
    case 0x0800: return decodeIpv4(off, end, out, depth);
    case 0x86DD: return decodeIpv6(off, end, out, depth);
    case 0x0806: return decodeArp(off, end, out);
    case 0x8847:
    case 0x8848: return decodeMpls(off, end, out, depth);
    case 0x8863: return decodePppoe(off, end, false, out, depth);
    case 0x8864: return decodePppoe(off, end, true, out, depth);
    case 0x88CC: return decodeLldp(off, end, out);
    case 0x6558: return decodeEthernet(off, end, out, depth + 1);
    default: return off;
    }
}

int PacketDecoder::decodeLlc(int off, int end, Out &out, int depth)
{
    if (off + 3 > end)
        return off;
    quint32 dsap = u8(off), ssap = u8(off + 1);
    DecodedField llc = header("LLC", off, 3);
    llc.children << uintField("DSAP", off, 1, 0, 0,
                              dsap == 0x42 ? "STP" : QString(), true)
                 << uintField("SSAP", off + 1, 1, 0, 0, QString(), true)
                 << uintField(tr("Control"), off + 2, 1, 0, 0,
                              QString(), true);
    out << llc;
    off += 3;

    if (dsap == 0x42 && ssap == 0x42)
        return decodeStp(off, end, out);

    if (dsap == 0xAA && ssap == 0xAA && off + 5 <= end) {
        quint32 oui = (u8(off) << 16) | u16(off + 1);
        DecodedField snap = header("SNAP", off, 5);
        snap.children << uintField("OUI", off, 3, 0, 0,
                                   oui == 0x00000C ? "Cisco" : QString(), true)
                      << uintField(tr("Protocol ID"), off + 3, 2, 0, 0,
                                   oui == 0 ? etherTypeName(u16(off + 3))
                                            : QString(), true);
        out << snap;
        int pid = int(u16(off + 3));
        off += 5;
        if (oui == 0)
            return dispatchEtherType(pid, off, end, out, depth);
    }
    return off;
}

int PacketDecoder::decodeStp(int off, int end, Out &out)
{
    if (off + 4 > end)
        return off;
    int version = int(u8(off + 2));
    int type = int(u8(off + 3));
    QString kind = (type == 0x80) ? tr("Topology Change Notification")
                 : (version >= 2) ? "RSTP/MSTP" : "STP";
    DecodedField stp = header(tr("Spanning Tree (BPDU)"), off,
                              qMin(end - off, type == 0x80 ? 4 : 35), kind);
    stp.children << uintField(tr("Protocol ID"), off, 2, 0, 0, QString(), true)
                 << uintField(tr("Version"), off + 2, 1)
                 << uintField(tr("BPDU type"), off + 3, 1, 0, 0, QString(),
                              true);
    if (type != 0x80 && off + 35 <= end) {
        stp.children
            << uintField(tr("Flags"), off + 4, 1, 0, 0, QString(), true)
            << uintField(tr("Root priority"), off + 5, 2, 0xF000, 12,
                         tr("x 4096"))
            << macField(tr("Root bridge MAC"), off + 7)
            << uintField(tr("Root path cost"), off + 13, 4)
            << uintField(tr("Bridge priority"), off + 17, 2, 0xF000, 12,
                         tr("x 4096"))
            << macField(tr("Bridge MAC"), off + 19)
            << uintField(tr("Port ID"), off + 25, 2, 0, 0, QString(), true)
            << uintField(tr("Message age"), off + 27, 2, 0, 0, tr("1/256 s"))
            << uintField(tr("Max age"), off + 29, 2, 0, 0, tr("1/256 s"))
            << uintField(tr("Hello time"), off + 31, 2, 0, 0, tr("1/256 s"))
            << uintField(tr("Forward delay"), off + 33, 2, 0, 0,
                         tr("1/256 s"));
    }
    out << stp;
    return off + stp.length;
}

int PacketDecoder::decodeArp(int off, int end, Out &out)
{
    if (off + 8 > end)
        return off;

    quint32 op = u16(off + 6);
    QString opName = (op == 1) ? tr("Request") : (op == 2) ? tr("Reply")
                                                         : QString();
    DecodedField arp = header("ARP", off, 8);
    arp.children
        << uintField(tr("Hardware type"), off, 2, 0, 0,
                     u16(off) == 1 ? "Ethernet" : QString())
        << uintField(tr("Protocol type"), off + 2, 2, 0, 0,
                     etherTypeName(u16(off + 2)), true)
        << uintField(tr("Hardware size"), off + 4, 1)
        << uintField(tr("Protocol size"), off + 5, 1)
        << uintField(tr("Operation"), off + 6, 2, 0, 0, opName);

    if (u8(off + 4) == 6 && u8(off + 5) == 4 && off + 28 <= end) {
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

int PacketDecoder::decodeMpls(int off, int end, Out &out, int depth)
{
    bool bottom = false;
    while (!bottom && off + 4 <= end) {
        quint32 word = u32(off);
        bottom = word & 0x100;
        DecodedField mpls = header("MPLS", off, 4,
                tr("Label %1").arg(word >> 12));
        mpls.children
            << uintField(tr("Label"), off, 4, 0xFFFFF000, 12)
            << uintField(tr("Traffic class"), off, 4, 0x00000E00, 9)
            << uintField(tr("Bottom of stack"), off, 4, 0x00000100, 8)
            << uintField("TTL", off, 4, 0x000000FF, 0);
        out << mpls;
        off += 4;
    }
    if (!bottom)
        return off;
    // No protocol field in MPLS - guess IPv4/IPv6 from the version nibble
    return decodeIpByVersion(off, end, out, depth);
}

int PacketDecoder::decodePppoe(int off, int end, bool session, Out &out,
                               int depth)
{
    if (off + 6 > end)
        return off;
    static const QMap<quint32, QString> codes {
        {0x00, "Session Data"}, {0x09, "PADI"}, {0x07, "PADO"},
        {0x19, "PADR"}, {0x65, "PADS"}, {0xA7, "PADT"}};

    int plen = int(u16(off + 4));
    DecodedField pppoe = header(session ? tr("PPPoE Session")
                                        : tr("PPPoE Discovery"),
                                off, 6, codes.value(u8(off + 1)));
    DecodedField len = uintField(tr("Payload length"), off + 4, 2);
    len.error = off + 6 + plen > end;
    pppoe.children << uintField(tr("Version"), off, 1, 0xF0, 4)
                   << uintField(tr("Type"), off, 1, 0x0F, 0)
                   << uintField(tr("Code"), off + 1, 1, 0, 0,
                                codes.value(u8(off + 1)), true)
                   << uintField(tr("Session ID"), off + 2, 2, 0, 0,
                                QString(), true)
                   << len;
    int payEnd = qMin(end, off + 6 + plen);
    off += 6;
    if (session && off + 2 <= payEnd) {
        quint32 proto = u16(off);
        QString name = (proto == 0x0021) ? "IPv4" : (proto == 0x0057) ? "IPv6"
                     : (proto == 0xC021) ? "LCP" : (proto == 0x8021) ? "IPCP"
                     : (proto == 0xC023) ? "PAP" : (proto == 0xC223) ? "CHAP"
                     : QString();
        pppoe.children << uintField(tr("PPP protocol"), off, 2, 0, 0, name,
                                    true);
        pppoe.length += 2;
        out << pppoe;
        off += 2;
        if (proto == 0x0021)
            return decodeIpv4(off, payEnd, out, depth);
        if (proto == 0x0057)
            return decodeIpv6(off, payEnd, out, depth);
        addData(off, payEnd - off, tr("PPP payload"), out);
        return payEnd;
    }
    out << pppoe;
    addData(off, payEnd - off, tr("Tags"), out);
    return payEnd;
}

int PacketDecoder::decodeLldp(int off, int end, Out &out)
{
    static const QMap<int, QString> names {
        {0, "End of LLDPDU"}, {1, "Chassis ID"}, {2, "Port ID"},
        {3, "Time To Live"}, {4, "Port Description"}, {5, "System Name"},
        {6, "System Description"}, {7, "System Capabilities"},
        {8, "Management Address"}, {127, "Organizationally Specific"}};

    DecodedField lldp = header("LLDP", off, 0);
    int start = off;
    while (off + 2 <= end) {
        int type = int(u16(off) >> 9);
        int len = int(u16(off) & 0x1FF);
        int vlen = qMin(len, end - off - 2);
        DecodedField tlv = header(names.value(type, tr("TLV %1").arg(type)),
                                  off, 2 + vlen);
        if (type == 4 || type == 5 || type == 6)
            tlv.value = QString::fromUtf8(pkt_.mid(off + 2, vlen));
        else if (type == 3 && vlen >= 2)
            tlv.value = tr("%1 s").arg(u16(off + 2));
        tlv.children << uintField(tr("Type"), off, 2, 0xFE00, 9)
                     << uintField(tr("Length"), off, 2, 0x01FF, 0);
        addData(off + 2, vlen, tr("Value"), tlv.children);
        lldp.children << tlv;
        off += 2 + vlen;
        if (type == 0)
            break;
    }
    lldp.length = off - start;
    out << lldp;
    return off;
}

// ---- Layer 3 -----------------------------------------------------------

int PacketDecoder::decodeIpByVersion(int off, int end, Out &out, int depth)
{
    if (off >= end || depth > kMaxDepth)
        return off;
    int version = int(u8(off) >> 4);
    if (version == 4)
        return decodeIpv4(off, end, out, depth);
    if (version == 6)
        return decodeIpv6(off, end, out, depth);
    return off;
}

int PacketDecoder::decodeIpv4(int off, int end, Out &out, int depth)
{
    if (off + 20 > end)
        return off;

    int ihl = int(u8(off) & 0x0F);
    int hlen = ihl * 4;
    int avail = end - off;
    int total = int(u16(off + 2));

    DecodedField ip = header(depth ? tr("Inner IPv4") : tr("IPv4"), off,
            qMin(qMax(hlen, 20), avail),
            ipv4Text(pkt_, off + 12) + kArrow + ipv4Text(pkt_, off + 16));

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

    // Fragments other than the first carry no upper layer header
    bool firstFragment = (u16(off + 6) & 0x1FFF) == 0;
    int ipEnd = off + qMin(qMax(total, hlen), avail);
    int l4off = off + hlen;
    int l4len = ipEnd - l4off;

    QByteArray pseudo = pkt_.mid(off + 12, 8);
    pseudo.append(char(0));
    pseudo.append(char(u8(off + 9)));
    pseudo.append(char((l4len >> 8) & 0xFF));
    pseudo.append(char(l4len & 0xFF));

    int done = l4off;
    if (firstFragment)
        done = dispatchIpProto(int(u8(off + 9)), l4off, ipEnd, pseudo, out,
                               depth);
    addData(done, ipEnd - done,
            firstFragment ? tr("Data") : tr("Fragment data"), out);
    return ipEnd;
}

int PacketDecoder::decodeIpv6(int off, int end, Out &out, int depth)
{
    if (off + 40 > end)
        return off;

    int avail = end - off - 40;
    int plen = int(u16(off + 4));
    int nh = int(u8(off + 6));

    DecodedField ip = header(depth ? tr("Inner IPv6") : tr("IPv6"), off, 40,
            ipv6Text(pkt_, off + 8) + kArrow + ipv6Text(pkt_, off + 24));

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
    int ipEnd = l4off + qMin(plen, avail);

    // Extension headers
    bool fragment = false;
    while ((nh == 0 || nh == 43 || nh == 60 || nh == 44)
                && l4off + 8 <= ipEnd) {
        int len = (nh == 44) ? 8 : (int(u8(l4off + 1)) + 1) * 8;
        len = qMin(len, ipEnd - l4off);
        DecodedField ext = header(ipProtoName(nh), l4off, len);
        ext.children << uintField(tr("Next header"), l4off, 1, 0, 0,
                                  ipProtoName(u8(l4off)));
        if (nh == 44) {
            ext.children
                << uintField(tr("Fragment offset"), l4off + 2, 2, 0xFFF8, 3)
                << uintField(tr("More fragments"), l4off + 2, 2, 0x0001, 0)
                << uintField(tr("Identification"), l4off + 4, 4, 0, 0,
                             QString(), true);
            fragment = (u16(l4off + 2) & 0xFFF8) != 0;
        }
        else {
            ext.children << uintField(tr("Length"), l4off + 1, 1, 0, 0,
                                      tr("%1 bytes").arg(len));
            addData(l4off + 2, len - 2, tr("Options"), ext.children);
        }
        out << ext;
        nh = int(u8(l4off));
        l4off += len;
    }

    int l4len = ipEnd - l4off;
    QByteArray pseudo = pkt_.mid(off + 8, 32);
    pseudo.append(char((l4len >> 24) & 0xFF));
    pseudo.append(char((l4len >> 16) & 0xFF));
    pseudo.append(char((l4len >> 8) & 0xFF));
    pseudo.append(char(l4len & 0xFF));
    pseudo.append(QByteArray(3, char(0)));
    pseudo.append(char(nh));

    int done = l4off;
    if (!fragment)
        done = dispatchIpProto(nh, l4off, ipEnd, pseudo, out, depth);
    addData(done, ipEnd - done, fragment ? tr("Fragment data") : tr("Data"),
            out);
    return ipEnd;
}

int PacketDecoder::dispatchIpProto(int proto, int off, int end,
        const QByteArray &pseudo, Out &out, int depth)
{
    switch (proto) {
    case 6: return decodeTcp(off, end, pseudo, out);
    case 17: return decodeUdp(off, end, pseudo, out, depth);
    case 1: return decodeIcmp(off, end, out, depth);
    case 58: return decodeIcmp6(off, end, pseudo, out);
    case 2: return decodeIgmp(off, end, out);
    case 132: return decodeSctp(off, end, out);
    case 50: return decodeEsp(off, end, out);
    case 4:
        return depth < kMaxDepth ? decodeIpv4(off, end, out, depth + 1)
                                 : off;
    case 41:
        return depth < kMaxDepth ? decodeIpv6(off, end, out, depth + 1)
                                 : off;
    case 47: return decodeGre(off, end, out, depth);
    case 97: return decodeEtherIp(off, end, out, depth);
    default: return off;
    }
}

// ---- Layer 4 -----------------------------------------------------------

static quint16 l4Checksum(const QByteArray &pkt, int off, int len,
                          int csumOff, const QByteArray &pseudo)
{
    QByteArray seg = pkt.mid(off, len);
    seg[csumOff] = 0;
    seg[csumOff + 1] = 0;
    return internetChecksum(pseudo + seg);
}

int PacketDecoder::decodeTcp(int off, int end, const QByteArray &pseudo,
                             Out &out)
{
    int len = end - off;
    if (len < 20)
        return off;

    int doff = int(u8(off + 12) >> 4) * 4;
    quint32 flags = u16(off + 12) & 0x01FF;
    static const char *flagNames[] = {"FIN", "SYN", "RST", "PSH", "ACK",
                                      "URG", "ECE", "CWR", "NS"};
    QStringList set;
    for (int i = 0; i < 9; i++)
        if (flags & (1u << i))
            set << flagNames[i];

    DecodedField tcp = header("TCP", off, qBound(20, doff, len),
            QString("%1%2%3").arg(u16(off)).arg(kArrow).arg(u16(off + 2)));
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

    addData(off + tcp.length, len - tcp.length, tr("Payload"), out);
    return end;
}

int PacketDecoder::decodeUdp(int off, int end, const QByteArray &pseudo,
                             Out &out, int depth)
{
    int len = end - off;
    if (len < 8)
        return off;

    int sport = int(u16(off)), dport = int(u16(off + 2));
    DecodedField udp = header("UDP", off, 8,
            QString("%1%2%3").arg(sport).arg(kArrow).arg(dport));

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

    int done = dispatchUdpPort(sport, dport, off + 8, end, out, depth);
    addData(done, end - done, tr("Payload"), out);
    return end;
}

int PacketDecoder::decodeSctp(int off, int end, Out &out)
{
    if (off + 12 > end)
        return off;
    static const QMap<int, QString> chunkNames {
        {0, "DATA"}, {1, "INIT"}, {2, "INIT ACK"}, {3, "SACK"},
        {4, "HEARTBEAT"}, {5, "HEARTBEAT ACK"}, {6, "ABORT"},
        {7, "SHUTDOWN"}, {8, "SHUTDOWN ACK"}, {9, "ERROR"},
        {10, "COOKIE ECHO"}, {11, "COOKIE ACK"}, {14, "SHUTDOWN COMPLETE"}};

    DecodedField sctp = header("SCTP", off, 12,
            QString("%1%2%3").arg(u16(off)).arg(kArrow).arg(u16(off + 2)));
    sctp.children << uintField(tr("Source port"), off, 2)
                  << uintField(tr("Destination port"), off + 2, 2)
                  << uintField(tr("Verification tag"), off + 4, 4, 0, 0,
                               QString(), true)
                  << uintField(tr("Checksum (CRC32c)"), off + 8, 4, 0, 0,
                               QString(), true);
    out << sctp;
    off += 12;
    while (off + 4 <= end) {
        int type = int(u8(off));
        int len = int(u16(off + 2));
        int clen = qBound(4, len, end - off);
        DecodedField chunk = header(tr("Chunk: %1")
                .arg(chunkNames.value(type, QString::number(type))),
                off, clen);
        chunk.children << uintField(tr("Type"), off, 1, 0, 0,
                                    chunkNames.value(type))
                       << uintField(tr("Flags"), off + 1, 1, 0, 0,
                                    QString(), true)
                       << uintField(tr("Length"), off + 2, 2);
        addData(off + 4, clen - 4, tr("Value"), chunk.children);
        out << chunk;
        off += (clen + 3) & ~3;
    }
    return qMin(off, end);
}

int PacketDecoder::decodeIcmp(int off, int end, Out &out, int depth)
{
    int len = end - off;
    if (len < 4)
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

    DecodedField icmp = header("ICMP", off, qMin(8, len), name);
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

    // Error messages quote the offending packet's IP header
    int done = off + icmp.length;
    if ((type == 3 || type == 5 || type == 11) && len >= 28
            && depth < kMaxDepth)
        done = decodeIpv4(done, end, out, depth + 1);
    addData(done, end - done, tr("Data"), out);
    return end;
}

int PacketDecoder::decodeIcmp6(int off, int end, const QByteArray &pseudo,
                               Out &out)
{
    int len = end - off;
    if (len < 4)
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

    DecodedField icmp = header("ICMPv6", off, 4, name);
    icmp.children << uintField(tr("Type"), off, 1, 0, 0, name)
                  << uintField(tr("Code"), off + 1, 1)
                  << checksumField(tr("Checksum"), off + 2,
                                   l4Checksum(pkt_, off, len, 2, pseudo));
    if ((type == 128 || type == 129) && len >= 8) {
        icmp.length = 8;
        icmp.children << uintField(tr("Identifier"), off + 4, 2)
                      << uintField(tr("Sequence number"), off + 6, 2);
    }
    else if ((type == 135 || type == 136) && len >= 24) {
        icmp.length = 24;
        addData(off + 4, 4, tr("Flags / reserved"), icmp.children);
        icmp.children << ipv6Field(tr("Target address"), off + 8);
    }
    out << icmp;
    addData(off + icmp.length, len - icmp.length, tr("Data"), out);
    return end;
}

int PacketDecoder::decodeIgmp(int off, int end, Out &out)
{
    int len = end - off;
    if (len < 8)
        return off;
    QString name;
    switch (u8(off)) {
    case 0x11: name = tr("Membership Query"); break;
    case 0x12: name = tr("Membership Report v1"); break;
    case 0x16: name = tr("Membership Report v2"); break;
    case 0x17: name = tr("Leave Group"); break;
    case 0x22: name = tr("Membership Report v3"); break;
    default: break;
    }
    QByteArray msg = pkt_.mid(off, len);
    msg[2] = 0;
    msg[3] = 0;
    DecodedField igmp = header("IGMP", off, 8, name);
    igmp.children << uintField(tr("Type"), off, 1, 0, 0, name, true)
                  << uintField(tr("Max response time"), off + 1, 1, 0, 0,
                               tr("1/10 s"))
                  << checksumField(tr("Checksum"), off + 2,
                                   internetChecksum(msg));
    if (u8(off) == 0x22)
        igmp.children << uintField(tr("Number of group records"), off + 6, 2);
    else
        igmp.children << ipv4Field(tr("Group address"), off + 4);
    out << igmp;
    addData(off + 8, len - 8, tr("Data"), out);
    return end;
}

int PacketDecoder::decodeEsp(int off, int end, Out &out)
{
    if (off + 8 > end)
        return off;
    DecodedField esp = header("ESP", off, 8,
            tr("SPI %1").arg(hex(u32(off), 8)));
    esp.children << uintField("SPI", off, 4, 0, 0, QString(), true)
                 << uintField(tr("Sequence number"), off + 4, 4);
    out << esp;
    addData(off + 8, end - off - 8, tr("Encrypted data"), out);
    return end;
}

// ---- Tunnels carried directly in IP ------------------------------------

int PacketDecoder::decodeGre(int off, int end, Out &out, int depth)
{
    if (off + 4 > end)
        return off;
    quint32 flags = u16(off);
    int proto = int(u16(off + 2));
    int version = int(flags & 0x7);
    bool c = flags & 0x8000, k = flags & 0x2000, s = flags & 0x1000;
    int hlen = 4 + (c ? 4 : 0) + (k ? 4 : 0) + (s ? 4 : 0);
    if (off + hlen > end)
        hlen = end - off;

    DecodedField gre = header("GRE", off, hlen,
            etherTypeName(quint32(proto)));
    gre.children
        << uintField(tr("Checksum present"), off, 2, 0x8000, 15)
        << uintField(tr("Key present"), off, 2, 0x2000, 13)
        << uintField(tr("Sequence number present"), off, 2, 0x1000, 12)
        << uintField(tr("Version"), off, 2, 0x0007, 0,
                     version == 1 ? "PPTP" : QString())
        << uintField(tr("Protocol type"), off + 2, 2, 0, 0,
                     etherTypeName(quint32(proto)), true);
    int pos = off + 4;
    if (c && pos + 4 <= end) {
        QByteArray msg = pkt_.mid(off, end - off);
        msg[pos - off] = 0;
        msg[pos - off + 1] = 0;
        gre.children << checksumField(tr("Checksum"), pos,
                                      internetChecksum(msg));
        pos += 4;
    }
    if (k && pos + 4 <= end) {
        if (version == 1)
            gre.children << uintField(tr("Payload length"), pos, 2)
                         << uintField(tr("Call ID"), pos + 2, 2);
        else if (proto == 0x6558)
            gre.children << uintField(tr("Virtual subnet ID (NVGRE)"), pos,
                                      4, 0xFFFFFF00, 8)
                         << uintField(tr("Flow ID"), pos, 4, 0xFF, 0);
        else
            gre.children << uintField(tr("Key"), pos, 4, 0, 0, QString(),
                                      true);
        pos += 4;
    }
    if (s && pos + 4 <= end) {
        gre.children << uintField(tr("Sequence number"), pos, 4);
        pos += 4;
    }
    out << gre;

    if (depth >= kMaxDepth)
        return pos;

    if (proto == 0x88BE && pos + 8 <= end) {      // ERSPAN Type II
        DecodedField er = header(tr("ERSPAN Type II"), pos, 8,
                tr("Session %1").arg(u16(pos + 2) & 0x3FF));
        er.children << uintField(tr("Version"), pos, 2, 0xF000, 12)
                    << uintField(tr("VLAN"), pos, 2, 0x0FFF, 0)
                    << uintField("CoS", pos + 2, 2, 0xE000, 13)
                    << uintField(tr("Encapsulation type"), pos + 2, 2,
                                 0x1800, 11)
                    << uintField(tr("Truncated"), pos + 2, 2, 0x0400, 10)
                    << uintField(tr("Session ID"), pos + 2, 2, 0x03FF, 0)
                    << uintField(tr("Index"), pos + 4, 4, 0x000FFFFF, 0);
        out << er;
        return decodeEthernet(pos + 8, end, out, depth + 1);
    }
    if (proto == 0x22EB && pos + 12 <= end) {     // ERSPAN Type III
        bool o = u8(pos + 11) & 0x01;
        int elen = o ? 20 : 12;
        DecodedField er = header(tr("ERSPAN Type III"), pos,
                qMin(elen, end - pos),
                tr("Session %1").arg(u16(pos + 2) & 0x3FF));
        er.children << uintField(tr("Version"), pos, 2, 0xF000, 12)
                    << uintField(tr("VLAN"), pos, 2, 0x0FFF, 0)
                    << uintField(tr("Session ID"), pos + 2, 2, 0x03FF, 0)
                    << uintField(tr("Timestamp"), pos + 4, 4);
        addData(pos + 8, er.length - 8, tr("Flags / platform info"),
                er.children);
        out << er;
        return decodeEthernet(pos + er.length, end, out, depth + 1);
    }
    return dispatchEtherType(proto, pos, end, out, depth + 1);
}

int PacketDecoder::decodeEtherIp(int off, int end, Out &out, int depth)
{
    if (off + 2 > end)
        return off;
    DecodedField eip = header("EtherIP", off, 2,
            tr("version %1").arg(u8(off) >> 4));
    DecodedField ver = uintField(tr("Version"), off, 2, 0xF000, 12);
    ver.error = (u8(off) >> 4) != 3;
    eip.children << ver << uintField(tr("Reserved"), off, 2, 0x0FFF, 0);
    out << eip;
    if (depth >= kMaxDepth)
        return off + 2;
    return decodeEthernet(off + 2, end, out, depth + 1);
}

// ---- UDP based tunnels and applications ---------------------------------

int PacketDecoder::dispatchUdpPort(int sport, int dport, int off, int end,
                                   Out &out, int depth)
{
    if (off >= end || depth >= kMaxDepth)
        return off;
    // Prefer the destination port, then the source port
    for (int port : {dport, sport}) {
        switch (port) {
        case 4789: return decodeVxlan(off, end, out, depth);
        case 6081: return decodeGeneve(off, end, out, depth);
        case 5246: return decodeCapwap(off, end, false, out, depth);
        case 5247: return decodeCapwap(off, end, true, out, depth);
        case 2152: return decodeGtpu(off, end, out, depth);
        case 53:
        case 5353: return decodeDns(off, end, out);
        case 67:
        case 68: return decodeDhcp(off, end, out);
        default: break;
        }
    }
    return off;
}

int PacketDecoder::decodeVxlan(int off, int end, Out &out, int depth)
{
    if (off + 8 > end)
        return off;
    DecodedField vx = header("VXLAN", off, 8,
            tr("VNI %1").arg(u32(off + 4) >> 8));
    vx.children << uintField(tr("Flags"), off, 1, 0, 0,
                             (u8(off) & 0x08) ? tr("VNI valid") : QString(),
                             true)
                << uintField(tr("Reserved"), off + 1, 3, 0, 0, QString(),
                             true)
                << uintField(tr("VNI"), off + 4, 4, 0xFFFFFF00, 8)
                << uintField(tr("Reserved"), off + 7, 1, 0, 0, QString(),
                             true);
    out << vx;
    return decodeEthernet(off + 8, end, out, depth + 1);
}

int PacketDecoder::decodeGeneve(int off, int end, Out &out, int depth)
{
    if (off + 8 > end)
        return off;
    int optLen = int(u8(off) & 0x3F) * 4;
    int proto = int(u16(off + 2));
    int hlen = qMin(8 + optLen, end - off);
    DecodedField gn = header("Geneve", off, hlen,
            tr("VNI %1").arg(u32(off + 4) >> 8));
    gn.children << uintField(tr("Version"), off, 1, 0xC0, 6)
                << uintField(tr("Options length"), off, 1, 0x3F, 0,
                             tr("%1 bytes").arg(optLen))
                << uintField(tr("OAM"), off + 1, 1, 0x80, 7)
                << uintField(tr("Critical options"), off + 1, 1, 0x40, 6)
                << uintField(tr("Protocol type"), off + 2, 2, 0, 0,
                             etherTypeName(quint32(proto)), true)
                << uintField(tr("VNI"), off + 4, 4, 0xFFFFFF00, 8);
    addData(off + 8, hlen - 8, tr("Options"), gn.children);
    out << gn;
    return dispatchEtherType(proto, off + hlen, end, out, depth + 1);
}

int PacketDecoder::decodeCapwap(int off, int end, bool dataChannel,
                                Out &out, int depth)
{
    if (off + 1 > end)
        return off;

    int type = int(u8(off) & 0x0F);
    if (type == 1) {
        // DTLS: preamble + 3 reserved bytes, then a DTLS record
        DecodedField dtls = header(tr("CAPWAP (DTLS)"), off,
                                   qMin(4, end - off), tr("encrypted"));
        dtls.children << uintField(tr("Version"), off, 1, 0xF0, 4)
                      << uintField(tr("Type"), off, 1, 0x0F, 0, "DTLS");
        out << dtls;
        addData(off + 4, end - off - 4, tr("DTLS record"), out);
        return end;
    }
    if (off + 8 > end)
        return off;

    quint32 w = u32(off);
    int hlen = int((w >> 19) & 0x1F) * 4;
    int wbid = int((w >> 9) & 0x1F);
    bool t = w & 0x100, f = w & 0x80;
    bool lastFragment = !(w & 0x40);
    int fragOff = int(u16(off + 6) >> 3);
    hlen = qBound(8, hlen, end - off);

    QString wbidName = (wbid == 1) ? "IEEE 802.11" : (wbid == 3) ? "EPCGlobal"
                                                               : QString();
    DecodedField cw = header(dataChannel ? tr("CAPWAP Data")
                                         : tr("CAPWAP Control"),
                             off, hlen);
    DecodedField hl = uintField(tr("Header length"), off, 4, 0x00F80000, 19,
                                tr("%1 bytes").arg(int((w >> 19) & 0x1F) * 4));
    hl.error = int((w >> 19) & 0x1F) * 4 < 8;
    cw.children
        << uintField(tr("Version"), off, 4, 0xF0000000, 28)
        << uintField(tr("Type"), off, 4, 0x0F000000, 24, tr("CAPWAP header"))
        << hl
        << uintField(tr("Radio ID"), off, 4, 0x0007C000, 14)
        << uintField(tr("Wireless binding ID"), off, 4, 0x00003E00, 9,
                     wbidName)
        << uintField(tr("T: native frame"), off, 4, 0x00000100, 8,
                     t ? tr("native (see binding)") : tr("IEEE 802.3"))
        << uintField(tr("F: fragment"), off, 4, 0x00000080, 7)
        << uintField(tr("L: not last fragment"), off, 4, 0x00000040, 6)
        << uintField(tr("W: wireless info present"), off, 4, 0x00000020, 5)
        << uintField(tr("M: radio MAC present"), off, 4, 0x00000010, 4)
        << uintField(tr("K: keep-alive"), off, 4, 0x00000008, 3)
        << uintField(tr("Fragment ID"), off + 4, 2)
        << uintField(tr("Fragment offset"), off + 6, 2, 0xFFF8, 3);
    addData(off + 8, hlen - 8, tr("Optional fields (radio MAC / wireless info)"),
            cw.children);

    int pos = off + hlen;
    if (f && fragOff != 0) {
        cw.value = tr("fragment");
        out << cw;
        addData(pos, end - pos, tr("Fragment data"), out);
        return end;
    }
    Q_UNUSED(lastFragment);

    if (dataChannel) {
        if (w & 0x08) {
            cw.value = tr("keep-alive");
            out << cw;
            return pos;
        }
        cw.value = t ? (wbid == 1 ? tr("802.11 frame") : tr("native frame"))
                     : tr("802.3 frame");
        out << cw;
        if (!t)
            return decodeEthernet(pos, end, out, depth + 1);
        addData(pos, end - pos, wbid == 1 ? tr("IEEE 802.11 frame")
                                          : tr("Native frame"), out);
        return end;
    }

    // Control channel: control header + message elements
    out << cw;
    if (pos + 8 > end)
        return pos;
    static const QMap<int, QString> msgNames {
        {1, "Discovery Request"}, {2, "Discovery Response"},
        {3, "Join Request"}, {4, "Join Response"},
        {5, "Configuration Status Request"},
        {6, "Configuration Status Response"},
        {7, "Configuration Update Request"},
        {8, "Configuration Update Response"},
        {9, "WTP Event Request"}, {10, "WTP Event Response"},
        {11, "Change State Event Request"},
        {12, "Change State Event Response"},
        {13, "Echo Request"}, {14, "Echo Response"},
        {15, "Image Data Request"}, {16, "Image Data Response"},
        {17, "Reset Request"}, {18, "Reset Response"},
        {19, "Primary Discovery Request"}, {20, "Primary Discovery Response"},
        {21, "Data Transfer Request"}, {22, "Data Transfer Response"},
        {23, "Clear Configuration Request"},
        {24, "Clear Configuration Response"},
        {25, "Station Configuration Request"},
        {26, "Station Configuration Response"}};
    int msgType = int(u8(pos + 3));
    int elemLen = int(u16(pos + 5));
    DecodedField ctl = header(tr("CAPWAP Control Message"), pos, 8,
            msgNames.value(msgType));
    // RFC 5415: the length counts the bytes following the Sequence Number
    // (i.e. the length field itself, the flags and the elements)
    DecodedField el = uintField(tr("Message elements length"), pos + 5, 2);
    el.error = elemLen < 3 || pos + 5 + elemLen > end;
    ctl.children << uintField(tr("Enterprise number"), pos, 3)
                 << uintField(tr("Message type"), pos + 3, 1, 0, 0,
                              msgNames.value(msgType))
                 << uintField(tr("Sequence number"), pos + 4, 1)
                 << el
                 << uintField(tr("Flags"), pos + 7, 1, 0, 0, QString(), true);
    int elemEnd = qMin(end, pos + 5 + elemLen);
    int e = pos + 8;
    while (e + 4 <= elemEnd) {
        int etype = int(u16(e)), elen = int(u16(e + 2));
        int vlen = qMin(elen, elemEnd - e - 4);
        DecodedField me = header(tr("Element %1").arg(etype), e, 4 + vlen);
        me.children << uintField(tr("Type"), e, 2)
                    << uintField(tr("Length"), e + 2, 2);
        addData(e + 4, vlen, tr("Value"), me.children);
        ctl.children << me;
        e += 4 + vlen;
    }
    ctl.length = e - pos;
    out << ctl;
    return e;
}

int PacketDecoder::decodeGtpu(int off, int end, Out &out, int depth)
{
    if (off + 8 > end)
        return off;
    quint32 flags = u8(off);
    int msgType = int(u8(off + 1));
    bool opt = flags & 0x07;
    int hlen = opt ? 12 : 8;
    if (off + hlen > end)
        return off;
    DecodedField gtp = header("GTP-U", off, hlen,
            tr("TEID %1").arg(hex(u32(off + 4), 8)));
    gtp.children << uintField(tr("Version"), off, 1, 0xE0, 5)
                 << uintField(tr("Protocol type"), off, 1, 0x10, 4)
                 << uintField(tr("Extension header flag"), off, 1, 0x04, 2)
                 << uintField(tr("Sequence number flag"), off, 1, 0x02, 1)
                 << uintField(tr("N-PDU number flag"), off, 1, 0x01, 0)
                 << uintField(tr("Message type"), off + 1, 1, 0, 0,
                              msgType == 255 ? "G-PDU"
                              : msgType == 1 ? "Echo Request"
                              : msgType == 2 ? "Echo Response" : QString())
                 << uintField(tr("Length"), off + 2, 2)
                 << uintField("TEID", off + 4, 4, 0, 0, QString(), true);
    int pos = off + 8;
    if (opt) {
        gtp.children << uintField(tr("Sequence number"), pos, 2)
                     << uintField(tr("N-PDU number"), pos + 2, 1)
                     << uintField(tr("Next extension header"), pos + 3, 1,
                                  0, 0, QString(), true);
        int next = int(u8(pos + 3));
        pos += 4;
        while (next && pos + 4 <= end) {   // skip extension headers
            int elen = int(u8(pos)) * 4;
            if (!elen || pos + elen > end)
                break;
            addData(pos, elen, tr("Extension header"), gtp.children);
            next = int(u8(pos + elen - 1));
            pos += elen;
        }
        gtp.length = pos - off;
    }
    out << gtp;
    if (msgType == 255)
        return decodeIpByVersion(pos, end, out, depth + 1);
    return pos;
}

QString PacketDecoder::dnsName(int off, int msgStart, int end,
                               int *next) const
{
    QStringList labels;
    int pos = off;
    int jumps = 0;
    *next = -1;
    while (pos < end) {
        int len = int(u8(pos));
        if (len == 0) {
            if (*next < 0)
                *next = pos + 1;
            break;
        }
        if ((len & 0xC0) == 0xC0) {           // compression pointer
            if (pos + 1 >= end || ++jumps > 16)
                break;
            if (*next < 0)
                *next = pos + 2;
            pos = msgStart + (((len & 0x3F) << 8) | int(u8(pos + 1)));
            continue;
        }
        if (pos + 1 + len > end)
            break;
        labels << QString::fromLatin1(pkt_.mid(pos + 1, len));
        pos += 1 + len;
    }
    if (*next < 0)
        *next = end;
    return labels.isEmpty() ? QString(".") : labels.join('.');
}

int PacketDecoder::decodeDns(int off, int end, Out &out)
{
    if (off + 12 > end)
        return off;
    bool response = u8(off + 2) & 0x80;
    int qd = int(u16(off + 4));
    DecodedField dns = header("DNS", off, 12,
            response ? tr("Response") : tr("Query"));
    dns.children << uintField(tr("Transaction ID"), off, 2, 0, 0, QString(),
                              true)
                 << uintField(tr("Response"), off + 2, 2, 0x8000, 15)
                 << uintField(tr("Opcode"), off + 2, 2, 0x7800, 11)
                 << uintField(tr("Authoritative"), off + 2, 2, 0x0400, 10)
                 << uintField(tr("Truncated"), off + 2, 2, 0x0200, 9)
                 << uintField(tr("Recursion desired"), off + 2, 2, 0x0100, 8)
                 << uintField(tr("Recursion available"), off + 2, 2, 0x0080,
                              7)
                 << uintField(tr("Response code"), off + 2, 2, 0x000F, 0)
                 << uintField(tr("Questions"), off + 4, 2)
                 << uintField(tr("Answer RRs"), off + 6, 2)
                 << uintField(tr("Authority RRs"), off + 8, 2)
                 << uintField(tr("Additional RRs"), off + 10, 2);
    int pos = off + 12;
    for (int i = 0; i < qd && i < 16 && pos < end; i++) {
        int next;
        QString name = dnsName(pos, off, end, &next);
        if (next + 4 > end)
            break;
        int qtype = int(u16(next));
        QString typeName = (qtype == 1) ? "A" : (qtype == 28) ? "AAAA"
                         : (qtype == 5) ? "CNAME" : (qtype == 15) ? "MX"
                         : (qtype == 2) ? "NS" : (qtype == 16) ? "TXT"
                         : (qtype == 12) ? "PTR" : (qtype == 33) ? "SRV"
                         : (qtype == 255) ? "ANY" : QString();
        DecodedField q = header(tr("Question"), pos, next + 4 - pos,
                QString("%1 %2").arg(name, typeName));
        DecodedField nameField;
        nameField.name = tr("Name");
        nameField.kind = DecodedField::Bytes;
        nameField.offset = pos;
        nameField.length = next - pos;
        nameField.value = name;
        q.children << nameField
                   << uintField(tr("Type"), next, 2, 0, 0, typeName)
                   << uintField(tr("Class"), next + 2, 2, 0, 0,
                                u16(next + 2) == 1 ? "IN" : QString());
        dns.children << q;
        pos = next + 4;
    }
    dns.length = pos - off;
    out << dns;
    addData(pos, end - pos, tr("Resource records"), out);
    return end;
}

int PacketDecoder::decodeDhcp(int off, int end, Out &out)
{
    if (off + 240 > end)
        return off;
    static const QMap<int, QString> optNames {
        {1, "Subnet Mask"}, {3, "Router"}, {6, "Domain Name Server"},
        {12, "Host Name"}, {15, "Domain Name"}, {28, "Broadcast Address"},
        {50, "Requested IP Address"}, {51, "IP Address Lease Time"},
        {53, "DHCP Message Type"}, {54, "Server Identifier"},
        {55, "Parameter Request List"}, {57, "Maximum Message Size"},
        {58, "Renewal Time"}, {59, "Rebinding Time"},
        {60, "Vendor Class Identifier"}, {61, "Client Identifier"},
        {82, "Relay Agent Information"}, {255, "End"}};
    static const QMap<int, QString> msgTypes {
        {1, "DISCOVER"}, {2, "OFFER"}, {3, "REQUEST"}, {4, "DECLINE"},
        {5, "ACK"}, {6, "NAK"}, {7, "RELEASE"}, {8, "INFORM"}};

    DecodedField dhcp = header("DHCP", off, 240);
    dhcp.children
        << uintField(tr("Operation"), off, 1, 0, 0,
                     u8(off) == 1 ? tr("Request") : tr("Reply"))
        << uintField(tr("Hardware type"), off + 1, 1)
        << uintField(tr("Hardware address length"), off + 2, 1)
        << uintField(tr("Hops"), off + 3, 1)
        << uintField(tr("Transaction ID"), off + 4, 4, 0, 0, QString(), true)
        << uintField(tr("Seconds elapsed"), off + 8, 2)
        << uintField(tr("Broadcast flag"), off + 10, 2, 0x8000, 15)
        << ipv4Field(tr("Client IP"), off + 12)
        << ipv4Field(tr("Your (client) IP"), off + 16)
        << ipv4Field(tr("Next server IP"), off + 20)
        << ipv4Field(tr("Relay agent IP"), off + 24)
        << macField(tr("Client MAC"), off + 28);
    addData(off + 34, 10, tr("Client hardware address padding"),
            dhcp.children);
    addData(off + 44, 64, tr("Server host name"), dhcp.children);
    addData(off + 108, 128, tr("Boot file name"), dhcp.children);
    DecodedField magic = uintField(tr("Magic cookie"), off + 236, 4, 0, 0,
                                   QString(), true);
    magic.error = u32(off + 236) != 0x63825363;
    dhcp.children << magic;

    int pos = off + 240;
    while (pos < end) {
        int code = int(u8(pos));
        if (code == 0) {                       // pad
            pos++;
            continue;
        }
        if (code == 255) {
            DecodedField endOpt = header(tr("Option %1").arg(code), pos, 1,
                                         "End");
            dhcp.children << endOpt;
            pos++;
            break;
        }
        if (pos + 2 > end)
            break;
        int len = qMin(int(u8(pos + 1)), end - pos - 2);
        QString name = optNames.value(code);
        DecodedField opt = header(tr("Option %1").arg(code), pos, 2 + len,
                                  name);
        if (code == 53 && len >= 1) {
            QString mt = msgTypes.value(int(u8(pos + 2)));
            opt.value = QString("%1: %2").arg(name, mt);
            dhcp.value = mt;
        }
        opt.children << uintField(tr("Code"), pos, 1, 0, 0, name)
                     << uintField(tr("Length"), pos + 1, 1);
        if (len == 4 && (code == 1 || code == 3 || code == 6 || code == 28
                         || code == 50 || code == 54))
            opt.children << ipv4Field(tr("Value"), pos + 2);
        else
            addData(pos + 2, len, tr("Value"), opt.children);
        dhcp.children << opt;
        pos += 2 + len;
    }
    dhcp.length = pos - off;
    out << dhcp;
    return pos;
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
        bool ok = QRegularExpression("^[0-9A-Fa-f]{12}$")
                      .match(digits).hasMatch();
        if (!ok) {
            *error = tr("Enter a MAC address such as 00:11:22:33:44:55.");
            return false;
        }
        pkt.replace(f.offset, 6, QByteArray::fromHex(digits.toLatin1()));
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
    const QByteArray original = pkt;
    // An inner (tunnelled) checksum fix changes the outer payload, so the
    // outer checksum must be recomputed - iterate until nothing changes
    QSet<int> spots;
    for (int pass = 0; pass < kMaxDepth + 3; pass++) {
        PacketDecoder dec(pkt);
        int n = 0;
        for (const ChecksumSpot &spot : dec.checksums()) {
            spots.insert(spot.offset);
            quint16 cur = quint16((quint8(pkt.at(spot.offset)) << 8)
                                  | quint8(pkt.at(spot.offset + 1)));
            if (cur != spot.correct) {
                pkt[spot.offset] = char(spot.correct >> 8);
                pkt[spot.offset + 1] = char(spot.correct & 0xFF);
                n++;
            }
        }
        if (!n)
            break;
    }
    // Report how many distinct checksums ended up different
    int changed = 0;
    for (int off : spots)
        if (pkt.mid(off, 2) != original.mid(off, 2))
            changed++;
    return changed;
}
