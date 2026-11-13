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

#ifndef _PACKET_DECODER_H
#define _PACKET_DECODER_H

#include <QByteArray>
#include <QCoreApplication>
#include <QList>
#include <QSet>
#include <QString>

/*
 * Lightweight decoder for the hex packet editor. Decodes the common
 * Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6 headers into a tree of
 * fields that know their byte position, so that the editor can highlight
 * and edit them. It never modifies the packet itself.
 */

struct DecodedField
{
    enum Kind {
        Header,   // protocol header (group node), not editable itself
        UInt,     // big-endian integer, optionally a bit-field (mask/shift)
        Mac,      // 6 byte MAC address
        Ipv4,     // 4 byte IPv4 address
        Ipv6,     // 16 byte IPv6 address
        Bytes     // opaque bytes - edit in the hex pane
    };

    QString name;
    QString value;          // human readable value
    Kind kind{Bytes};
    int offset{0};          // byte offset in the packet
    int length{0};          // bytes
    quint64 mask{0};        // UInt: bits of the (length-byte) word; 0 = all
    int shift{0};           // UInt: right shift after masking
    bool hexStyle{false};   // UInt: show/edit as 0x.. rather than decimal
    bool error{false};      // e.g. bad checksum - shown highlighted
    QList<DecodedField> children;

    bool isEditable() const {
        return kind == UInt || kind == Mac || kind == Ipv4 || kind == Ipv6;
    }
};

struct ChecksumSpot
{
    int offset;             // where the 16-bit checksum lives
    quint16 correct;        // value it should have
};

class PacketDecoder
{
    Q_DECLARE_TR_FUNCTIONS(PacketDecoder)

public:
    explicit PacketDecoder(const QByteArray &packet);

    const QList<DecodedField>& fields() const { return fields_; }
    const QList<ChecksumSpot>& checksums() const { return checksums_; }

    // Value helpers (also used by the editor to write fields back)
    static quint64 readUInt(const QByteArray &pkt, const DecodedField &f);
    static void writeUInt(QByteArray &pkt, const DecodedField &f, quint64 v);
    static quint64 maxValue(const DecodedField &f);

    // Parse user input for field f and write it into pkt.
    // Returns false (and sets *error) if the text is not a valid value.
    static bool writeText(QByteArray &pkt, const DecodedField &f,
                          const QString &text, QString *error);

    // Text to pre-fill an edit box with for field f
    static QString editText(const QByteArray &pkt, const DecodedField &f);

    // Overwrite every known checksum with its correct value.
    // Returns the number of checksums that changed.
    static int fixChecksums(QByteArray &pkt);
    // Same, but only touches checksums at the given offsets
    static int fixChecksums(QByteArray &pkt, const QSet<int> &onlyAt);
    // Offsets of the checksums that are currently correct
    static QSet<int> correctChecksums(const QByteArray &pkt);

    // Parse hex text in common formats (plain, spaced, 0x.., hex dumps
    // with offsets from Wireshark, tcpdump or xxd). Returns false with
    // *error set if the text is not hex or longer than maxLength bytes.
    static bool parseHexText(const QString &text, QByteArray *out,
                             QString *error, int maxLength);

private:
    // Every decodeXxx() decodes the bytes [off, end) and appends one or
    // more nodes to out. It returns the offset up to which it consumed
    // bytes (callers show anything left as data). depth counts tunnel
    // nesting so that crafted packets can't recurse forever.
    typedef QList<DecodedField> Out;

    // Layer 2
    int decodeEthernet(int off, int end, Out &out, int depth);
    int decodeVlan(int off, int tpid, Out &out, int *type);
    int decodeLlc(int off, int end, Out &out, int depth);
    int decodeStp(int off, int end, Out &out);
    int dispatchEtherType(int type, int off, int end, Out &out, int depth);
    int decodeArp(int off, int end, Out &out);
    int decodeMpls(int off, int end, Out &out, int depth);
    int decodePppoe(int off, int end, bool session, Out &out, int depth);
    int decodeLldp(int off, int end, Out &out);

    // Layer 3
    int decodeIpv4(int off, int end, Out &out, int depth);
    int decodeIpv6(int off, int end, Out &out, int depth);
    int dispatchIpProto(int proto, int off, int end,
                        const QByteArray &pseudo, Out &out, int depth);
    int decodeIpByVersion(int off, int end, Out &out, int depth);

    // Layer 4 and above
    int decodeTcp(int off, int end, const QByteArray &pseudo, Out &out);
    int decodeUdp(int off, int end, const QByteArray &pseudo, Out &out,
                  int depth);
    int decodeSctp(int off, int end, Out &out);
    int decodeIcmp(int off, int end, Out &out, int depth);
    int decodeIcmp6(int off, int end, const QByteArray &pseudo, Out &out);
    int decodeIgmp(int off, int end, Out &out);
    int decodeGre(int off, int end, Out &out, int depth);
    int decodeEtherIp(int off, int end, Out &out, int depth);
    int decodeEsp(int off, int end, Out &out);

    // UDP based tunnels/applications
    int dispatchUdpPort(int sport, int dport, int off, int end, Out &out,
                        int depth);
    int decodeVxlan(int off, int end, Out &out, int depth);
    int decodeGeneve(int off, int end, Out &out, int depth);
    int decodeCapwap(int off, int end, bool dataChannel, Out &out,
                     int depth);
    int decodeGtpu(int off, int end, Out &out, int depth);
    int decodeDns(int off, int end, Out &out);
    int decodeDhcp(int off, int end, Out &out);

    void addData(int off, int len, const QString &name, Out &out);
    DecodedField header(const QString &name, int off, int len,
                        const QString &value = QString());
    QString dnsName(int off, int msgStart, int end, int *next) const;

    DecodedField uintField(const QString &name, int off, int len,
                           quint64 mask = 0, int shift = 0,
                           const QString &meaning = QString(),
                           bool hexStyle = false);
    DecodedField macField(const QString &name, int off);
    DecodedField ipv4Field(const QString &name, int off);
    DecodedField ipv6Field(const QString &name, int off);
    DecodedField checksumField(const QString &name, int off, quint16 correct,
                               bool verifiable = true);
    // L4 checksums can only be checked when the whole datagram is here
    DecodedField l4ChecksumField(const QString &name, int off,
                                 quint16 correct) {
        return checksumField(name, off, correct, l4Complete_);
    }

    bool has(int off, int len) const {
        return off >= 0 && len >= 0 && off + len <= pkt_.size();
    }
    static const int kMaxDepth = 6;
    bool l4Complete_{true};   // current IP payload is complete
    bool inQuote_{false};     // decoding the packet quoted in ICMP
    quint32 u8(int off) const { return quint8(pkt_.at(off)); }
    quint32 u16(int off) const { return (u8(off) << 8) | u8(off + 1); }
    quint32 u32(int off) const { return (u16(off) << 16) | u16(off + 2); }

    const QByteArray pkt_;
    QList<DecodedField> fields_;
    QList<ChecksumSpot> checksums_;
};

// Internet (ones' complement) checksum over data, starting from sum
quint16 internetChecksum(const QByteArray &data, quint32 sum = 0);

#endif
