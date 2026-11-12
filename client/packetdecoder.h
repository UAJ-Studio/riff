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

private:
    int decodeEthernet(int off, QList<DecodedField> &out);
    int decodeVlan(int off, int tpid, QList<DecodedField> &out, int *type);
    int decodeArp(int off, QList<DecodedField> &out);
    int decodeIpv4(int off, QList<DecodedField> &out);
    int decodeIpv6(int off, QList<DecodedField> &out);
    int decodeTcp(int off, int len, const QByteArray &pseudo,
                  QList<DecodedField> &out);
    int decodeUdp(int off, int len, const QByteArray &pseudo,
                  QList<DecodedField> &out);
    int decodeIcmp(int off, int len, QList<DecodedField> &out);
    int decodeIcmp6(int off, int len, const QByteArray &pseudo,
                    QList<DecodedField> &out);
    void addData(int off, int len, const QString &name,
                 QList<DecodedField> &out);

    DecodedField uintField(const QString &name, int off, int len,
                           quint64 mask = 0, int shift = 0,
                           const QString &meaning = QString(),
                           bool hexStyle = false);
    DecodedField macField(const QString &name, int off);
    DecodedField ipv4Field(const QString &name, int off);
    DecodedField ipv6Field(const QString &name, int off);
    DecodedField checksumField(const QString &name, int off, quint16 correct);

    bool has(int off, int len) const {
        return off >= 0 && len >= 0 && off + len <= pkt_.size();
    }
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
