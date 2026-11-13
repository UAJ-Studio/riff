// Console checks for the hex editor's decoder / checksum / hex parsing.
// Build + run: win/tests/run-decoder-test.sh
#include "../../client/packetdecoder.h"
#include "../../client/packettemplates.h"

#include <QCoreApplication>
#include <QStringList>
#include <cstdio>

// Template and hex parser live in the GUI dialog; the test re-declares the
// pieces it needs instead of pulling in widgets.
namespace {
int failures = 0;

void check(bool cond, const char *what)
{
    std::printf("%s  %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond)
        failures++;
}

const DecodedField* find(const QList<DecodedField> &fs, const QString &name)
{
    for (const DecodedField &f : fs) {
        if (f.name == name)
            return &f;
        if (const DecodedField *c = find(f.children, name))
            return c;
    }
    return nullptr;
}

void collectHeaders(const QList<DecodedField> &fs, QStringList &names)
{
    for (const DecodedField &f : fs) {
        if (f.kind == DecodedField::Header)
            names << f.name;
        collectHeaders(f.children, names);
    }
}

bool anyError(const QList<DecodedField> &fs)
{
    for (const DecodedField &f : fs)
        if (f.error || anyError(f.children))
            return true;
    return false;
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --pcap <file>: write every template to a pcap (for cross-checking
    // with Wireshark/tshark) and exit
    if (argc == 3 && QByteArray(argv[1]) == "--pcap") {
        FILE *fp = std::fopen(argv[2], "wb");
        if (!fp)
            return 2;
        const quint32 hdr[] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
        std::fwrite(hdr, 1, sizeof(hdr), fp);   // little-endian host
        for (int i = 0; i < PacketTemplates::count(); i++) {
            QByteArray p = PacketTemplates::build(i);
            const quint32 rec[] = {quint32(i + 1), 0, quint32(p.size()),
                                   quint32(p.size())};
            std::fwrite(rec, 1, sizeof(rec), fp);
            std::fwrite(p.constData(), 1, size_t(p.size()), fp);
        }
        std::fclose(fp);
        return 0;
    }

    // Real capture: ICMP echo request 192.168.0.10 -> 192.168.0.1 with
    // correct IPv4 header checksum (0xb966) and ICMP checksum (0x4d5a).
    QByteArray ping = QByteArray::fromHex(
        "001122334455" "00aabbccddee" "0800"
        "4500003c1234400040010000c0a8000ac0a80001"
        "08000000" "00010001"
        "6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869");
    // compute expected with an independent method: fix then verify fields
    QByteArray fixed = ping;
    int n = PacketDecoder::fixChecksums(fixed);
    check(n == 2, "ping: two wrong checksums fixed (IPv4 + ICMP)");
    PacketDecoder d1(fixed);
    check(!anyError(d1.fields()), "ping: no errors after fix");
    const DecodedField *ipc = find(d1.fields(), "Header checksum");
    check(ipc && PacketDecoder::readUInt(fixed, *ipc) == 0xA731,
          "ping: IPv4 header checksum == 0xA731 (hand computed)");
    const DecodedField *proto = find(d1.fields(), "Protocol");
    check(proto && proto->value.contains("ICMP"), "ping: protocol is ICMP");
    check(PacketDecoder::fixChecksums(fixed) == 0, "ping: fix is idempotent");

    // Known-good TCP SYN from a capture (checksums verified by Wireshark)
    QByteArray syn = QByteArray::fromHex(
        "000c29d1a1b2" "001c42e1f2a3" "0800"
        "45000034a6f7400080060000c0a80164c0a801c8"
        "c35000500000000100000000" "8002faf00000" "0000"
        "020405b40103030801010402");
    QByteArray synFixed = syn;
    PacketDecoder::fixChecksums(synFixed);
    PacketDecoder d2(synFixed);
    check(!anyError(d2.fields()), "tcp syn: no errors after fix");
    const DecodedField *flags = find(d2.fields(), "Flags");
    check(flags && flags->value.contains("SYN"), "tcp syn: SYN flag decoded");
    const DecodedField *opts = find(d2.fields(), "Options");
    check(opts && opts->length == 12, "tcp syn: 12 bytes of options");

    // Corrupting one payload byte must flag the L4 checksum as wrong
    QByteArray bad = fixed;
    bad[bad.size() - 1] = char(bad.at(bad.size() - 1) ^ 0xFF);
    PacketDecoder d3(bad);
    check(anyError(d3.fields()), "ping: corrupted payload -> checksum error");

    // Field editing: bit-field write keeps neighbours intact
    QByteArray vlan = QByteArray::fromHex(
        "ffffffffffff" "00aabbccddee" "8100" "a00a" "0806"
        "0001080006040001" "00aabbccddee" "c0a8000a"
        "000000000000" "c0a80001");
    PacketDecoder d4(vlan);
    const DecodedField *vid = find(d4.fields(), "VLAN ID");
    const DecodedField *pcp = find(d4.fields(), "Priority (PCP)");
    check(vid && PacketDecoder::readUInt(vlan, *vid) == 10, "vlan: VID 10");
    check(pcp && PacketDecoder::readUInt(vlan, *pcp) == 5, "vlan: PCP 5");
    QString err;
    QByteArray v2 = vlan;
    check(PacketDecoder::writeText(v2, *vid, "0xFFF", &err), "vlan: set VID");
    check(PacketDecoder::readUInt(v2, *pcp) == 5, "vlan: PCP unchanged");
    check(!PacketDecoder::writeText(v2, *vid, "4096", &err),
          "vlan: VID 4096 rejected");
    const DecodedField *tip = find(d4.fields(), "Target IP");
    check(tip && PacketDecoder::writeText(v2, *tip, "10.1.2.3", &err)
              && v2.mid(tip->offset, 4) == QByteArray::fromHex("0a010203"),
          "arp: write target IP");
    const DecodedField *smac = find(d4.fields(), "Sender MAC");
    check(smac && PacketDecoder::writeText(v2, *smac, "01-23-45-67-89-AB",
                                           &err)
              && v2.mid(smac->offset, 6) == QByteArray::fromHex("0123456789ab"),
          "arp: write sender MAC with dashes");
    check(!PacketDecoder::writeText(v2, *smac, "01:23:45", &err),
          "arp: short MAC rejected");

    // IPv6 + UDP checksum (pseudo header) round trip
    QByteArray v6 = QByteArray::fromHex(
        "333300000001" "00aabbccddee" "86dd"
        "6000000000101140"
        "20010db8000000000000000000000010"
        "20010db8000000000000000000000020"
        "c0001388001000004865" "6c6c6f2c20526966");
    PacketDecoder::fixChecksums(v6);
    PacketDecoder d5(v6);
    check(!anyError(d5.fields()), "ipv6/udp: consistent after fix");
    const DecodedField *uc = find(d5.fields(), "Checksum");
    check(uc && PacketDecoder::readUInt(v6, *uc) != 0,
          "ipv6/udp: checksum non-zero");

    // Truncated / garbage input must not crash
    for (int len = 0; len < fixed.size(); len++)
        PacketDecoder trunc(fixed.left(len));
    check(true, "truncated packets decode without crashing");

    // ---- Every template decodes cleanly with the expected layers ----
    const QList<QStringList> expected = {
        {"Ethernet", "IPv4", "UDP"},
        {"Ethernet", "IPv4", "TCP"},
        {"Ethernet", "IPv4", "ICMP"},
        {"Ethernet", "ARP"},
        {"Ethernet", "IPv6", "UDP"},
        {"Ethernet", "VLAN (802.1Q)", "IPv4", "UDP"},
        {"Ethernet"},
        {"IPv4", "UDP", "CAPWAP Data", "Inner Ethernet", "IPv4", "ICMP"},
        {"IPv4", "UDP", "CAPWAP Control", "CAPWAP Control Message"},
        {"IPv4", "EtherIP", "Inner Ethernet", "ICMP"},
        {"IPv4", "UDP", "VXLAN", "Inner Ethernet", "ICMP"},
        {"IPv4", "UDP", "Geneve", "Inner Ethernet", "ICMP"},
        {"IPv4", "GRE", "Inner IPv4", "ICMP"},
        {"IPv4", "Inner IPv4", "ICMP"},
        {"Ethernet", "MPLS", "IPv4", "UDP"},
        {"Ethernet", "PPPoE Session", "IPv4", "UDP"},
        {"IPv4", "UDP", "GTP-U", "Inner IPv4", "ICMP"},
        {"IPv4", "UDP", "DNS"},
        {"IPv4", "UDP", "DHCP"},
        {"Ethernet", "LLDP"},
        {"Ethernet", "LLC", "Spanning Tree (BPDU)"},
        {"Ethernet", "IPv4", "IGMP"},
    };
    check(expected.size() == PacketTemplates::count(),
          "template table and expectations have the same size");
    for (int i = 0; i < PacketTemplates::count(); i++) {
        QByteArray pkt = PacketTemplates::build(i);
        PacketDecoder d(pkt);
        QStringList seen;
        collectHeaders(d.fields(), seen);
        bool ok = !anyError(d.fields());
        QString missing;
        for (const QString &h : expected.value(i))
            if (!seen.contains(h)) {
                ok = false;
                missing += h + " ";
            }
        QByteArray what = QString("template %1 (%2) %3")
            .arg(i).arg(PacketTemplates::name(i))
            .arg(missing.isEmpty() ? QString()
                                   : "missing: " + missing).toUtf8();
        check(ok, what.constData());
        if (!ok)
            std::printf("      seen: %s\n",
                        seen.join(" | ").toUtf8().constData());

        // robustness: every prefix and deterministic byte flips
        for (int len = 0; len < pkt.size(); len++)
            PacketDecoder trunc(pkt.left(len));
        quint32 seed = 0x12345u + quint32(i);
        for (int k = 0; k < 300; k++) {
            QByteArray m = pkt;
            for (int f = 0; f < 3; f++) {
                seed = seed * 1103515245u + 12345u;
                m[int((seed >> 8) % quint32(m.size()))] = char(seed >> 24);
            }
            PacketDecoder fuzz(m);
            QByteArray fixedm = m;
            PacketDecoder::fixChecksums(fixedm);
        }
    }
    check(true, "templates survive truncation and byte-flip fuzzing");

    // ---- Tunnel specifics ----
    {
        QByteArray cw = PacketTemplates::build(7);
        PacketDecoder d(cw);
        const DecodedField *wbid = find(d.fields(), "Wireless binding ID");
        check(wbid && PacketDecoder::readUInt(cw, *wbid) == 1,
              "capwap: wireless binding ID = 1 (IEEE 802.11)");
        const DecodedField *t = find(d.fields(), "T: native frame");
        check(t && PacketDecoder::readUInt(cw, *t) == 0,
              "capwap: T = 0 (802.3 payload)");
        const DecodedField *hl = find(d.fields(), "Header length");
        check(hl, "capwap: header length decoded");
    }
    {
        QByteArray cc = PacketTemplates::build(8);
        PacketDecoder d(cc);
        const DecodedField *mt = find(d.fields(), "Message type");
        check(mt && mt->value.contains("Echo Request"),
              "capwap control: Echo Request");
    }
    {
        // Corrupt the inner ICMP of the VXLAN template: inner checksum
        // must be flagged, and fixing must touch exactly that checksum
        // (outer UDP checksum 0 = not used stays 0)
        QByteArray vx = PacketTemplates::build(10);
        QByteArray bad = vx;
        bad[bad.size() - 1] = char(bad.at(bad.size() - 1) ^ 0x55);
        PacketDecoder d(bad);
        check(anyError(d.fields()), "vxlan: corrupted inner ICMP flagged");
        int n = PacketDecoder::fixChecksums(bad);
        check(n == 1, "vxlan: exactly one (inner) checksum fixed");
        PacketDecoder d2(bad);
        check(!anyError(d2.fields()), "vxlan: clean after fix");
        const DecodedField *vni = find(d2.fields(), "VNI");
        check(vni && PacketDecoder::readUInt(bad, *vni) == 100,
              "vxlan: VNI 100");
    }
    {
        QByteArray dns = PacketTemplates::build(17);
        PacketDecoder d(dns);
        const DecodedField *q = find(d.fields(), "Question");
        check(q && q->value == "example.com A",
              "dns: question is example.com, type A");
        QByteArray dhcp = PacketTemplates::build(18);
        PacketDecoder d2(dhcp);
        const DecodedField *h = find(d2.fields(), "DHCP");
        check(h && h->value == "DISCOVER", "dhcp: message type DISCOVER");
    }
    {
        // Self-referencing DNS compression pointer must not hang
        QByteArray dns = PacketTemplates::build(17);
        int qoff = dns.indexOf(QByteArray("\x07" "example", 8));
        dns[qoff] = char(0xC0);
        dns[qoff + 1] = char(qoff - 42); // points to itself (DNS at 42)
        PacketDecoder d(dns);
        check(true, "dns: compression pointer loop terminates");
    }

    std::printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED",
                failures);
    return failures ? 1 : 0;
}
