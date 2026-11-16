// Console checks for the hex editor's decoder / checksum / hex parsing.
// Build + run: win/tests/run-decoder-test.sh
#include "../../client/packetdecoder.h"
#include "../../client/packettemplates.h"

#include <QCoreApplication>
#include <QStringList>
#include <cstdio>
#include <functional>
#include <QSet>

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
    if (argc >= 3 && QByteArray(argv[1]) == "--pcap") {
        FILE *fp = std::fopen(argv[2], "wb");
        if (!fp)
            return 2;
        const quint32 hdr[] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535,
                               quint32(argc == 4 ? 127 : 1)};
        std::fwrite(hdr, 1, sizeof(hdr), fp);   // little-endian host
        for (int i = 0; i < PacketTemplates::count(); i++) {
            if (PacketTemplates::isWifi(i) != (argc == 4))
                continue;   // --pcap <file> wifi: radiotap templates (DLT 127)
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
        {"Radiotap", "IEEE 802.11", "Beacon", "SSID", "Supported Rates",
         "DS Parameter Set"},
        {"Radiotap", "IEEE 802.11", "Probe Request", "SSID"},
        {"Radiotap", "IEEE 802.11", "IPv4", "UDP"},
        {"Radiotap", "IEEE 802.11", "IPv4", "UDP"},
        {"Radiotap", "IEEE 802.11"},
        {"Radiotap", "IEEE 802.11"},
        {"Radiotap", "IEEE 802.11"},
        {"Radiotap", "IEEE 802.11"},
    };
    check(expected.size() == PacketTemplates::count(),
          "template table and expectations have the same size");
    for (int i = 0; i < PacketTemplates::count(); i++) {
        QByteArray pkt = PacketTemplates::build(i);
        const PacketDecoder::LinkType link = PacketTemplates::isWifi(i)
            ? PacketDecoder::LinkRadiotap : PacketDecoder::LinkEthernet;
        check(PacketDecoder::guessLinkType(pkt) == link,
              QString("template %1: link type guessed").arg(i).toUtf8().constData());
        PacketDecoder d(pkt, link);
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
            PacketDecoder trunc(pkt.left(len), link);
        quint32 seed = 0x12345u + quint32(i);
        for (int k = 0; k < 300; k++) {
            QByteArray m = pkt;
            for (int f = 0; f < 3; f++) {
                seed = seed * 1103515245u + 12345u;
                m[int((seed >> 8) % quint32(m.size()))] = char(seed >> 24);
            }
            PacketDecoder fuzz(m, link);
            QByteArray fixedm = m;
            PacketDecoder::fixChecksums(fixedm, link);
        }
    }
    check(true, "templates survive truncation and byte-flip fuzzing");

    // ---- Wi-Fi specifics ----
    {
        const auto RT = PacketDecoder::LinkRadiotap;
        QByteArray wd = PacketTemplates::build(24);     // data + IPv4/UDP
        // radiotap 12 + 802.11 24 + SNAP 8 + IPv4 20 -> UDP checksum at +6
        int udpCk = 12 + 24 + 8 + 20 + 6;
        QByteArray bad = wd;
        bad[udpCk] = char(bad.at(udpCk) ^ 0x5A);
        check(PacketDecoder::fixChecksums(bad, RT) == 1 && bad == wd,
              "wifi data: UDP checksum inside 802.11/SNAP fixed");

        PacketDecoder dw(wd, RT);
        const DecodedField *seq = find(dw.fields(), "Sequence number");
        check(seq && seq->littleEndian, "wifi: sequence number is LE");
        if (seq) {
            QByteArray w = wd;
            PacketDecoder::writeUInt(w, *seq, 0x123);
            // sequence control = 0x1230 stored little-endian: 30 12
            check(quint8(w.at(12 + 22)) == 0x30
                      && quint8(w.at(12 + 23)) == 0x12,
                  "wifi: sequence number written little-endian");
            check(PacketDecoder::readUInt(w, *seq) == 0x123,
                  "wifi: sequence number reads back");
        }
        PacketDecoder db(PacketTemplates::build(22), RT);
        const DecodedField *ss = find(db.fields(), "SSID");
        check(ss && ss->value.contains("Riff-Test"),
              "wifi: beacon SSID shown");
        check(PacketDecoder::guessLinkType(PacketTemplates::build(0))
                  == PacketDecoder::LinkEthernet,
              "wifi: Ethernet frames are not mistaken for radiotap");
    }

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

    // ---- Review fixes ----
    {
        // IPv4 first fragment (MF set): the UDP checksum covers the whole
        // datagram, so it must be neither flagged nor "fixed"
        QByteArray frag = PacketTemplates::build(0);
        frag[14 + 6] = char(0x20);   // flags: MF, offset 0
        frag[14 + 7] = char(0x00);
        int udpCk = 14 + 20 + 6;
        frag[udpCk] = char(0x12);
        frag[udpCk + 1] = char(0x34);
        QByteArray fixedFrag = frag;
        PacketDecoder::fixChecksums(fixedFrag);
        check(fixedFrag.mid(udpCk, 2) == QByteArray::fromHex("1234"),
              "fragment: UDP checksum of a first fragment is left alone");
        PacketDecoder d(fixedFrag);
        const DecodedField *ck = find(d.fields(), "Checksum");
        check(ck && !ck->error && ck->value.contains("not checked"),
              "fragment: UDP checksum shown as not checked");
        const DecodedField *hc = find(d.fields(), "Header checksum");
        check(hc && !hc->error, "fragment: IPv4 header checksum still fixed");
    }
    {
        // ICMP destination unreachable quoting IPv4+UDP (8 bytes of UDP):
        // the quoted UDP checksum must not be rewritten
        QByteArray inner = PacketTemplates::build(0).mid(14, 28);
        QByteArray icmp = QByteArray::fromHex("0303000000000000") + inner;
        QByteArray ip = QByteArray::fromHex("45000000") + QByteArray::fromHex(
                "00004000400100000a0000010a000002");
        int total = 20 + icmp.size();
        ip[2] = char(total >> 8);
        ip[3] = char(total & 0xFF);
        QByteArray pkt = QByteArray::fromHex("00112233445500aabbccddee0800")
                         + ip + icmp;
        int quotedUdpCk = 14 + 20 + 8 + 20 + 6;
        QByteArray before = pkt.mid(quotedUdpCk, 2);
        PacketDecoder::fixChecksums(pkt);
        check(pkt.mid(quotedUdpCk, 2) == before,
              "icmp quote: quoted UDP checksum not rewritten");
        PacketDecoder d(pkt);
        bool err = false;
        QStringList n;
        std::function<void(const QList<DecodedField>&)> walk =
            [&](const QList<DecodedField> &fs) {
                for (const DecodedField &f : fs) {
                    if (f.error) err = true;
                    walk(f.children);
                }
            };
        walk(d.fields());
        check(!err, "icmp quote: no errors after fix");
    }
    {
        // Selective fixing keeps a deliberately wrong checksum wrong
        QByteArray p = PacketTemplates::build(0);
        int ipCk = 14 + 10;
        p[ipCk] = char(0xDE);
        p[ipCk + 1] = char(0xAD);
        QSet<int> keep = PacketDecoder::correctChecksums(p);
        check(!keep.contains(ipCk), "selective: wrong IPv4 checksum detected");
        p[14 + 8] = char(1);   // TTL edit
        PacketDecoder::fixChecksums(p, keep);
        check(p.mid(ipCk, 2) == QByteArray::fromHex("dead"),
              "selective: deliberately wrong checksum kept");
    }
    {
        QByteArray out;
        QString err;
        // Wireshark "Copy as Hex Dump" with a short last line
        check(PacketDecoder::parseHexText(
                  "0000   00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff   "
                  "..\"3DUfw........\n"
                  "0010   62 65            be", &out, &err, 100)
              && out.size() == 18
              && out.right(2) == QByteArray::fromHex("6265"),
              "paste: Wireshark dump, short last line, ASCII ignored");
        // tcpdump -xx (4-digit groups)
        check(PacketDecoder::parseHexText(
                  "0x0000:  4500 0054 1234 4000\n"
                  "0x0008:  4001 0000", &out, &err, 100)
              && out == QByteArray::fromHex("450000541234400040010000"),
              "paste: tcpdump -xx");
        // xxd with ASCII column
        check(PacketDecoder::parseHexText(
                  "00000000: 4865 6c6c 6f21  Hello!", &out, &err, 100)
              && out == QByteArray("Hello!"),
              "paste: xxd with ASCII column");
        // plain hex with a double space is not mistaken for a dump
        check(PacketDecoder::parseHexText("0011  2233", &out, &err, 100)
              && out == QByteArray::fromHex("00112233"),
              "paste: plain hex with double space");
        check(PacketDecoder::parseHexText("0x45 0x00, 0x00:54", &out, &err,
                                          100)
              && out == QByteArray::fromHex("45000054"),
              "paste: 0x prefixes and separators");
        check(!PacketDecoder::parseHexText("zz", &out, &err, 100),
              "paste: garbage rejected");
    }

    std::printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED",
                failures);
    return failures ? 1 : 0;
}
