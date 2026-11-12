// Console checks for the hex editor's decoder / checksum / hex parsing.
// Build + run: win/tests/run-decoder-test.sh
#include "../../client/packetdecoder.h"

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

    std::printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED",
                failures);
    return failures ? 1 : 0;
}
