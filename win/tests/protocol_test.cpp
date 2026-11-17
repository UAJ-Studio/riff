// Builds streams with the real protocol engine (libostproto, the same code
// the agent uses to build packets) and checks the generated frames with
// the hex editor's decoder. Covers the Riff additions: EtherIP, CAPWAP and
// the source MAC mode "Self".
//
// Build + run: win/tests/run-protocol-test.sh
// --pcap <file>: also write the frames for a tshark cross-check
#include "../../client/packetdecoder.h"

#include "../../common/protocolmanager.h"
#include "../../common/streambase.h"

#include "capwap.pb.h"
#include "dot11.pb.h"
#include "eth2.pb.h"
#include "etherip.pb.h"
#include "hexdump.pb.h"
#include "ip4.pb.h"
#include "mac.pb.h"
#include "payload.pb.h"
#include "udp.pb.h"

#include <QCoreApplication>
#include <QSet>
#include <QStringList>
#include <cstdio>

extern ProtocolManager *OstProtocolManager;  // defined in libostproto

// Provided by the agent / controller in the real programs
quint64 getDeviceMacAddress(int, int, int) { return 0; }
quint64 getNeighborMacAddress(int, int, int) { return 0; }
const quint64 kPortMac = 0x0011223344aaULL;
quint64 getPortMacAddress(int) { return kPortMac; }

namespace {
int failures = 0;

void check(bool cond, const QString &what)
{
    std::printf("%s  %s\n", cond ? "PASS" : "FAIL", what.toUtf8().constData());
    if (!cond)
        failures++;
}

void collect(const QList<DecodedField> &fs, QStringList &names, bool &err)
{
    for (const DecodedField &f : fs) {
        if (f.kind == DecodedField::Header)
            names << f.name;
        if (f.error)
            err = true;
        collect(f.children, names, err);
    }
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

OstProto::Protocol* add(OstProto::Stream &s, int id)
{
    OstProto::Protocol *p = s.add_protocol();
    p->mutable_protocol_id()->set_id(id);
    return p;
}

void addMac(OstProto::Stream &s, bool selfSrc, quint64 dst, quint64 src)
{
    OstProto::Mac *m = add(s, OstProto::Protocol::kMacFieldNumber)
                           ->MutableExtension(OstProto::mac);
    m->set_dst_mac_mode(OstProto::Mac::e_mm_fixed);
    m->set_dst_mac(dst);
    if (selfSrc) {
        m->set_src_mac_mode(OstProto::Mac::e_mm_self);
    }
    else {
        m->set_src_mac_mode(OstProto::Mac::e_mm_fixed);
        m->set_src_mac(src);
    }
    add(s, OstProto::Protocol::kEth2FieldNumber);
}

void addIp4(OstProto::Stream &s, quint32 src, quint32 dst)
{
    OstProto::Ip4 *ip = add(s, OstProto::Protocol::kIp4FieldNumber)
                            ->MutableExtension(OstProto::ip4);
    ip->set_src_ip(src);
    ip->set_dst_ip(dst);
}

QByteArray build(const OstProto::Stream &s, int frameIndex = 0)
{
    StreamBase stream(0);
    stream.protoDataCopyFrom(s);
    QByteArray buf(2048, 0);
    int n = stream.frameValue(reinterpret_cast<uchar*>(buf.data()),
                              buf.size(), frameIndex);
    return buf.left(n);
}

OstProto::Stream baseStream(int frameLen)
{
    OstProto::Stream s;
    s.mutable_stream_id()->set_id(1);
    s.mutable_core()->set_is_enabled(true);
    s.mutable_core()->set_frame_len(quint32(frameLen));
    return s;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    OstProtocolManager = new ProtocolManager();

    QList<QByteArray> frames;

    // 1. CAPWAP data: Self src MAC, IPv4/UDP(auto port) / CAPWAP / Ethernet
    {
        OstProto::Stream s = baseStream(128);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        add(s, OstProto::Protocol::kCapwapFieldNumber);   // defaults
        addMac(s, false, 0x020000000002ULL, 0x020000000001ULL);
        addIp4(s, 0x0a000001, 0x0a000002);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        add(s, OstProto::Protocol::kPayloadFieldNumber);

        QByteArray f = build(s);
        frames << f;
        PacketDecoder d(f);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        check(f.size() == 124, QString("capwap data: frame is 124 bytes "
                                       "(got %1)").arg(f.size()));
        check(f.mid(6, 6) == QByteArray::fromHex("0011223344aa"),
              "self: source MAC is the port's own MAC");
        check(names.contains("CAPWAP Data")
                  && names.contains("Inner Ethernet")
                  && names.count("UDP") == 2,
              "capwap data: layers " + names.join(" > "));
        check(!err, "capwap data: no decode errors / bad checksums");
        const DecodedField *dport = find(d.fields(), "Destination port");
        check(dport && PacketDecoder::readUInt(f, *dport) == 5247,
              "capwap data: UDP destination port set to 5247 automatically");
        const DecodedField *hl = find(d.fields(), "Header length");
        check(f.mid(42, 8) == QByteArray::fromHex("0010420000000000"),
              "capwap data: header bytes 00 10 42 00 00 00 00 00 "
              "(HLEN 2, RID 1, WBID 1, T 0)");
        Q_UNUSED(hl);
    }

    // 2. CAPWAP control: Echo Request, sequence 7, no elements
    {
        OstProto::Stream s = baseStream(64);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        OstProto::Capwap *c = add(s, OstProto::Protocol::kCapwapFieldNumber)
                                  ->MutableExtension(OstProto::capwap);
        c->set_is_control(true);
        c->set_message_type(13);
        c->set_seq_num(7);

        QByteArray f = build(s);
        frames << f;
        PacketDecoder d(f);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        const DecodedField *dport = find(d.fields(), "Destination port");
        check(dport && PacketDecoder::readUInt(f, *dport) == 5246,
              "capwap control: UDP destination port 5246");
        const DecodedField *mt = find(d.fields(), "Message type");
        check(mt && mt->value.contains("Echo Request"),
              "capwap control: message type Echo Request");
        const DecodedField *el = find(d.fields(), "Message elements length");
        check(el && PacketDecoder::readUInt(f, *el) == 3 && !el->error,
              "capwap control: element length 3 (no elements)");
        check(!err, "capwap control: no decode errors");
    }

    // 3. EtherIP: IPv4 proto 97 (auto) / EtherIP / Ethernet / IPv4 / UDP
    {
        OstProto::Stream s = baseStream(128);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kEtherIpFieldNumber);
        addMac(s, false, 0x020000000002ULL, 0x020000000001ULL);
        addIp4(s, 0x0a000001, 0x0a000002);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        add(s, OstProto::Protocol::kPayloadFieldNumber);

        QByteArray f = build(s);
        frames << f;
        PacketDecoder d(f);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        const DecodedField *proto = find(d.fields(), "Protocol");
        check(proto && PacketDecoder::readUInt(f, *proto) == 97,
              "etherip: IPv4 protocol set to 97 automatically");
        check(f.mid(34, 2) == QByteArray::fromHex("3000"),
              "etherip: header 30 00 (version 3)");
        check(names.contains("EtherIP") && names.contains("Inner Ethernet"),
              "etherip: layers " + names.join(" > "));
        check(!err, "etherip: no decode errors / bad checksums");
    }

    // 4. Variable field on CAPWAP (fragment ID, counter16 at offset 4):
    //    must change per frame
    {
        OstProto::Stream s = baseStream(128);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        OstProto::Protocol *cp = add(s, OstProto::Protocol::kCapwapFieldNumber);
        OstProto::VariableField *vf = cp->add_variable_field();
        vf->set_type(OstProto::VariableField::kCounter16);
        vf->set_offset(4);
        vf->set_mask(0xffff);
        vf->set_value(100);
        vf->set_count(3);
        add(s, OstProto::Protocol::kPayloadFieldNumber);

        QByteArray f0 = build(s, 0), f1 = build(s, 1), f2 = build(s, 2);
        check(f0.mid(46, 2) == QByteArray::fromHex("0064")
                  && f1.mid(46, 2) == QByteArray::fromHex("0065")
                  && f2.mid(46, 2) == QByteArray::fromHex("0066"),
              "capwap: variable field changes the fragment ID per frame "
              "(100, 101, 102)");
        check(f0.mid(42, 4) == QByteArray::fromHex("00104200"),
              "capwap: rest of header unaffected by the variable field");
    }

    // 5. CAPWAP DTLS (type 1): 4-byte preamble only
    {
        OstProto::Stream s = baseStream(64);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        OstProto::Capwap *c = add(s, OstProto::Protocol::kCapwapFieldNumber)
                                  ->MutableExtension(OstProto::capwap);
        c->set_type(1);
        c->set_is_control(true);
        add(s, OstProto::Protocol::kPayloadFieldNumber);

        QByteArray f = build(s);
        frames << f;
        const quint32 udpLen = (quint8(f.at(38)) << 8) | quint8(f.at(39));
        check(f.mid(42, 4) == QByteArray::fromHex("01000000"),
              "capwap dtls: preamble 01 00 00 00");
        check(udpLen == quint32(f.size() - 34),
              "capwap dtls: UDP length consistent with 4-byte preamble");
    }

    // 6. EtherIP with a variable field on the reserved bits
    {
        OstProto::Stream s = baseStream(128);
        addMac(s, true, 0x001b21000001ULL, 0);
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        OstProto::Protocol *ep = add(s, OstProto::Protocol::kEtherIpFieldNumber);
        OstProto::VariableField *vf = ep->add_variable_field();
        vf->set_type(OstProto::VariableField::kCounter8);
        vf->set_offset(1);
        vf->set_value(1);
        vf->set_count(4);
        addMac(s, false, 0x020000000002ULL, 0x020000000001ULL);
        add(s, OstProto::Protocol::kPayloadFieldNumber);
        QByteArray f0 = build(s, 0), f2 = build(s, 2);
        check(f0.mid(34, 2) == QByteArray::fromHex("3001")
                  && f2.mid(34, 2) == QByteArray::fromHex("3003"),
              "etherip: variable field applied (30 01, 30 03)");
    }

    // ---- IEEE 802.11 (Radiotap TX / 802.11 / Mgmt / IE) ----------------
    QList<QByteArray> wifiFrames;
    const QByteArray kRadiotap = QByteArray::fromHex("00000c0004800000"
                                                     "0c000000");
    auto addIe = [](OstProto::Stream &s) {
        return add(s, OstProto::Protocol::kDot11IeFieldNumber)
                   ->MutableExtension(OstProto::dot11_ie);
    };

    // 7. Probe Request: radiotap + header (auto subtype) + SSID + rates;
    //    stream frame length 200 must not pad the frame
    {
        OstProto::Stream s = baseStream(200);
        add(s, OstProto::Protocol::kDot11RadiotapFieldNumber);
        OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
                                 ->MutableExtension(OstProto::dot11);
        h->set_seq_num(100);
        add(s, OstProto::Protocol::kDot11MgmtFieldNumber);   // probe req
        addIe(s);                                            // SSID "Riff"
        addIe(s)->set_kind(OstProto::Dot11Ie::kRates);

        QByteArray f0 = build(s, 0), f1 = build(s, 1), f4095 = build(s, 4095);
        wifiFrames << f0;
        QByteArray want = kRadiotap + QByteArray::fromHex(
            "40000000ffffffffffff020000000001ffffffffffff4006"
            "000452696666" "010882848b960c121824");
        check(f0 == want, "dot11 probe request: exact bytes\n      got  "
              + QString(f0.toHex(' ')) + "\n      want " + want.toHex(' '));
        check(f0.size() == 52, QString("dot11: no padding / truncation to "
              "the frame length (52 bytes, got %1)").arg(f0.size()));
        check(f1.mid(34, 2) == QByteArray::fromHex("5006")
                  && f4095.mid(34, 2) == QByteArray::fromHex("3006"),
              "dot11: sequence number increments little-endian, mod 4096 "
              "(101 -> 50 06, 4195%4096=99 -> 30 06)");
        PacketDecoder d(f0, PacketDecoder::LinkRadiotap);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        check(names.contains("Probe Request") && !err,
              "dot11 probe request: decoder sees " + names.join(" > "));
        StreamBase stream(0);
        stream.protoDataCopyFrom(s);
        check(stream.frameVariableCount() == 4096,
              QString("dot11: variable count 4096 for the sequence number "
                      "(got %1)").arg(stream.frameVariableCount()));
        QStringList pf;
        stream.preflightCheck(pf);
        check(pf.isEmpty(), "dot11: no preflight warnings: " + pf.join("; "));
    }

    // 8. Beacon: auto subtype 8, fixed fields, DS parameter, numbered SSID
    {
        OstProto::Stream s = baseStream(64);
        add(s, OstProto::Protocol::kDot11RadiotapFieldNumber);
        OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
                                 ->MutableExtension(OstProto::dot11);
        h->set_addr2(0x020000000100ULL);
        h->set_addr3(0x020000000100ULL);
        h->set_seq_increment(false);
        h->set_seq_num(0xabc);
        OstProto::Dot11Mgmt *m = add(s, OstProto::Protocol::kDot11MgmtFieldNumber)
                                     ->MutableExtension(OstProto::dot11_mgmt);
        m->set_kind(OstProto::Dot11Mgmt::kBeacon);
        m->set_timestamp(0x0102030405060708ULL);
        OstProto::Dot11Ie *ss = addIe(s);
        ss->set_ssid_numbered(true);
        ss->set_ssid_count(3);
        OstProto::Dot11Ie *r = addIe(s);
        r->set_kind(OstProto::Dot11Ie::kRates);
        r->set_rates("6*,9,12*,18,24*,36,48,54,6.5");  // 9th -> ext rates
        OstProto::Dot11Ie *ds = addIe(s);
        ds->set_kind(OstProto::Dot11Ie::kDsParam);
        ds->set_channel(36);

        const QByteArray want = kRadiotap + QByteArray::fromHex(
            "80000000ffffffffffff020000000100020000000100c0ab"
            "0807060504030201" "6400" "0104"
            "00055269666631"
            "01088c129824b048606c" "32010d"
            "030124");
        QByteArray f0 = build(s, 0), f2 = build(s, 2), f3 = build(s, 3);
        wifiFrames << f0;
        check(f0 == want, "dot11 beacon: exact bytes\n      got  "
              + QString(f0.toHex(' ')) + "\n      want " + want.toHex(' '));
        check(f2.mid(36 + 12 + 2, 5) == QByteArray("Riff3")
                  && f3.mid(36 + 12 + 2, 5) == QByteArray("Riff1"),
              "dot11 ie: numbered SSID Riff1..Riff3 repeats");
        PacketDecoder d(f0, PacketDecoder::LinkRadiotap);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        check(names.contains("Beacon") && !err,
              "dot11 beacon: decoder sees " + names.join(" > "));
    }

    // 9. Random source address: locally administered unicast, repeatable
    {
        OstProto::Stream s = baseStream(64);
        add(s, OstProto::Protocol::kDot11RadiotapFieldNumber);
        OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
                                 ->MutableExtension(OstProto::dot11);
        h->mutable_addr2_vary()->set_mode(OstProto::Dot11Vary::kRandom);
        h->mutable_addr2_vary()->set_count(64);
        add(s, OstProto::Protocol::kDot11MgmtFieldNumber);
        addIe(s);

        bool unicastLocal = true;
        QSet<QByteArray> seen;
        for (int i = 0; i < 64; i++) {
            QByteArray sa = build(s, i).mid(12 + 10, 6);
            if ((uchar(sa[0]) & 0x03) != 0x02)
                unicastLocal = false;
            seen.insert(sa);
        }
        check(unicastLocal, "dot11 random SA: every address is unicast + "
                            "locally administered (byte0 & 3 == 2)");
        check(seen.size() >= 60, QString("dot11 random SA: %1 distinct "
                                         "addresses in 64 frames")
                                     .arg(seen.size()));
        check(build(s, 5).mid(22, 6) == build(s, 5).mid(22, 6)
                  && build(s, 5).mid(22, 6) == build(s, 69).mid(22, 6),
              "dot11 random SA: same per frame index, repeats after count");
        wifiFrames << build(s, 1);
        StreamBase stream(0);
        stream.protoDataCopyFrom(s);
        check(stream.frameVariableCount() == 4096,
              "dot11: variable count lcm(64, 4096) = 4096");
    }

    // 10. Incrementing destination, control frames, QoS data with 4 addrs
    {
        OstProto::Stream s = baseStream(64);
        add(s, OstProto::Protocol::kDot11RadiotapFieldNumber);
        OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
                                 ->MutableExtension(OstProto::dot11);
        h->set_is_auto_type(false);
        h->set_type(1);
        h->set_subtype(12);   // CTS
        h->set_addr1(0x0200000000ffULL);
        h->mutable_addr1_vary()->set_mode(OstProto::Dot11Vary::kIncrement);
        h->mutable_addr1_vary()->set_count(4);
        h->mutable_addr1_vary()->set_step(2);
        QByteArray f0 = build(s, 0), f1 = build(s, 1), f5 = build(s, 5);
        check(f0 == kRadiotap + QByteArray::fromHex("c40000000200000000ff"),
              "dot11 CTS: 10 bytes " + QString(f0.mid(12).toHex(' ')));
        check(f1.mid(16, 6) == QByteArray::fromHex("020000000101")
                  && f5.mid(16, 6) == QByteArray::fromHex("020000000101"),
              "dot11: address increment by 2 with carry, count 4");
        wifiFrames << f0;

        h->set_subtype(11);   // RTS
        check(build(s, 0).size() == 12 + 16, "dot11 RTS: 16 bytes");

        h->set_type(2);
        h->set_subtype(8);    // QoS data
        h->set_flags(0x03);   // To DS + From DS
        h->set_addr4(0x020000000004ULL);
        h->set_qos_control(0x0005);
        QByteArray q = build(s, 0);
        check(q.size() == 12 + 32 && q.mid(12, 2) == QByteArray::fromHex("8803")
                  && q.mid(12 + 24, 6) == QByteArray::fromHex("020000000004")
                  && q.mid(12 + 30, 2) == QByteArray::fromHex("0500"),
              "dot11 QoS data, To+From DS: 32-byte header with Address 4 "
              "and QoS control 05 00");
    }

    // 11. Data frame: 802.11 (auto -> data) / LLC SNAP / IPv4 / UDP / data
    {
        OstProto::Stream s = baseStream(100);
        add(s, OstProto::Protocol::kDot11RadiotapFieldNumber);
        OstProto::Dot11 *h = add(s, OstProto::Protocol::kDot11FieldNumber)
                                 ->MutableExtension(OstProto::dot11);
        h->set_flags(0x01);   // To DS
        add(s, OstProto::Protocol::kLlcFieldNumber);    // not 802.2 SNAP:
        add(s, OstProto::Protocol::kSnapFieldNumber);   // no 802.3 length
        addIp4(s, 0xc0a8000a, 0xc0a80014);
        add(s, OstProto::Protocol::kUdpFieldNumber);
        add(s, OstProto::Protocol::kPayloadFieldNumber);
        QByteArray f = build(s);
        wifiFrames << f;
        check(f.mid(12, 2) == QByteArray::fromHex("0801")
                  && f.mid(36, 8) == QByteArray::fromHex("aaaa030000000800"),
              "dot11 data: FC 08 01 (auto data, To DS), SNAP type 0x0800 "
              + QString(f.left(60).toHex(' ')));
        PacketDecoder d(f, PacketDecoder::LinkRadiotap);
        QStringList names;
        bool err = false;
        collect(d.fields(), names, err);
        check(names.contains("IPv4") && names.contains("UDP") && !err,
              "dot11 data: decoder sees " + names.join(" > ")
              + (err ? " (errors)" : ""));
    }

    // 12. Radiotap with retries + MCS: alignment, present bits, length
    {
        OstProto::Stream s = baseStream(64);
        OstProto::Dot11Radiotap *rt =
            add(s, OstProto::Protocol::kDot11RadiotapFieldNumber)
                ->MutableExtension(OstProto::dot11_radiotap);
        rt->set_tx_flags(0x0008);
        rt->set_use_retries(true);
        rt->set_retries(3);
        rt->set_use_mcs(true);
        rt->set_mcs_index(7);
        rt->set_mcs_bw(1);
        rt->set_mcs_sgi(true);
        QByteArray f = build(s);
        check(f == QByteArray::fromHex("00001000" "04800a00" "0c00" "0800"
                                       "03" "070507"),
              "radiotap: rate, pad, TX flags no-ACK, retries 3, MCS 7 "
              "40 MHz short GI -> " + QString(f.toHex(' ')));
        rt->set_use_rate(false);
        f = build(s);
        check(f.left(8) == QByteArray::fromHex("00000e0000800a00")
                  && f.size() == 14,
              "radiotap: without rate no pad, length 14");
    }

    if (argc == 3 && QByteArray(argv[1]) == "--pcap") {
        // Wi-Fi frames as DLT 127 (radiotap) next to the Ethernet file
        FILE *wp = std::fopen((QByteArray(argv[2]) + "-wifi.pcap")
                                  .constData(), "wb");
        const quint32 whdr[] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 127};
        std::fwrite(whdr, 1, sizeof(whdr), wp);
        for (int i = 0; i < wifiFrames.size(); i++) {
            const quint32 rec[] = {quint32(i + 1), 0,
                                   quint32(wifiFrames[i].size()),
                                   quint32(wifiFrames[i].size())};
            std::fwrite(rec, 1, sizeof(rec), wp);
            std::fwrite(wifiFrames[i].constData(), 1,
                        size_t(wifiFrames[i].size()), wp);
        }
        std::fclose(wp);
    }

    if (argc == 3 && QByteArray(argv[1]) == "--pcap") {
        FILE *fp = std::fopen(argv[2], "wb");
        const quint32 hdr[] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
        std::fwrite(hdr, 1, sizeof(hdr), fp);
        for (int i = 0; i < frames.size(); i++) {
            const quint32 rec[] = {quint32(i + 1), 0,
                                   quint32(frames[i].size()),
                                   quint32(frames[i].size())};
            std::fwrite(rec, 1, sizeof(rec), fp);
            std::fwrite(frames[i].constData(), 1, size_t(frames[i].size()),
                        fp);
        }
        std::fclose(fp);
    }

    std::printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED",
                failures);
    return failures ? 1 : 0;
}
