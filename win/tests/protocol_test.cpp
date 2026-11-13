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
#include "eth2.pb.h"
#include "etherip.pb.h"
#include "hexdump.pb.h"
#include "ip4.pb.h"
#include "mac.pb.h"
#include "payload.pb.h"
#include "udp.pb.h"

#include <QCoreApplication>
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
