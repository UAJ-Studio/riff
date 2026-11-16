package pcapts

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

type rec struct {
	us  int64
	tsf uint64
	has bool
}

func records(t *testing.T, b []byte) []rec {
	t.Helper()
	var out []rec
	p := 24
	for p+16 <= len(b) {
		sec := int64(binary.LittleEndian.Uint32(b[p:]))
		usec := int64(binary.LittleEndian.Uint32(b[p+4:]))
		n := int(binary.LittleEndian.Uint32(b[p+8:]))
		data := b[p+16 : p+16+n]
		tsf, ok := radiotapTSFT(data)
		out = append(out, rec{sec*1_000_000 + usec, tsf, ok})
		p += 16 + n
	}
	return out
}

// synth builds a pcap of radiotap(TSFT-only) frames.
func synth(frames [][2]int64) []byte { // {host µs, tsf}
	var b bytes.Buffer
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(gh[16:], 65535)
	binary.LittleEndian.PutUint32(gh[20:], 127)
	b.Write(gh)
	for _, f := range frames {
		rt := make([]byte, 16) // ver,pad,len=16,present=TSFT, tsft @8
		binary.LittleEndian.PutUint16(rt[2:], 16)
		binary.LittleEndian.PutUint32(rt[4:], 1)
		binary.LittleEndian.PutUint64(rt[8:], uint64(f[1]))
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:], uint32(f[0]/1_000_000))
		binary.LittleEndian.PutUint32(rh[4:], uint32(f[0]%1_000_000))
		binary.LittleEndian.PutUint32(rh[8:], 16)
		binary.LittleEndian.PutUint32(rh[12:], 16)
		b.Write(rh)
		b.Write(rt)
	}
	return b.Bytes()
}

func TestWrap32(t *testing.T) {
	const w = int64(1) << 32
	base := int64(1_700_000_000_000_000)
	in := synth([][2]int64{
		{base, w - 3000},
		{base + 1500, w - 1000}, // +2000 on air, arrives with less latency
		{base + 4000, 500},      // wrapped: +1500 on air
		{base + 9000, 4500},     // +4000
	})
	var out bytes.Buffer
	var st Stats
	if err := Copy(&out, bytes.NewReader(in), &st); err != nil {
		t.Fatal(err)
	}
	r := records(t, out.Bytes())
	want := []int64{0, 2000, 3500, 7500}
	for i := range r {
		if got := r[i].us - r[0].us; got != want[i] {
			t.Fatalf("frame %d: gap %d, want %d", i, got, want[i])
		}
	}
	if st.Reanchors != 0 {
		t.Fatalf("re-anchored %d times across a wrap", st.Reanchors)
	}
}

// WIFICAP_PCAP=/path/raw.pcap go test ./internal/pcapts
func TestRealCapture(t *testing.T) {
	path := os.Getenv("WIFICAP_PCAP")
	if path == "" {
		t.Skip("set WIFICAP_PCAP to a raw tcpdump pcap")
	}
	in, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var st Stats
	if err := Copy(&out, bytes.NewReader(in), &st); err != nil {
		t.Fatal(err)
	}
	if out.Len() != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), out.Len())
	}
	a, b := records(t, in), records(t, out.Bytes())
	var bad, maxShift int64
	for i := 1; i < len(b); i++ {
		if b[i].has && b[i-1].has && b[i].tsf >= b[i-1].tsf {
			want := int64(b[i].tsf - b[i-1].tsf)
			got := b[i].us - b[i-1].us
			if got != want {
				bad++
			}
		}
		if d := b[i].us - a[i].us; abs(d) > maxShift {
			maxShift = abs(d)
		}
	}
	t.Logf("frames=%d rewritten=%d reanchors=%d interval mismatches=%d max shift vs host=%dus",
		st.Frames, st.Rewritten, st.Reanchors, bad, maxShift)
	if bad > st.Reanchors {
		t.Fatalf("%d intervals differ from TSFT deltas", bad)
	}
	// show first few original vs rewritten gaps
	for i := 1; i < 8 && i < len(b); i++ {
		t.Logf("#%d host gap %6dus  rewritten gap %6dus  tsft gap %6d", i+1, a[i].us-a[i-1].us, b[i].us-b[i-1].us, int64(b[i].tsf-b[i-1].tsf))
	}
}
