// Package pcapts rewrites pcap record timestamps from the radiotap TSFT
// (the radio's microsecond MAC timestamp), so inter-frame timing reflects
// when frames were on the air instead of when they reached the host after
// USB / USB-IP batching.
//
//	time = TSFT + offset,  offset = host_time(first frame) - TSFT(first frame)
//
// The offset is re-anchored when the TSF jumps (reset, wrap, channel change)
// or when it drifts more than MaxDrift from the host clock.
package pcapts

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// MaxDrift is how far the TSF-derived time may wander from the host
// timestamp before we re-anchor.
var MaxDrift int64 = 2_000_000 // µs

// wrapWindow: a backwards TSF step from the last 10 s of the 32-bit range to
// its first 10 s is treated as a wrap.
const wrapWindow = 10_000_000

type Stats struct {
	Frames, Rewritten, Reanchors int64
}

// Copy reads a pcap stream from r, rewrites timestamps and writes it to w,
// flushing after every record so Wireshark sees frames immediately.
func Copy(w io.Writer, r io.Reader, st *Stats) error {
	br := bufio.NewReaderSize(r, 1<<20)
	bw := bufio.NewWriterSize(w, 1<<16)

	var gh [24]byte
	if _, err := io.ReadFull(br, gh[:]); err != nil {
		return err
	}
	var bo binary.ByteOrder
	nano := false
	switch binary.LittleEndian.Uint32(gh[0:4]) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	default:
		switch binary.BigEndian.Uint32(gh[0:4]) {
		case 0xa1b2c3d4:
			bo = binary.BigEndian
		case 0xa1b23c4d:
			bo, nano = binary.BigEndian, true
		default:
			return fmt.Errorf("not a pcap stream")
		}
	}
	linktype := bo.Uint32(gh[20:24]) & 0x0fffffff
	if _, err := bw.Write(gh[:]); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	unit := int64(1) // sub-second units per µs
	if nano {
		unit = 1000
	}
	var (
		anchored bool
		offset   int64 // µs: host - tsft
		lastRaw  uint64
		ext      uint64 // added after 32-bit TSF wraps
		lastTSF  uint64
		rh       [16]byte
		buf      = make([]byte, 0, 65536)
	)
	for {
		if _, err := io.ReadFull(br, rh[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				bw.Flush()
				return nil
			}
			return err
		}
		incl := int(bo.Uint32(rh[8:12]))
		if incl < 0 || incl > 1<<20 {
			return fmt.Errorf("bad record length %d", incl)
		}
		if cap(buf) < incl {
			buf = make([]byte, incl)
		}
		buf = buf[:incl]
		if _, err := io.ReadFull(br, buf); err != nil {
			bw.Flush()
			return nil
		}
		st.Frames++

		if linktype == 127 { // DLT_IEEE802_11_RADIO
			if raw, ok := radiotapTSFT(buf); ok {
				host := int64(bo.Uint32(rh[0:4]))*1_000_000 + int64(bo.Uint32(rh[4:8]))/unit
				// Many drivers (rtw89) report a 32-bit µs counter that wraps
				// every 71.6 min: extend it instead of re-anchoring, so the
				// gap across the wrap stays exact.
				if anchored && raw < lastRaw && lastRaw < 1<<32 && lastRaw > 1<<32-wrapWindow && raw < wrapWindow {
					ext += 1 << 32
				}
				lastRaw = raw
				tsf := raw + ext
				// The offset is deliberately kept fixed (no lower-envelope
				// tracking): moving it would change frame-to-frame gaps,
				// and exact gaps matter more than absolute time here.
				t := int64(tsf) + offset
				if !anchored || tsf < lastTSF || abs(t-host) > MaxDrift {
					if anchored {
						st.Reanchors++
					}
					offset = host - int64(tsf)
					anchored = true
					t = host
				}
				lastTSF = tsf
				bo.PutUint32(rh[0:4], uint32(t/1_000_000))
				bo.PutUint32(rh[4:8], uint32((t%1_000_000)*unit))
				st.Rewritten++
			}
		}
		if _, err := bw.Write(rh[:]); err != nil {
			return err
		}
		if _, err := bw.Write(buf); err != nil {
			return err
		}
		pending := br.Buffered()
		if bq, ok := r.(interface{ Buffered() int }); ok {
			pending += bq.Buffered()
		}
		if pending < 16 { // nothing more queued: push it out now
			if err := bw.Flush(); err != nil {
				return err
			}
		}
	}
}

// radiotapTSFT returns the TSFT field of a radiotap header, if present.
func radiotapTSFT(p []byte) (uint64, bool) {
	if len(p) < 8 || p[0] != 0 {
		return 0, false
	}
	hlen := int(binary.LittleEndian.Uint16(p[2:4]))
	if hlen > len(p) {
		return 0, false
	}
	present := binary.LittleEndian.Uint32(p[4:8])
	if present&1 == 0 {
		return 0, false
	}
	off := 8
	for w := present; w&(1<<31) != 0; { // extended presence bitmaps
		if off+4 > hlen {
			return 0, false
		}
		w = binary.LittleEndian.Uint32(p[off : off+4])
		off += 4
	}
	off = (off + 7) &^ 7 // TSFT is 8-byte aligned
	if off+8 > hlen {
		return 0, false
	}
	return binary.LittleEndian.Uint64(p[off : off+8]), true
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
