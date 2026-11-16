package pcapts

import (
	"io"
	"testing"
	"time"
)

// smallWrites delivers n chunks of size bytes, one per Read, like wsl.exe.
type smallWrites struct{ n, size int }

func (s *smallWrites) Read(p []byte) (int, error) {
	if s.n == 0 {
		return 0, io.EOF
	}
	s.n--
	return copy(p, make([]byte, s.size)), nil
}

// A stalled consumer must not block the producer before the byte limit.
func TestQueueBoundedByBytes(t *testing.T) {
	src := &smallWrites{n: 50000, size: 300} // 15 MB in 300-byte reads
	q := NewQueue(src, 64<<20)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if q.Buffered() == 50000*300 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := q.Buffered(); got != 50000*300 {
		t.Fatalf("producer stalled: only %d bytes queued", got)
	}
	n, err := io.Copy(io.Discard, q)
	if err != nil || n != 50000*300 {
		t.Fatalf("drain: n=%d err=%v", n, err)
	}
	if q.Overflow {
		t.Fatal("overflow below limit")
	}
}
