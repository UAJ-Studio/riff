package pcapts

import (
	"bytes"
	"io"
	"sync"
)

// Queue decouples a producer (wsl.exe stdout) from a slow consumer
// (Wireshark's pipe): a goroutine keeps draining the source into memory, so
// a Wireshark stall never back-pressures tcpdump into kernel drops.
//
// The limit is in bytes. (An earlier version bounded the number of reads;
// wsl.exe delivers roughly one packet per read, so that capped the queue at
// ~1 MB and caused drops when a capture started.)
type Queue struct {
	mu        sync.Mutex
	cond      *sync.Cond
	buf       bytes.Buffer
	limit     int
	done      bool
	err       error
	HighWater int64 // max bytes ever queued
	Overflow  bool  // limit was hit (producer had to wait)
}

// NewQueue starts draining src; at most limit bytes are held in memory.
func NewQueue(src io.Reader, limit int64) *Queue {
	q := &Queue{limit: int(limit)}
	q.cond = sync.NewCond(&q.mu)
	go func() {
		tmp := make([]byte, 256<<10)
		for {
			n, err := src.Read(tmp)
			q.mu.Lock()
			if n > 0 {
				for q.buf.Len()+n > q.limit {
					q.Overflow = true
					q.cond.Wait()
				}
				q.buf.Write(tmp[:n])
				if l := int64(q.buf.Len()); l > q.HighWater {
					q.HighWater = l
				}
			}
			if err != nil {
				q.done = true
				if err != io.EOF {
					q.err = err
				}
			}
			q.cond.Broadcast()
			q.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return q
}

func (q *Queue) Read(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.buf.Len() == 0 && !q.done {
		q.cond.Wait()
	}
	if q.buf.Len() == 0 {
		if q.err != nil {
			return 0, q.err
		}
		return 0, io.EOF
	}
	n, _ := q.buf.Read(p)
	q.cond.Broadcast()
	return n, nil
}

// Buffered reports how many bytes are ready without blocking.
func (q *Queue) Buffered() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.buf.Len()
}
