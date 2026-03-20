package sandbox

import (
	"io"
	"sync"
)

// synchronizedWriter wraps w with a mutex so concurrent writes from
// command stdout/stderr pipes do not race on non-thread-safe writers
// (for example, bytes.Buffer used in tests).
func synchronizedWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return &lockedWriter{w: w}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
