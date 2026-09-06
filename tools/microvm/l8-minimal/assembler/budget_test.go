//go:build linux

package main

import (
	"errors"
	"testing"
	"time"
)

func TestNativeAssemblyFiniteBudgets(t *testing.T) {
	if nativeAssemblyTimeout != 490*time.Minute {
		t.Errorf("assembler deadline = %v, want 490m", nativeAssemblyTimeout)
	}
	if nativeAssemblyWaitDelay != 90*time.Second {
		t.Errorf("owned cleanup wait = %v, want unchanged 90s", nativeAssemblyWaitDelay)
	}
	// The actual shell arguments are independently exercised by the tagged
	// real-entrypoint fixture; this locks their relationship to the Go owner.
	const containerBudget = 28800 * time.Second
	const runnerBudget = 481 * time.Minute
	const runnerKillGrace = 10 * time.Second
	if containerBudget >= runnerBudget || runnerBudget+runnerKillGrace+nativeAssemblyWaitDelay >= nativeAssemblyTimeout {
		t.Error("finite container, runner and assembler cleanup budgets are not nested")
	}
}

type nativeBudgetCountingWriter struct {
	bytes int64
	err   error
}

func (w *nativeBudgetCountingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.bytes += int64(len(p))
	return len(p), nil
}

func TestNativeAssemblyLogCapDrainsBeyond64MiB(t *testing.T) {
	dest := new(nativeBudgetCountingWriter)
	w := &logWriter{dest: dest, remaining: nativeAssemblyLogBytes}
	// Reuse 16KiB: the test neither allocates nor retains a 64MiB payload.
	var chunk [16 << 10]byte
	const sent = (64 << 20) + 17
	for remaining := sent; remaining > 0; {
		length := min(remaining, len(chunk))
		n, err := w.Write(chunk[:length])
		if err != nil || n != length {
			t.Fatalf("log draining stopped: n=%d want=%d err=%v", n, length, err)
		}
		remaining -= length
	}
	if dest.bytes != 64<<20 || w.remaining != 0 {
		t.Errorf("retained %d bytes, remaining %d; want exactly 64MiB and zero", dest.bytes, w.remaining)
	}
	// Once capped, the runtime pipe must continue draining without touching
	// the destination, even if it would now reject writes.
	dest.err = errors.New("destination must not receive discarded bytes")
	if n, err := w.Write(chunk[:]); err != nil || n != len(chunk) {
		t.Fatalf("capped writer did not drain: n=%d err=%v", n, err)
	}
}

func TestNativeAssemblyLogWriterKeepsPartialCapAndErrors(t *testing.T) {
	dest := new(nativeBudgetCountingWriter)
	w := &logWriter{dest: dest, remaining: 3}
	if n, err := w.Write([]byte("12345")); n != 5 || err != nil || dest.bytes != 3 || w.remaining != 0 {
		t.Fatalf("partial cap: n=%d err=%v retained=%d remaining=%d", n, err, dest.bytes, w.remaining)
	}
	failure := errors.New("write failure")
	dest = &nativeBudgetCountingWriter{err: failure}
	w = &logWriter{dest: dest, remaining: 3}
	if n, err := w.Write([]byte("1")); n != 0 || !errors.Is(err, failure) || w.remaining != 3 {
		t.Fatalf("destination error lost: n=%d err=%v remaining=%d", n, err, w.remaining)
	}
}
