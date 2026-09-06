//go:build linux

package linuxtopology

import "testing"

func TestLinuxTopologyBoundedBufferNeverGrowsPastLimit(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if written, err := buffer.Write([]byte("123456789")); err != nil || written != 9 {
		t.Fatalf("Write = %d, %v", written, err)
	}
	if got := string(buffer.Bytes()); got != "1234" {
		t.Fatalf("buffer = %q, want bounded prefix", got)
	}
	if !buffer.Truncated() {
		t.Fatal("Truncated = false, want true")
	}
}
