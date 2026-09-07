package minimalcontrol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestWorkloadCodecRejectsEveryChangedEnvelopeByte(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	wire := []byte(workloadCodecGolden)
	inner := bytes.Index(wire, []byte("b3BhcXVl"))
	for index := range wire {
		if index >= inner && index < inner+8 {
			continue // Inner bytes are deliberately opaque, not fixed authority.
		}
		changed := bytes.Clone(wire)
		changed[index] ^= 1
		for _, response := range []bool{false, true} {
			if value, err := decodeWorkloadCodec(binding, response, changed, 1, id); err == nil || value != nil {
				t.Fatalf("changed envelope byte %d accepted", index)
			}
		}
	}
	for end := range len(wire) {
		if value, err := binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, wire[:end], 1, id); err == nil || value != nil {
			t.Fatalf("truncated envelope accepted at %d", end)
		}
	}
}

func TestWorkloadCodecStrictAlphabetAndPadding(t *testing.T) {
	binding, id, _ := hostCodecGuestFixture(t)
	for _, encoded := range []string{"Zm9v\r\r\r\r", "Zm9v\n\n\n\n", "Zg\r\n", "Zm9v\r\nAA", "====", "A===", "=AAA", "AA=A", "A", "AA", "AAA", "Zh==", "Zm9="} {
		wire := []byte(strings.Replace(workloadCodecGolden, "b3BhcXVl", encoded, 1))
		if value, err := binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, wire, 1, id); err == nil || value != nil {
			t.Fatalf("noncanonical base64 %q accepted", encoded)
		}
	}
	tooLarge := make([]byte, MaxWorkloadMessageBytes+1)
	if allocations := testing.AllocsPerRun(5, func() {
		if value, err := binding.DecodeWorkloadRequest(session.FrameTypeControlRequest, tooLarge, 1, id); err == nil || value != nil {
			panic("oversized input accepted")
		}
	}); allocations != 0 {
		t.Fatalf("oversized outer input allocated before its bound: %g", allocations)
	}
}
