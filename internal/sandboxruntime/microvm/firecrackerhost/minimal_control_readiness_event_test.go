package firecrackerhost

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMinimalReadinessEventEveryVariableExtent(t *testing.T) {
	gold, value := minimalReadinessGolden(t)
	for n := 1; n <= 64; n++ {
		current := value
		current.processGeneration = "P" + strings.Repeat("_", n-1)
		// Assemble only from the independently fixed golden prefix/tail. No
		// production offsets, encoder or decoder constructs the expected bytes.
		want := append(bytes.Clone(gold[:101]), byte(n))
		want = append(want, current.processGeneration...)
		want = append(want, gold[113:]...)
		encoded, err := encodeMinimalControlReadinessEvent(current)
		if err != nil || len(encoded) != 174+n || !bytes.Equal(encoded, want) {
			t.Fatalf("variable extent %d changed fixed wire layout: %v", n, err)
		}
		decoded, err := decodeMinimalControlReadinessEvent(want)
		if err != nil || decoded != current {
			t.Fatalf("variable extent %d did not decode exactly: %v", n, err)
		}
		minimalReadinessRejectWire(t, want[:len(want)-1])
		minimalReadinessRejectWire(t, append(want, 0))
	}
}

func TestMinimalReadinessEventSparseNonzeroAndLegacyTokenRules(t *testing.T) {
	_, value := minimalReadinessGolden(t)
	supervisor := [32]byte{0xfb, 0xff} // Canonical URL alphabet includes '-' and '_'.
	value.supervisorGeneration = base64.RawURLEncoding.EncodeToString(supervisor[:])
	value.configSHA256 = [32]byte{31: 1}
	value.sessionID = [32]byte{31: 1}
	value.readinessBindingSHA256 = [32]byte{31: 1}
	value.transportGeneration = ^uint64(0)
	encoded, err := encodeMinimalControlReadinessEvent(value)
	if err != nil {
		t.Fatal("nonzero means not all-zero, with the full unsigned counter range", err)
	}
	decoded, err := decodeMinimalControlReadinessEvent(encoded)
	if err != nil || decoded != value {
		t.Fatal("sparse nonzero values changed", err)
	}
	value.supervisorGeneration = strings.Repeat("A", 43)
	if !validL8RuntimeOwnerToken(value.supervisorGeneration) {
		t.Fatal("selected event changed the legacy zero-token vocabulary")
	}
	minimalReadinessRejectValue(t, value)
}
