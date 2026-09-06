package firecracker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL7GuestReadinessBindingIsLiveOnlyAndSanitized(t *testing.T) {
	result := SanitizeGuestReadinessResult(GuestReadinessResult{
		State:                      sandboxruntime.RuntimeGuestReadinessStateReady,
		Transport:                  "vsock",
		Labels:                     []string{"proof"},
		IsolationProofGeneration:   "topology-generation-a",
		IsolationRuntimeGeneration: "runtime-generation-a",
	})
	if result.IsolationProofGeneration != "topology-generation-a" || result.IsolationRuntimeGeneration != "runtime-generation-a" {
		t.Fatalf("sanitized result = %#v, want safe live-only binding", result)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "topology-generation") || strings.Contains(string(payload), "runtime-generation") {
		t.Fatalf("readiness JSON persisted live proof binding: %s", payload)
	}

	unsafe := SanitizeGuestReadinessResult(GuestReadinessResult{
		State:                      sandboxruntime.RuntimeGuestReadinessStateReady,
		IsolationProofGeneration:   "https://private.example/proof",
		IsolationRuntimeGeneration: "/private/runtime",
	})
	if unsafe.IsolationProofGeneration != "" || unsafe.IsolationRuntimeGeneration != "" {
		t.Fatalf("unsafe proof binding survived sanitization: %#v", unsafe)
	}
}
