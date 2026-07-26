package build

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL5ProvenanceSchemaContainsOnlySafeReproducibilityFacts(t *testing.T) {
	provenance := Provenance{
		SchemaVersion:   SchemaVersionV1,
		SourceRevision:  "762ee1a61d2efc5bb9241a6e87409ca20d68f976",
		SourceTree:      "tree-0123456789abcdef",
		SourceDateEpoch: 1785024000,
		Architecture:    "x86_64",
		Versions: Versions{
			Buildroot: "2026.02.1",
			Linux:     "6.12.40",
			BusyBox:   "1.37.0",
			Go:        "1.25.7",
		},
		GuestAgent: GuestAgent{
			Protocol: "guest-agent-v1",
			Features: []string{"readiness", "exec", "copy_in", "copy_out"},
		},
		Outputs: []Output{{
			ID:        "kernel",
			Kind:      "kernel_image",
			SizeBytes: 4096,
			SHA256:    strings.Repeat("a", 64),
		}},
	}
	if err := ValidateProvenance(provenance); err != nil {
		t.Fatalf("ValidateProvenance() error = %v", err)
	}
	encoded, err := json.Marshal(provenance)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"path", "endpoint", "hostname", "username", "command", "environment"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("provenance contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestL5VerifyDependencyLocksFailsClosedOnMissingExtraOrMismatch(t *testing.T) {
	locks := []DependencyLock{
		{Name: "buildroot", Version: "2026.02.1", SHA256: strings.Repeat("a", 64)},
		{Name: "linux", Version: "6.12.40", SHA256: strings.Repeat("b", 64)},
	}
	valid := map[string]string{
		"buildroot": strings.Repeat("a", 64),
		"linux":     strings.Repeat("b", 64),
	}
	if err := VerifyDependencyLocks(locks, valid); err != nil {
		t.Fatalf("VerifyDependencyLocks(valid) error = %v", err)
	}
	for name, digests := range map[string]map[string]string{
		"missing":  {"buildroot": strings.Repeat("a", 64)},
		"extra":    {"buildroot": strings.Repeat("a", 64), "linux": strings.Repeat("b", 64), "other": strings.Repeat("c", 64)},
		"mismatch": {"buildroot": strings.Repeat("a", 64), "linux": strings.Repeat("c", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyDependencyLocks(locks, digests); err == nil {
				t.Fatal("VerifyDependencyLocks() error = nil, want fail-closed error")
			}
		})
	}
}
