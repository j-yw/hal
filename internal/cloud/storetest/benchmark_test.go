package storetest

import (
	"encoding/json"
	"testing"
)

func TestPercentile(t *testing.T) {
	tests := []struct {
		name string
		data []float64
		p    float64
		want float64
	}{
		{name: "empty", data: nil, p: 95, want: 0},
		{name: "single", data: []float64{42}, p: 95, want: 42},
		{name: "p50_even", data: []float64{1, 2, 3, 4}, p: 50, want: 2.5},
		{name: "p95_20_elements", data: []float64{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		}, p: 95, want: 19.05},
		{name: "p0", data: []float64{5, 10, 15}, p: 0, want: 5},
		{name: "p100", data: []float64{5, 10, 15}, p: 100, want: 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentile(tt.data, tt.p)
			if diff := got - tt.want; diff > 0.01 || diff < -0.01 {
				t.Errorf("percentile(%v, %v) = %v, want %v", tt.data, tt.p, got, tt.want)
			}
		})
	}
}

func TestBenchmarkResultJSON(t *testing.T) {
	result := &BenchmarkResult{
		Scenario:                 "claim_contention",
		Adapter:                  "turso",
		Runs:                     20,
		Errors:                   0,
		ClaimP95Ms:               1.5,
		HeartbeatP95Ms:           0.8,
		DuplicateClaims:          0,
		LockOvercommitViolations: 0,
	}

	data, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// Verify round-trip.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	requiredKeys := []string{
		"scenario", "adapter", "runs", "errors",
		"claim_p95_ms", "heartbeat_p95_ms",
		"duplicate_claims", "lock_overcommit_violations",
	}

	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if len(raw) != len(requiredKeys) {
		t.Errorf("JSON has %d keys, want exactly %d; keys: %v", len(raw), len(requiredKeys), raw)
	}

	if raw["scenario"] != "claim_contention" {
		t.Errorf("scenario = %v, want %q", raw["scenario"], "claim_contention")
	}
	if raw["adapter"] != "turso" {
		t.Errorf("adapter = %v, want %q", raw["adapter"], "turso")
	}
}
