package networkenforcement

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRawPacketIsolationProofSanitizesAndFailsClosed(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	correlation := aggregationCorrelation(plan)
	proof := RawPacketIsolationProof{
		ID:                  "raw-packet-proof-aggregation",
		Status:              RawPacketIsolationStatusVerified,
		VerifiedAtUnixMilli: 1735689600000,
		Correlation:         &correlation,
		ReasonCode:          LifecycleReasonRawPacketIsolationVerified,
	}

	if got := SanitizeRawPacketIsolationProof(proof); !reflect.DeepEqual(got, proof) {
		t.Fatalf("SanitizeRawPacketIsolationProof = %#v, want %#v", got, proof)
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, unsafe := range []string{"/tmp", "socket", "endpoint", "token", "secret"} {
		if strings.Contains(strings.ToLower(string(payload)), unsafe) {
			t.Fatalf("proof leaked unsafe fragment %q in %s", unsafe, payload)
		}
	}

	invalid := proof
	invalid.ID = "/tmp/raw-packet-proof-token=secret"
	got := SanitizeRawPacketIsolationProof(invalid)
	if got.Status != RawPacketIsolationStatusStale || got.ReasonCode != LifecycleReasonProofMismatch ||
		!reflect.DeepEqual(got.WarningCodes, []LifecycleWarningCode{LifecycleWarningProofMismatch}) {
		t.Fatalf("unsafe verified proof did not fail closed: %#v", got)
	}
}

func TestLiveEnforcementAggregationRequiresCorrelatedRawPacketIsolationProof(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationActiveListenerResult(plan)
	correlation := aggregationCorrelation(plan)
	validProof := RawPacketIsolationProof{
		ID:                  "raw-packet-proof-aggregation",
		Status:              RawPacketIsolationStatusVerified,
		VerifiedAtUnixMilli: 1735689600000,
		Correlation:         &correlation,
		ReasonCode:          LifecycleReasonRawPacketIsolationVerified,
	}

	rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	rules.Active.Inspection.CapabilityLabels = aggregationDefaultDenyRuleCapabilityLabels()
	rules.Active.RawPacketIsolation = &validProof
	result := AggregateLiveEnforcementResult(plan, &listener, &rules)
	assertStrongAggregatedEnforcement(t, result, ResultModeProxyFirewall, []EnforcementMechanism{
		EnforcementMechanismProxy,
		EnforcementMechanismFirewall,
	})

	for _, test := range []struct {
		name   string
		mutate func(*RawPacketIsolationProof)
	}{
		{name: "missing proof", mutate: func(proof *RawPacketIsolationProof) { *proof = RawPacketIsolationProof{} }},
		{name: "missing id", mutate: func(proof *RawPacketIsolationProof) { proof.ID = "" }},
		{name: "missing timestamp", mutate: func(proof *RawPacketIsolationProof) { proof.VerifiedAtUnixMilli = 0 }},
		{name: "stale status", mutate: func(proof *RawPacketIsolationProof) { proof.Status = RawPacketIsolationStatusStale }},
		{name: "warning", mutate: func(proof *RawPacketIsolationProof) {
			proof.WarningCodes = []LifecycleWarningCode{LifecycleWarningProofMismatch}
		}},
		{name: "mismatched generation", mutate: func(proof *RawPacketIsolationProof) {
			mismatch := *proof.Correlation
			mismatch.RuntimeID = "runtime-other"
			proof.Correlation = &mismatch
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validProof
			test.mutate(&candidate)
			rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
			rules.Active.Inspection.CapabilityLabels = aggregationDefaultDenyRuleCapabilityLabels()
			if test.name != "missing proof" {
				rules.Active.RawPacketIsolation = &candidate
			}
			result := AggregateLiveEnforcementResult(plan, &listener, &rules)
			assertNoStrongAggregatedEnforcement(t, result)
		})
	}
}
