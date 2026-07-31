package linuxrules

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestLinuxRulesApplyUsesOneAtomicBatchAndInspectionBeforeProof(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-one")
	executor := newFakeNFTExecutor(expected)
	adapter := NewAdapter(executor, AdapterOptions{})

	metadata, err := adapter.ApplyAndInspect(context.Background(), expected)
	if err != nil {
		t.Fatalf("ApplyAndInspect: %v", err)
	}
	if len(executor.batches) != 1 {
		t.Fatalf("batches = %d, want one atomic batch", len(executor.batches))
	}
	batch := string(executor.batches[0])
	for _, required := range []string{"add table inet", "hook output", "policy drop", "tcp dport", "icmpv6 type"} {
		if !strings.Contains(batch, required) {
			t.Fatalf("batch missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "iptables", "sudo", "sh -c"} {
		if strings.Contains(strings.ToLower(batch), forbidden) {
			t.Fatalf("batch contains forbidden operation %q", forbidden)
		}
	}
	if strings.Contains(batch, "ct state established,related accept") {
		t.Fatalf("output profile contains broad established accept: %s", batch)
	}
	if metadata.Inspection == nil || metadata.Inspection.Status != networkenforcement.RuleInspectionStatusInspected {
		t.Fatalf("metadata = %#v, want inspected proof", metadata)
	}
	if metadata.Inspection.InspectedAtUnixMilli <= 0 {
		t.Fatalf("inspection timestamp = %d, want positive epoch millis", metadata.Inspection.InspectedAtUnixMilli)
	}
	if executor.listCalls < 2 {
		t.Fatalf("list calls = %d, want ownership check and post-apply inspection", executor.listCalls)
	}
}

func TestLinuxRulesForwardedTAPProfileInspectsInputAndForwardChains(t *testing.T) {
	expected := testExpectedRuleSetForProfile(t, "generation-forwarded", RuleProfileForwardedTAP)
	executor := newFakeNFTExecutor(expected)
	adapter := NewAdapter(executor, AdapterOptions{})

	metadata, err := adapter.ApplyAndInspect(context.Background(), expected)
	if err != nil {
		t.Fatalf("ApplyAndInspect: %v", err)
	}
	batch := string(executor.batches[0])
	for _, required := range []string{"hook input", "hook forward", "iifname", "oifname", "tcp sport", "tcp dport"} {
		if !strings.Contains(batch, required) {
			t.Fatalf("forwarded batch missing %q", required)
		}
	}
	if strings.Contains(batch, "hook output") {
		t.Fatalf("forwarded profile unexpectedly used output chain: %s", batch)
	}
	for _, required := range []string{
		"iifname \"eth0\" oifname \"pasta0\"",
		"iifname \"pasta0\" oifname \"eth0\"",
	} {
		if !strings.Contains(batch, required) {
			t.Fatalf("forwarded batch does not bind both directions to exact interfaces %q: %s", required, batch)
		}
	}
	establishedRules := 0
	for _, line := range strings.Split(batch, "\n") {
		if !strings.Contains(line, "ct state") {
			continue
		}
		establishedRules++
		for _, required := range []string{"oifname", "saddr", "tcp sport", "ct state established accept"} {
			if !strings.Contains(line, required) {
				t.Fatalf("return-state rule is not tuple constrained by %q: %s", required, line)
			}
		}
		if strings.Contains(line, "related") {
			t.Fatalf("return-state rule accepted unrelated traffic: %s", line)
		}
	}
	if establishedRules != 1 {
		t.Fatalf("forwarded profile established rules = %d, want one constrained return rule", establishedRules)
	}
	if metadata.Inspection == nil {
		t.Fatalf("forwarded profile omitted inspection proof: %#v", metadata)
	}
	for _, label := range metadata.Inspection.CapabilityLabels {
		if label == "domain_rules" {
			t.Fatalf("firewall proof claimed proxy-owned domain_rules: %#v", metadata.Inspection)
		}
	}
}

func TestLinuxRulesForwardedProfileRequiresDistinctMappingInterface(t *testing.T) {
	for _, mappingInterface := range []string{"", "eth0", "../../host0"} {
		config := testRuleSetConfig("generation-mapping", RuleProfileForwardedTAP)
		config.MappingInterfaceName = mappingInterface
		if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("mapping interface %q error = %v, want ErrInvalidConfiguration", mappingInterface, err)
		}
	}
}

func TestLinuxRulesForwardedInspectionRejectsMappingInterfaceDrift(t *testing.T) {
	expected := testExpectedRuleSetForProfile(t, "generation-mapping-drift", RuleProfileForwardedTAP)
	executor := newFakeNFTExecutor(expected)
	executor.postApplyMutation = "wrong_mapping_interface"
	adapter := NewAdapter(executor, AdapterOptions{})

	metadata, err := adapter.ApplyAndInspect(context.Background(), expected)
	if !errors.Is(err, ErrInspectionFailed) {
		t.Fatalf("error = %v, want ErrInspectionFailed", err)
	}
	if metadata.Inspection != nil && metadata.Inspection.Status == networkenforcement.RuleInspectionStatusInspected {
		t.Fatalf("mapping drift produced inspected proof: %#v", metadata)
	}
}

func TestLinuxRulesRequiresOwningUserAndNetworkNamespaces(t *testing.T) {
	config := testRuleSetConfig("generation-namespace", RuleProfileWorkloadOutput)
	config.Namespace = NewNamespaceHandle(0, 11)
	if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing user namespace error = %v, want ErrInvalidConfiguration", err)
	}
	config.Namespace = NewNamespaceHandle(10, 0)
	if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing network namespace error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestLinuxRulesWorkloadOutputRequiresIndependentRawPacketIsolation(t *testing.T) {
	config := RuleSetConfig{
		Correlation: networkenforcement.EnforcementCorrelation{
			SandboxID:            "sandbox-raw-packet",
			ExecutionID:          "execution-raw-packet",
			WorkerID:             "worker-raw-packet",
			RuntimeID:            "runtime-raw-packet",
			PlanID:               "plan-raw-packet",
			PolicySnapshotID:     "policy-raw-packet",
			ProxySessionID:       "proxy-raw-packet",
			ProxyGenerationID:    "proxy-generation-raw-packet",
			TopologyGenerationID: "topology-raw-packet",
			RuleGenerationID:     "rules-raw-packet",
		},
		Profile:       RuleProfileWorkloadOutput,
		Namespace:     NewNamespaceHandle(10, 11),
		TableName:     "hal_l7_raw_packet",
		InterfaceName: "eth0",
		ProxyAddress:  "192.0.2.10",
		ProxyPort:     3128,
	}
	if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing raw-packet isolation verifier error = %v, want ErrInvalidConfiguration", err)
	}
}

type allowRawPacketIsolationVerifier struct{}

func (allowRawPacketIsolationVerifier) VerifyRawPacketIsolation(context.Context, networkenforcement.EnforcementCorrelation) error {
	return nil
}

type recordingRawPacketIsolationVerifier struct {
	err         error
	calls       int
	correlation networkenforcement.EnforcementCorrelation
}

func (v *recordingRawPacketIsolationVerifier) VerifyRawPacketIsolation(_ context.Context, correlation networkenforcement.EnforcementCorrelation) error {
	v.calls++
	v.correlation = correlation
	return v.err
}

func TestLinuxRulesRawPacketIsolationIsCheckedBeforeMutationAndNotProjected(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-raw-check")
	verifier := &recordingRawPacketIsolationVerifier{}
	expected.rawPacketIsolation = verifier
	executor := newFakeNFTExecutor(expected)

	metadata, err := NewAdapter(executor, AdapterOptions{}).ApplyAndInspect(context.Background(), expected)
	if err != nil {
		t.Fatalf("ApplyAndInspect: %v", err)
	}
	if verifier.calls != 1 || verifier.correlation != expected.correlation {
		t.Fatalf("verifier calls/correlation = %d/%#v, want one exact correlation", verifier.calls, verifier.correlation)
	}
	for _, label := range metadata.CapabilityLabels {
		if label == "raw_protocols" {
			t.Fatalf("private runtime verifier was projected as rule proof: %#v", metadata)
		}
	}

	expected = testExpectedRuleSet(t, "generation-raw-failure")
	verifier = &recordingRawPacketIsolationVerifier{err: errors.New("seeded private runtime detail")}
	expected.rawPacketIsolation = verifier
	executor = newFakeNFTExecutor(expected)
	metadata, err = NewAdapter(executor, AdapterOptions{}).ApplyAndInspect(context.Background(), expected)
	if !errors.Is(err, ErrRawPacketIsolation) {
		t.Fatalf("verifier failure error = %v, want ErrRawPacketIsolation", err)
	}
	if len(executor.batches) != 0 || executor.listCalls != 0 {
		t.Fatalf("verifier failure reached nft executor: batches=%d lists=%d", len(executor.batches), executor.listCalls)
	}
	if strings.Contains(err.Error(), "seeded") || metadata.Status == networkenforcement.LifecycleStatusActive {
		t.Fatalf("verifier failure leaked detail or became active: err=%v metadata=%#v", err, metadata)
	}
}

func TestLinuxRulesForwardedTAPMediatesGuestPacketsWithoutHostRawSocketVerifier(t *testing.T) {
	config := testRuleSetConfig("generation-forwarded-no-verifier", RuleProfileForwardedTAP)
	config.RawPacketIsolation = nil
	if _, err := NewExpectedRuleSet(config); err != nil {
		t.Fatalf("forwarded TAP rules unexpectedly required host raw-packet verifier: %v", err)
	}
}

func TestLinuxRulesNeighborDiscoveryUsesExactConfiguredIPv6Link(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile RuleProfile
		local   string
		peer    string
		dad     bool
	}{
		{name: "workload-ula", profile: RuleProfileWorkloadOutput, local: "fd00:7::2", peer: "fd00:7::1"},
		{name: "workload-global", profile: RuleProfileWorkloadOutput, local: "2001:db8:7::2", peer: "2001:db8:7::1"},
		{name: "forwarded-ula", profile: RuleProfileForwardedTAP, local: "fd00:7::2", peer: "fd00:7::1", dad: true},
		{name: "forwarded-global", profile: RuleProfileForwardedTAP, local: "2001:db8:7::2", peer: "2001:db8:7::1", dad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testRuleSetConfig("generation-nd", test.profile)
			config.WorkloadIPv6Address = test.local
			config.GatewayIPv6Address = test.peer
			config.IPv6PrefixBits = 64
			config.AllowIPv6DAD = test.dad
			expected, err := NewExpectedRuleSet(config)
			if err != nil {
				t.Fatalf("NewExpectedRuleSet: %v", err)
			}
			batch := string(expected.fullBatch(false))
			ndLines := make([]string, 0, 5)
			for _, line := range strings.Split(batch, "\n") {
				if strings.Contains(line, "icmpv6 type") {
					ndLines = append(ndLines, line)
				}
			}
			wantRules := 4
			if test.dad {
				wantRules++
			}
			if len(ndLines) != wantRules {
				t.Fatalf("neighbor-discovery rules = %d, want %d exact semantic cases: %s", len(ndLines), wantRules, batch)
			}
			joined := strings.Join(ndLines, "\n")
			peerSolicited := solicitedNodeMulticast(netip.MustParseAddr(test.peer)).String()
			for _, required := range []string{
				"ip6 hoplimit 255",
				"ip6 saddr " + test.local,
				"ip6 daddr " + test.peer,
				"ip6 daddr " + peerSolicited,
				"icmpv6 taddr " + test.local,
				"icmpv6 taddr " + test.peer,
				"nd-neighbor-solicit",
				"nd-neighbor-advert",
			} {
				if !strings.Contains(joined, required) {
					t.Fatalf("neighbor-discovery batch missing %q: %s", required, joined)
				}
			}
			if strings.Contains(joined, "fe80::/10") {
				t.Fatalf("configured-link neighbor discovery retained a broad link-local prefix: %s", joined)
			}
			if test.profile == RuleProfileWorkloadOutput && !strings.Contains(joined, `oifname "eth0"`) {
				t.Fatalf("workload neighbor discovery is not output-interface bound: %s", joined)
			}
			if test.profile == RuleProfileForwardedTAP && !strings.Contains(joined, `iifname "eth0"`) {
				t.Fatalf("forwarded neighbor discovery is not input-interface bound: %s", joined)
			}
			if test.dad && !strings.Contains(joined, "ip6 saddr ::") {
				t.Fatalf("required DAD case missing: %s", joined)
			}
			if test.dad {
				localSolicited := solicitedNodeMulticast(netip.MustParseAddr(test.local)).String()
				if !strings.Contains(joined, "ip6 daddr "+localSolicited) {
					t.Fatalf("DAD did not use the exact configured solicited-node destination %s: %s", localSolicited, joined)
				}
			}
			if !test.dad && strings.Contains(joined, "ip6 saddr ::") {
				t.Fatalf("unexpected DAD case admitted: %s", joined)
			}

			inspection := string(expectedInspectionJSON(expected))
			for _, required := range []string{
				`"field":"hoplimit"`,
				`"field":"saddr"`,
				`"field":"daddr"`,
				`"field":"taddr"`,
				`"right":"ipv6-icmp"`,
				`"right":"` + test.local + `"`,
				`"right":"` + test.peer + `"`,
			} {
				if !strings.Contains(inspection, required) {
					t.Fatalf("exact inspection model missing %s: %s", required, inspection)
				}
			}
		})
	}
}

func TestLinuxRulesRejectsInvalidConfiguredIPv6Links(t *testing.T) {
	for _, test := range []struct {
		name       string
		local      string
		peer       string
		prefixBits uint8
	}{
		{name: "missing local", peer: "fd00:7::1", prefixBits: 64},
		{name: "missing peer", local: "fd00:7::2", prefixBits: 64},
		{name: "ipv4 local", local: "192.0.2.2", peer: "fd00:7::1", prefixBits: 64},
		{name: "multicast local", local: "ff02::2", peer: "fd00:7::1", prefixBits: 64},
		{name: "unspecified peer", local: "fd00:7::2", peer: "::", prefixBits: 64},
		{name: "loopback peer", local: "fd00:7::2", peer: "::1", prefixBits: 64},
		{name: "same endpoint", local: "fd00:7::2", peer: "fd00:7::2", prefixBits: 64},
		{name: "not on link", local: "fd00:7::2", peer: "fd00:8::1", prefixBits: 64},
		{name: "missing prefix", local: "fd00:7::2", peer: "fd00:7::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testRuleSetConfig("generation-invalid-link", RuleProfileForwardedTAP)
			config.WorkloadIPv6Address = test.local
			config.GatewayIPv6Address = test.peer
			config.IPv6PrefixBits = test.prefixBits
			if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewExpectedRuleSet error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
	for _, profile := range []RuleProfile{RuleProfileWorkloadOutput, RuleProfileForwardedTAP} {
		config := testRuleSetConfig("generation-invalid-dad-role", profile)
		config.AllowIPv6DAD = profile != RuleProfileForwardedTAP
		if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("profile %s mismatched DAD role error = %v, want ErrInvalidConfiguration", profile, err)
		}
	}
}

func TestLinuxRulesInspectionRejectsConfiguredIPv6NeighborDrift(t *testing.T) {
	for _, profile := range []RuleProfile{RuleProfileWorkloadOutput, RuleProfileForwardedTAP} {
		for _, mutation := range []string{"wrong_nd_source", "wrong_nd_destination", "wrong_nd_target"} {
			t.Run(string(profile)+"/"+mutation, func(t *testing.T) {
				expected := testExpectedRuleSetForProfile(t, "generation-nd-drift", profile)
				executor := newFakeNFTExecutor(expected)
				executor.postApplyMutation = mutation
				metadata, err := NewAdapter(executor, AdapterOptions{}).ApplyAndInspect(context.Background(), expected)
				if !errors.Is(err, ErrInspectionFailed) {
					t.Fatalf("error = %v, want ErrInspectionFailed", err)
				}
				if metadata.Status == networkenforcement.LifecycleStatusActive || executor.quarantineCalls != 1 {
					t.Fatalf("neighbor drift became active or was not quarantined: metadata=%#v quarantine=%d", metadata, executor.quarantineCalls)
				}
			})
		}
	}
}

func TestLinuxRulesProxyDestinationCoversIPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
		marker  string
	}{
		{name: "ipv4", address: "192.0.2.10", marker: "ip daddr 192.0.2.10"},
		{name: "ipv6", address: "2001:db8::10", marker: "ip6 daddr 2001:db8::10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testRuleSetConfig("generation-"+test.name, RuleProfileForwardedTAP)
			config.ProxyAddress = test.address
			expected, err := NewExpectedRuleSet(config)
			if err != nil {
				t.Fatalf("NewExpectedRuleSet: %v", err)
			}
			if batch := string(expected.fullBatch(false)); !strings.Contains(batch, test.marker) {
				t.Fatalf("proxy batch missing %q: %s", test.marker, batch)
			}
		})
	}
}

func TestLinuxRulesRejectsLoopbackProxyAddress(t *testing.T) {
	config := testRuleSetConfig("generation-loopback", RuleProfileWorkloadOutput)
	config.ProxyAddress = "127.0.0.1"
	if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("loopback proxy error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestLinuxRulesRejectsKnownMetadataProxyAddresses(t *testing.T) {
	for _, address := range []string{
		"169.254.169.254",
		"fd00:ec2::254",
		"fd20:ce::254",
	} {
		t.Run(address, func(t *testing.T) {
			config := testRuleSetConfig("generation-metadata", RuleProfileWorkloadOutput)
			config.ProxyAddress = address
			if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("metadata proxy error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestLinuxRulesDigestBindsProxyGeneration(t *testing.T) {
	first := testExpectedRuleSet(t, "generation-digest")
	config := testRuleSetConfig("generation-digest", RuleProfileWorkloadOutput)
	config.Correlation.ProxyGenerationID = "proxy-generation-other"
	second, err := NewExpectedRuleSet(config)
	if err != nil {
		t.Fatalf("NewExpectedRuleSet: %v", err)
	}
	if first.ruleDigest == second.ruleDigest || first.ownerToken == second.ownerToken {
		t.Fatalf("proxy generation did not change ownership/digest: first=%s/%s second=%s/%s", first.ownerToken, first.ruleDigest, second.ownerToken, second.ruleDigest)
	}
}

func TestLinuxRulesInspectionRejectsStructuralDrift(t *testing.T) {
	for _, mutation := range []string{
		"extra_rule",
		"missing_rule",
		"reordered_rule",
		"wrong_verdict",
		"jump",
		"goto",
		"nat",
		"wrong_interface",
		"wrong_generation",
	} {
		t.Run(mutation, func(t *testing.T) {
			expected := testExpectedRuleSet(t, "generation-drift")
			executor := newFakeNFTExecutor(expected)
			executor.postApplyMutation = mutation
			adapter := NewAdapter(executor, AdapterOptions{})

			metadata, err := adapter.ApplyAndInspect(context.Background(), expected)
			if !errors.Is(err, ErrInspectionFailed) {
				t.Fatalf("error = %v, want ErrInspectionFailed", err)
			}
			if metadata.Inspection != nil && metadata.Inspection.Status == networkenforcement.RuleInspectionStatusInspected {
				t.Fatalf("drift produced inspected proof: %#v", metadata)
			}
			if executor.quarantineCalls != 1 {
				t.Fatalf("quarantine calls = %d, want one", executor.quarantineCalls)
			}
		})
	}
}

func TestLinuxRulesBoundsInspectionAndRedactsErrors(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-bounded")
	executor := newFakeNFTExecutor(expected)
	executor.inspection = []byte(strings.Repeat("x", 1025))
	adapter := NewAdapter(executor, AdapterOptions{MaxInspectionBytes: 1024})

	_, err := adapter.ApplyAndInspect(context.Background(), expected)
	if !errors.Is(err, ErrInspectionTooLarge) {
		t.Fatalf("error = %v, want ErrInspectionTooLarge", err)
	}
	for _, forbidden := range []string{expected.tableName, expected.interfaceName, expected.proxyAddress.String()} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked private state %q: %v", forbidden, err)
		}
	}
}

func TestLinuxRulesRejectsOversizedBatchBeforeExecutorMutation(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-batch-bound")
	executor := newFakeNFTExecutor(expected)
	adapter := NewAdapter(executor, AdapterOptions{MaxBatchBytes: 8})

	_, err := adapter.ApplyAndInspect(context.Background(), expected)
	if !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("error = %v, want ErrBatchTooLarge", err)
	}
	if len(executor.batches) != 0 {
		t.Fatalf("executor received %d batches after bound rejection", len(executor.batches))
	}
}

func TestLinuxRulesRejectsOptionsAboveHardBoundsBeforeExecutorWork(t *testing.T) {
	for _, options := range []AdapterOptions{
		{MaxBatchBytes: hardMaxBatchBytes + 1},
		{MaxInspectionBytes: hardMaxInspectionBytes + 1},
	} {
		expected := testExpectedRuleSet(t, "generation-option-bound")
		executor := newFakeNFTExecutor(expected)
		adapter := NewAdapter(executor, options)

		_, err := adapter.ApplyAndInspect(context.Background(), expected)
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("options %#v error = %v, want ErrInvalidConfiguration", options, err)
		}
		if len(executor.batches) != 0 || executor.listCalls != 0 {
			t.Fatalf("options %#v reached executor: batches=%d listCalls=%d", options, len(executor.batches), executor.listCalls)
		}
	}
}

func TestLinuxRulesApplyFailureQuarantinesOwnedGeneration(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-partial")
	executor := newFakeNFTExecutor(expected)
	executor.applyErrorAfterMutation = true
	adapter := NewAdapter(executor, AdapterOptions{})

	metadata, err := adapter.ApplyAndInspect(context.Background(), expected)
	if !errors.Is(err, ErrApplyFailed) {
		t.Fatalf("error = %v, want ErrApplyFailed", err)
	}
	if executor.quarantineCalls != 1 {
		t.Fatalf("quarantine calls = %d, want one", executor.quarantineCalls)
	}
	if metadata.Status == networkenforcement.LifecycleStatusActive {
		t.Fatalf("apply failure reported active: %#v", metadata)
	}
}

func TestLinuxRulesCleanupRequiresExactGenerationAndInspectsAbsence(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-current")
	executor := newFakeNFTExecutor(expected)
	executor.installExpected()
	adapter := NewAdapter(executor, AdapterOptions{})

	stale := testExpectedRuleSet(t, "generation-stale")
	if err := adapter.Cleanup(context.Background(), stale); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale cleanup error = %v, want ErrStaleGeneration", err)
	}
	if executor.deleteCalls != 0 {
		t.Fatalf("stale cleanup deleted current generation")
	}

	if err := adapter.Cleanup(context.Background(), expected); err != nil {
		t.Fatalf("Cleanup current generation: %v", err)
	}
	if executor.quarantineCalls != 1 || executor.deleteCalls != 1 {
		t.Fatalf("quarantine/delete = %d/%d, want 1/1", executor.quarantineCalls, executor.deleteCalls)
	}
	if executor.present {
		t.Fatal("owned table remained after cleanup")
	}
}

func TestLinuxRulesForwardedCleanupQuarantinesExactOwnedGeneration(t *testing.T) {
	expected := testExpectedRuleSetForProfile(t, "generation-forwarded-cleanup", RuleProfileForwardedTAP)
	executor := newFakeNFTExecutor(expected)
	executor.installExpected()
	adapter := NewAdapter(executor, AdapterOptions{})

	if err := adapter.Cleanup(context.Background(), expected); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if executor.quarantineCalls != 1 || executor.deleteCalls != 1 || executor.present {
		t.Fatalf("forwarded cleanup quarantine/delete/present = %d/%d/%t, want 1/1/false", executor.quarantineCalls, executor.deleteCalls, executor.present)
	}
}

func TestLinuxRulesSerializesConcurrentOperations(t *testing.T) {
	expected := testExpectedRuleSet(t, "generation-concurrent")
	executor := newFakeNFTExecutor(expected)
	executor.delay = 5 * time.Millisecond
	adapter := NewAdapter(executor, AdapterOptions{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = adapter.ApplyAndInspect(context.Background(), expected)
		}()
	}
	wg.Wait()
	if executor.maxConcurrent != 1 {
		t.Fatalf("executor max concurrency = %d, want 1", executor.maxConcurrent)
	}
}

func TestLinuxRulesPrivateInputsAreNotJSON(t *testing.T) {
	expected := testExpectedRuleSetForProfile(t, "generation-json", RuleProfileForwardedTAP)
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{
		expected.tableName,
		expected.interfaceName,
		expected.mappingInterfaceName,
		expected.proxyAddress.String(),
		expected.workloadIPv6Address.String(),
		expected.gatewayIPv6Address.String(),
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("JSON leaked %q in %s", forbidden, payload)
		}
	}
	configPayload, err := json.Marshal(testRuleSetConfig("generation-config-json", RuleProfileWorkloadOutput))
	if err != nil {
		t.Fatalf("Marshal config: %v", err)
	}
	for _, forbidden := range []string{"fd00:7::2", "fd00:7::1"} {
		if strings.Contains(string(configPayload), forbidden) {
			t.Fatalf("config JSON leaked private IPv6 link input %q in %s", forbidden, configPayload)
		}
	}
}

func testExpectedRuleSet(t *testing.T, generation string) ExpectedRuleSet {
	return testExpectedRuleSetForProfile(t, generation, RuleProfileWorkloadOutput)
}

func testExpectedRuleSetForProfile(t *testing.T, generation string, profile RuleProfile) ExpectedRuleSet {
	t.Helper()
	rules, err := NewExpectedRuleSet(testRuleSetConfig(generation, profile))
	if err != nil {
		t.Fatalf("NewExpectedRuleSet: %v", err)
	}
	return rules
}

func testRuleSetConfig(generation string, profile RuleProfile) RuleSetConfig {
	config := RuleSetConfig{
		Correlation: networkenforcement.EnforcementCorrelation{
			SandboxID:            "sandbox-linuxrules",
			ExecutionID:          "execution-linuxrules",
			WorkerID:             "worker-linuxrules",
			RuntimeID:            "runtime-linuxrules",
			PlanID:               "plan-linuxrules",
			PolicySnapshotID:     "policy-linuxrules",
			ProxySessionID:       "proxy-linuxrules",
			ProxyGenerationID:    "proxy-generation-linuxrules",
			TopologyGenerationID: "topology-linuxrules",
			RuleGenerationID:     generation,
		},
		Profile:       profile,
		Namespace:     NewNamespaceHandle(10, 11),
		TableName:     "hal_l7_rules",
		InterfaceName: "eth0",
		ProxyAddress:  "192.0.2.10",
		ProxyPort:     3128,
	}
	if profile == RuleProfileForwardedTAP {
		config.MappingInterfaceName = "pasta0"
		config.AllowIPv6DAD = true
	} else {
		config.RawPacketIsolation = allowRawPacketIsolationVerifier{}
	}
	config.WorkloadIPv6Address = "fd00:7::2"
	config.GatewayIPv6Address = "fd00:7::1"
	config.IPv6PrefixBits = 64
	return config
}
