package linuxrules

import (
	"context"
	"encoding/json"
	"errors"
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
	if metadata.Inspection == nil {
		t.Fatalf("forwarded profile omitted inspection proof: %#v", metadata)
	}
	for _, label := range metadata.Inspection.CapabilityLabels {
		if label == "domain_rules" {
			t.Fatalf("firewall proof claimed proxy-owned domain_rules: %#v", metadata.Inspection)
		}
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

func TestLinuxRulesRejectsLoopbackProxyAddress(t *testing.T) {
	config := testRuleSetConfig("generation-loopback", RuleProfileWorkloadOutput)
	config.ProxyAddress = "127.0.0.1"
	if _, err := NewExpectedRuleSet(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("loopback proxy error = %v, want ErrInvalidConfiguration", err)
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
	expected := testExpectedRuleSet(t, "generation-json")
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{expected.tableName, expected.interfaceName, expected.proxyAddress.String()} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("JSON leaked %q in %s", forbidden, payload)
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
	return RuleSetConfig{
		Correlation: networkenforcement.EnforcementCorrelation{
			SandboxID:            "sandbox-linuxrules",
			ExecutionID:          "execution-linuxrules",
			WorkerID:             "worker-linuxrules",
			RuntimeID:            "runtime-linuxrules",
			PlanID:               "plan-linuxrules",
			PolicySnapshotID:     "policy-linuxrules",
			ProxySessionID:       "proxy-linuxrules",
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
}
