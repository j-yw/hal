package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestSandboxSecurityMetadataIncludesEffectivePolicyResult(t *testing.T) {
	security := testEffectiveSandboxSecurityMetadata()
	store := sandboxexecution.NewStore(t.TempDir())
	startedAt := time.Date(2026, 7, 2, 3, 0, 0, 0, time.UTC)

	err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID: "run-security-metadata",
		ProjectDir:  "/repo",
		SandboxName: "policy-target",
		Security:    runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, startedAt, nil, &sandbox.SandboxState{
		Name:     "policy-target",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
		Security: security,
	})
	if err != nil {
		t.Fatalf("saveRunSandboxManifest() error: %v", err)
	}

	manifest, err := store.LoadManifest("run-security-metadata")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	requireEffectiveSandboxPolicyResult(t, manifest.Security.Network.PolicyResult)

	summary := newSandboxRuntimeSecuritySummary(security)
	requireEffectiveSandboxPolicyResult(t, summary.NetworkPolicyResult)

	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	for _, forbidden := range []string{"ghp_secret_policy_value", "https://token@", "/Users/private", "worker.sock"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("sandbox security metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestSandboxManifestsUseRequestedSecurityIntentWhenTargetHasLegacySecurity(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 3, 2, 0, 0, time.UTC)
	securityReq := sandbox.SecurityEvaluationRequest{
		RuntimeDriver: sandbox.SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicyIntent: &sandbox.SandboxNetworkPolicyIntent{
			Preset: sandbox.SandboxNetworkPolicyPresetDisabled,
		},
		RequestedSecretModes:  []string{sandbox.SandboxSecretModeSSHAgent},
		ActiveSecretModes:     []string{sandbox.SandboxSecretModeSSHAgent},
		CompatibilityAuthSync: true,
	}
	legacyTarget := &sandbox.SandboxState{
		Name:     "legacy-security-target",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
				ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
			},
		},
	}

	runStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID: "run-typed-security-manifest",
		ProjectDir:  "/repo",
		Security:    securityReq,
	}, sandboxexecution.StatusSucceeded, startedAt, nil, legacyTarget); err != nil {
		t.Fatalf("saveRunSandboxManifest() error: %v", err)
	}
	runManifest, err := runStore.LoadManifest("run-typed-security-manifest")
	if err != nil {
		t.Fatalf("LoadManifest(run) error: %v", err)
	}
	requireDisabledSandboxSecurityIntent(t, runManifest.Security)

	autoStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID: "auto-typed-security-manifest",
		ProjectDir:  "/repo",
		Security:    securityReq,
	}, sandboxexecution.StatusSucceeded, startedAt, nil, legacyTarget); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error: %v", err)
	}
	autoManifest, err := autoStore.LoadManifest("auto-typed-security-manifest")
	if err != nil {
		t.Fatalf("LoadManifest(auto) error: %v", err)
	}
	requireDisabledSandboxSecurityIntent(t, autoManifest.Security)
}

func TestFactorySandboxSecurityPolicyEventIncludesEffectivePolicyResult(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	now := time.Date(2026, 7, 2, 3, 1, 0, 0, time.UTC)
	secretValue := "ghp_secret_policy_event_value"
	target := &sandbox.SandboxState{
		Name:     "factory-policy-target",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
		Security: testEffectiveSandboxSecurityMetadata(),
	}

	err := recordFactorySandboxSecurityPolicyEvent(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &factory.RunRecord{RunID: "run-policy-event"}, target, factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{{
		Name:  "TOKEN",
		Value: secretValue,
	}}))
	if err != nil {
		t.Fatalf("recordFactorySandboxSecurityPolicyEvent() error: %v", err)
	}

	events, err := store.LoadEvents("run-policy-event")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	securityMap := requireSandboxSecurityMap(t, events[0].Metadata["security"])
	network := requireSandboxSecurityMap(t, securityMap["network"])
	policyResult := requireSandboxSecurityMap(t, network["policyResult"])
	requireEffectivePolicyResultMap(t, policyResult)

	encoded := mustMarshalSandboxSecurityMetadata(t, events[0].Metadata)
	for _, forbidden := range []string{secretValue, "https://token@", "/Users/private", "worker.sock"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory policy event leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestFactorySandboxSecretMetadataIncludesDeliveryModesOnly(t *testing.T) {
	rawSecret := "ghp_secret_delivery_mode_value"
	metadata := factorySandboxSecurityMetadata(&sandbox.SandboxSecurity{
		Secrets: &sandbox.SandboxSecretSecurity{
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy, sandbox.SandboxSecretModeFileTmpfs},
			ActiveModes:    []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync},
		},
	})
	if metadata == nil || metadata.Secrets == nil {
		t.Fatalf("factorySandboxSecurityMetadata() = %#v, want secret metadata", metadata)
	}
	if !reflect.DeepEqual(metadata.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeHTTPProxy, sandbox.SandboxSecretModeFileTmpfs}) {
		t.Fatalf("requested secret modes = %#v", metadata.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(metadata.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("active secret modes = %#v", metadata.Secrets.ActiveModes)
	}

	encoded := mustMarshalSandboxSecurityMetadata(t, factory.SandboxMetadata{
		Security: metadata,
	})
	for _, want := range []string{sandbox.SandboxSecretModeHTTPProxy, sandbox.SandboxSecretModeFileTmpfs, sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("factory secret metadata = %s, want mode %q", encoded, want)
		}
	}
	for _, forbidden := range []string{rawSecret, "value", "credential", "token=", "/tmp/secret-file"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory secret metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func testEffectiveSandboxSecurityMetadata() *sandbox.SandboxSecurity {
	return sandbox.EvaluateSandboxSecurity(sandbox.SecurityEvaluationRequest{
		RuntimeDriver:          sandbox.SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:      []string{sandbox.SandboxSecretModeEnv},
		CompatibilityAuthSync:  true,
	})
}

func requireEffectiveSandboxPolicyResult(t *testing.T, result *sandbox.SandboxNetworkPolicyResult) {
	t.Helper()
	if result == nil {
		t.Fatal("policy result = nil")
	}
	if result.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("requested preset = %q, want %q", result.Requested.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if result.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("effective preset = %q, want %q", result.Effective.Preset, sandbox.SandboxNetworkPolicyPresetLegacyDefault)
	}
	if result.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcement mode = %q, want %q", result.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if result.Capability.Supported {
		t.Fatalf("capability supported = true, compatibility metadata must not claim enforcement")
	}
	if len(result.Warnings) == 0 {
		t.Fatal("warnings = empty, want unsupported enforcement warning")
	}
	if result.Warnings[0].Code != sandbox.SandboxNetworkPolicyWarningUnsupportedEnforcement {
		t.Fatalf("warning code = %q, want %q", result.Warnings[0].Code, sandbox.SandboxNetworkPolicyWarningUnsupportedEnforcement)
	}
}

func requireDisabledSandboxSecurityIntent(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.Network == nil || security.Network.PolicyResult == nil {
		t.Fatalf("security = %#v, want additive policy result", security)
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyRequested = %q, want best_effort disabled compatibility label", security.Network.PolicyRequested)
	}
	if security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.requested.preset = %q, want disabled", security.Network.PolicyResult.Requested.Preset)
	}
	if security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.effective.preset = %q, want disabled", security.Network.PolicyResult.Effective.Preset)
	}
	if security.Secrets == nil {
		t.Fatal("secret security metadata = nil")
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeSSHAgent}) {
		t.Fatalf("requestedModes = %#v, want ssh_agent", security.Secrets.RequestedModes)
	}
	wantActiveModes := []string{sandbox.SandboxSecretModeSSHAgent, sandbox.SandboxSecretModeLegacyAuthSync}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, wantActiveModes) {
		t.Fatalf("activeModes = %#v, want %#v", security.Secrets.ActiveModes, wantActiveModes)
	}
}

func requireEffectivePolicyResultMap(t *testing.T, result map[string]any) {
	t.Helper()
	requested := requireSandboxSecurityMap(t, result["requested"])
	if requested["preset"] != string(sandbox.SandboxNetworkPolicyPresetDenyByDefault) {
		t.Fatalf("requested policy result = %#v", requested)
	}
	effective := requireSandboxSecurityMap(t, result["effective"])
	if effective["preset"] != string(sandbox.SandboxNetworkPolicyPresetLegacyDefault) {
		t.Fatalf("effective policy result = %#v", effective)
	}
	if result["enforcementMode"] != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("policy result enforcementMode = %#v", result["enforcementMode"])
	}
	capability := requireSandboxSecurityMap(t, result["capability"])
	if capability["supported"] != false {
		t.Fatalf("policy result capability = %#v", capability)
	}
	warnings, ok := result["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("policy result warnings = %#v", result["warnings"])
	}
	warning := requireSandboxSecurityMap(t, warnings[0])
	if warning["code"] != string(sandbox.SandboxNetworkPolicyWarningUnsupportedEnforcement) {
		t.Fatalf("policy result warning = %#v", warning)
	}
}

func requireSandboxSecurityMap(t *testing.T, value any) map[string]any {
	t.Helper()
	metadata, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("metadata = %#v, want map[string]any", value)
	}
	return metadata
}

func mustMarshalSandboxSecurityMetadata(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	return string(data)
}
