package microvm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestLiveE2ENetworkEnforcementReadinessRequiresExplicitMarkers(t *testing.T) {
	result := ProjectLiveE2ENetworkEnforcementReadiness(LiveE2ENetworkEnforcementReadinessInput{
		NetworkEnforcement: liveE2ENetworkEnforcementReadyMetadata(),
	})

	if !result.ShouldSkipLiveAction() {
		t.Fatalf("ShouldSkipLiveAction() = false, want true for missing markers: %#v", result)
	}
	requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, LiveE2EPrerequisiteNetworkProxyMarker)
	requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, LiveE2EPrerequisiteFirewallMarker)
	if result.NetworkEnforcement != nil {
		t.Fatalf("networkEnforcement = %#v, want omitted while markers are missing", result.NetworkEnforcement)
	}
	assertLiveE2ENetworkReadinessNoUnsafeFragments(t, "missing markers", result)
}

func TestLiveE2ENetworkEnforcementReadinessAllowsProxyFirewallOnlyWithActiveLifecycle(t *testing.T) {
	result := ProjectLiveE2ENetworkEnforcementReadiness(LiveE2ENetworkEnforcementReadinessInput{
		LiveMarker:         true,
		ProxyMarker:        true,
		FirewallMarker:     true,
		NetworkEnforcement: liveE2ENetworkEnforcementReadyMetadata(),
	})

	if !result.CanRunLiveAction() {
		t.Fatalf("CanRunLiveAction() = false, want true: %#v", result)
	}
	if !liveE2EReadinessReady(result.NetworkProxy) || !liveE2EReadinessReady(result.Firewall) {
		t.Fatalf("readiness = proxy %#v firewall %#v, want both ready", result.NetworkProxy, result.Firewall)
	}
	if result.NetworkEnforcement == nil ||
		result.NetworkEnforcement.Result == nil ||
		result.NetworkEnforcement.Result.EnforcementMode != "proxy_firewall" {
		t.Fatalf("networkEnforcement = %#v, want proxy_firewall metadata", result.NetworkEnforcement)
	}
	assertLiveE2ENetworkReadinessNoUnsafeFragments(t, "ready metadata", result)
}

func TestLiveE2ENetworkEnforcementReadinessFailsSanitizedForInconsistentClaims(t *testing.T) {
	metadata := liveE2ENetworkEnforcementReadyMetadata()
	metadata.Orchestration.Rules = nil
	metadata.Result.AdapterID = "https://proxy.internal.example.test:8443/adapter?token=ghp_secret"
	metadata.Result.Operations = append(metadata.Result.Operations, "/tmp/firewall.sock", "Authorization: Bearer ghp_secret")

	result := ProjectLiveE2ENetworkEnforcementReadiness(LiveE2ENetworkEnforcementReadinessInput{
		LiveMarker:         true,
		ProxyMarker:        true,
		FirewallMarker:     true,
		NetworkEnforcement: metadata,
	})

	if !result.ShouldFailLiveAction() {
		t.Fatalf("ShouldFailLiveAction() = false, want failure for missing active firewall lifecycle: %#v", result)
	}
	if result.ShouldSkipLiveAction() {
		t.Fatalf("ShouldSkipLiveAction() = true, want explicit inconsistent claims to fail: %#v", result)
	}
	if result.ReasonCode != LiveE2EReasonFirewallUnavailable {
		t.Fatalf("reason = %q, want %q", result.ReasonCode, LiveE2EReasonFirewallUnavailable)
	}
	message := LiveE2ENetworkEnforcementReadinessFailureMessage(result)
	for _, want := range []string{
		"microVM live E2E network enforcement readiness failed",
		"reason firewall_unavailable",
		"networkProxy status ready",
		"firewall status unavailable",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("failure message = %q, want fragment %q", message, want)
		}
	}
	assertLiveE2ENetworkReadinessNoUnsafeFragments(t, "inconsistent metadata", result, message)
}

func TestLiveE2ENetworkEnforcementReadinessRejectsResultWithoutDefaultDenyCapability(t *testing.T) {
	metadata := liveE2ENetworkEnforcementReadyMetadata()
	metadata.Result.Capability.SupportsDefaultDenyPosture = false

	result := ProjectLiveE2ENetworkEnforcementReadiness(LiveE2ENetworkEnforcementReadinessInput{
		LiveMarker:         true,
		ProxyMarker:        true,
		FirewallMarker:     true,
		NetworkEnforcement: metadata,
	})

	if !result.ShouldFailLiveAction() {
		t.Fatalf("ShouldFailLiveAction() = false, want failure for missing default-deny capability: %#v", result)
	}
	if result.NetworkEnforcement == nil || result.NetworkEnforcement.Result == nil || result.NetworkEnforcement.Result.Capability == nil {
		t.Fatalf("sanitized capability = %#v, want capability metadata preserved for diagnostics", result.NetworkEnforcement)
	}
	if result.NetworkEnforcement.Result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("SupportsDefaultDenyPosture = true, want preserved false capability claim")
	}
	assertLiveE2ENetworkReadinessNoUnsafeFragments(t, "missing default deny capability", result)
}

func TestLiveE2ENetworkEnforcementReadinessContractFieldsAndJSONNames(t *testing.T) {
	resultType := reflect.TypeOf(LiveE2ENetworkEnforcementReadinessResult{})
	assertConfigField(t, resultType, "Status", reflect.TypeOf(LiveE2EReadinessStatus("")), `json:"status,omitempty"`)
	assertConfigField(t, resultType, "ReasonCode", reflect.TypeOf(LiveE2EReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, resultType, "NetworkProxy", reflect.TypeOf((*LiveE2EReadinessMetadata)(nil)), `json:"networkProxy,omitempty"`)
	assertConfigField(t, resultType, "Firewall", reflect.TypeOf((*LiveE2EReadinessMetadata)(nil)), `json:"firewall,omitempty"`)
	assertConfigField(t, resultType, "NetworkEnforcement", reflect.TypeOf((*sandboxruntime.RuntimeNetworkEnforcementMetadata)(nil)), `json:"networkEnforcement,omitempty"`)
	assertConfigField(t, resultType, "Diagnostics", reflect.TypeOf([]LiveE2EPrerequisiteDiagnostic{}), `json:"diagnostics,omitempty"`)
}

func liveE2ENetworkEnforcementReadyMetadata() *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(&sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               "live-e2e-network-plan",
			Source:           "microvm",
			Operation:        "live_e2e",
			PolicySnapshotID: "live-e2e-policy",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "http_connect", "https_connect"},
		},
		Orchestration: &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           "live-e2e-network-plan",
			AdapterID:        "live-e2e-network-adapter",
			Status:           "active",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"start_proxy", "apply_rules"},
			PolicySnapshotID: "live-e2e-policy",
			PolicyPreset:     "deny_by_default",
			Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               "live-e2e-proxy",
				PlanID:           "live-e2e-network-plan",
				AdapterID:        "live-e2e-network-adapter",
				Status:           "active",
				Mechanisms:       []string{"proxy"},
				Operations:       []string{"start_proxy"},
				PolicySnapshotID: "live-e2e-policy",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"http_proxy"},
				ReasonCode:       "active",
			},
			Rules: []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				{
					ID:               "live-e2e-firewall-rules",
					PlanID:           "live-e2e-network-plan",
					AdapterID:        "live-e2e-network-adapter",
					Status:           "active",
					Mechanisms:       []string{"firewall"},
					Operations:       []string{"apply_rules"},
					PolicySnapshotID: "live-e2e-policy",
					PolicyPreset:     "deny_by_default",
					CapabilityLabels: []string{"default_deny"},
					ReasonCode:       "applied",
				},
			},
			CapabilityLabels: []string{"proxy_active", "rules_active"},
			ReasonCode:       "active",
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:           "live-e2e-network-plan",
			AdapterID:        "live-e2e-network-adapter",
			Outcome:          "success",
			EnforcementMode:  "proxy_firewall",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_route", "firewall_apply"},
			PolicySnapshotID: "live-e2e-policy",
			PolicyPreset:     "deny_by_default",
			Capability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	})
}

func assertLiveE2ENetworkReadinessNoUnsafeFragments(t *testing.T, label string, values ...any) {
	t.Helper()
	var publicText strings.Builder
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("Marshal(%s) error: %v", label, err)
		}
		publicText.Write(encoded)
		publicText.WriteString(" ")
		if result, ok := value.(LiveE2ENetworkEnforcementReadinessResult); ok {
			publicText.WriteString(LiveE2ENetworkEnforcementReadinessSkipMessage(result))
			publicText.WriteString(" ")
			publicText.WriteString(LiveE2ENetworkEnforcementReadinessFailureMessage(result))
		}
	}
	for _, unsafe := range []string{
		"proxy.internal.example.test",
		"8443",
		"127.0.0.1",
		"localhost",
		"https://",
		"/tmp/",
		".sock",
		"Authorization",
		"Bearer",
		"token=",
		"ghp_secret",
		"iptables",
		"nft",
		"pfctl",
	} {
		if strings.Contains(publicText.String(), unsafe) {
			t.Fatalf("%s leaked unsafe network readiness fragment %q in %s", label, unsafe, publicText.String())
		}
	}
}
