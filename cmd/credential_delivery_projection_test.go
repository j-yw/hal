package cmd

import (
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestCredentialDeliveryProjectionAcrossRunAutoAndFactoryIsPlanOnly(t *testing.T) {
	networkProxySession := &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     "network-proxy-session-01",
		Source: sandbox.SandboxNetworkPolicyDecisionSourceRun,
	}
	security := sandbox.SecurityEvaluationRequest{
		RequestedSecretModes: []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
	}

	runManifest := &sandboxexecution.Manifest{}
	applyRunSandboxCredentialProxyMetadata(runManifest, runSandboxRequest{
		ExecutionID:         "run-exec-01",
		Security:            security,
		NetworkProxySession: networkProxySession,
	})
	assertPlanOnlyCredentialDeliveryStatus(t, "run", runManifest.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)

	autoManifest := &sandboxexecution.Manifest{}
	applyAutoSandboxCredentialProxyMetadata(autoManifest, autoSandboxRequest{
		ExecutionID:         "auto-exec-01",
		Security:            security,
		NetworkProxySession: networkProxySession,
	})
	assertPlanOnlyCredentialDeliveryStatus(t, "auto", autoManifest.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)

	factoryMetadata := &factory.SandboxMetadata{Name: "sandbox", Provider: "worker", Status: "running"}
	applyFactorySandboxCredentialProxyMetadata(factoryMetadata, factorySandboxExecutorRequest{
		Security: security,
	}, factory.RunRecord{RunID: "factory-run-01"}, networkProxySession)
	assertPlanOnlyCredentialDeliveryStatus(t, "factory", factoryMetadata.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)
}

func TestCredentialDeliveryProjectionRepresentsLegacyAuthSyncAsRequestedOnly(t *testing.T) {
	status := sandboxManifestCredentialDeliveryStatus(sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-legacy",
			Source: sandbox.SandboxCredentialProxySourceRun,
			Status: sandbox.SandboxCredentialProxyStatusPlanned,
		},
	}, sandbox.SecurityEvaluationRequest{CompatibilityAuthSync: true})

	assertPlanOnlyCredentialDeliveryStatus(t, "legacy", status, sandbox.SandboxSecretModeLegacyAuthSync)
}

func TestCredentialProxyIntentKeepsLegacyAuthSyncRequestedOnly(t *testing.T) {
	intent := sandboxManifestCredentialProxySecretDeliveryIntent(sandbox.SecurityEvaluationRequest{
		RequestedSecretModes:  []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:     []string{sandbox.SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync: true,
	})
	if intent == nil {
		t.Fatal("intent = nil")
	}
	if containsString(intent.ActiveModes, sandbox.SandboxSecretModeLegacyAuthSync) {
		t.Fatalf("active modes = %#v, legacy auth sync must not be active credential proxy delivery", intent.ActiveModes)
	}
	if !containsString(intent.RequestedModes, sandbox.SandboxSecretModeLegacyAuthSync) {
		t.Fatalf("requested modes = %#v, want legacy auth sync represented as requested compatibility mode", intent.RequestedModes)
	}

	projection := sandbox.ProjectSandboxCredentialProxyMetadata(sandbox.SandboxCredentialProxyProjectionRequest{
		PlanID:                "credential-plan-01",
		SessionID:             "credential-session-01",
		BindingIDPrefix:       "credential-binding",
		Source:                sandbox.SandboxCredentialProxySourceRun,
		SecretBrokerSessionID: "secret-broker-session-01",
		SecretIDs:             []string{"env:GITHUB_TOKEN"},
		SecretDeliveryIntent:  intent,
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     "network-proxy-session-01",
			Source: sandbox.SandboxNetworkPolicyDecisionSourceRun,
		},
		RequestCategory:     sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory: sandbox.SandboxNetworkPolicyDestinationUnknown,
	})
	var legacy *sandbox.SandboxCredentialProxyBindingMetadata
	for i := range projection.Bindings {
		if projection.Bindings[i].DeliveryMode == sandbox.SandboxCredentialProxyDeliveryModeLegacyAuthSync {
			legacy = &projection.Bindings[i]
			break
		}
	}
	if legacy == nil {
		t.Fatalf("legacy auth sync binding missing from projection: %#v", projection.Bindings)
	}
	if legacy.Status != sandbox.SandboxCredentialProxyStatusPlanned || legacy.Outcome != sandbox.SandboxCredentialProxyBindingOutcomePlanned {
		t.Fatalf("legacy binding = %#v, want planned/requested compatibility metadata only", *legacy)
	}
}

func assertPlanOnlyCredentialDeliveryStatus(t *testing.T, label string, status *sandbox.SandboxCredentialDeliveryStatusMetadata, wantMode string) {
	t.Helper()
	if status == nil {
		t.Fatalf("%s credentialDelivery = nil", label)
	}
	if status.ID == "" || status.PlanID == "" {
		t.Fatalf("%s credentialDelivery identifiers = %#v", label, status)
	}
	if status.Status != "planned" {
		t.Fatalf("%s credentialDelivery status = %q, want planned", label, status.Status)
	}
	if len(status.RequestedModes) != 1 || status.RequestedModes[0] != wantMode {
		t.Fatalf("%s credentialDelivery requested modes = %#v, want %q", label, status.RequestedModes, wantMode)
	}
	if len(status.ActiveModes) != 0 {
		t.Fatalf("%s credentialDelivery active modes = %#v, want omitted for plan-only projection", label, status.ActiveModes)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
