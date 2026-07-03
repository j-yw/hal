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
