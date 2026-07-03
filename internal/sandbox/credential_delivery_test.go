package sandbox

import "testing"

func TestProjectSandboxCredentialDeliveryStatusMetadataIsPlanOnly(t *testing.T) {
	status := ProjectSandboxCredentialDeliveryStatusMetadata(SandboxCredentialDeliveryStatusProjectionRequest{
		Plan: &SandboxCredentialProxyPlanMetadata{
			ID:     " credential-plan-01 ",
			Status: SandboxCredentialProxyStatusActive,
		},
		RequestedModes: []string{SandboxSecretModeHTTPProxy, SandboxSecretModeEnv},
	})
	if status == nil {
		t.Fatal("status = nil")
	}
	if status.ID != "credential-plan-01" || status.PlanID != "credential-plan-01" {
		t.Fatalf("identifiers = %#v, want credential-plan-01", status)
	}
	if status.Status != "ready" {
		t.Fatalf("status = %q, want ready for active credential proxy metadata", status.Status)
	}
	if len(status.RequestedModes) != 2 || status.RequestedModes[0] != SandboxSecretModeHTTPProxy || status.RequestedModes[1] != SandboxSecretModeEnv {
		t.Fatalf("requested modes = %#v", status.RequestedModes)
	}
	if len(status.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want omitted for plan-only projection", status.ActiveModes)
	}
}

func TestProjectSandboxCredentialDeliveryStatusMetadataTreatsLegacyAsRequestedOnly(t *testing.T) {
	status := ProjectSandboxCredentialDeliveryStatusMetadata(SandboxCredentialDeliveryStatusProjectionRequest{
		Plan: &SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-legacy",
			Status: SandboxCredentialProxyStatusPlanned,
		},
		CompatibilityAuthSync: true,
	})
	if status == nil {
		t.Fatal("status = nil")
	}
	if len(status.RequestedModes) != 1 || status.RequestedModes[0] != SandboxSecretModeLegacyAuthSync {
		t.Fatalf("requested modes = %#v, want legacy auth sync", status.RequestedModes)
	}
	if len(status.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want legacy auth sync omitted from active modes", status.ActiveModes)
	}
}

func TestProjectSandboxCredentialDeliveryStatusMetadataFallsBackToBindingModes(t *testing.T) {
	status := ProjectSandboxCredentialDeliveryStatusMetadata(SandboxCredentialDeliveryStatusProjectionRequest{
		Plan: &SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-bindings",
			Status: SandboxCredentialProxyStatusPlanned,
		},
		Bindings: []SandboxCredentialProxyBindingMetadata{{
			ID:           "credential-binding-01",
			PlanID:       "credential-plan-bindings",
			SecretID:     "env:GITHUB_TOKEN",
			DeliveryMode: SandboxCredentialProxyDeliveryModeSSHAgent,
			Status:       SandboxCredentialProxyStatusPlanned,
		}},
	})
	if status == nil {
		t.Fatal("status = nil")
	}
	if len(status.RequestedModes) != 1 || status.RequestedModes[0] != SandboxSecretModeSSHAgent {
		t.Fatalf("requested modes = %#v, want ssh agent from bindings", status.RequestedModes)
	}
}
