package cmd

import (
	"testing"

	"github.com/jywlabs/hal/internal/credentialdelivery"
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

func TestCredentialDeliveryActivationProjectionAcrossRunAutoAndFactory(t *testing.T) {
	activation := credentialDeliveryProjectionHTTPProxyActivationResult(t, true)
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
		ExecutionID:                  "run-exec-active",
		Security:                     security,
		NetworkProxySession:          networkProxySession,
		CredentialDeliveryActivation: activation,
	})
	assertActiveCredentialDeliveryStatus(t, "run", runManifest.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)

	autoManifest := &sandboxexecution.Manifest{}
	applyAutoSandboxCredentialProxyMetadata(autoManifest, autoSandboxRequest{
		ExecutionID:                  "auto-exec-active",
		Security:                     security,
		NetworkProxySession:          networkProxySession,
		CredentialDeliveryActivation: activation,
	})
	assertActiveCredentialDeliveryStatus(t, "auto", autoManifest.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)

	factoryMetadata := &factory.SandboxMetadata{Name: "sandbox", Provider: "worker", Status: "running"}
	applyFactorySandboxCredentialProxyMetadata(factoryMetadata, factorySandboxExecutorRequest{
		Security:                     security,
		CredentialDeliveryActivation: activation,
	}, factory.RunRecord{RunID: "factory-run-active"}, networkProxySession)
	assertActiveCredentialDeliveryStatus(t, "factory", factoryMetadata.CredentialDelivery, sandbox.SandboxSecretModeHTTPProxy)
}

func TestCredentialDeliveryHTTPProxyProjectionRequiresProvenActivationResult(t *testing.T) {
	activation := credentialDeliveryProjectionHTTPProxyActivationResult(t, false)
	if activation.Status == credentialdelivery.StatusActive || len(activation.ActiveModes) != 0 {
		t.Fatalf("fixture activation = %#v, want US-002 fail-closed non-active result", activation)
	}
	status := sandboxManifestCredentialDeliveryStatus(sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-http-proxy",
			Source: sandbox.SandboxCredentialProxySourceRun,
			Status: sandbox.SandboxCredentialProxyStatusReady,
		},
		Session: &sandbox.SandboxCredentialProxySessionMetadata{
			ID:     "credential-session-http-proxy",
			PlanID: "credential-plan-http-proxy",
			Source: sandbox.SandboxCredentialProxySourceRun,
			Status: sandbox.SandboxCredentialProxyStatusReady,
		},
	}, sandbox.SecurityEvaluationRequest{
		RequestedSecretModes: []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
	}, activation)

	if status == nil {
		t.Fatal("credentialDelivery = nil")
	}
	if status.Status == "active" {
		t.Fatalf("status = %#v, want non-active without proven HTTP proxy activation", status)
	}
	if len(status.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want omitted without proven HTTP proxy activation", status.ActiveModes)
	}
	if status.ActivationID == "" {
		t.Fatalf("activation id = %q, want persisted non-active activation result metadata", status.ActivationID)
	}
}

func TestCredentialDeliveryDefaultProjectionOmitsActivationFieldsWithoutActivationResult(t *testing.T) {
	runManifest := &sandboxexecution.Manifest{}
	applyRunSandboxCredentialProxyMetadata(runManifest, runSandboxRequest{ExecutionID: "run-default"})
	if runManifest.CredentialDelivery != nil {
		t.Fatalf("run credentialDelivery = %#v, want omitted for default metadata without activation result", runManifest.CredentialDelivery)
	}

	autoManifest := &sandboxexecution.Manifest{}
	applyAutoSandboxCredentialProxyMetadata(autoManifest, autoSandboxRequest{ExecutionID: "auto-default"})
	if autoManifest.CredentialDelivery != nil {
		t.Fatalf("auto credentialDelivery = %#v, want omitted for default metadata without activation result", autoManifest.CredentialDelivery)
	}

	factoryMetadata := &factory.SandboxMetadata{Name: "sandbox", Provider: "worker", Status: "running"}
	applyFactorySandboxCredentialProxyMetadata(factoryMetadata, factorySandboxExecutorRequest{}, factory.RunRecord{RunID: "factory-default"}, nil)
	if factoryMetadata.CredentialDelivery != nil {
		t.Fatalf("factory credentialDelivery = %#v, want omitted for default metadata without activation result", factoryMetadata.CredentialDelivery)
	}

	planOnlyStatus := sandboxManifestCredentialDeliveryStatus(sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-no-activation",
			Source: sandbox.SandboxCredentialProxySourceRun,
			Status: sandbox.SandboxCredentialProxyStatusReady,
		},
	}, sandbox.SecurityEvaluationRequest{
		RequestedSecretModes: []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
	}, credentialdelivery.ActivationResult{})
	if planOnlyStatus == nil {
		t.Fatal("plan-only credentialDelivery = nil")
	}
	if planOnlyStatus.ActivationID != "" {
		t.Fatalf("activation id = %q, want omitted without activation result", planOnlyStatus.ActivationID)
	}
	if len(planOnlyStatus.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want omitted without activation result", planOnlyStatus.ActiveModes)
	}
}

func TestCredentialDeliveryProjectionRepresentsLegacyAuthSyncAsRequestedOnly(t *testing.T) {
	status := sandboxManifestCredentialDeliveryStatus(sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:     "credential-plan-legacy",
			Source: sandbox.SandboxCredentialProxySourceRun,
			Status: sandbox.SandboxCredentialProxyStatusPlanned,
		},
	}, sandbox.SecurityEvaluationRequest{CompatibilityAuthSync: true}, credentialdelivery.ActivationResult{})

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
	if status.ActivationID != "" {
		t.Fatalf("%s credentialDelivery activation id = %q, want omitted for plan-only projection", label, status.ActivationID)
	}
}

func assertActiveCredentialDeliveryStatus(t *testing.T, label string, status *sandbox.SandboxCredentialDeliveryStatusMetadata, wantMode string) {
	t.Helper()
	if status == nil {
		t.Fatalf("%s credentialDelivery = nil", label)
	}
	if status.ID == "" || status.PlanID == "" || status.ActivationID == "" {
		t.Fatalf("%s credentialDelivery identifiers = %#v", label, status)
	}
	if status.Status != "active" {
		t.Fatalf("%s credentialDelivery status = %q, want active", label, status.Status)
	}
	if len(status.RequestedModes) != 1 || status.RequestedModes[0] != wantMode {
		t.Fatalf("%s credentialDelivery requested modes = %#v, want %q", label, status.RequestedModes, wantMode)
	}
	if len(status.ActiveModes) != 1 || status.ActiveModes[0] != wantMode {
		t.Fatalf("%s credentialDelivery active modes = %#v, want %q", label, status.ActiveModes, wantMode)
	}
}

func credentialDeliveryProjectionHTTPProxyActivationResult(t *testing.T, proven bool) credentialdelivery.ActivationResult {
	t.Helper()
	binding := credentialdelivery.Binding{
		ID:                    "delivery-binding-http-proxy",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "env:GITHUB_TOKEN",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-source-control",
		DestinationCategory:   credentialdelivery.DestinationPublicInternet,
		DeliveryMode:          credentialdelivery.ModeHTTPProxy,
		Status:                credentialdelivery.StatusPlanned,
		ReasonCode:            credentialdelivery.ReasonRequested,
	}
	plan := credentialdelivery.Plan{
		ID:                    "delivery-plan-http-proxy",
		RequestID:             "delivery-request-http-proxy",
		NetworkProxySessionID: "network-proxy-session-01",
		HTTPProxyProof: &credentialdelivery.HTTPProxyProof{
			BindingID:                binding.ID,
			SecretID:                 binding.SecretRef,
			SecretBrokerSessionID:    "secret-broker-session-01",
			CredentialProxyPlanID:    "credential-proxy-plan-01",
			CredentialProxySessionID: "credential-proxy-session-01",
			CredentialProxyBindingID: "credential-proxy-binding-01",
			NetworkEnforcement: &sandbox.SandboxNetworkEnforcementProofMetadata{
				NetworkProxySessionID:    "network-proxy-session-01",
				PolicySnapshotID:         "policy-snapshot-01",
				NetworkEnforcementPlanID: "network-enforcement-plan-01",
				ProxyLifecycleStatus:     "active",
				ProxyLifecycleReasonCode: "active",
				ResultOutcome:            "success",
				ResultEnforcementMode:    sandbox.SandboxNetworkEnforcementModeProxyFirewall,
				ResultSupported:          true,
			},
		},
		RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Status:         credentialdelivery.StatusPlanned,
	}
	if !proven {
		plan.HTTPProxyProof.NetworkEnforcement.ResultSupported = false
	}

	result := credentialdelivery.ActivateDelivery(credentialdelivery.ActivationRequest{
		ActivationID: "delivery-activation-http-proxy",
		Plan:         plan,
		Bindings:     []credentialdelivery.Binding{binding},
	}, credentialDeliveryProjectionActivationAdapter{})
	if proven && result.Status != credentialdelivery.StatusActive {
		t.Fatalf("fixture activation = %#v, want active", result)
	}
	return result
}

type credentialDeliveryProjectionActivationAdapter struct{}

func (credentialDeliveryProjectionActivationAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	result := credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    request.Plan.RequestedModes,
		Status:         credentialdelivery.StatusActive,
	}
	for _, binding := range request.Bindings {
		result.Bindings = append(result.Bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
		})
	}
	return result, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
