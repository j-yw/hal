package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

func TestRunSandboxCredentialActivationManifestProjection(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	activation := phase51CredentialActivationSkippedResult()
	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID:                  "run-credential-activation-manifest",
		ProjectDir:                   "/repo",
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun),
		CredentialDeliveryActivation: activation,
	}, sandboxexecution.StatusSucceeded, time.Date(2026, 7, 4, 3, 0, 0, 0, time.UTC), nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-credential-activation-manifest")
	assertPhase51CredentialActivationStatus(t, "run manifest", manifest.CredentialDelivery, credentialdelivery.StatusSkipped, credentialdelivery.ReasonActivationUnavailable, 1, 0)
	assertPhase51CredentialActivationPayloadRedacted(t, "run manifest", manifest)
}

func TestAutoSandboxCredentialActivationManifestProjection(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	activation := phase51CredentialActivationFailedResult()
	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID:                  "auto-credential-activation-manifest",
		ProjectDir:                   "/repo",
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto),
		CredentialDeliveryActivation: activation,
	}, sandboxexecution.StatusFailed, time.Date(2026, 7, 4, 3, 5, 0, 0, time.UTC), nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-credential-activation-manifest")
	assertPhase51CredentialActivationStatus(t, "auto manifest", manifest.CredentialDelivery, credentialdelivery.StatusFailed, credentialdelivery.ReasonActivationUnavailable, 1, 1)
	assertPhase51CredentialActivationPayloadRedacted(t, "auto manifest", manifest)
}

func TestRunSandboxCredentialActivationCommandJSONProjection(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID:                  "run-credential-activation-json",
		ProjectDir:                   "/repo",
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun),
		CredentialDeliveryActivation: phase51CredentialActivationSkippedResult(),
	}, sandboxexecution.StatusSucceeded, time.Date(2026, 7, 4, 3, 10, 0, 0, time.UTC), nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	remoteJSON := []byte(`{"contractVersion":1,"ok":true,"iterations":1,"complete":true,"summary":"remote run"}` + "\n")
	var out bytes.Buffer
	if err := outputSandboxSyncOutAugmentedJSON(&out, remoteJSON, store, "run-credential-activation-json"); err != nil {
		t.Fatalf("outputSandboxSyncOutAugmentedJSON() error = %v", err)
	}
	status := decodePhase51CredentialActivationCommandJSON(t, "run command JSON", out.Bytes())
	assertPhase51CredentialActivationStatus(t, "run command JSON", status, credentialdelivery.StatusSkipped, credentialdelivery.ReasonActivationUnavailable, 1, 0)
	assertPhase51CredentialActivationPayloadRedacted(t, "run command JSON", out.String())
}

func TestAutoSandboxCredentialActivationCommandJSONProjection(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID:                  "auto-credential-activation-json",
		ProjectDir:                   "/repo",
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto),
		CredentialDeliveryActivation: phase51CredentialActivationFailedResult(),
	}, sandboxexecution.StatusFailed, time.Date(2026, 7, 4, 3, 15, 0, 0, time.UTC), nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	remoteJSON := []byte(autoSandboxRemoteSuccessJSON("remote auto") + "\n")
	var out bytes.Buffer
	if err := outputSandboxSyncOutAugmentedJSON(&out, remoteJSON, store, "auto-credential-activation-json"); err != nil {
		t.Fatalf("outputSandboxSyncOutAugmentedJSON() error = %v", err)
	}
	status := decodePhase51CredentialActivationCommandJSON(t, "auto command JSON", out.Bytes())
	assertPhase51CredentialActivationStatus(t, "auto command JSON", status, credentialdelivery.StatusFailed, credentialdelivery.ReasonActivationUnavailable, 1, 1)
	assertPhase51CredentialActivationPayloadRedacted(t, "auto command JSON", out.String())
}

func TestRunSandboxCredentialActivationDefaultOmission(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	startedAt := time.Date(2026, 7, 4, 3, 20, 0, 0, time.UTC)
	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID: "run-credential-activation-default",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusSucceeded, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest(default) error = %v", err)
	}
	assertPhase51CredentialActivationManifestOmitted(t, store, "run-credential-activation-default")
	assertPhase51CredentialActivationCommandJSONOmitted(t, store, "run-credential-activation-default", []byte(`{"contractVersion":1,"ok":true,"summary":"default run"}`+"\n"))

	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID:         "run-credential-activation-plan-only",
		ProjectDir:          "/repo",
		Security:            phase51CredentialActivationSecurity(),
		NetworkProxySession: phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun),
	}, sandboxexecution.StatusSucceeded, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest(plan-only) error = %v", err)
	}
	planOnly := mustLoadSandboxExecutionManifest(t, store, "run-credential-activation-plan-only")
	if planOnly.CredentialDelivery == nil {
		t.Fatal("plan-only run credentialDelivery = nil, want existing plan metadata")
	}
	if planOnly.CredentialDelivery.ActivationID != "" {
		t.Fatalf("plan-only run activation id = %q, want omitted", planOnly.CredentialDelivery.ActivationID)
	}
	assertPhase51CredentialActivationCommandJSONOmitted(t, store, "run-credential-activation-plan-only", []byte(`{"contractVersion":1,"ok":true,"summary":"plan run"}`+"\n"))
}

func TestAutoSandboxCredentialActivationDefaultOmission(t *testing.T) {
	store := sandboxexecution.NewStore(t.TempDir())
	startedAt := time.Date(2026, 7, 4, 3, 25, 0, 0, time.UTC)
	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-credential-activation-default",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusSucceeded, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest(default) error = %v", err)
	}
	assertPhase51CredentialActivationManifestOmitted(t, store, "auto-credential-activation-default")
	assertPhase51CredentialActivationCommandJSONOmitted(t, store, "auto-credential-activation-default", []byte(autoSandboxRemoteSuccessJSON("default auto")+"\n"))

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID:         "auto-credential-activation-plan-only",
		ProjectDir:          "/repo",
		Security:            phase51CredentialActivationSecurity(),
		NetworkProxySession: phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto),
	}, sandboxexecution.StatusSucceeded, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest(plan-only) error = %v", err)
	}
	planOnly := mustLoadSandboxExecutionManifest(t, store, "auto-credential-activation-plan-only")
	if planOnly.CredentialDelivery == nil {
		t.Fatal("plan-only auto credentialDelivery = nil, want existing plan metadata")
	}
	if planOnly.CredentialDelivery.ActivationID != "" {
		t.Fatalf("plan-only auto activation id = %q, want omitted", planOnly.CredentialDelivery.ActivationID)
	}
	assertPhase51CredentialActivationCommandJSONOmitted(t, store, "auto-credential-activation-plan-only", []byte(autoSandboxRemoteSuccessJSON("plan auto")+"\n"))
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

func phase51CredentialActivationSecurity() sandbox.SecurityEvaluationRequest {
	return sandbox.SecurityEvaluationRequest{
		RequestedSecretModes: []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveSecretModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
	}
}

func phase51CredentialActivationNetworkProxySession(source sandbox.SandboxNetworkPolicyDecisionSource) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:              "network-proxy-session-phase51",
		Source:          source,
		EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxy,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:     "policy-snapshot-phase51",
			Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
		},
	}
}

func phase51CredentialActivationSkippedResult() credentialdelivery.ActivationResult {
	return phase51CredentialActivationResult(credentialdelivery.StatusSkipped)
}

func phase51CredentialActivationFailedResult() credentialdelivery.ActivationResult {
	return phase51CredentialActivationResult(credentialdelivery.StatusFailed)
}

func phase51CredentialActivationResult(status credentialdelivery.Status) credentialdelivery.ActivationResult {
	return credentialdelivery.ActivationResult{
		ID:             "credential-activation-phase51",
		PlanID:         "run-auto-credential-plan-phase51",
		RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.Mode("ghp_phase51_secret")},
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.Mode("sk-phase51-secret")},
		Bindings: []credentialdelivery.BindingActivationResult{{
			BindingID:    "credential-binding-phase51",
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
			Status:       status,
			ReasonCode:   credentialdelivery.ReasonActivationUnavailable,
			ProofRef:     "credential-proof-phase51",
		}, {
			BindingID:    "ghp_phase51_secret",
			DeliveryMode: credentialdelivery.Mode("sk-phase51-secret"),
			Status:       credentialdelivery.Status("PHASE51_SECRET_VALUE"),
			ReasonCode:   credentialdelivery.ReasonCode("PHASE51_SECRET_VALUE"),
			ProofRef:     "sk-phase51-secret",
		}},
		ProofRefs: []credentialdelivery.ActivationProofReference{{
			ProofID:      "credential-proof-phase51",
			BindingID:    "credential-binding-phase51",
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
		}, {
			ProofID:      "sk-phase51-secret",
			BindingID:    "ghp_phase51_secret",
			DeliveryMode: credentialdelivery.Mode("PHASE51_SECRET_VALUE"),
		}},
		Status:     status,
		ReasonCode: credentialdelivery.ReasonActivationUnavailable,
		Warnings: []credentialdelivery.Warning{{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: credentialdelivery.ReasonActivationUnavailable,
			BindingID:  "credential-binding-phase51",
			Mode:       credentialdelivery.ModeHTTPProxy,
		}, {
			Code:       credentialdelivery.WarningCode("PHASE51_SECRET_VALUE"),
			ReasonCode: credentialdelivery.ReasonCode("sk-phase51-secret"),
			BindingID:  "ghp_phase51_secret",
			Mode:       credentialdelivery.Mode("PHASE51_SECRET_VALUE"),
		}},
	}
}

func assertPhase51CredentialActivationStatus(t *testing.T, label string, status *sandbox.SandboxCredentialDeliveryStatusMetadata, wantStatus credentialdelivery.Status, wantReason credentialdelivery.ReasonCode, wantWarnings, wantErrors int) {
	t.Helper()
	if status == nil {
		t.Fatalf("%s credentialDelivery = nil", label)
	}
	if status.ID == "" || status.PlanID == "" || status.ActivationID == "" {
		t.Fatalf("%s credentialDelivery identifiers = %#v", label, status)
	}
	if status.Status != string(wantStatus) {
		t.Fatalf("%s status = %q, want %q", label, status.Status, wantStatus)
	}
	if status.ReasonCode != string(wantReason) {
		t.Fatalf("%s reasonCode = %q, want %q", label, status.ReasonCode, wantReason)
	}
	if len(status.RequestedModes) != 1 || status.RequestedModes[0] != sandbox.SandboxSecretModeHTTPProxy {
		t.Fatalf("%s requested modes = %#v, want http_proxy only", label, status.RequestedModes)
	}
	if len(status.ActiveModes) != 0 {
		t.Fatalf("%s active modes = %#v, want omitted for non-active activation", label, status.ActiveModes)
	}
	if status.WarningCount != wantWarnings || status.ErrorCount != wantErrors {
		t.Fatalf("%s counts = warnings %d errors %d, want %d/%d", label, status.WarningCount, status.ErrorCount, wantWarnings, wantErrors)
	}
	assertPhase51CredentialActivationCompactStatus(t, label, status)
}

func decodePhase51CredentialActivationCommandJSON(t *testing.T, label string, payload []byte) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v\n%s", label, err, string(payload))
	}
	rawStatus, ok := fields["credentialDelivery"]
	if !ok {
		t.Fatalf("%s omitted credentialDelivery: %s", label, string(payload))
	}
	assertPhase51CredentialActivationNoFullResultFields(t, label, fields)
	var status sandbox.SandboxCredentialDeliveryStatusMetadata
	if err := json.Unmarshal(rawStatus, &status); err != nil {
		t.Fatalf("Unmarshal(%s credentialDelivery) error = %v\n%s", label, err, string(rawStatus))
	}
	return &status
}

func assertPhase51CredentialActivationManifestOmitted(t *testing.T, store sandboxexecution.Store, executionID string) {
	t.Helper()
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.CredentialDelivery != nil {
		t.Fatalf("%s credentialDelivery = %#v, want omitted without activation result", executionID, manifest.CredentialDelivery)
	}
	fields := sandboxManifestJSONFields(t, manifest)
	if _, ok := fields["credentialDelivery"]; ok {
		t.Fatalf("%s manifest JSON included credentialDelivery without activation result: %#v", executionID, fields)
	}
}

func assertPhase51CredentialActivationCommandJSONOmitted(t *testing.T, store sandboxexecution.Store, executionID string, remoteJSON []byte) {
	t.Helper()
	var out bytes.Buffer
	if err := outputSandboxSyncOutAugmentedJSON(&out, remoteJSON, store, executionID); err != nil {
		t.Fatalf("outputSandboxSyncOutAugmentedJSON(%s) error = %v", executionID, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatalf("Unmarshal(command JSON %s) error = %v\n%s", executionID, err, out.String())
	}
	if _, ok := fields["credentialDelivery"]; ok {
		t.Fatalf("%s command JSON included credentialDelivery without activation result: %s", executionID, out.String())
	}
	if strings.Contains(out.String(), "activationId") {
		t.Fatalf("%s command JSON included activationId without activation result: %s", executionID, out.String())
	}
}

func assertPhase51CredentialActivationPayloadRedacted(t *testing.T, label string, value any) {
	t.Helper()
	var payload string
	switch typed := value.(type) {
	case string:
		payload = typed
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			t.Fatalf("Marshal(%s) error = %v", label, err)
		}
		payload = string(data)
	}
	for _, forbidden := range []string{"ghp_phase51_secret", "sk-phase51-secret", "PHASE51_SECRET_VALUE"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked Phase 51 secret marker %q in %s", label, forbidden, payload)
		}
	}
}

func assertPhase51CredentialActivationNoFullResultFields(t *testing.T, label string, fields map[string]json.RawMessage) {
	t.Helper()
	for _, field := range []string{"credentialActivation", "activationResult", "bindings", "proofRefs", "warnings"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("%s included full activation field %q: %#v", label, field, fields)
		}
	}
}

func assertPhase51CredentialActivationCompactStatus(t *testing.T, label string, status *sandbox.SandboxCredentialDeliveryStatusMetadata) {
	t.Helper()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal(%s compact credentialDelivery) error = %v", label, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("Unmarshal(%s compact credentialDelivery) error = %v", label, err)
	}
	assertPhase51CredentialActivationNoFullResultFields(t, label+" credentialDelivery", fields)
}
