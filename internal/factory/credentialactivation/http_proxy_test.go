package credentialactivation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	halfactory "github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestHTTPProxyHandoffActivationUsesExistingCredentialAndNetworkProxyProofMetadata(t *testing.T) {
	rawRoot := t.TempDir()
	rawSocketPath := filepath.Join(rawRoot, "phase51-http-proxy.sock")
	request := phase51HTTPProxyActivationRequest()
	request.Bindings[0].ServiceLabels = append(request.Bindings[0].ServiceLabels, rawSocketPath)
	adapter := NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true})

	activation := credentialdelivery.ActivateDelivery(request, adapter)

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active: %#v", activation.Status, activation)
	}
	if len(activation.ActiveModes) != 1 || activation.ActiveModes[0] != credentialdelivery.ModeHTTPProxy {
		t.Fatalf("active modes = %#v, want http_proxy only", activation.ActiveModes)
	}
	assertHTTPProxyBindingStatus(t, activation, "binding-http-proxy-one", credentialdelivery.ModeHTTPProxy, credentialdelivery.StatusActive, credentialdelivery.ReasonRequested)
	assertHTTPProxyHandoffProofsSafe(t, activation)

	calls := adapter.Calls()
	if len(calls) != 1 {
		t.Fatalf("adapter calls = %d, want 1", len(calls))
	}
	if len(calls[0].Bindings[0].ServiceLabels) != 0 {
		t.Fatalf("adapter observed unsafe service metadata: %#v", calls[0].Bindings[0])
	}
	assertHTTPProxyPathAbsent(t, rawSocketPath)
	assertHTTPProxyDirectoryEmpty(t, rawRoot)
	assertHTTPProxyValuesAbsentFromJSON(t, activation, calls)
}

func TestHTTPProxyHandoffActivationDisabledByDefaultReturnsDisabledMetadata(t *testing.T) {
	adapter := NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{})

	activation := credentialdelivery.ActivateDelivery(phase51HTTPProxyActivationRequest(), adapter)

	if activation.Status != credentialdelivery.StatusDisabled || activation.ReasonCode != credentialdelivery.ReasonDisabled {
		t.Fatalf("activation = %#v, want disabled metadata", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertHTTPProxyBindingStatus(t, activation, "binding-http-proxy-one", credentialdelivery.ModeHTTPProxy, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled)
	assertHTTPProxyValuesAbsentFromJSON(t, activation)
}

func TestHTTPProxyHandoffActivationMissingProofFailsClosed(t *testing.T) {
	request := phase51HTTPProxyActivationRequest()
	request.Plan.HTTPProxyProof = nil
	request.Plan.NetworkProxySessionID = ""
	request.Plan.ActiveModes = nil

	activation := credentialdelivery.ActivateDelivery(request, NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true}))

	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonMissingActivationProof {
		t.Fatalf("activation = %#v, want sanitized missing-proof skip", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertHTTPProxyBindingStatus(t, activation, "binding-http-proxy-one", credentialdelivery.ModeHTTPProxy, credentialdelivery.StatusSkipped, credentialdelivery.ReasonMissingActivationProof)
	assertHTTPProxyWarning(t, activation, credentialdelivery.WarningActivationSkipped, credentialdelivery.ReasonMissingActivationProof, credentialdelivery.ModeHTTPProxy)
	assertHTTPProxyValuesAbsentFromJSON(t, activation)
}

func TestHTTPProxyHandoffActivationUnsupportedCapabilityMetadataIsSkipped(t *testing.T) {
	request := phase51HTTPProxyActivationRequest()
	request.Plan.HTTPProxyProof.NetworkEnforcement.ResultSupported = false

	activation := credentialdelivery.ActivateDelivery(request, NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true}))

	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonUnsupportedCapability {
		t.Fatalf("activation = %#v, want sanitized unsupported-capability skip", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertHTTPProxyBindingStatus(t, activation, "binding-http-proxy-one", credentialdelivery.ModeHTTPProxy, credentialdelivery.StatusSkipped, credentialdelivery.ReasonUnsupportedCapability)
	assertHTTPProxyWarning(t, activation, credentialdelivery.WarningActivationSkipped, credentialdelivery.ReasonUnsupportedCapability, credentialdelivery.ModeHTTPProxy)
	assertHTTPProxyValuesAbsentFromJSON(t, activation)
}

func TestCredentialActivationRedactionOmitsHTTPProxyHandoffSecretsFromDurableSurfaces(t *testing.T) {
	rawRoot := t.TempDir()
	rawSocketPath := filepath.Join(rawRoot, "phase51-http-proxy.sock")
	rawURL := "https://proxy.example.invalid:8443/session?token=sk-phase51-secret"
	rawHeader := "Proxy-Authorization: Bearer ghp_phase51_secret"
	request := phase51HTTPProxyActivationRequest()
	request.Bindings[0].ServiceLabels = []string{"http-proxy", rawHeader}
	request.Bindings[0].DomainLabels = []string{"source-control", "PHASE51_SECRET_VALUE"}
	request.Bindings[0].NetworkProxySessionID = rawSocketPath
	request.Plan.HTTPProxyProof.CredentialProxySessionID = rawURL

	activation := credentialdelivery.ActivateDelivery(request, NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true}))
	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonMissingActivationProof {
		t.Fatalf("activation = %#v, want missing-proof skip after unsafe proof metadata is removed", activation)
	}

	status := phase51HTTPProxySandboxCredentialDeliveryStatus(activation)
	now := time.Date(2026, 7, 4, 2, 55, 0, 0, time.UTC)
	runtimeCredentialDelivery := phase51RuntimeCredentialDeliveryMetadata(status)
	manifest := sandboxexecution.Manifest{
		ID:                 "execution-http-proxy",
		Purpose:            sandboxexecution.PurposeRun,
		Status:             sandboxexecution.StatusFailed,
		StartedAt:          now,
		CredentialDelivery: &status,
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-http-proxy",
			Image:          "image-http-proxy",
			WorkerID:       "worker-http-proxy",
		},
	}
	run := halfactory.RunRecord{
		RunID:        "run-http-proxy-activation",
		Status:       halfactory.RunStatusFailed,
		ExecutorMode: halfactory.ExecutorModeSandbox,
		Source:       halfactory.SourceMetadata{Kind: halfactory.SourceKindPRD},
		RepoPath:     "repo-http-proxy",
		BranchName:   "branch-http-proxy",
		BaseBranch:   "base-http-proxy",
		CurrentStep:  halfactory.RunDurationStepFinalization,
		CreatedAt:    now,
		UpdatedAt:    now,
		Sandbox: &halfactory.SandboxMetadata{
			Name:               "sandbox-http-proxy",
			Provider:           "worker",
			Status:             "failed",
			CredentialDelivery: &status,
		},
	}
	timeline := []halfactory.EventRecord{{
		Sequence:  1,
		RunID:     run.RunID,
		EventType: halfactory.EventTypeStepEnded,
		Timestamp: now.Add(time.Second),
		Message:   "http_proxy credential delivery handoff skipped",
		Metadata: map[string]any{
			"credentialDelivery": status,
			"activation":         activation,
		},
	}}
	logs := []halfactory.LogChunk{{
		RunID:   run.RunID,
		Stream:  halfactory.LogStreamSummary,
		Source:  halfactory.LogSourceEngine,
		Text:    "http_proxy credential delivery handoff skipped",
		Summary: "http_proxy handoff skipped",
	}}
	runtimeMetadata := sandboxruntime.RuntimeMetadata{CredentialDelivery: runtimeCredentialDelivery}
	workerControls := sandboxworker.SecurityControls{CredentialDelivery: runtimeCredentialDelivery}
	commandJSON := struct {
		Activation credentialdelivery.ActivationResult `json:"activation"`
		Status     sandbox.SandboxCredentialDeliveryStatusMetadata
	}{
		Activation: activation,
		Status:     status,
	}
	diagnostics := sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:          sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
		HighestSeverity: sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning,
		Items: []sandbox.SandboxSecurityCapabilityReadinessDiagnosticItem{{
			Code:           sandbox.SandboxSecurityCapabilityDiagnosticCodeBlocked,
			Severity:       sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning,
			Classification: sandbox.SandboxSecurityCapabilityDiagnosticClassificationBlocked,
			Family:         sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:     sandbox.SandboxSecurityCapabilitySecretHTTPProxy,
			ReasonCode:     sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
		}},
	}

	assertHTTPProxyPathAbsent(t, rawSocketPath)
	assertHTTPProxyValuesAbsentFromJSON(t,
		activation,
		status,
		manifest,
		run,
		timeline,
		logs,
		runtimeMetadata,
		workerControls,
		commandJSON,
		diagnostics,
		activation.Warnings,
	)
	assertHTTPProxyValuesAbsentFromText(t, "http_proxy handoff skipped: "+string(activation.ReasonCode))
}

func phase51HTTPProxyActivationRequest() credentialdelivery.ActivationRequest {
	binding := credentialdelivery.Binding{
		ID:                    "binding-http-proxy-one",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "env:PHASE51_HTTP_PROXY_ONE",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-http-proxy-one",
		DeliveryMode:          credentialdelivery.ModeHTTPProxy,
		Status:                credentialdelivery.StatusPlanned,
		ReasonCode:            credentialdelivery.ReasonRequested,
	}
	return credentialdelivery.ActivationRequest{
		ActivationID: "delivery-activation-http-proxy",
		Plan: credentialdelivery.Plan{
			ID:                    "delivery-plan-http-proxy",
			RequestID:             "delivery-request-http-proxy",
			NetworkProxySessionID: "network-proxy-session-01",
			RequestedModes:        []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
			ActiveModes:           []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
			HTTPProxyProof: &credentialdelivery.HTTPProxyProof{
				BindingID:                binding.ID,
				SecretID:                 binding.SecretRef,
				SecretBrokerSessionID:    "secret-broker-session-http-proxy",
				CredentialProxyPlanID:    "credential-proxy-plan-http-proxy",
				CredentialProxySessionID: "credential-proxy-session-http-proxy",
				CredentialProxyBindingID: "credential-proxy-binding-http-proxy",
				NetworkEnforcement: &sandbox.SandboxNetworkEnforcementProofMetadata{
					NetworkProxySessionID:    "network-proxy-session-01",
					PolicySnapshotID:         "policy-snapshot-01",
					NetworkEnforcementPlanID: "network-enforcement-plan-http-proxy",
					ProxyLifecycleStatus:     "active",
					ProxyLifecycleReasonCode: "active",
					ResultOutcome:            "success",
					ResultEnforcementMode:    sandbox.SandboxNetworkEnforcementModeProxyFirewall,
					ResultSupported:          true,
				},
			},
			Status: credentialdelivery.StatusPlanned,
		},
		Bindings: []credentialdelivery.Binding{binding},
	}
}

func phase51HTTPProxySandboxCredentialDeliveryStatus(activation credentialdelivery.ActivationResult) sandbox.SandboxCredentialDeliveryStatusMetadata {
	status := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-delivery-http-proxy",
		RequestID:      "delivery-request-http-proxy",
		PlanID:         activation.PlanID,
		ActivationID:   activation.ID,
		RequestedModes: phase51ModeStrings(activation.RequestedModes),
		ActiveModes:    phase51ModeStrings(activation.ActiveModes),
		Status:         string(activation.Status),
		ReasonCode:     string(activation.ReasonCode),
		WarningCount:   len(activation.Warnings),
	})
	if status.ID == "" {
		panic("invalid phase51 http_proxy credential delivery status fixture")
	}
	return status
}

func assertHTTPProxyHandoffProofsSafe(t *testing.T, activation credentialdelivery.ActivationResult) {
	t.Helper()

	if len(activation.ProofRefs) != 1 {
		t.Fatalf("proof refs = %#v, want one http_proxy proof", activation.ProofRefs)
	}
	proof := activation.ProofRefs[0]
	if proof.DeliveryMode != credentialdelivery.ModeHTTPProxy || proof.BindingID != "binding-http-proxy-one" {
		t.Fatalf("proof = %#v, want http_proxy binding proof", proof)
	}
	for _, binding := range activation.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeHTTPProxy || binding.Status != credentialdelivery.StatusActive {
			continue
		}
		if binding.ProofRef != proof.ProofID {
			t.Fatalf("binding = %#v, want proof ref %q", binding, proof.ProofID)
		}
	}
	for _, forbidden := range []string{"/", "\\", ":", ".", "PHASE51", "TOKEN", "SECRET", "ghp_", "sk-"} {
		if strings.Contains(proof.ProofID, forbidden) {
			t.Fatalf("proof ID %q contains unsafe marker %q", proof.ProofID, forbidden)
		}
	}
}

func assertHTTPProxyBindingStatus(t *testing.T, activation credentialdelivery.ActivationResult, bindingID string, mode credentialdelivery.Mode, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) {
	t.Helper()

	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID && binding.DeliveryMode == mode && binding.Status == status && binding.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q status %q reason %q", activation.Bindings, bindingID, mode, status, reason)
}

func assertHTTPProxyWarning(t *testing.T, activation credentialdelivery.ActivationResult, code credentialdelivery.WarningCode, reason credentialdelivery.ReasonCode, mode credentialdelivery.Mode) {
	t.Helper()

	for _, warning := range activation.Warnings {
		if warning.Code == code && warning.ReasonCode == reason && warning.Mode == mode {
			return
		}
	}
	t.Fatalf("activation warnings = %#v, want code %q reason %q mode %q", activation.Warnings, code, reason, mode)
}

func assertHTTPProxyPathAbsent(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("path %q exists, want http_proxy handoff to avoid listener/socket creation", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %q error = %v, want not-exist", path, err)
	}
}

func assertHTTPProxyDirectoryEmpty(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", path, err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory %q entries = %#v, want no http_proxy handoff files", path, entries)
	}
}

func assertHTTPProxyValuesAbsentFromJSON(t *testing.T, values ...any) {
	t.Helper()

	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	assertHTTPProxyValuesAbsentFromText(t, string(data))
}

func assertHTTPProxyValuesAbsentFromText(t *testing.T, payload string) {
	t.Helper()

	for _, raw := range []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"phase51-http-proxy.sock",
		"proxy.example.invalid",
		"Proxy-Authorization",
		"Bearer",
	} {
		if strings.Contains(payload, raw) {
			t.Fatalf("durable payload leaked raw phase51 http_proxy value %q in %s", raw, payload)
		}
	}
}
