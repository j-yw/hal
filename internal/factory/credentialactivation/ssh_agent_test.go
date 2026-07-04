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

func TestSSHAgentHandoffActivationUsesExistingProofMetadataWithoutAgentAccess(t *testing.T) {
	rawRoot := t.TempDir()
	rawSocketPath := filepath.Join(rawRoot, "phase51-agent.sock")
	t.Setenv("SSH_AUTH_SOCK", rawSocketPath)
	request := phase51SSHAgentActivationRequest()
	request.Bindings[0].ServiceID = rawSocketPath
	request.Bindings[0].NetworkProxySessionID = rawSocketPath
	adapter := NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true})

	activation := credentialdelivery.ActivateDelivery(request, adapter)

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active: %#v", activation.Status, activation)
	}
	if len(activation.ActiveModes) != 1 || activation.ActiveModes[0] != credentialdelivery.ModeSSHAgent {
		t.Fatalf("active modes = %#v, want ssh_agent only", activation.ActiveModes)
	}
	if len(activation.Bindings) != 1 {
		t.Fatalf("activation bindings = %#v, want one ssh_agent binding", activation.Bindings)
	}
	assertSSHAgentBindingStatus(t, activation, "binding-ssh-one", credentialdelivery.ModeSSHAgent, credentialdelivery.StatusActive, credentialdelivery.ReasonRequested)
	assertSSHAgentHandoffProofsSafe(t, activation)

	calls := adapter.Calls()
	if len(calls) != 1 {
		t.Fatalf("adapter calls = %d, want 1", len(calls))
	}
	if calls[0].Bindings[0].ServiceID != "" || calls[0].Bindings[0].NetworkProxySessionID != "" {
		t.Fatalf("adapter observed unsafe socket metadata: %#v", calls[0].Bindings[0])
	}
	assertSSHAgentPathAbsent(t, rawSocketPath)
	assertSSHAgentDirectoryEmpty(t, rawRoot)
	assertSSHAgentValuesAbsentFromJSON(t, activation, calls)
}

func TestSSHAgentHandoffActivationDisabledByDefaultReturnsDisabledMetadata(t *testing.T) {
	adapter := NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{})

	activation := credentialdelivery.ActivateDelivery(phase51SSHAgentActivationRequest(), adapter)

	if activation.Status != credentialdelivery.StatusDisabled || activation.ReasonCode != credentialdelivery.ReasonDisabled {
		t.Fatalf("activation = %#v, want disabled metadata", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertSSHAgentBindingStatus(t, activation, "binding-ssh-one", credentialdelivery.ModeSSHAgent, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled)
	assertSSHAgentValuesAbsentFromJSON(t, activation)
}

func TestSSHAgentHandoffActivationMissingProofFailsClosed(t *testing.T) {
	request := phase51SSHAgentActivationRequest()
	request.Plan.SSHAgentProof = nil

	activation := credentialdelivery.ActivateDelivery(request, NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true}))

	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonMissingActivationProof {
		t.Fatalf("activation = %#v, want sanitized missing-proof skip", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertSSHAgentBindingStatus(t, activation, "binding-ssh-one", credentialdelivery.ModeSSHAgent, credentialdelivery.StatusSkipped, credentialdelivery.ReasonMissingActivationProof)
	assertSSHAgentWarning(t, activation, credentialdelivery.WarningActivationSkipped, credentialdelivery.ReasonMissingActivationProof, credentialdelivery.ModeSSHAgent)
	assertSSHAgentValuesAbsentFromJSON(t, activation)
}

func TestSSHAgentHandoffActivationUnsupportedCapabilityMetadataIsSkipped(t *testing.T) {
	request := phase51SSHAgentActivationRequest()
	request.Plan.SSHAgentProof.CapabilityReady = false

	activation := credentialdelivery.ActivateDelivery(request, NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true}))

	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonUnsupportedCapability {
		t.Fatalf("activation = %#v, want sanitized unsupported-capability skip", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	assertSSHAgentBindingStatus(t, activation, "binding-ssh-one", credentialdelivery.ModeSSHAgent, credentialdelivery.StatusSkipped, credentialdelivery.ReasonUnsupportedCapability)
	assertSSHAgentWarning(t, activation, credentialdelivery.WarningActivationSkipped, credentialdelivery.ReasonUnsupportedCapability, credentialdelivery.ModeSSHAgent)
	assertSSHAgentValuesAbsentFromJSON(t, activation)
}

func TestCredentialActivationRedactionOmitsSSHAgentHandoffSecretsFromDurableSurfaces(t *testing.T) {
	rawRoot := t.TempDir()
	rawSocketPath := filepath.Join(rawRoot, "phase51-agent.sock")
	rawKeyMaterial := "-----BEGIN OPENSSH PRIVATE KEY----- ghp_phase51_secret"
	rawCommandOutput := "ssh-add -l sk-phase51-secret PHASE51_SECRET_VALUE"
	request := phase51SSHAgentActivationRequest()
	request.Bindings[0].ServiceID = rawSocketPath
	request.Bindings[0].ServiceLabels = []string{"ssh-agent", rawKeyMaterial}
	request.Bindings[0].DomainLabels = []string{"source-control", rawCommandOutput}
	request.Plan.SSHAgentProof.HandoffID = rawSocketPath
	request.Plan.SSHAgentProof.CapabilityID = "https://agent.example.invalid/capability?token=sk-phase51-secret"

	activation := credentialdelivery.ActivateDelivery(request, NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true}))
	if activation.Status != credentialdelivery.StatusSkipped ||
		activation.ReasonCode != credentialdelivery.ReasonMissingActivationProof {
		t.Fatalf("activation = %#v, want missing-proof skip after unsafe proof metadata is removed", activation)
	}

	status := phase51SSHAgentSandboxCredentialDeliveryStatus(activation)
	now := time.Date(2026, 7, 4, 2, 55, 0, 0, time.UTC)
	runtimeCredentialDelivery := phase51RuntimeCredentialDeliveryMetadata(status)
	manifest := sandboxexecution.Manifest{
		ID:                 "execution-ssh-agent",
		Purpose:            sandboxexecution.PurposeRun,
		Status:             sandboxexecution.StatusFailed,
		StartedAt:          now,
		CredentialDelivery: &status,
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeSSHAgent},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-ssh-agent",
			Image:          "image-ssh-agent",
			WorkerID:       "worker-ssh-agent",
		},
	}
	run := halfactory.RunRecord{
		RunID:        "run-ssh-agent-activation",
		Status:       halfactory.RunStatusFailed,
		ExecutorMode: halfactory.ExecutorModeSandbox,
		Source:       halfactory.SourceMetadata{Kind: halfactory.SourceKindPRD},
		RepoPath:     "repo-ssh-agent",
		BranchName:   "branch-ssh-agent",
		BaseBranch:   "base-ssh-agent",
		CurrentStep:  halfactory.RunDurationStepFinalization,
		CreatedAt:    now,
		UpdatedAt:    now,
		Sandbox: &halfactory.SandboxMetadata{
			Name:               "sandbox-ssh-agent",
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
		Message:   "ssh_agent credential delivery handoff skipped",
		Metadata: map[string]any{
			"credentialDelivery": status,
			"activation":         activation,
		},
	}}
	logs := []halfactory.LogChunk{{
		RunID:   run.RunID,
		Stream:  halfactory.LogStreamSummary,
		Source:  halfactory.LogSourceEngine,
		Text:    "ssh_agent credential delivery handoff skipped",
		Summary: "ssh_agent handoff skipped",
	}}
	runtimeMetadata := sandboxruntime.RuntimeMetadata{CredentialDelivery: runtimeCredentialDelivery}
	workerControls := sandboxworker.SecurityControls{CredentialDelivery: runtimeCredentialDelivery}
	diagnostics := sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:          sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
		HighestSeverity: sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning,
		Items: []sandbox.SandboxSecurityCapabilityReadinessDiagnosticItem{{
			Code:           sandbox.SandboxSecurityCapabilityDiagnosticCodeBlocked,
			Severity:       sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning,
			Classification: sandbox.SandboxSecurityCapabilityDiagnosticClassificationBlocked,
			Family:         sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:     sandbox.SandboxSecurityCapabilitySecretSSHAgent,
			ReasonCode:     sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
		}},
	}

	assertSSHAgentPathAbsent(t, rawSocketPath)
	assertSSHAgentValuesAbsentFromJSON(t,
		activation,
		status,
		manifest,
		run,
		timeline,
		logs,
		runtimeMetadata,
		workerControls,
		diagnostics,
		activation.Warnings,
	)
	assertSSHAgentValuesAbsentFromText(t, "ssh_agent handoff skipped: "+string(activation.ReasonCode))
}

func phase51SSHAgentActivationRequest() credentialdelivery.ActivationRequest {
	binding := credentialdelivery.Binding{
		ID:           "binding-ssh-one",
		SecretRef:    "env:PHASE51_SSH_ONE",
		DeliveryMode: credentialdelivery.ModeSSHAgent,
		Status:       credentialdelivery.StatusPlanned,
		ReasonCode:   credentialdelivery.ReasonRequested,
	}
	return credentialdelivery.ActivationRequest{
		ActivationID: "delivery-activation-ssh-agent",
		Plan: credentialdelivery.Plan{
			ID:             "delivery-plan-ssh-agent",
			RequestID:      "delivery-request-ssh-agent",
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeSSHAgent},
			ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeSSHAgent},
			SSHAgentProof: &credentialdelivery.SSHAgentProof{
				BindingID:             binding.ID,
				SecretID:              binding.SecretRef,
				SecretBrokerSessionID: "secret-broker-session-ssh-agent",
				DeliveryPlanID:        "delivery-plan-proof-ssh-agent",
				DeliverySessionID:     "delivery-session-proof-ssh-agent",
				DeliveryBindingID:     "delivery-binding-proof-ssh-agent",
				HandoffID:             "ssh-agent-handoff-01",
				HandoffStatus:         credentialdelivery.StatusReady,
				HandoffReasonCode:     credentialdelivery.ReasonRequested,
				CapabilityID:          "ssh-agent-capability-01",
				CapabilityMode:        credentialdelivery.ModeSSHAgent,
				CapabilityStatus:      credentialdelivery.StatusReady,
				CapabilityReady:       true,
			},
			Status: credentialdelivery.StatusPlanned,
		},
		Bindings: []credentialdelivery.Binding{binding},
	}
}

func phase51SSHAgentSandboxCredentialDeliveryStatus(activation credentialdelivery.ActivationResult) sandbox.SandboxCredentialDeliveryStatusMetadata {
	status := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-delivery-ssh-agent",
		RequestID:      "delivery-request-ssh-agent",
		PlanID:         activation.PlanID,
		ActivationID:   activation.ID,
		RequestedModes: phase51ModeStrings(activation.RequestedModes),
		ActiveModes:    phase51ModeStrings(activation.ActiveModes),
		Status:         string(activation.Status),
		ReasonCode:     string(activation.ReasonCode),
		WarningCount:   len(activation.Warnings),
	})
	if status.ID == "" {
		panic("invalid phase51 ssh_agent credential delivery status fixture")
	}
	return status
}

func assertSSHAgentHandoffProofsSafe(t *testing.T, activation credentialdelivery.ActivationResult) {
	t.Helper()

	if len(activation.ProofRefs) != 1 {
		t.Fatalf("proof refs = %#v, want one ssh_agent proof", activation.ProofRefs)
	}
	proof := activation.ProofRefs[0]
	if proof.DeliveryMode != credentialdelivery.ModeSSHAgent || proof.BindingID != "binding-ssh-one" {
		t.Fatalf("proof = %#v, want ssh_agent binding proof", proof)
	}
	for _, binding := range activation.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeSSHAgent || binding.Status != credentialdelivery.StatusActive {
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

func assertSSHAgentBindingStatus(t *testing.T, activation credentialdelivery.ActivationResult, bindingID string, mode credentialdelivery.Mode, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) {
	t.Helper()

	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID && binding.DeliveryMode == mode && binding.Status == status && binding.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q status %q reason %q", activation.Bindings, bindingID, mode, status, reason)
}

func assertSSHAgentWarning(t *testing.T, activation credentialdelivery.ActivationResult, code credentialdelivery.WarningCode, reason credentialdelivery.ReasonCode, mode credentialdelivery.Mode) {
	t.Helper()

	for _, warning := range activation.Warnings {
		if warning.Code == code && warning.ReasonCode == reason && warning.Mode == mode {
			return
		}
	}
	t.Fatalf("activation warnings = %#v, want code %q reason %q mode %q", activation.Warnings, code, reason, mode)
}

func assertSSHAgentPathAbsent(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("path %q exists, want ssh_agent handoff to avoid socket creation", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %q error = %v, want not-exist", path, err)
	}
}

func assertSSHAgentDirectoryEmpty(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", path, err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory %q entries = %#v, want no ssh_agent handoff files", path, entries)
	}
}

func assertSSHAgentValuesAbsentFromJSON(t *testing.T, values ...any) {
	t.Helper()

	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	assertSSHAgentValuesAbsentFromText(t, string(data))
}

func assertSSHAgentValuesAbsentFromText(t *testing.T, payload string) {
	t.Helper()

	for _, raw := range []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"phase51-agent.sock",
		"OPENSSH PRIVATE KEY",
		"ssh-add -l",
		"agent.example.invalid",
	} {
		if strings.Contains(payload, raw) {
			t.Fatalf("durable payload leaked raw phase51 ssh_agent value %q in %s", raw, payload)
		}
	}
}
