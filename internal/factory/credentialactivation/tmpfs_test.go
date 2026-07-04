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

func TestFileTmpfsSimulationActivationUsesBrokerSessionWithoutFilesystemMutation(t *testing.T) {
	rawRoot := t.TempDir()
	rawSecretPath := filepath.Join(rawRoot, "phase51", "PHASE51_SECRET_VALUE")
	rawSocketPath := filepath.Join(rawRoot, "phase51-agent.sock")
	broker := phase51TmpfsBrokerSession(t)
	adapter := NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
		Enabled:               true,
		Broker:                broker,
		SecretBrokerSessionID: "broker-session-tmpfs",
	})
	request := phase51FileTmpfsActivationRequest()
	request.Bindings[0].ServiceID = rawSecretPath
	request.Bindings[0].NetworkProxySessionID = rawSocketPath

	activation := credentialdelivery.ActivateDelivery(request, adapter)

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active: %#v", activation.Status, activation)
	}
	if len(activation.ActiveModes) != 1 || activation.ActiveModes[0] != credentialdelivery.ModeFileTmpfs {
		t.Fatalf("active modes = %#v, want file_tmpfs only", activation.ActiveModes)
	}
	if len(activation.Bindings) != 3 {
		t.Fatalf("activation bindings = %#v, want three file_tmpfs bindings", activation.Bindings)
	}
	for _, binding := range activation.Bindings {
		if binding.Status != credentialdelivery.StatusActive || binding.ReasonCode != credentialdelivery.ReasonRequested {
			t.Fatalf("binding activation = %#v, want active/requested", binding)
		}
		if binding.ProofRef == "" {
			t.Fatalf("binding activation = %#v, want synthetic proof ref", binding)
		}
	}
	if len(activation.ProofRefs) != 3 {
		t.Fatalf("proof refs = %#v, want one per file_tmpfs binding", activation.ProofRefs)
	}
	assertFileTmpfsSimulationProofsSafe(t, activation)

	calls := adapter.Calls()
	if len(calls) != 1 {
		t.Fatalf("adapter calls = %d, want 1", len(calls))
	}
	if calls[0].Bindings[0].ServiceID != "" || calls[0].Bindings[0].NetworkProxySessionID != "" {
		t.Fatalf("adapter observed unsafe path metadata: %#v", calls[0].Bindings[0])
	}

	session, ok := broker.SessionMetadata("broker-session-tmpfs")
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want broker session")
	}
	for _, secret := range session.Secrets {
		resolved, ok := broker.LookupSecretByID(session.ID, secret.ID)
		if !ok {
			t.Fatalf("LookupSecretByID(%q) ok = false, want in-memory value", secret.ID)
		}
		if resolved.Value == "" {
			t.Fatalf("resolved value for %s is empty, want seeded in-memory secret", secret.Name)
		}
	}
	assertTmpfsPathAbsent(t, rawSecretPath)
	assertTmpfsPathAbsent(t, rawSocketPath)
	assertTmpfsDirectoryEmpty(t, rawRoot)
	assertFileTmpfsValuesAbsentFromJSON(t, activation, calls, session)
}

func TestFileTmpfsSimulationDisabledByDefaultReturnsDisabledMetadata(t *testing.T) {
	adapter := NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
		Broker:                phase51TmpfsBrokerSession(t),
		SecretBrokerSessionID: "broker-session-tmpfs",
	})

	activation := credentialdelivery.ActivateDelivery(phase51FileTmpfsActivationRequest(), adapter)

	if activation.Status != credentialdelivery.StatusDisabled || activation.ReasonCode != credentialdelivery.ReasonDisabled {
		t.Fatalf("activation = %#v, want disabled metadata", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	for _, binding := range activation.Bindings {
		if binding.Status != credentialdelivery.StatusDisabled || binding.ReasonCode != credentialdelivery.ReasonDisabled {
			t.Fatalf("binding activation = %#v, want disabled", binding)
		}
	}
	assertFileTmpfsValuesAbsentFromJSON(t, activation)
}

func TestFileTmpfsSimulationUnsupportedModesAreSkipped(t *testing.T) {
	broker := phase51TmpfsBrokerSession(t)
	request := phase51FileTmpfsActivationRequest()
	request.Plan.RequestedModes = []credentialdelivery.Mode{credentialdelivery.ModeFileTmpfs, credentialdelivery.ModeEnv}
	request.Bindings = []credentialdelivery.Binding{
		request.Bindings[0],
		{
			ID:           "binding-env-unsupported",
			SecretRef:    "env:PHASE51_TMPFS_TWO",
			DeliveryMode: credentialdelivery.ModeEnv,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
	}

	activation := credentialdelivery.ActivateDelivery(request, NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
		Enabled:               true,
		Broker:                broker,
		SecretBrokerSessionID: "broker-session-tmpfs",
	}))

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active for supported file_tmpfs binding", activation.Status)
	}
	if len(activation.ActiveModes) != 1 || activation.ActiveModes[0] != credentialdelivery.ModeFileTmpfs {
		t.Fatalf("active modes = %#v, want file_tmpfs only", activation.ActiveModes)
	}
	assertFileTmpfsBindingStatus(t, activation, "binding-tmpfs-one", credentialdelivery.ModeFileTmpfs, credentialdelivery.StatusActive, credentialdelivery.ReasonRequested)
	assertFileTmpfsBindingStatus(t, activation, "binding-env-unsupported", credentialdelivery.ModeEnv, credentialdelivery.StatusSkipped, credentialdelivery.ReasonUnsupportedMode)
	assertFileTmpfsWarning(t, activation, credentialdelivery.WarningUnsupportedMode, credentialdelivery.ReasonUnsupportedMode, credentialdelivery.ModeEnv)
	assertFileTmpfsValuesAbsentFromJSON(t, activation)
}

func TestFileTmpfsSimulationCredentialActivationRedactionOmitsSecretsFromDurableSurfaces(t *testing.T) {
	rawRoot := t.TempDir()
	rawSecretPath := filepath.Join(rawRoot, "PHASE51_SECRET_VALUE")
	broker := phase51TmpfsBrokerSession(t)
	request := phase51FileTmpfsActivationRequest()
	request.Bindings[1].SecretRef = "env:PHASE51_TMPFS_MISSING"

	unsafeActivation := credentialdelivery.ActivateDelivery(request, NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
		Enabled:               true,
		Broker:                broker,
		SecretBrokerSessionID: "/tmp/phase51-ghp_phase51_secret.sock",
	}))
	if unsafeActivation.Status != credentialdelivery.StatusFailed ||
		unsafeActivation.ReasonCode != credentialdelivery.ReasonActivationUnavailable {
		t.Fatalf("unsafe session activation = %#v, want sanitized unavailable failure", unsafeActivation)
	}
	assertFileTmpfsValuesAbsentFromJSON(t, unsafeActivation)

	activation := credentialdelivery.ActivateDelivery(request, NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
		Enabled:               true,
		Broker:                broker,
		SecretBrokerSessionID: "broker-session-tmpfs",
	}))

	if activation.Status != credentialdelivery.StatusFailed {
		t.Fatalf("activation status = %q, want failed", activation.Status)
	}
	if activation.ReasonCode != credentialdelivery.ReasonMissingSecretReference {
		t.Fatalf("activation reason = %q, want missing_secret_reference", activation.ReasonCode)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("failed activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}

	session, ok := broker.SessionMetadata("broker-session-tmpfs")
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want broker session")
	}
	status := phase51TmpfsSandboxCredentialDeliveryStatus(activation)
	runtimeCredentialDelivery := phase51RuntimeCredentialDeliveryMetadata(status)
	now := time.Date(2026, 7, 4, 2, 55, 0, 0, time.UTC)
	manifest := sandboxexecution.Manifest{
		ID:                 "execution-tmpfs",
		Purpose:            sandboxexecution.PurposeRun,
		Status:             sandboxexecution.StatusFailed,
		StartedAt:          now,
		CredentialDelivery: &status,
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeFileTmpfs},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-tmpfs",
			Image:          "image-tmpfs",
			WorkerID:       "worker-tmpfs",
		},
	}
	run := halfactory.RunRecord{
		RunID:        "run-tmpfs-activation",
		Status:       halfactory.RunStatusFailed,
		ExecutorMode: halfactory.ExecutorModeSandbox,
		Source:       halfactory.SourceMetadata{Kind: halfactory.SourceKindPRD},
		RepoPath:     "repo-tmpfs",
		BranchName:   "branch-tmpfs",
		BaseBranch:   "base-tmpfs",
		CurrentStep:  halfactory.RunDurationStepFinalization,
		CreatedAt:    now,
		UpdatedAt:    now,
		Sandbox: &halfactory.SandboxMetadata{
			Name:               "sandbox-tmpfs",
			Provider:           "worker",
			Status:             "failed",
			CredentialDelivery: &status,
			Runtime: &halfactory.SandboxRuntimeMetadata{
				Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
				RuntimeID:      "runtime-tmpfs",
				Image:          "image-tmpfs",
				WorkerID:       "worker-tmpfs",
			},
		},
	}
	timeline := []halfactory.EventRecord{{
		Sequence:  1,
		RunID:     run.RunID,
		EventType: halfactory.EventTypeStepEnded,
		Timestamp: now.Add(time.Second),
		Message:   "file_tmpfs credential delivery simulation failed closed",
		Metadata: map[string]any{
			"credentialDelivery": status,
			"activation":         activation,
			"broker":             session,
		},
	}}
	logs := []halfactory.LogChunk{{
		RunID:   run.RunID,
		Stream:  halfactory.LogStreamSummary,
		Source:  halfactory.LogSourceEngine,
		Text:    "file_tmpfs credential delivery simulation failed closed",
		Summary: "file_tmpfs simulation failed closed",
	}}
	sandboxState := sandbox.SandboxState{
		ID:       "sandbox-state-tmpfs",
		Name:     "sandbox-tmpfs",
		Provider: "worker",
		Status:   "failed",
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-tmpfs",
			Image:          "image-tmpfs",
			WorkerID:       "worker-tmpfs",
		},
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeFileTmpfs},
			},
		},
	}
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
			Capability:     sandbox.SandboxSecurityCapabilitySecretFileTmpfs,
			ReasonCode:     sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
		}},
	}

	assertTmpfsPathAbsent(t, rawSecretPath)
	assertFileTmpfsValuesAbsentFromJSON(t,
		activation,
		session,
		manifest,
		run,
		timeline,
		logs,
		sandboxState,
		runtimeMetadata,
		workerControls,
		commandJSON,
		diagnostics,
		unsafeActivation,
		activation.Warnings,
	)
	assertFileTmpfsValuesAbsentFromText(t, "file_tmpfs simulation failed closed: "+string(activation.ReasonCode))
}

func phase51FileTmpfsActivationRequest() credentialdelivery.ActivationRequest {
	bindings := []credentialdelivery.Binding{
		{
			ID:           "binding-tmpfs-one",
			SecretRef:    "env:PHASE51_TMPFS_ONE",
			DeliveryMode: credentialdelivery.ModeFileTmpfs,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
		{
			ID:           "binding-tmpfs-two",
			SecretRef:    "env:PHASE51_TMPFS_TWO",
			DeliveryMode: credentialdelivery.ModeFileTmpfs,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
		{
			ID:           "binding-tmpfs-three",
			SecretRef:    "env:PHASE51_TMPFS_THREE",
			DeliveryMode: credentialdelivery.ModeFileTmpfs,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
	}
	return credentialdelivery.ActivationRequest{
		ActivationID: "delivery-activation-tmpfs",
		Plan: credentialdelivery.Plan{
			ID:             "delivery-plan-tmpfs",
			RequestID:      "delivery-request-tmpfs",
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeFileTmpfs},
			Status:         credentialdelivery.StatusPlanned,
		},
		Bindings: bindings,
	}
}

func phase51TmpfsBrokerSession(t *testing.T) *halfactory.InMemorySecretBroker {
	t.Helper()

	broker := halfactory.NewInMemorySecretBroker()
	_, err := broker.CreateSession(halfactory.SecretBrokerSessionRequest{
		ID: "broker-session-tmpfs",
		ResolvedSecrets: []halfactory.ResolvedRunSecret{
			{Name: "PHASE51_TMPFS_ONE", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "ghp_phase51_secret"},
			{Name: "PHASE51_TMPFS_TWO", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "sk-phase51-secret"},
			{Name: "PHASE51_TMPFS_THREE", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "PHASE51_SECRET_VALUE"},
		},
		RequestedDeliveryModes: []string{halfactory.SecretBrokerDeliveryModeFileTmpfs},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	return broker
}

func phase51TmpfsSandboxCredentialDeliveryStatus(activation credentialdelivery.ActivationResult) sandbox.SandboxCredentialDeliveryStatusMetadata {
	status := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-delivery-tmpfs",
		RequestID:      "delivery-request-tmpfs",
		PlanID:         activation.PlanID,
		ActivationID:   activation.ID,
		RequestedModes: phase51ModeStrings(activation.RequestedModes),
		ActiveModes:    phase51ModeStrings(activation.ActiveModes),
		Status:         string(activation.Status),
		ReasonCode:     string(activation.ReasonCode),
		WarningCount:   len(activation.Warnings),
	})
	if status.ID == "" {
		panic("invalid phase51 tmpfs credential delivery status fixture")
	}
	return status
}

func assertFileTmpfsSimulationProofsSafe(t *testing.T, activation credentialdelivery.ActivationResult) {
	t.Helper()

	proofsByID := make(map[string]credentialdelivery.ActivationProofReference, len(activation.ProofRefs))
	for _, proof := range activation.ProofRefs {
		proofsByID[proof.ProofID] = proof
		if proof.DeliveryMode != credentialdelivery.ModeFileTmpfs {
			t.Fatalf("proof = %#v, want file_tmpfs mode", proof)
		}
		if !strings.Contains(proof.ProofID, "tmpfs") || !strings.Contains(proof.ProofID, "simulation") {
			t.Fatalf("proof ID = %q, want synthetic tmpfs simulation proof", proof.ProofID)
		}
		for _, forbidden := range []string{"/", "\\", ":", ".", "PHASE51", "TOKEN", "SECRET", "ghp_", "sk-"} {
			if strings.Contains(proof.ProofID, forbidden) {
				t.Fatalf("proof ID %q contains unsafe marker %q", proof.ProofID, forbidden)
			}
		}
	}
	for _, binding := range activation.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeFileTmpfs || binding.Status != credentialdelivery.StatusActive {
			continue
		}
		proof, ok := proofsByID[binding.ProofRef]
		if !ok {
			t.Fatalf("binding = %#v, want proof ref present in proofRefs", binding)
		}
		if proof.BindingID != binding.BindingID {
			t.Fatalf("proof = %#v, want binding ID %q", proof, binding.BindingID)
		}
	}
}

func assertFileTmpfsBindingStatus(t *testing.T, activation credentialdelivery.ActivationResult, bindingID string, mode credentialdelivery.Mode, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) {
	t.Helper()

	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID && binding.DeliveryMode == mode && binding.Status == status && binding.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q status %q reason %q", activation.Bindings, bindingID, mode, status, reason)
}

func assertFileTmpfsWarning(t *testing.T, activation credentialdelivery.ActivationResult, code credentialdelivery.WarningCode, reason credentialdelivery.ReasonCode, mode credentialdelivery.Mode) {
	t.Helper()

	for _, warning := range activation.Warnings {
		if warning.Code == code && warning.ReasonCode == reason && warning.Mode == mode {
			return
		}
	}
	t.Fatalf("activation warnings = %#v, want code %q reason %q mode %q", activation.Warnings, code, reason, mode)
}

func assertTmpfsPathAbsent(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("path %q exists, want tmpfs simulation to avoid filesystem mutation", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %q error = %v, want not-exist", path, err)
	}
}

func assertTmpfsDirectoryEmpty(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", path, err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory %q entries = %#v, want no tmpfs simulation files", path, entries)
	}
}

func assertFileTmpfsValuesAbsentFromJSON(t *testing.T, values ...any) {
	t.Helper()

	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	assertFileTmpfsValuesAbsentFromText(t, string(data))
}

func assertFileTmpfsValuesAbsentFromText(t *testing.T, payload string) {
	t.Helper()

	for _, raw := range []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"/tmp/phase51-ghp_phase51_secret.sock",
		"phase51-agent.sock",
	} {
		if strings.Contains(payload, raw) {
			t.Fatalf("durable payload leaked raw phase51 value %q in %s", raw, payload)
		}
	}
}
