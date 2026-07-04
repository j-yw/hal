package credentialactivation

import (
	"encoding/json"
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

func TestEnvResolverActivationResolvesEnvReferencesIntoBrokerSession(t *testing.T) {
	broker := halfactory.NewInMemorySecretBroker()
	env := phase51EnvFixture()
	calls := map[string]int{}
	adapter := NewEnvAdapter(EnvOptions{
		Enabled:           true,
		Broker:            broker,
		Environment:       countingEnvLookup(env, calls),
		SecretBrokerID:    "broker-session-env",
		RequiredSecretIDs: []string{"env:PHASE51_ENV_ONE", "env:PHASE51_ENV_TWO", "env:PHASE51_ENV_THREE"},
	})

	activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), adapter)

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active: %#v", activation.Status, activation)
	}
	if len(activation.ActiveModes) != 1 || activation.ActiveModes[0] != credentialdelivery.ModeEnv {
		t.Fatalf("active modes = %#v, want env only", activation.ActiveModes)
	}
	if len(activation.Bindings) != 3 {
		t.Fatalf("activation bindings = %#v, want three env bindings", activation.Bindings)
	}
	for _, binding := range activation.Bindings {
		if binding.Status != credentialdelivery.StatusActive || binding.ReasonCode != credentialdelivery.ReasonRequested {
			t.Fatalf("binding activation = %#v, want active/requested", binding)
		}
		if binding.ProofRef == "" {
			t.Fatalf("binding activation = %#v, want safe proof ref", binding)
		}
	}
	if len(activation.ProofRefs) != 3 {
		t.Fatalf("proof refs = %#v, want one per env binding", activation.ProofRefs)
	}
	for name := range env {
		if calls[name] != 1 {
			t.Fatalf("env lookup %s calls = %d, want 1", name, calls[name])
		}
	}

	session, ok := broker.SessionMetadata("broker-session-env")
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want active broker session")
	}
	if session.ID != "broker-session-env" || len(session.Secrets) != 3 {
		t.Fatalf("session metadata = %#v, want safe metadata for three env secrets", session)
	}
	if session.DeliveryModes == nil ||
		!stringSliceContains(session.DeliveryModes.RequestedModes, halfactory.SecretBrokerDeliveryModeEnv) ||
		!stringSliceContains(session.DeliveryModes.ActiveModes, halfactory.SecretBrokerDeliveryModeEnv) {
		t.Fatalf("session delivery modes = %#v, want env requested and active", session.DeliveryModes)
	}
	for _, secret := range session.Secrets {
		resolved, ok := broker.LookupSecretByID(session.ID, secret.ID)
		if !ok {
			t.Fatalf("LookupSecretByID(%q) ok = false, want raw in-memory value", secret.ID)
		}
		if resolved.Value != env[secret.Name] {
			t.Fatalf("resolved value for %s = %q, want injected env value", secret.Name, resolved.Value)
		}
	}
	assertPhase51ValuesAbsentFromJSON(t, activation, session)
}

func TestBrokerSessionActivationDisabledByDefaultDoesNotReadEnvironment(t *testing.T) {
	broker := halfactory.NewInMemorySecretBroker()
	called := false
	adapter := NewEnvAdapter(EnvOptions{
		Broker:      broker,
		Environment: func(string) (string, bool) { called = true; return "ghp_phase51_secret", true },
	})

	activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), adapter)

	if called {
		t.Fatal("environment lookup was called without explicit activation opt-in")
	}
	if activation.Status != credentialdelivery.StatusDisabled || activation.ReasonCode != credentialdelivery.ReasonDisabled {
		t.Fatalf("activation = %#v, want disabled fake metadata", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	for _, binding := range activation.Bindings {
		if binding.Status != credentialdelivery.StatusDisabled || binding.ReasonCode != credentialdelivery.ReasonDisabled {
			t.Fatalf("binding activation = %#v, want disabled", binding)
		}
	}
	if _, ok := broker.SessionMetadata("broker-session-env"); ok {
		t.Fatal("broker session exists without explicit activation opt-in")
	}
	assertPhase51ValuesAbsentFromJSON(t, activation)
}

func TestEnvResolverActivationUnsupportedReferencesFailClosedWithoutLookup(t *testing.T) {
	broker := halfactory.NewInMemorySecretBroker()
	called := false
	request := phase51EnvActivationRequest()
	request.Bindings[0].SecretRef = "file:PHASE51_ENV_ONE"
	request.Bindings = request.Bindings[:1]

	activation := credentialdelivery.ActivateDelivery(request, NewEnvAdapter(EnvOptions{
		Enabled:        true,
		Broker:         broker,
		Environment:    func(string) (string, bool) { called = true; return "ghp_phase51_secret", true },
		SecretBrokerID: "broker-session-env",
	}))

	if called {
		t.Fatal("environment lookup was called for unsupported non-env reference")
	}
	if activation.Status != credentialdelivery.StatusFailed ||
		activation.ReasonCode != credentialdelivery.ReasonMissingSecretReference {
		t.Fatalf("activation = %#v, want sanitized missing-reference failure", activation)
	}
	if len(activation.ActiveModes) != 0 || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation active/proof metadata = %#v/%#v, want none", activation.ActiveModes, activation.ProofRefs)
	}
	if _, ok := broker.SessionMetadata("broker-session-env"); ok {
		t.Fatal("broker session exists after unsupported reference failure")
	}
	assertPhase51ValuesAbsentFromJSON(t, activation, activation.Warnings)
}

func TestEnvResolverActivationUsesInjectedEnvironmentSourceOnly(t *testing.T) {
	for name, value := range phase51EnvFixture() {
		t.Setenv(name, value)
	}
	broker := halfactory.NewInMemorySecretBroker()

	activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), NewEnvAdapter(EnvOptions{
		Enabled: true,
		Broker:  broker,
		Environment: func(string) (string, bool) {
			return "", false
		},
		SecretBrokerID: "broker-session-env",
	}))

	if activation.Status != credentialdelivery.StatusFailed ||
		activation.ReasonCode != credentialdelivery.ReasonMissingSecretReference {
		t.Fatalf("activation = %#v, want failure from injected lookup instead of process env", activation)
	}
	if _, ok := broker.SessionMetadata("broker-session-env"); ok {
		t.Fatal("broker session exists after injected lookup denied every env value")
	}
	assertPhase51ValuesAbsentFromJSON(t, activation)
}

func TestBrokerSessionActivationCleanupDiscardsResolvedValues(t *testing.T) {
	broker := halfactory.NewInMemorySecretBroker()
	adapter := NewEnvAdapter(EnvOptions{
		Enabled:        true,
		Broker:         broker,
		Environment:    mapEnvLookup(phase51EnvFixture()),
		SecretBrokerID: "broker-session-env",
	})

	activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), adapter)
	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active", activation.Status)
	}
	session, ok := broker.SessionMetadata("broker-session-env")
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want active broker session")
	}
	for _, secret := range session.Secrets {
		if _, ok := broker.LookupSecretByID(session.ID, secret.ID); !ok {
			t.Fatalf("LookupSecretByID(%q) ok = false before cleanup, want true", secret.ID)
		}
	}

	if !broker.CloseSession(session.ID) {
		t.Fatal("CloseSession() = false, want true")
	}
	for _, secret := range session.Secrets {
		if resolved, ok := broker.LookupSecretByID(session.ID, secret.ID); ok {
			t.Fatalf("LookupSecretByID(%q) after cleanup = %#v, want discarded", secret.ID, resolved)
		}
	}
}

func TestCredentialActivationRedactionOmitsEnvValuesFromDurableSurfaces(t *testing.T) {
	broker := halfactory.NewInMemorySecretBroker()
	activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), NewEnvAdapter(EnvOptions{
		Enabled:        true,
		Broker:         broker,
		Environment:    mapEnvLookup(phase51EnvFixture()),
		SecretBrokerID: "broker-session-env",
	}))
	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active", activation.Status)
	}
	session, ok := broker.SessionMetadata("broker-session-env")
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want active broker session")
	}

	now := time.Date(2026, 7, 4, 2, 55, 0, 0, time.UTC)
	status := phase51SandboxCredentialDeliveryStatus(activation)
	runtimeCredentialDelivery := phase51RuntimeCredentialDeliveryMetadata(status)
	manifest := sandboxexecution.Manifest{
		ID:                 "execution-env",
		Purpose:            sandboxexecution.PurposeRun,
		Status:             sandboxexecution.StatusSucceeded,
		StartedAt:          now,
		CredentialDelivery: &status,
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-env",
			Image:          "image-env",
			WorkerID:       "worker-env",
		},
	}
	run := halfactory.RunRecord{
		RunID:        "run-env-activation",
		Status:       halfactory.RunStatusSucceeded,
		ExecutorMode: halfactory.ExecutorModeSandbox,
		Source:       halfactory.SourceMetadata{Kind: halfactory.SourceKindPRD},
		RepoPath:     "repo-env",
		BranchName:   "branch-env",
		BaseBranch:   "base-env",
		CurrentStep:  halfactory.RunDurationStepFinalization,
		CreatedAt:    now,
		UpdatedAt:    now,
		Sandbox: &halfactory.SandboxMetadata{
			Name:               "sandbox-env",
			Provider:           "worker",
			Status:             "running",
			CredentialDelivery: &status,
			Runtime: &halfactory.SandboxRuntimeMetadata{
				Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
				RuntimeID:      "runtime-env",
				Image:          "image-env",
				WorkerID:       "worker-env",
			},
			WorkerRouting: &sandbox.WorkerRoutingMetadata{
				SelectedWorkerHostID:   "worker-host-env",
				SelectedWorkerHostName: "worker-host-env",
				RuntimeDriverID:        "runtime-driver-env",
				IsolationLevel:         sandbox.SandboxIsolationLevelContainer,
				EndpointSummary:        "worker-endpoint",
			},
		},
	}
	timeline := []halfactory.EventRecord{{
		Sequence:  1,
		RunID:     run.RunID,
		EventType: halfactory.EventTypeStepEnded,
		Timestamp: now.Add(time.Second),
		Message:   "credential delivery activation active",
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
		Text:    "credential delivery activation active",
		Summary: "env delivery active",
	}}
	sandboxState := sandbox.SandboxState{
		ID:       "sandbox-state-env",
		Name:     "sandbox-env",
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-env",
			Image:          "image-env",
			WorkerID:       "worker-env",
		},
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
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
		Status:          sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusReady,
		HighestSeverity: sandbox.SandboxSecurityCapabilityDiagnosticSeverityInfo,
		Items: []sandbox.SandboxSecurityCapabilityReadinessDiagnosticItem{{
			Code:           sandbox.SandboxSecurityCapabilityDiagnosticCodeReady,
			Severity:       sandbox.SandboxSecurityCapabilityDiagnosticSeverityInfo,
			Classification: sandbox.SandboxSecurityCapabilityDiagnosticClassificationReady,
			Family:         sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:     sandbox.SandboxSecurityCapabilitySecretEnv,
			ReasonCode:     sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
		}},
	}

	assertPhase51ValuesAbsentFromJSON(t,
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
		activation.Warnings,
	)
}

func phase51EnvActivationRequest() credentialdelivery.ActivationRequest {
	bindings := []credentialdelivery.Binding{
		{
			ID:           "binding-env-one",
			SecretRef:    "env:PHASE51_ENV_ONE",
			DeliveryMode: credentialdelivery.ModeEnv,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
		{
			ID:           "binding-env-two",
			SecretRef:    "env:PHASE51_ENV_TWO",
			DeliveryMode: credentialdelivery.ModeEnv,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
		{
			ID:           "binding-env-three",
			SecretRef:    "env:PHASE51_ENV_THREE",
			DeliveryMode: credentialdelivery.ModeEnv,
			Status:       credentialdelivery.StatusPlanned,
			ReasonCode:   credentialdelivery.ReasonRequested,
		},
	}
	return credentialdelivery.ActivationRequest{
		ActivationID: "delivery-activation-env",
		Plan: credentialdelivery.Plan{
			ID:             "delivery-plan-env",
			RequestID:      "delivery-request-env",
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeEnv},
			Status:         credentialdelivery.StatusPlanned,
		},
		Bindings: bindings,
	}
}

func phase51EnvFixture() map[string]string {
	return map[string]string{
		"PHASE51_ENV_ONE":   "ghp_phase51_secret",
		"PHASE51_ENV_TWO":   "sk-phase51-secret",
		"PHASE51_ENV_THREE": "PHASE51_SECRET_VALUE",
	}
}

func mapEnvLookup(values map[string]string) halfactory.RunSecretLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func countingEnvLookup(values map[string]string, calls map[string]int) halfactory.RunSecretLookup {
	return func(name string) (string, bool) {
		calls[name]++
		value, ok := values[name]
		return value, ok
	}
}

func phase51SandboxCredentialDeliveryStatus(activation credentialdelivery.ActivationResult) sandbox.SandboxCredentialDeliveryStatusMetadata {
	status := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-delivery-env",
		RequestID:      "delivery-request-env",
		PlanID:         activation.PlanID,
		ActivationID:   activation.ID,
		RequestedModes: phase51ModeStrings(activation.RequestedModes),
		ActiveModes:    phase51ModeStrings(activation.ActiveModes),
		Status:         string(activation.Status),
		ReasonCode:     string(activation.ReasonCode),
		WarningCount:   len(activation.Warnings),
	})
	if status.ID == "" {
		panic("invalid phase51 credential delivery status fixture")
	}
	return status
}

func phase51RuntimeCredentialDeliveryMetadata(status sandbox.SandboxCredentialDeliveryStatusMetadata) *sandboxruntime.RuntimeCredentialDeliveryMetadata {
	return sandboxruntime.SanitizeRuntimeCredentialDeliveryMetadata(&sandboxruntime.RuntimeCredentialDeliveryMetadata{
		ID:             status.ID,
		RequestID:      status.RequestID,
		PlanID:         status.PlanID,
		ActivationID:   status.ActivationID,
		RequestedModes: status.RequestedModes,
		ActiveModes:    status.ActiveModes,
		Status:         status.Status,
		ReasonCode:     status.ReasonCode,
		WarningCount:   status.WarningCount,
		ErrorCount:     status.ErrorCount,
	})
}

func phase51ModeStrings(modes []credentialdelivery.Mode) []string {
	if len(modes) == 0 {
		return nil
	}
	out := make([]string, 0, len(modes))
	for _, mode := range modes {
		out = append(out, string(mode))
	}
	return out
}

func assertPhase51ValuesAbsentFromJSON(t *testing.T, values ...any) {
	t.Helper()
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload := string(data)
	for _, raw := range []string{"ghp_phase51_secret", "sk-phase51-secret", "PHASE51_SECRET_VALUE"} {
		if strings.Contains(payload, raw) {
			t.Fatalf("durable payload leaked raw phase51 value %q in %s", raw, payload)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
