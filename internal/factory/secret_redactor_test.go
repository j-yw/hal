package factory

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/verify"
)

func TestRunSecretRedactorRedactsSingleValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactString("using token ghp_factory_secret_value_123 for checkout")
	want := "using token " + RunSecretRedactionPlaceholder + " for checkout"
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsMultipleValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
		{Name: "NPM_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "npm_factory_secret_value_456"},
	})

	got := redactor.RedactString("git=ghp_factory_secret_value_123 npm=npm_factory_secret_value_456")
	want := "git=" + RunSecretRedactionPlaceholder + " npm=" + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsRepeatedValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactString("ghp_factory_secret_value_123 then ghp_factory_secret_value_123")
	want := RunSecretRedactionPlaceholder + " then " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorIgnoresEmptyValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "EMPTY_TOKEN", Source: RunSecretSourceEnv, Required: false, Value: ""},
		{Name: "SPACE_TOKEN", Source: RunSecretSourceEnv, Required: false, Value: " \t "},
	})

	got := redactor.RedactString("factory output should remain unchanged")
	want := "factory output should remain unchanged"
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorPrefersLongestValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "SHORT", Source: RunSecretSourceEnv, Required: true, Value: "token"},
		{Name: "LONG", Source: RunSecretSourceEnv, Required: true, Value: "token-extra"},
	})

	got := redactor.RedactString("token-extra token")
	want := RunSecretRedactionPlaceholder + " " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsMultilineValueFragments(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "PRIVATE_KEY", Source: RunSecretSourceEnv, Required: true, Value: "-----BEGIN PRIVATE KEY-----\nline_one_secret_fragment\nline_two_secret_fragment\n-----END PRIVATE KEY-----"},
	})

	got := redactor.RedactString("key fragment line_one_secret_fragment\nnext line line_two_secret_fragment")
	want := "key fragment " + RunSecretRedactionPlaceholder + "\nnext line " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsURLEncodedValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "p@ss word"},
	})

	got := redactor.RedactString("remote=https://x:p%40ss%20word@github.com/example/repo.git query=token=p%40ss+word")
	want := "remote=https://x:" + RunSecretRedactionPlaceholder + "@github.com/example/repo.git query=token=" + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsPostRunPublishPullRequestURL(t *testing.T) {
	secretValue := "ghp_publish_url_secret_789"
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: secretValue},
	})

	record := RunRecord{
		RunID:  "run-post-run-publish-redaction",
		Status: RunStatusSucceeded,
		PostRun: &PostRunState{
			Publish: &PublishOutcome{
				Status:         RunStatusSucceeded,
				Policy:         PublishPolicyPR,
				BranchName:     "hal/redact-publish-url",
				PullRequestURL: "https://github.com/jywlabs/hal/pull/9?token=" + secretValue,
				Source:         "manual",
			},
		},
	}

	safe := redactor.RedactRunRecord(record)
	data, err := json.Marshal(safe)
	if err != nil {
		t.Fatalf("json.Marshal(redacted record) error: %v", err)
	}
	if strings.Contains(string(data), secretValue) {
		t.Fatalf("redacted postRun publish leaked secret value: %s", data)
	}
	if !strings.Contains(string(data), RunSecretRedactionPlaceholder) {
		t.Fatalf("redacted postRun publish missing placeholder: %s", data)
	}
}

func TestRunSecretRedactorRedactsArtifactSummaryTypedCollections(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactArtifactReference(ArtifactReference{
		Name: "artifact",
		Type: "json",
		Summary: map[string]any{
			"typed_maps": []map[string]string{
				{"token": "ghp_factory_secret_value_123"},
			},
			"map_to_slice": map[string][]string{
				"values": {"prefix ghp_factory_secret_value_123"},
			},
			"typed_any_maps": []map[string]any{
				{"nested": []string{"ghp_factory_secret_value_123"}},
			},
		},
	})

	typedMaps := got.Summary["typed_maps"].([]any)
	firstTypedMap := typedMaps[0].(map[string]any)
	if firstTypedMap["token"] != RunSecretRedactionPlaceholder {
		t.Fatalf("typed map value = %q, want redacted", firstTypedMap["token"])
	}

	mapToSlice := got.Summary["map_to_slice"].(map[string]any)
	values := mapToSlice["values"].([]any)
	if values[0] != "prefix "+RunSecretRedactionPlaceholder {
		t.Fatalf("map slice value = %q, want redacted", values[0])
	}

	typedAnyMaps := got.Summary["typed_any_maps"].([]any)
	firstAnyMap := typedAnyMaps[0].(map[string]any)
	nestedValues := firstAnyMap["nested"].([]any)
	if nestedValues[0] != RunSecretRedactionPlaceholder {
		t.Fatalf("nested value = %q, want redacted", nestedValues[0])
	}
}

func TestRunSecretRedactorSanitizesCredentialDeliveryEventMetadataWithoutConfiguredSecrets(t *testing.T) {
	redactor := NewRunSecretRedactor(nil)
	event := redactor.RedactEventRecord(EventRecord{
		RunID:     "run-credential-delivery-redaction",
		EventType: EventTypePolicyDecision,
		Metadata: map[string]any{
			"credentialDelivery": map[string]any{
				"id":             "credential-delivery-active",
				"requestId":      "https://credentials.example.invalid/request?token=raw",
				"planId":         "credential-plan-active",
				"activationId":   "credential-activation-active",
				"requestedModes": []string{sandbox.SandboxSecretModeHTTPProxy, "Authorization: Bearer raw-token"},
				"activeModes":    []string{sandbox.SandboxSecretModeHTTPProxy},
				"status":         "active",
				"reasonCode":     "requested",
			},
			"providerPayload": "Authorization: Bearer raw-token",
		},
	})

	status := requireRedactedCredentialDeliveryMetadata(t, event.Metadata)
	if status.Status == "active" {
		t.Fatalf("credentialDelivery status = %#v, want non-active without proof summary", status)
	}
	if len(status.ActiveModes) != 0 || len(status.ActiveProofs) != 0 {
		t.Fatalf("credentialDelivery active metadata = modes %#v proofs %#v, want omitted without proof", status.ActiveModes, status.ActiveProofs)
	}
	assertFactoryCredentialDeliveryRedactionAbsent(t, event, []string{
		"https://credentials.example.invalid",
		"raw-token",
		"Authorization",
	})
}

func TestRunSecretRedactorPreservesSanitizedCredentialDeliveryProofMetadata(t *testing.T) {
	redactor := NewRunSecretRedactor(nil)
	event := redactor.RedactEventRecord(EventRecord{
		RunID:     "run-credential-delivery-proof",
		EventType: EventTypePolicyDecision,
		Metadata: map[string]any{
			"credentialDelivery": sandbox.SandboxCredentialDeliveryStatusMetadata{
				ID:             "credential-delivery-active",
				PlanID:         "credential-plan-active",
				ActivationID:   "credential-activation-active",
				RequestedModes: []string{sandbox.SandboxSecretModeFileTmpfs, sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeFileTmpfs, sandbox.SandboxSecretModeEnv},
				ActiveProofs: []sandbox.SandboxCredentialDeliveryProofSummary{{
					ProofID:      "credential-proof-file-tmpfs",
					BindingID:    "credential-binding-file-tmpfs",
					DeliveryMode: sandbox.SandboxSecretModeFileTmpfs,
					Status:       "active",
					Source:       "simulation",
				}, {
					ProofID:      "/private/tmp/credential.sock",
					BindingID:    "credential-binding-unsafe",
					DeliveryMode: sandbox.SandboxSecretModeHTTPProxy,
					Status:       "active",
					Source:       "credential_proxy",
				}},
				Status:     "active",
				ReasonCode: "requested",
			},
		},
	})

	status := requireRedactedCredentialDeliveryMetadata(t, event.Metadata)
	if status.Status != "active" {
		t.Fatalf("credentialDelivery status = %#v, want active with proof summary", status)
	}
	if len(status.ActiveModes) != 1 || status.ActiveModes[0] != sandbox.SandboxSecretModeFileTmpfs {
		t.Fatalf("active modes = %#v, want file_tmpfs only", status.ActiveModes)
	}
	if len(status.ActiveProofs) != 1 {
		t.Fatalf("active proofs = %#v, want only safe proof", status.ActiveProofs)
	}
	if proof := status.ActiveProofs[0]; proof.ProofID != "credential-proof-file-tmpfs" || proof.BindingID != "credential-binding-file-tmpfs" || proof.DeliveryMode != sandbox.SandboxSecretModeFileTmpfs {
		t.Fatalf("active proof = %#v, want sanitized file_tmpfs proof", proof)
	}
	assertFactoryCredentialDeliveryRedactionAbsent(t, event, []string{
		"/private/tmp/credential.sock",
	})
}

func TestRunSecretRedactorPreservesSecretMetadataIdentifiers(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "env", Source: RunSecretSourceEnv, Required: true, Value: "env"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		Secrets: []RunSecretMetadata{{
			Name:     "env",
			Source:   RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}},
	})

	wantSecret := RunSecretMetadata{
		Name:     "env",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}
	if got.Secrets[0] != wantSecret {
		t.Fatalf("Secrets[0] = %#v, want %#v", got.Secrets[0], wantSecret)
	}
}

func requireRedactedCredentialDeliveryMetadata(t *testing.T, metadata map[string]any) sandbox.SandboxCredentialDeliveryStatusMetadata {
	t.Helper()
	raw, ok := metadata["credentialDelivery"]
	if !ok {
		t.Fatalf("credentialDelivery metadata missing: %#v", metadata)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal(credentialDelivery) error = %v", err)
	}
	var status sandbox.SandboxCredentialDeliveryStatusMetadata
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("Unmarshal(credentialDelivery) error = %v\n%s", err, string(data))
	}
	return status
}

func assertFactoryCredentialDeliveryRedactionAbsent(t *testing.T, value any, forbidden []string) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(redacted value) error = %v", err)
	}
	payload := string(data)
	for _, needle := range forbidden {
		if strings.Contains(payload, needle) {
			t.Fatalf("redacted value leaked %q in %s", needle, payload)
		}
	}
}

func TestRunSecretRedactorRedactsVerificationArtifactIdentifiers(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "RUN_SECRET", Source: RunSecretSourceEnv, Required: true, Value: "secret-fragment"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		Verification: &VerificationRecord{
			Artifacts: []verify.ArtifactReference{{
				CheckID: "check-secret-fragment",
				Kind:    "kind-secret-fragment",
				Path:    ".hal/reports/secret-fragment.txt",
			}},
		},
	})

	if got.Verification.Artifacts[0].CheckID != "check-"+RunSecretRedactionPlaceholder {
		t.Fatalf("Verification.Artifacts[0].CheckID = %q, want redacted", got.Verification.Artifacts[0].CheckID)
	}
	if got.Verification.Artifacts[0].Kind != "kind-"+RunSecretRedactionPlaceholder {
		t.Fatalf("Verification.Artifacts[0].Kind = %q, want redacted", got.Verification.Artifacts[0].Kind)
	}
	if got.Verification.Artifacts[0].Path != ".hal/reports/"+RunSecretRedactionPlaceholder+".txt" {
		t.Fatalf("Verification.Artifacts[0].Path = %q, want redacted", got.Verification.Artifacts[0].Path)
	}
}

func TestRunSecretRedactorPreservesRunRecordControlFields(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "EXECUTOR_MODE", Source: RunSecretSourceEnv, Required: true, Value: ExecutorModeSandbox},
		{Name: "STATUS", Source: RunSecretSourceEnv, Required: true, Value: RunStatusRunning},
		{Name: "ENGINE", Source: RunSecretSourceEnv, Required: true, Value: "codex"},
		{Name: "BRANCH", Source: RunSecretSourceEnv, Required: true, Value: "hal/factory-secret"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		Status:       RunStatusRunning,
		ExecutorMode: ExecutorModeSandbox,
		Engine:       "codex",
		Source: SourceMetadata{
			Kind:       "prd",
			Path:       "/tmp/hal/factory-secret/prd.json",
			ReportPath: "/tmp/report-codex.json",
			Title:      "use codex safely",
		},
		RepoPath:    "/tmp/work/hal/factory-secret",
		RepoRemote:  "https://example.invalid/codex/repo.git",
		BranchName:  "hal/factory-secret",
		BaseBranch:  "hal/factory-secret",
		SandboxName: "sandbox",
		CurrentStep: RunStatusRunning,
		Policy: &FactoryPolicy{
			AllowedEngines:  []string{"codex"},
			CleanupBehavior: "sandbox",
		},
		Sandbox: &SandboxMetadata{
			Name:           "sandbox",
			Provider:       "codex",
			Size:           "sandbox",
			Status:         RunStatusRunning,
			SSHCommand:     "ssh sandbox",
			CleanupCommand: "delete sandbox",
		},
		Telemetry: &RunTelemetry{
			StepDurations: []RunStepDuration{{
				Step: RunStatusRunning,
			}},
			Engine: &EngineTelemetry{
				Name:  "codex",
				Model: "codex",
			},
			Sandbox: &RunSandboxTelemetry{
				Provider: "sandbox",
				Size:     "sandbox",
			},
			CIOutcome:           RunStatusRunning,
			VerificationOutcome: RunStatusRunning,
			FailureCategory:     RunStatusRunning,
		},
		Failure: &FailureSummary{
			Step:             RunStatusRunning,
			Category:         RunStatusRunning,
			Message:          "failed with codex",
			SuggestedCommand: "retry codex",
		},
	})

	if got.Status != RunStatusRunning {
		t.Fatalf("Status = %q, want control field preserved", got.Status)
	}
	if got.ExecutorMode != ExecutorModeSandbox {
		t.Fatalf("ExecutorMode = %q, want control field preserved", got.ExecutorMode)
	}
	if got.Engine != RunSecretRedactionPlaceholder {
		t.Fatalf("Engine = %q, want redacted config field", got.Engine)
	}
	if got.Source.Kind != "prd" {
		t.Fatalf("Source.Kind = %q, want control field preserved", got.Source.Kind)
	}
	if got.BranchName != RunSecretRedactionPlaceholder {
		t.Fatalf("BranchName = %q, want redacted branch name", got.BranchName)
	}
	if got.BaseBranch != RunSecretRedactionPlaceholder {
		t.Fatalf("BaseBranch = %q, want redacted base branch", got.BaseBranch)
	}
	if got.SandboxName != RunSecretRedactionPlaceholder {
		t.Fatalf("SandboxName = %q, want redacted sandbox name", got.SandboxName)
	}
	if got.CurrentStep != RunStatusRunning {
		t.Fatalf("CurrentStep = %q, want control field preserved", got.CurrentStep)
	}
	if got.Source.Path != "/tmp/"+RunSecretRedactionPlaceholder+"/prd.json" {
		t.Fatalf("Source.Path = %q, want redacted free-form path", got.Source.Path)
	}
	if got.RepoRemote != "https://example.invalid/"+RunSecretRedactionPlaceholder+"/repo.git" {
		t.Fatalf("RepoRemote = %q, want redacted free-form remote", got.RepoRemote)
	}
	if got.Policy.AllowedEngines[0] != "codex" {
		t.Fatalf("Policy.AllowedEngines[0] = %q, want control field preserved", got.Policy.AllowedEngines[0])
	}
	if got.Policy.CleanupBehavior != "sandbox" {
		t.Fatalf("Policy.CleanupBehavior = %q, want control field preserved", got.Policy.CleanupBehavior)
	}
	if got.Sandbox.Name != RunSecretRedactionPlaceholder {
		t.Fatalf("Sandbox.Name = %q, want redacted sandbox name", got.Sandbox.Name)
	}
	if got.Sandbox.Provider != "codex" {
		t.Fatalf("Sandbox.Provider = %q, want control field preserved", got.Sandbox.Provider)
	}
	if got.Sandbox.Status != RunStatusRunning {
		t.Fatalf("Sandbox.Status = %q, want control field preserved", got.Sandbox.Status)
	}
	if got.Sandbox.Size != RunSecretRedactionPlaceholder {
		t.Fatalf("Sandbox.Size = %q, want redacted free-form size", got.Sandbox.Size)
	}
	if got.Sandbox.SSHCommand != "ssh "+RunSecretRedactionPlaceholder {
		t.Fatalf("Sandbox.SSHCommand = %q, want redacted command", got.Sandbox.SSHCommand)
	}
	if got.Telemetry.StepDurations[0].Step != RunStatusRunning {
		t.Fatalf("Telemetry.StepDurations[0].Step = %q, want control field preserved", got.Telemetry.StepDurations[0].Step)
	}
	if got.Telemetry.Engine.Name != "codex" {
		t.Fatalf("Telemetry.Engine.Name = %q, want control field preserved", got.Telemetry.Engine.Name)
	}
	if got.Telemetry.Engine.Model != RunSecretRedactionPlaceholder {
		t.Fatalf("Telemetry.Engine.Model = %q, want redacted free-form model", got.Telemetry.Engine.Model)
	}
	if got.Telemetry.Sandbox.Provider != "sandbox" {
		t.Fatalf("Telemetry.Sandbox.Provider = %q, want control field preserved", got.Telemetry.Sandbox.Provider)
	}
	if got.Telemetry.Sandbox.Size != RunSecretRedactionPlaceholder {
		t.Fatalf("Telemetry.Sandbox.Size = %q, want redacted free-form size", got.Telemetry.Sandbox.Size)
	}
	if got.Telemetry.FailureCategory != RunStatusRunning {
		t.Fatalf("Telemetry.FailureCategory = %q, want control field preserved", got.Telemetry.FailureCategory)
	}
	if got.Failure.Step != RunStatusRunning {
		t.Fatalf("Failure.Step = %q, want control field preserved", got.Failure.Step)
	}
	if got.Failure.Category != RunStatusRunning {
		t.Fatalf("Failure.Category = %q, want control field preserved", got.Failure.Category)
	}
	if got.Failure.Message != "failed with "+RunSecretRedactionPlaceholder {
		t.Fatalf("Failure.Message = %q, want redacted output", got.Failure.Message)
	}
}

func TestRunSecretRedactorRedactsPublishOutcomeMetadata(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "PUBLISH_SECRET", Source: RunSecretSourceEnv, Required: true, Value: "secret-fragment"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		PostRun: &PostRunState{
			Publish: &PublishOutcome{
				Status:          RunStatusSucceeded,
				Policy:          "pr",
				BranchName:      "hal/secret-fragment",
				RecoveredBundle: "recovery/secret-fragment",
				PullRequestURL:  "https://github.com/jywlabs/secret-fragment/pull/42",
				Runner:          PublishRunnerSandbox,
				FallbackFrom:    PublishRunnerHost,
				CredentialMode:  "env-secret-fragment",
				Commit:          "abc123-secret-fragment",
				Attempts: []PublishAttempt{{
					Runner: PublishRunnerSandbox,
					Status: RunStatusFailed,
					Error:  "sandbox publish failed: secret-fragment",
				}},
				Source: "manual-secret-fragment",
			},
		},
	})

	if got.PostRun == nil || got.PostRun.Publish == nil {
		t.Fatalf("PostRun.Publish = %#v, want redacted publish outcome", got.PostRun)
	}
	publish := got.PostRun.Publish
	if publish.Runner != PublishRunnerSandbox || publish.FallbackFrom != PublishRunnerHost {
		t.Fatalf("publish runner metadata = %#v", publish)
	}
	if publish.BranchName != "hal/"+RunSecretRedactionPlaceholder {
		t.Fatalf("BranchName = %q, want redacted branch", publish.BranchName)
	}
	if publish.CredentialMode != "env-"+RunSecretRedactionPlaceholder {
		t.Fatalf("CredentialMode = %q, want redacted credential mode", publish.CredentialMode)
	}
	if publish.Commit != "abc123-"+RunSecretRedactionPlaceholder {
		t.Fatalf("Commit = %q, want redacted commit metadata", publish.Commit)
	}
	if len(publish.Attempts) != 1 {
		t.Fatalf("attempts = %#v, want one redacted attempt", publish.Attempts)
	}
	if publish.Attempts[0].Error != "sandbox publish failed: "+RunSecretRedactionPlaceholder {
		t.Fatalf("attempt error = %q, want redacted error", publish.Attempts[0].Error)
	}
	assertFactoryCredentialDeliveryRedactionAbsent(t, got, []string{"secret-fragment"})
}

func TestRunSecretRedactorRedactsSandboxMetadataName(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "SANDBOX_SECRET", Source: RunSecretSourceEnv, Required: true, Value: "secret-sandbox"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		SandboxName: "factory-secret-sandbox",
		Sandbox: &SandboxMetadata{
			Name:       "factory-secret-sandbox",
			Provider:   "hetzner",
			Status:     "running",
			SSHCommand: "hal sandbox ssh factory-secret-sandbox",
		},
	})

	if got.SandboxName != "factory-"+RunSecretRedactionPlaceholder {
		t.Fatalf("SandboxName = %q, want redacted sandbox name", got.SandboxName)
	}
	if got.Sandbox.Name != "factory-"+RunSecretRedactionPlaceholder {
		t.Fatalf("Sandbox.Name = %q, want redacted sandbox metadata name", got.Sandbox.Name)
	}
	if got.Sandbox.SSHCommand != "hal sandbox ssh factory-"+RunSecretRedactionPlaceholder {
		t.Fatalf("Sandbox.SSHCommand = %q, want redacted sandbox command", got.Sandbox.SSHCommand)
	}
}
