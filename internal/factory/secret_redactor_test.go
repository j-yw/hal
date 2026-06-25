package factory

import (
	"testing"

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

func TestRunSecretRedactorPreservesSecretMetadataIdentifiers(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "env", Source: RunSecretSourceEnv, Required: true, Value: "env"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		BranchName: "branch-env",
		Secrets: []RunSecretMetadata{{
			Name:     "env",
			Source:   RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}},
	})

	if got.BranchName != "branch-env" {
		t.Fatalf("BranchName = %q, want control field preserved", got.BranchName)
	}
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
	if got.Engine != "codex" {
		t.Fatalf("Engine = %q, want control field preserved", got.Engine)
	}
	if got.Source.Kind != "prd" {
		t.Fatalf("Source.Kind = %q, want control field preserved", got.Source.Kind)
	}
	if got.BranchName != "hal/factory-secret" {
		t.Fatalf("BranchName = %q, want control field preserved", got.BranchName)
	}
	if got.BaseBranch != "hal/factory-secret" {
		t.Fatalf("BaseBranch = %q, want control field preserved", got.BaseBranch)
	}
	if got.SandboxName != "sandbox" {
		t.Fatalf("SandboxName = %q, want control field preserved", got.SandboxName)
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
	if got.Sandbox.Name != "sandbox" {
		t.Fatalf("Sandbox.Name = %q, want control field preserved", got.Sandbox.Name)
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
