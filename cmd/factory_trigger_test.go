package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

func TestRunFactoryTriggerWithDepsCreatesMarkdownRunAndQueueEntry(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 0, 0, 0, time.UTC)

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "hal/local-factory-queue-and-worker-commands",
		ExecutorMode: factory.ExecutorModeLocal,
		JSON:         true,
	}, factoryTriggerTestDeps(store, now, "run-trigger-prd", "queue-trigger-prd"))
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "runId", "run", "entry", "summary"})
	if raw["contractVersion"] != FactoryTriggerContractVersion {
		t.Fatalf("contractVersion = %v, want %q", raw["contractVersion"], FactoryTriggerContractVersion)
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.RunID != "run-trigger-prd" {
		t.Fatalf("runId = %q, want run-trigger-prd", resp.RunID)
	}
	if resp.Entry == nil {
		t.Fatal("entry = nil, want queued entry")
	}
	if resp.Entry.QueueID != "queue-trigger-prd" {
		t.Fatalf("queueId = %q, want queue-trigger-prd", resp.Entry.QueueID)
	}
	if resp.Entry.Status != factory.QueueStatusQueued {
		t.Fatalf("entry status = %q, want queued", resp.Entry.Status)
	}
	if resp.Run.Status != factory.RunStatusPending {
		t.Fatalf("run status = %q, want pending", resp.Run.Status)
	}
	if resp.Run.CurrentStep != factory.QueueStatusQueued {
		t.Fatalf("currentStep = %q, want queued", resp.Run.CurrentStep)
	}
	if resp.Run.Source != (factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-feature.md"}) {
		t.Fatalf("run source = %#v", resp.Run.Source)
	}
	if resp.Run.RepoPath != filepath.Clean(repoDir) {
		t.Fatalf("repoPath = %q, want %q", resp.Run.RepoPath, filepath.Clean(repoDir))
	}
	if resp.Run.BaseBranch != "hal/local-factory-queue-and-worker-commands" {
		t.Fatalf("baseBranch = %q", resp.Run.BaseBranch)
	}
	if resp.Run.Policy == nil {
		t.Fatal("run policy snapshot = nil, want trigger-time policy snapshot")
	}
	if resp.Run.Engine != factory.PolicyEngineCodex {
		t.Fatalf("run engine = %q, want %q", resp.Run.Engine, factory.PolicyEngineCodex)
	}
	if got, want := strings.Join(resp.Run.Policy.AllowedEngines, ","), strings.Join(factory.SupportedPolicyEngines(), ","); got != want {
		t.Fatalf("policy.allowedEngines = %q, want %q", got, want)
	}
	if resp.Summary != "queued triggered run run-trigger-prd as queue-trigger-prd" {
		t.Fatalf("summary = %q", resp.Summary)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 || entries[0].QueueID != "queue-trigger-prd" {
		t.Fatalf("queue entries = %#v, want one triggered entry", entries)
	}

	events, err := store.LoadEvents("run-trigger-prd")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeCommandOutputSummary,
	})
	if events[0].Summary != "Factory run created from trigger" {
		t.Fatalf("created event summary = %q", events[0].Summary)
	}
	if events[0].Metadata["triggerKind"] != factory.SourceKindMarkdown {
		t.Fatalf("triggerKind metadata = %#v", events[0].Metadata["triggerKind"])
	}
}

func TestRunFactoryTriggerWithDepsRejectsSandboxRequiredBeforeEnqueue(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 2, 0, 0, time.UTC)
	policy := factory.DefaultFactoryPolicy()
	policy.SandboxRequired = true
	deps := factoryTriggerTestDeps(store, now, "run-trigger-policy-sandbox", "queue-trigger-policy-sandbox")
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return &policy, nil
	}

	err := runFactoryTriggerWithDeps(&bytes.Buffer{}, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		ExecutorMode: factory.ExecutorModeLocal,
	}, deps)
	if err == nil {
		t.Fatal("runFactoryTriggerWithDeps() error = nil, want sandboxRequired rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.sandboxRequired") {
		t.Fatalf("runFactoryTriggerWithDeps() error = %q, want sandboxRequired rejection", err.Error())
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want 0: %#v", len(entries), entries)
	}

	record, err := store.LoadRun("run-trigger-policy-sandbox")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", record.Status)
	}
	if record.Policy == nil || !record.Policy.SandboxRequired {
		t.Fatalf("policy snapshot = %#v, want sandboxRequired snapshot", record.Policy)
	}
	if record.Failure == nil || record.Failure.Step != "policy" {
		t.Fatalf("failure = %#v, want policy failure", record.Failure)
	}

	events, err := store.LoadEvents("run-trigger-policy-sandbox")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypePolicyDecision,
		factory.EventTypeFailureClassification,
	})
	assertPolicyDecisionMetadata(t, events[1].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.sandboxRequired",
		Decision:    factory.PolicyDecisionRejectedExecution,
		Outcome:     factory.PolicyOutcomeRejected,
		Reason:      "requires sandbox executor (requested local)",
	})
}

func TestRunFactoryTriggerWithDepsJSONPolicyRejectionUsesTriggerContract(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 2, 30, 0, time.UTC)
	policy := factory.DefaultFactoryPolicy()
	policy.SandboxRequired = true
	deps := factoryTriggerTestDeps(store, now, "run-trigger-json-policy", "queue-trigger-json-policy")
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return &policy, nil
	}

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		ExecutorMode: factory.ExecutorModeLocal,
		JSON:         true,
	}, deps)
	if err == nil {
		t.Fatal("runFactoryTriggerWithDeps() error = nil, want sandboxRequired rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.sandboxRequired") {
		t.Fatalf("runFactoryTriggerWithDeps() error = %q, want sandboxRequired rejection", err.Error())
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "runId", "run", "summary"})
	if raw["contractVersion"] != FactoryTriggerContractVersion {
		t.Fatalf("contractVersion = %v, want %q", raw["contractVersion"], FactoryTriggerContractVersion)
	}
	if _, ok := raw["version"]; ok {
		t.Fatalf("unexpected factory-run-v1 version key in trigger response: %#v", raw)
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.Entry != nil {
		t.Fatalf("entry = %#v, want nil before enqueue", resp.Entry)
	}
	if resp.RunID != "run-trigger-json-policy" || resp.Run.RunID != resp.RunID {
		t.Fatalf("run IDs = response %q run %q, want run-trigger-json-policy", resp.RunID, resp.Run.RunID)
	}
	if resp.Run.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", resp.Run.Status)
	}
	if resp.Run.Failure == nil || resp.Run.Failure.Step != "policy" {
		t.Fatalf("run failure = %#v, want policy failure", resp.Run.Failure)
	}

	entries, loadErr := store.LoadQueue()
	if loadErr != nil {
		t.Fatalf("LoadQueue() error: %v", loadErr)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want 0: %#v", len(entries), entries)
	}
}

func TestRunFactoryTriggerWithDepsRejectsDisallowedEngineBeforeEnqueue(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 3, 0, 0, time.UTC)
	policy := factory.DefaultFactoryPolicy()
	policy.AllowedEngines = []string{factory.PolicyEngineClaude}
	deps := factoryTriggerTestDeps(store, now, "run-trigger-policy-engine", "queue-trigger-policy-engine")
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return &policy, nil
	}
	deps.loadEngine = func(string) (string, error) {
		return factory.PolicyEngineCodex, nil
	}

	err := runFactoryTriggerWithDeps(&bytes.Buffer{}, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		ExecutorMode: factory.ExecutorModeLocal,
	}, deps)
	if err == nil {
		t.Fatal("runFactoryTriggerWithDeps() error = nil, want allowedEngines rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.allowedEngines") {
		t.Fatalf("runFactoryTriggerWithDeps() error = %q, want allowedEngines rejection", err.Error())
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want 0: %#v", len(entries), entries)
	}
	record, err := store.LoadRun("run-trigger-policy-engine")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Policy == nil || strings.Join(record.Policy.AllowedEngines, ",") != factory.PolicyEngineClaude {
		t.Fatalf("policy snapshot = %#v, want claude-only snapshot", record.Policy)
	}
	if record.Engine != factory.PolicyEngineCodex {
		t.Fatalf("engine snapshot = %q, want %q", record.Engine, factory.PolicyEngineCodex)
	}

	events, err := store.LoadEvents("run-trigger-policy-engine")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypePolicyDecision,
		factory.EventTypeFailureClassification,
	})
	assertPolicyDecisionMetadata(t, events[1].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.allowedEngines",
		Decision:    factory.PolicyDecisionRejectedExecution,
		Outcome:     factory.PolicyOutcomeRejected,
		Reason:      `does not allow engine "codex"`,
	})
}

func TestFactoryTriggerRequestFromCommandParsesSecretEnvFlags(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("repo", ".", "")
	cmd.Flags().String("prd", "", "")
	cmd.Flags().String("report", "", "")
	cmd.Flags().Bool("discover-report", false, "")
	cmd.Flags().String("reports-dir", "", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().String("executor", factory.ExecutorModeLocal, "")
	cmd.Flags().StringArray("secret-env", nil, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("prd", ".hal/prd-feature.md"); err != nil {
		t.Fatalf("Set(prd) error: %v", err)
	}
	if err := cmd.Flags().Set("secret-env", "GITHUB_TOKEN"); err != nil {
		t.Fatalf("Set(secret-env) error: %v", err)
	}

	req, err := factoryTriggerRequestFromCommand(cmd)
	if err != nil {
		t.Fatalf("factoryTriggerRequestFromCommand() unexpected error: %v", err)
	}

	wantSecrets := []factory.RunSecretInput{{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true}}
	if !reflect.DeepEqual(req.Secrets, wantSecrets) {
		t.Fatalf("secrets = %#v, want %#v", req.Secrets, wantSecrets)
	}
}

func TestRunFactoryTriggerWithDepsPersistsSecretRequirementsForQueueWorker(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 2, 0, 0, time.UTC)
	secretValue := "ghp_trigger_secret_12345"
	deps := factoryTriggerTestDeps(store, now, "run-trigger-secret", "queue-trigger-secret")
	deps.repoRemote = func(string) (string, error) {
		return "https://x:" + secretValue + "@github.com/ReScienceLab/hal.git", nil
	}

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		ExecutorMode: factory.ExecutorModeSandbox,
		JSON:         true,
		Secrets: []factory.RunSecretInput{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		}},
	}, deps)
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(out.String(), secretValue) {
		t.Fatalf("trigger JSON leaked secret value: %s", out.String())
	}
	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	if resp.Run.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/ReScienceLab/hal.git" {
		t.Fatalf("response repo remote = %q, want redacted secret value", resp.Run.RepoRemote)
	}

	record, err := store.LoadRun("run-trigger-secret")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/ReScienceLab/hal.git" {
		t.Fatalf("stored repo remote = %q, want redacted secret value", record.RepoRemote)
	}
	wantMetadata := []factory.RunSecretMetadata{{
		Name:     "GITHUB_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Present:  false,
	}}
	if !reflect.DeepEqual(record.Secrets, wantMetadata) {
		t.Fatalf("secrets metadata = %#v, want %#v", record.Secrets, wantMetadata)
	}
	req := factoryRunRequestFromQueueRecord(*record)
	wantSecrets := []factory.RunSecretInput{{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true}}
	if !reflect.DeepEqual(req.Secrets, wantSecrets) {
		t.Fatalf("queue request secrets = %#v, want %#v", req.Secrets, wantSecrets)
	}
}

func TestRunFactoryTriggerWithDepsPolicyLoadFailureKeepsSecretMetadataUnresolved(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 2, 0, 0, time.UTC)
	deps := factoryTriggerTestDeps(store, now, "run-trigger-policy-load-secret", "queue-trigger-policy-load-secret")
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return nil, errors.New("policy read failed")
	}

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		ExecutorMode: factory.ExecutorModeSandbox,
		JSON:         true,
		Secrets: []factory.RunSecretInput{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		}},
	}, deps)
	if err == nil {
		t.Fatal("runFactoryTriggerWithDeps() error = nil, want policy load failure")
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	if resp.Run.Failure == nil {
		t.Fatal("response failure = nil, want policy load failure")
	}

	record, err := store.LoadRun("run-trigger-policy-load-secret")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Failure == nil {
		t.Fatal("stored failure = nil, want policy load failure")
	}
	wantMetadata := []factory.RunSecretMetadata{{
		Name:     "GITHUB_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Present:  false,
	}}
	if !reflect.DeepEqual(record.Secrets, wantMetadata) {
		t.Fatalf("secrets metadata = %#v, want %#v", record.Secrets, wantMetadata)
	}
}

func TestRunFactoryTriggerWithDepsRedactsCredentialedRemoteWhenSecretValueMissing(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 3, 0, 0, time.UTC)
	credential := "factory-secret-12345"
	deps := factoryTriggerTestDeps(store, now, "run-trigger-missing-secret", "queue-trigger-missing-secret")
	deps.repoRemote = func(string) (string, error) {
		return "https://" + credential + ":x-oauth-basic@github.com/ReScienceLab/hal.git", nil
	}

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		ExecutorMode: factory.ExecutorModeLocal,
		JSON:         true,
		Secrets: []factory.RunSecretInput{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		}},
	}, deps)
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(out.String(), credential) {
		t.Fatalf("trigger JSON leaked credentialed remote secret: %s", out.String())
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	wantRemote := "https://" + factory.RunSecretRedactionPlaceholder + "@github.com/ReScienceLab/hal.git"
	if resp.Run.RepoRemote != wantRemote {
		t.Fatalf("response repo remote = %q, want %q", resp.Run.RepoRemote, wantRemote)
	}

	record, err := store.LoadRun("run-trigger-missing-secret")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.RepoRemote != wantRemote {
		t.Fatalf("stored repo remote = %q, want %q", record.RepoRemote, wantRemote)
	}
}

func TestRunFactoryTriggerWithDepsRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 4, 0, 0, time.UTC)
	credential := "factory-trigger-remote-token"
	deps := factoryTriggerTestDeps(store, now, "run-trigger-credentialed-remote", "queue-trigger-credentialed-remote")
	deps.repoRemote = func(string) (string, error) {
		return "https://" + credential + ":x-oauth-basic@github.com/ReScienceLab/hal.git", nil
	}

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		ExecutorMode: factory.ExecutorModeLocal,
		JSON:         true,
	}, deps)
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(out.String(), credential) {
		t.Fatalf("trigger JSON leaked credentialed remote secret: %s", out.String())
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	wantRemote := "https://" + factory.RunSecretRedactionPlaceholder + "@github.com/ReScienceLab/hal.git"
	if resp.Run.RepoRemote != wantRemote {
		t.Fatalf("response repo remote = %q, want %q", resp.Run.RepoRemote, wantRemote)
	}

	record, err := store.LoadRun("run-trigger-credentialed-remote")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.RepoRemote != wantRemote {
		t.Fatalf("stored repo remote = %q, want %q", record.RepoRemote, wantRemote)
	}
	if len(record.Secrets) != 0 {
		t.Fatalf("secrets metadata = %#v, want none", record.Secrets)
	}
}

func TestRunFactoryTriggerWithDepsMarksRunFailedWhenEnqueueFails(t *testing.T) {
	repoDir := t.TempDir()
	halDir := filepath.Join(repoDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := os.MkdirAll(filepath.Dir(store.QueuePath()), 0o755); err != nil {
		t.Fatalf("mkdir queue dir: %v", err)
	}
	if err := os.WriteFile(store.QueuePath(), []byte("{"), 0o600); err != nil {
		t.Fatalf("write corrupt queue: %v", err)
	}
	now := time.Date(2026, 6, 21, 22, 5, 0, 0, time.UTC)

	err := runFactoryTriggerWithDeps(&bytes.Buffer{}, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		ExecutorMode: factory.ExecutorModeLocal,
	}, factoryTriggerTestDeps(store, now, "run-trigger-enqueue-failure", "queue-trigger-enqueue-failure"))
	if err == nil {
		t.Fatal("runFactoryTriggerWithDeps() error = nil, want enqueue failure")
	}
	if !strings.Contains(err.Error(), `enqueue triggered factory run "run-trigger-enqueue-failure"`) {
		t.Fatalf("runFactoryTriggerWithDeps() error = %q, want enqueue failure", err.Error())
	}

	record, loadErr := store.LoadRun("run-trigger-enqueue-failure")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", record.Status)
	}
	if record.CurrentStep != factory.QueueStatusQueued {
		t.Fatalf("currentStep = %q, want queued failure step", record.CurrentStep)
	}
	if record.Failure == nil || !strings.Contains(record.Failure.Message, `enqueue triggered factory run "run-trigger-enqueue-failure"`) {
		t.Fatalf("failure = %#v, want enqueue failure message", record.Failure)
	}

	events, loadEventsErr := store.LoadEvents("run-trigger-enqueue-failure")
	if loadEventsErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadEventsErr)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeFailureClassification,
	})
	if events[1].Summary != "Factory run enqueue failed" {
		t.Fatalf("enqueue failure event summary = %q", events[1].Summary)
	}
}

func TestRunFactoryTriggerWithDepsCreatesReportRun(t *testing.T) {
	repoDir := t.TempDir()
	reportsDir := filepath.Join(repoDir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}
	writeFile(t, reportsDir, "analysis.md", "# Analysis\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 22, 30, 0, 0, time.UTC)

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:     repoDir,
		ReportPath:   ".hal/reports/analysis.md",
		ExecutorMode: factory.ExecutorModeLocal,
	}, factoryTriggerTestDeps(store, now, "run-trigger-report", "queue-trigger-report"))
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "queued triggered run run-trigger-report as queue-trigger-report" {
		t.Fatalf("output = %q, want trigger summary", got)
	}

	record, err := store.LoadRun("run-trigger-report")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	wantSource := factory.SourceMetadata{
		Kind:       factory.SourceKindReport,
		Path:       ".hal/reports/analysis.md",
		ReportPath: ".hal/reports/analysis.md",
	}
	if record.Source != wantSource {
		t.Fatalf("source = %#v, want %#v", record.Source, wantSource)
	}
}

func TestRunFactoryTriggerWithDepsDiscoversLatestReportDeterministically(t *testing.T) {
	repoDir := t.TempDir()
	reportsDir := filepath.Join(repoDir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}

	writeFile(t, reportsDir, ".hidden.md", "# hidden\n")
	writeFile(t, reportsDir, "review-loop-20260621.md", "# review loop\n")
	writeFile(t, reportsDir, "analysis-b.md", "# B\n")
	writeFile(t, reportsDir, "analysis-a.md", "# A\n")
	writeFile(t, reportsDir, "older.md", "# older\n")

	older := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	for path, modTime := range map[string]time.Time{
		filepath.Join(reportsDir, "older.md"):                older,
		filepath.Join(reportsDir, "analysis-a.md"):           latest,
		filepath.Join(reportsDir, "analysis-b.md"):           latest,
		filepath.Join(reportsDir, "review-loop-20260621.md"): latest.Add(time.Hour),
	} {
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatalf("Chtimes(%s) error: %v", path, err)
		}
	}

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 23, 0, 0, 0, time.UTC)

	var out bytes.Buffer
	err := runFactoryTriggerWithDeps(&out, factoryTriggerRequest{
		RepoPath:       repoDir,
		DiscoverReport: true,
		ReportsDir:     ".hal/reports",
		ExecutorMode:   factory.ExecutorModeLocal,
		JSON:           true,
	}, factoryTriggerTestDeps(store, now, "run-trigger-discovery", "queue-trigger-discovery"))
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}

	var resp FactoryTriggerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	wantReportPath := filepath.Join(".hal", "reports", "analysis-a.md")
	if resp.Run.Source.Kind != factory.SourceKindReport {
		t.Fatalf("source kind = %q, want report", resp.Run.Source.Kind)
	}
	if resp.Run.Source.ReportPath != wantReportPath {
		t.Fatalf("reportPath = %q, want %q", resp.Run.Source.ReportPath, wantReportPath)
	}
	if resp.Run.Source.Path != wantReportPath {
		t.Fatalf("source path = %q, want %q", resp.Run.Source.Path, wantReportPath)
	}

	events, err := store.LoadEvents("run-trigger-discovery")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if events[0].Metadata["triggerKind"] != "report_discovery" {
		t.Fatalf("triggerKind metadata = %#v, want report_discovery", events[0].Metadata["triggerKind"])
	}
}

func TestRunFactoryTriggerWithDepsRejectsMissingPayloads(t *testing.T) {
	tests := []struct {
		name    string
		req     factoryTriggerRequest
		wantErr string
	}{
		{
			name: "missing source",
			req: factoryTriggerRequest{
				RepoPath:     ".",
				ExecutorMode: factory.ExecutorModeLocal,
			},
			wantErr: "factory trigger payload is required",
		},
		{
			name: "conflicting sources",
			req: factoryTriggerRequest{
				RepoPath:       ".",
				MarkdownPath:   ".hal/prd.md",
				DiscoverReport: true,
				ExecutorMode:   factory.ExecutorModeLocal,
			},
			wantErr: "factory trigger accepts exactly one source",
		},
		{
			name: "reports dir without discovery",
			req: factoryTriggerRequest{
				RepoPath:     ".",
				ReportPath:   ".hal/reports/report.md",
				ReportsDir:   ".hal/reports",
				ExecutorMode: factory.ExecutorModeLocal,
			},
			wantErr: "--reports-dir requires --discover-report",
		},
		{
			name: "sandbox executor requires base",
			req: factoryTriggerRequest{
				RepoPath:     ".",
				MarkdownPath: ".hal/prd.md",
				ExecutorMode: factory.ExecutorModeSandbox,
			},
			wantErr: "--base is required when --executor sandbox is set",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := runFactoryTriggerWithDeps(&bytes.Buffer{}, tt.req, factoryTriggerDeps{})
			if err == nil {
				t.Fatalf("runFactoryTriggerWithDeps() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runFactoryTriggerWithDeps() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRunFactoryTriggerWithDepsRejectsMissingFilesAndReports(t *testing.T) {
	repoDir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 23, 30, 0, 0, time.UTC)
	deps := factoryTriggerTestDeps(store, now, "run-unused", "queue-unused")

	tests := []struct {
		name    string
		req     factoryTriggerRequest
		wantErr string
	}{
		{
			name: "missing prd file",
			req: factoryTriggerRequest{
				RepoPath:     repoDir,
				MarkdownPath: ".hal/missing.md",
				ExecutorMode: factory.ExecutorModeLocal,
			},
			wantErr: "factory trigger PRD path",
		},
		{
			name: "missing discovered report",
			req: factoryTriggerRequest{
				RepoPath:       repoDir,
				DiscoverReport: true,
				ReportsDir:     ".hal/reports",
				ExecutorMode:   factory.ExecutorModeLocal,
			},
			wantErr: "no report found for factory trigger",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := runFactoryTriggerWithDeps(&bytes.Buffer{}, tt.req, deps)
			if err == nil {
				t.Fatalf("runFactoryTriggerWithDeps() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runFactoryTriggerWithDeps() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func factoryTriggerTestDeps(store factory.Store, now time.Time, runID, queueID string) factoryTriggerDeps {
	return factoryTriggerDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return runID, nil },
		newQueueID:   func() (string, error) { return queueID, nil },
		now:          func() time.Time { return now },
		currentBranch: func(string) (string, error) {
			return "hal/factory-trigger-entrypoints", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:ReScienceLab/hal.git", nil
		},
		loadConfig: func(string) (*compound.AutoConfig, error) {
			cfg := compound.DefaultAutoConfig()
			return &cfg, nil
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			policy := factory.DefaultFactoryPolicy()
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		discoverLatestReport: discoverLatestReportCandidate,
	}
}
