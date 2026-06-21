package cmd

import (
	"bytes"
	"encoding/json"
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

	err := runFactoryTriggerWithDeps(&bytes.Buffer{}, factoryTriggerRequest{
		RepoPath:     repoDir,
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		ExecutorMode: factory.ExecutorModeSandbox,
		Secrets: []factory.RunSecretInput{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		}},
	}, factoryTriggerTestDeps(store, now, "run-trigger-secret", "queue-trigger-secret"))
	if err != nil {
		t.Fatalf("runFactoryTriggerWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-trigger-secret")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
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
			name: "sandbox executor missing base",
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
		discoverLatestReport: discoverLatestReportCandidate,
	}
}
