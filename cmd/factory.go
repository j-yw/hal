package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

const (
	FactoryRunContractVersion    = "factory-run-v1"
	FactoryListContractVersion   = "factory-list-v1"
	FactoryStatusContractVersion = "factory-status-v1"
)

var factoryListJSONFlag bool
var factoryStatusJSONFlag bool
var factoryRunReportFlag string
var factoryRunBaseFlag string
var factoryRunJSONFlag bool

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Run and inspect factory workflows",
	Long: `Run local factory workflows and inspect durable factory run history stored
under Hal's global config directory.

Factory run wraps the local auto pipeline while list and status read the global factory store,
which is separate from per-project .hal runtime state.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md --json
  hal factory list
  hal factory list --json
  hal factory status <run-id> --json`,
}

var factoryRunCmd = &cobra.Command{
	Use:   "run [prd-path]",
	Short: "Run the local factory executor",
	Args:  validateFactoryRunArgs,
	Long: `Run the local factory executor by wrapping the existing hal auto compound
pipeline.

Provide at most one positional PRD markdown path to start from an existing
spec, or use --report <path> to start from an analysis report. The positional
path and --report are mutually exclusive. Use --base <branch> to pass a target
base branch to the executor and --json for machine-readable factory-run-v1
output.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md
  hal factory run .hal/prd-feature.md --base main --json`,
	RunE: runFactoryRun,
}

var factoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored factory runs",
	Args:  noArgsValidation(),
	Long: `List stored factory runs from the global factory store.

The default output is a compact table of run IDs, statuses, branches, steps,
and update timestamps. Use --json for machine-readable output following the
factory-list-v1 contract. JSON output includes run summaries only; event
timelines are intentionally omitted from the list surface.`,
	Example: `  hal factory list
  hal factory list --json`,
	RunE: runFactoryList,
}

var factoryStatusCmd = &cobra.Command{
	Use:   "status <run-id>",
	Short: "Inspect a stored factory run",
	Args:  exactArgsValidation(1),
	Long: `Inspect one stored factory run from the global factory store.

The default output is a compact table with run metadata and timeline entries.
Use --json for machine-readable output following the factory-status-v1 contract.
JSON output includes the full run record and timeline events in append order.`,
	Example: `  hal factory status run-20260620-001
  hal factory status run-20260620-001 --json`,
	RunE: runFactoryStatus,
}

func init() {
	factoryRunCmd.Flags().StringVar(&factoryRunReportFlag, "report", "", "Start from an analysis report path")
	factoryRunCmd.Flags().StringVar(&factoryRunBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryRunCmd.Flags().BoolVar(&factoryRunJSONFlag, "json", false, "Output machine-readable JSON (factory-run-v1 contract)")
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryStatusCmd.Flags().BoolVar(&factoryStatusJSONFlag, "json", false, "Output machine-readable JSON (factory-status-v1 contract)")
	factoryCmd.AddCommand(factoryRunCmd)
	factoryCmd.AddCommand(factoryListCmd)
	factoryCmd.AddCommand(factoryStatusCmd)
	rootCmd.AddCommand(factoryCmd)
}

type factoryListDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryListDeps = factoryListDeps{
	defaultStore: factory.DefaultStore,
}

type factoryStatusDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryStatusDeps = factoryStatusDeps{
	defaultStore: factory.DefaultStore,
}

type factoryRunDeps struct {
	defaultStore  func() (factory.Store, error)
	newRunID      func() (string, error)
	now           func() time.Time
	workingDir    func() (string, error)
	currentBranch func(string) (string, error)
	repoRemote    func(string) (string, error)
	runPipeline   func(context.Context, factoryRunPipelineRequest) error
}

type factoryRunPipelineRequest struct {
	RunID          string
	Request        factoryRunRequest
	Record         factory.RunRecord
	Store          factory.Store
	RecordProgress func(factoryRunProgressEvent) error
}

var defaultFactoryRunDeps = factoryRunDeps{
	defaultStore:  factory.DefaultStore,
	newRunID:      sandbox.NewV7,
	now:           time.Now,
	workingDir:    os.Getwd,
	currentBranch: compound.CurrentBranchOptionalInDir,
	repoRemote:    readGitRemoteOptionalInDir,
	runPipeline:   runFactoryRunPipeline,
}

type factoryRunRequest struct {
	MarkdownPath string
	ReportPath   string
	BaseBranch   string
	JSON         bool
}

type factoryRunAutoRequest struct {
	Args       []string
	ReportPath string
	BaseBranch string
}

type factoryRunProgressEvent struct {
	Message  string
	Summary  string
	Metadata map[string]any
}

type factoryTimelineEvent struct {
	EventType string
	Message   string
	Summary   string
	Metadata  map[string]any
}

type factoryRunPipelineDeps struct {
	runAuto func(context.Context, factoryRunAutoRequest) error
}

// FactoryListResponse is the machine-readable JSON output for hal factory list --json.
type FactoryListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Runs            []FactoryRunSummary `json:"runs"`
}

// FactoryStatusResponse is the machine-readable JSON output for hal factory status --json.
type FactoryStatusResponse struct {
	ContractVersion string                `json:"contractVersion"`
	Run             factory.RunRecord     `json:"run"`
	Timeline        []factory.EventRecord `json:"timeline"`
}

// FactoryRunSummary is the list surface for one factory run. It intentionally
// excludes full artifact records and event timelines so list output stays small.
type FactoryRunSummary struct {
	RunID         string                  `json:"runId"`
	Status        string                  `json:"status"`
	Source        factory.SourceMetadata  `json:"source"`
	RepoPath      string                  `json:"repoPath"`
	RepoRemote    string                  `json:"repoRemote"`
	BranchName    string                  `json:"branchName"`
	BaseBranch    string                  `json:"baseBranch"`
	SandboxName   string                  `json:"sandboxName,omitempty"`
	CurrentStep   string                  `json:"currentStep"`
	CreatedAt     time.Time               `json:"createdAt"`
	UpdatedAt     time.Time               `json:"updatedAt"`
	FinishedAt    *time.Time              `json:"finishedAt,omitempty"`
	ArtifactCount int                     `json:"artifactCount"`
	Failure       *factory.FailureSummary `json:"failure,omitempty"`
}

func validateFactoryRunArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return maxArgsValidation(1)(cmd, args)
	}

	reportPath := ""
	if cmd != nil && cmd.Flags().Lookup("report") != nil {
		value, err := cmd.Flags().GetString("report")
		if err != nil {
			return err
		}
		reportPath = value
	}

	if _, err := parseFactoryRunRequest(args, reportPath, "", false); err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	return nil
}

func runFactoryRun(cmd *cobra.Command, args []string) error {
	req, err := factoryRunRequestFromCommand(cmd, args)
	if err != nil {
		return err
	}

	ctx := context.Background()
	out := io.Writer(os.Stdout)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
	}

	return runFactoryRunWithDeps(ctx, ".", req, out, defaultFactoryRunDeps)
}

func runFactoryRunWithDeps(ctx context.Context, dir string, req factoryRunRequest, out io.Writer, deps factoryRunDeps) error {
	_ = out
	deps = normalizeFactoryRunDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if deps.runPipeline == nil {
		return fmt.Errorf("factory run pipeline dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, err := newFactoryRunRecord(dir, req, deps)
	if err != nil {
		return err
	}
	if err := createFactoryRunRecord(store, record); err != nil {
		return err
	}
	if err := recordFactoryRunStarted(store, record); err != nil {
		return err
	}

	runningRecord, err := markFactoryRunInProgress(store, record, deps.now())
	if err != nil {
		return err
	}
	if err := recordFactoryRunPipelineStarted(store, runningRecord); err != nil {
		return err
	}

	pipelineReq := factoryRunPipelineRequest{
		RunID:   runningRecord.RunID,
		Request: req,
		Record:  runningRecord,
		Store:   store,
		RecordProgress: func(event factoryRunProgressEvent) error {
			return recordFactoryRunProgress(store, runningRecord.RunID, deps.now(), event)
		},
	}
	if err := deps.runPipeline(ctx, pipelineReq); err != nil {
		failedAt := deps.now()
		if _, artifactErr := recordFactoryRunArtifacts(store, runningRecord.RunID, dir, req, failedAt); artifactErr != nil {
			if eventErr := recordFactoryRunPipelineFailed(store, runningRecord.RunID, failedAt, err); eventErr != nil {
				return errors.Join(err, fmt.Errorf("record factory artifacts: %w", artifactErr), fmt.Errorf("record factory failure event: %w", eventErr))
			}
			return errors.Join(err, fmt.Errorf("record factory artifacts: %w", artifactErr))
		}
		if eventErr := recordFactoryRunPipelineFailed(store, runningRecord.RunID, failedAt, err); eventErr != nil {
			return errors.Join(err, fmt.Errorf("record factory failure event: %w", eventErr))
		}
		return err
	}

	completedAt := deps.now()
	if _, err := recordFactoryRunArtifacts(store, runningRecord.RunID, dir, req, completedAt); err != nil {
		return err
	}
	return recordFactoryRunPipelineSucceeded(store, runningRecord.RunID, completedAt)
}

func normalizeFactoryRunDeps(deps factoryRunDeps) factoryRunDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryRunDeps.defaultStore
	}
	if deps.newRunID == nil {
		deps.newRunID = defaultFactoryRunDeps.newRunID
	}
	if deps.now == nil {
		deps.now = defaultFactoryRunDeps.now
	}
	if deps.workingDir == nil {
		deps.workingDir = defaultFactoryRunDeps.workingDir
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultFactoryRunDeps.currentBranch
	}
	if deps.repoRemote == nil {
		deps.repoRemote = defaultFactoryRunDeps.repoRemote
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryRunDeps.runPipeline
	}
	return deps
}

func newFactoryRunRecord(dir string, req factoryRunRequest, deps factoryRunDeps) (factory.RunRecord, error) {
	runID, err := deps.newRunID()
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("create factory run ID: %w", err)
	}
	now := deps.now().UTC()
	repoPath, err := deps.workingDir()
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve repository path: %w", err)
	}
	branchName, err := deps.currentBranch(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve current branch: %w", err)
	}
	repoRemote, err := deps.repoRemote(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve repository remote: %w", err)
	}

	return factory.RunRecord{
		RunID:        runID,
		Status:       factory.RunStatusPending,
		ExecutorMode: factory.ExecutorModeLocal,
		Source:       factoryRunSourceFromRequest(req),
		RepoPath:     repoPath,
		RepoRemote:   repoRemote,
		BranchName:   branchName,
		BaseBranch:   strings.TrimSpace(req.BaseBranch),
		CurrentStep:  factory.RunStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func createFactoryRunRecord(store factory.Store, record factory.RunRecord) error {
	if err := store.SaveRun(&record); err != nil {
		return fmt.Errorf("create factory run record: %w", err)
	}
	return nil
}

func markFactoryRunInProgress(store factory.Store, record factory.RunRecord, now time.Time) (factory.RunRecord, error) {
	record.Status = factory.RunStatusRunning
	record.CurrentStep = "run"
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(&record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run in progress: %w", err)
	}
	return record, nil
}

func recordFactoryRunArtifacts(store factory.Store, runID, dir string, req factoryRunRequest, now time.Time) (factory.RunRecord, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("load factory run for artifacts: %w", err)
	}

	record.Artifacts = collectFactoryRunArtifacts(store, dir, req, *record)
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("record factory artifacts: %w", err)
	}
	return *record, nil
}

func collectFactoryRunArtifacts(store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord) []factory.ArtifactReference {
	collector := newFactoryArtifactCollector(dir)

	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		collector.add(factory.ArtifactReference{
			Name: "source-markdown",
			Type: factoryArtifactTypeForPath(markdownPath),
			Path: collector.displayPath(markdownPath),
		})
	}
	if reportPath := strings.TrimSpace(req.ReportPath); reportPath != "" {
		collector.add(factory.ArtifactReference{
			Name: "source-report",
			Type: factoryArtifactTypeForPath(reportPath),
			Path: collector.displayPath(reportPath),
		})
	}

	halDir := filepath.Join(dir, template.HalDir)
	collector.addExisting("canonical-prd", filepath.Join(template.HalDir, template.PRDFile))
	collector.addExisting("auto-state", filepath.Join(template.HalDir, template.AutoStateFile))

	if state, ok := loadFactoryRunPipelineState(filepath.Join(halDir, template.AutoStateFile)); ok {
		if sourceMarkdown := strings.TrimSpace(state.SourceMarkdown); sourceMarkdown != "" {
			collector.addExisting("pipeline-source-markdown", sourceMarkdown)
		}
		if reportPath := strings.TrimSpace(state.ReportPath); reportPath != "" {
			collector.addExisting(factoryGeneratedReportArtifactName(reportPath), reportPath)
		}
	}

	for _, artifact := range collectFactoryRunReportArtifacts(dir, record.CreatedAt) {
		collector.add(artifact)
	}

	if recordPath := factoryRunRecordArtifactPath(store, record.RunID); recordPath != "" {
		collector.add(factory.ArtifactReference{
			Name: "factory-run-record",
			Type: "json",
			Path: recordPath,
		})
	}

	return collector.artifacts
}

type factoryArtifactCollector struct {
	dir       string
	seen      map[string]struct{}
	artifacts []factory.ArtifactReference
}

func newFactoryArtifactCollector(dir string) *factoryArtifactCollector {
	return &factoryArtifactCollector{
		dir:  dir,
		seen: make(map[string]struct{}),
	}
}

func (c *factoryArtifactCollector) addExisting(name, path string) {
	if strings.TrimSpace(path) == "" || !factoryArtifactFileExists(c.resolvePath(path)) {
		return
	}
	c.add(factory.ArtifactReference{
		Name: name,
		Type: factoryArtifactTypeForPath(path),
		Path: c.displayPath(path),
	})
}

func (c *factoryArtifactCollector) add(artifact factory.ArtifactReference) {
	artifact.Name = strings.TrimSpace(artifact.Name)
	artifact.Type = strings.TrimSpace(artifact.Type)
	artifact.Path = strings.TrimSpace(artifact.Path)
	artifact.URL = strings.TrimSpace(artifact.URL)
	if artifact.Name == "" || artifact.Type == "" {
		return
	}

	key := artifact.Name + "\x00" + artifact.Type + "\x00" + artifact.Path + "\x00" + artifact.URL
	if artifact.Path != "" {
		key = "path\x00" + filepath.Clean(artifact.Path)
	}
	if artifact.URL != "" {
		key = "url\x00" + artifact.URL
	}
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.artifacts = append(c.artifacts, artifact)
}

func (c *factoryArtifactCollector) resolvePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.dir, path)
}

func (c *factoryArtifactCollector) displayPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		baseDir := c.dir
		if baseDir == "" {
			baseDir = "."
		}
		if absDir, err := filepath.Abs(baseDir); err == nil {
			if rel, err := filepath.Rel(absDir, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
				return filepath.Clean(rel)
			}
		}
		return filepath.Clean(path)
	}
	return filepath.Clean(path)
}

func loadFactoryRunPipelineState(path string) (*compound.PipelineState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var state compound.PipelineState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	return &state, true
}

func collectFactoryRunReportArtifacts(dir string, startedAt time.Time) []factory.ArtifactReference {
	reportsDir := filepath.Join(dir, template.HalDir, "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil
	}

	type reportFile struct {
		name    string
		path    string
		modTime time.Time
	}
	reportFiles := make([]reportFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(template.HalDir, "reports", name)
		info, err := entry.Info()
		if err != nil || info.IsDir() {
			continue
		}
		if !startedAt.IsZero() && info.ModTime().Before(startedAt) {
			continue
		}
		reportFiles = append(reportFiles, reportFile{
			name:    name,
			path:    path,
			modTime: info.ModTime(),
		})
	}

	sort.Slice(reportFiles, func(i, j int) bool {
		if !reportFiles[i].modTime.Equal(reportFiles[j].modTime) {
			return reportFiles[i].modTime.Before(reportFiles[j].modTime)
		}
		return reportFiles[i].path < reportFiles[j].path
	})

	artifacts := make([]factory.ArtifactReference, 0, len(reportFiles))
	for _, reportFile := range reportFiles {
		artifacts = append(artifacts, factory.ArtifactReference{
			Name: factoryGeneratedReportArtifactName(reportFile.name),
			Type: factoryArtifactTypeForPath(reportFile.path),
			Path: filepath.Clean(reportFile.path),
		})
	}
	return artifacts
}

func factoryGeneratedReportArtifactName(path string) string {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	switch {
	case strings.HasPrefix(name, "review-loop-"):
		return "review-loop-report"
	case strings.HasPrefix(name, "review-"):
		return "review-report"
	case strings.Contains(name, "ci"):
		return "ci-artifact"
	case strings.Contains(name, "pr"):
		return "pr-artifact"
	default:
		return "generated-report"
	}
}

func factoryArtifactTypeForPath(path string) string {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".json":
		return "json"
	case ".md", ".markdown":
		return "markdown"
	case ".log", ".txt":
		return "text"
	default:
		return "file"
	}
}

func factoryArtifactFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func factoryRunRecordArtifactPath(store factory.Store, runID string) string {
	if strings.TrimSpace(store.RunsDir()) == "" || strings.TrimSpace(runID) == "" {
		return ""
	}
	return filepath.Join(store.RunsDir(), runID+".json")
}

func recordFactoryRunStarted(store factory.Store, record factory.RunRecord) error {
	return appendFactoryRunTimelineEvent(store, record.RunID, record.CreatedAt, factoryTimelineEvent{
		EventType: factory.EventTypeRunCreated,
		Summary:   "Factory run started",
		Metadata: map[string]any{
			"executorMode": record.ExecutorMode,
			"sourceKind":   record.Source.Kind,
			"status":       record.Status,
		},
	})
}

func recordFactoryRunPipelineStarted(store factory.Store, record factory.RunRecord) error {
	return appendFactoryRunTimelineEvent(store, record.RunID, record.UpdatedAt, factoryTimelineEvent{
		EventType: factory.EventTypeStepStarted,
		Summary:   "Local compound pipeline started",
		Metadata: map[string]any{
			"step":   record.CurrentStep,
			"status": record.Status,
		},
	})
}

func recordFactoryRunProgress(store factory.Store, runID string, now time.Time, event factoryRunProgressEvent) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	})
}

func recordFactoryRunPipelineSucceeded(store factory.Store, runID string, now time.Time) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Local compound pipeline completed",
		Metadata: map[string]any{
			"step":   "run",
			"status": factory.RunStatusSucceeded,
		},
	})
}

func recordFactoryRunPipelineFailed(store factory.Store, runID string, now time.Time, pipelineErr error) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Local compound pipeline failed",
		Metadata: map[string]any{
			"step":   "run",
			"status": factory.RunStatusFailed,
			"error":  pipelineErr.Error(),
		},
	})
}

func appendFactoryRunTimelineEvent(store factory.Store, runID string, timestamp time.Time, event factoryTimelineEvent) error {
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline %q: %w", runID, err)
	}

	record := factory.EventRecord{
		Sequence:  nextFactoryRunEventSequence(events),
		RunID:     runID,
		EventType: event.EventType,
		Timestamp: timestamp.UTC(),
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	}
	if err := store.AppendEvent(&record); err != nil {
		return fmt.Errorf("append factory timeline event %q: %w", runID, err)
	}
	return nil
}

func nextFactoryRunEventSequence(events []factory.EventRecord) int64 {
	var maxSequence int64
	for _, event := range events {
		if event.Sequence > maxSequence {
			maxSequence = event.Sequence
		}
	}
	return maxSequence + 1
}

func factoryRunSourceFromRequest(req factoryRunRequest) factory.SourceMetadata {
	markdownPath := strings.TrimSpace(req.MarkdownPath)
	reportPath := strings.TrimSpace(req.ReportPath)

	switch {
	case markdownPath != "":
		return factory.SourceMetadata{
			Kind: factory.SourceKindMarkdown,
			Path: markdownPath,
		}
	case reportPath != "":
		return factory.SourceMetadata{
			Kind:       factory.SourceKindReport,
			Path:       reportPath,
			ReportPath: reportPath,
		}
	default:
		return factory.SourceMetadata{
			Kind: factory.SourceKindAutoDiscovery,
		}
	}
}

func runFactoryRunPipeline(ctx context.Context, req factoryRunPipelineRequest) error {
	return runFactoryRunPipelineWithDeps(ctx, req, factoryRunPipelineDeps{
		runAuto: runAutoForFactoryRun,
	})
}

func runFactoryRunPipelineWithDeps(ctx context.Context, req factoryRunPipelineRequest, deps factoryRunPipelineDeps) error {
	if deps.runAuto == nil {
		return fmt.Errorf("factory run auto dependency is required")
	}

	autoReq := factoryRunAutoRequest{
		ReportPath: strings.TrimSpace(req.Request.ReportPath),
		BaseBranch: strings.TrimSpace(req.Request.BaseBranch),
	}
	if markdownPath := strings.TrimSpace(req.Request.MarkdownPath); markdownPath != "" {
		autoReq.Args = []string{markdownPath}
	}

	return deps.runAuto(ctx, autoReq)
}

func runAutoForFactoryRun(ctx context.Context, req factoryRunAutoRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := &cobra.Command{Use: "auto"}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("no-ci", false, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
	cmd.Flags().String("report", strings.TrimSpace(req.ReportPath), "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", strings.TrimSpace(req.BaseBranch), "")
	cmd.Flags().Bool("json", false, "")

	return runAuto(cmd, req.Args)
}

func factoryRunRequestFromCommand(cmd *cobra.Command, args []string) (factoryRunRequest, error) {
	reportPath := factoryRunReportFlag
	baseBranch := factoryRunBaseFlag
	jsonMode := factoryRunJSONFlag

	if cmd != nil {
		if cmd.Flags().Lookup("report") != nil {
			value, err := cmd.Flags().GetString("report")
			if err != nil {
				return factoryRunRequest{}, err
			}
			reportPath = value
		}
		if cmd.Flags().Lookup("base") != nil {
			value, err := cmd.Flags().GetString("base")
			if err != nil {
				return factoryRunRequest{}, err
			}
			baseBranch = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return factoryRunRequest{}, err
			}
			jsonMode = value
		}
	}

	req, err := parseFactoryRunRequest(args, reportPath, baseBranch, jsonMode)
	if err != nil {
		return factoryRunRequest{}, exitWithCode(cmd, ExitCodeValidation, err)
	}
	return req, nil
}

func parseFactoryRunRequest(args []string, reportPath, baseBranch string, jsonMode bool) (factoryRunRequest, error) {
	if len(args) > 1 {
		return factoryRunRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}
	if len(args) == 1 && strings.TrimSpace(reportPath) != "" {
		return factoryRunRequest{}, fmt.Errorf("--report cannot be used with a positional PRD markdown path")
	}

	req := factoryRunRequest{
		ReportPath: reportPath,
		BaseBranch: baseBranch,
		JSON:       jsonMode,
	}
	if len(args) == 1 {
		req.MarkdownPath = args[0]
	}
	return req, nil
}

func runFactoryList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryListJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runFactoryListWithDeps(out, jsonMode, defaultFactoryListDeps)
}

func runFactoryListWithDeps(out io.Writer, jsonMode bool, deps factoryListDeps) error {
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	records, err := store.ListRuns()
	if err != nil {
		return fmt.Errorf("list factory runs: %w", err)
	}

	if jsonMode {
		return renderFactoryListJSON(out, records)
	}

	renderFactoryListTable(out, records)
	return nil
}

func runFactoryStatus(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryStatusJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runFactoryStatusWithDeps(out, args[0], jsonMode, defaultFactoryStatusDeps)
}

func runFactoryStatusWithDeps(out io.Writer, runID string, jsonMode bool, deps factoryStatusDeps) error {
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, err := store.LoadRun(runID)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("factory run %q not found", runID)
	}
	if err != nil {
		return fmt.Errorf("load factory run %q: %w", runID, err)
	}
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline %q: %w", runID, err)
	}
	if events == nil {
		events = []factory.EventRecord{}
	}

	if jsonMode {
		return renderFactoryStatusJSON(out, *record, events)
	}

	renderFactoryStatusTable(out, *record, events)
	return nil
}

func renderFactoryListJSON(out io.Writer, records []factory.RunRecord) error {
	summaries := make([]FactoryRunSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summarizeFactoryRun(record))
	}

	resp := FactoryListResponse{
		ContractVersion: FactoryListContractVersion,
		Runs:            summaries,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory list: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryStatusJSON(out io.Writer, record factory.RunRecord, events []factory.EventRecord) error {
	resp := FactoryStatusResponse{
		ContractVersion: FactoryStatusContractVersion,
		Run:             record,
		Timeline:        events,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory status: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func summarizeFactoryRun(record factory.RunRecord) FactoryRunSummary {
	return FactoryRunSummary{
		RunID:         record.RunID,
		Status:        record.Status,
		Source:        record.Source,
		RepoPath:      record.RepoPath,
		RepoRemote:    record.RepoRemote,
		BranchName:    record.BranchName,
		BaseBranch:    record.BaseBranch,
		SandboxName:   record.SandboxName,
		CurrentStep:   record.CurrentStep,
		CreatedAt:     record.CreatedAt,
		UpdatedAt:     record.UpdatedAt,
		FinishedAt:    record.FinishedAt,
		ArtifactCount: len(record.Artifacts),
		Failure:       record.Failure,
	}
}

func renderFactoryListTable(out io.Writer, records []factory.RunRecord) {
	if len(records) == 0 {
		fmt.Fprintln(out, "No factory runs found.")
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN ID\tSTATUS\tBRANCH\tSTEP\tUPDATED")
	for _, record := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			record.RunID,
			record.Status,
			record.BranchName,
			record.CurrentStep,
			formatFactoryListTime(record.UpdatedAt),
		)
	}
	_ = w.Flush()
}

func renderFactoryStatusTable(out io.Writer, record factory.RunRecord, events []factory.EventRecord) {
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", record.Status)
	fmt.Fprintf(out, "Branch: %s\n", record.BranchName)
	fmt.Fprintf(out, "Step: %s\n", record.CurrentStep)
	fmt.Fprintf(out, "Updated: %s\n", formatFactoryListTime(record.UpdatedAt))
	fmt.Fprintf(out, "Timeline events: %d\n", len(events))
	if len(events) == 0 {
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQUENCE\tTYPE\tTIMESTAMP\tSUMMARY")
	for _, event := range events {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			event.Sequence,
			event.EventType,
			formatFactoryListTime(event.Timestamp),
			event.Summary,
		)
	}
	_ = w.Flush()
}

func formatFactoryListTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func readGitRemoteOptionalInDir(dir string) (string, error) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("read git remote origin: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
