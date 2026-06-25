package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

const FactoryTriggerContractVersion = "factory-trigger-v1"

var factoryTriggerRepoFlag string
var factoryTriggerPRDFlag string
var factoryTriggerReportFlag string
var factoryTriggerDiscoverReportFlag bool
var factoryTriggerReportsDirFlag string
var factoryTriggerBaseFlag string
var factoryTriggerExecutorFlag string
var factoryTriggerSecretEnvFlags []string
var factoryTriggerJSONFlag bool

type factoryTriggerDeps struct {
	defaultStore         func() (factory.Store, error)
	newRunID             func() (string, error)
	newQueueID           func() (string, error)
	now                  func() time.Time
	currentBranch        func(string) (string, error)
	repoRemote           func(string) (string, error)
	lookupEnv            func(string) (string, bool)
	loadConfig           func(string) (*compound.AutoConfig, error)
	discoverLatestReport func(string, string) (string, bool, error)
}

type factoryTriggerRequest struct {
	RepoPath       string
	MarkdownPath   string
	ReportPath     string
	DiscoverReport bool
	ReportsDir     string
	BaseBranch     string
	ExecutorMode   string
	Secrets        []factory.RunSecretInput
	JSON           bool
}

// FactoryTriggerResponse is the machine-readable JSON output for
// hal factory trigger --json.
type FactoryTriggerResponse struct {
	ContractVersion string             `json:"contractVersion"`
	RunID           string             `json:"runId"`
	Run             factory.RunRecord  `json:"run"`
	Entry           factory.QueueEntry `json:"entry"`
	Summary         string             `json:"summary"`
}

var defaultFactoryTriggerDeps = factoryTriggerDeps{
	defaultStore:         factory.DefaultStore,
	newRunID:             defaultFactoryRunDeps.newRunID,
	now:                  time.Now,
	currentBranch:        compound.CurrentBranchOptionalInDir,
	repoRemote:           readGitRemoteOptionalInDir,
	lookupEnv:            os.LookupEnv,
	loadConfig:           compound.LoadConfig,
	discoverLatestReport: discoverLatestReportCandidate,
}

var factoryTriggerCmd = &cobra.Command{
	Use:   "trigger",
	Short: "Create queued factory runs from trigger payloads",
	Args:  noArgsValidation(),
	Long: `Create a queued factory run from external trigger context without starting
an always-on server.

Pass exactly one source payload: --prd <path>, --report <path>, or
--discover-report. Use --repo <path> to target a repository explicitly from
cron jobs or GitHub Actions workflows. The command creates a pending factory
run record, enqueues it in the durable factory queue, and exits. A separate
worker can later process the entry with hal factory queue work. Use
--secret-env to persist required environment variable names that the worker
must resolve only when it executes the run.`,
	Example: `  hal factory trigger --repo . --prd .hal/prd-feature.md
  hal factory trigger --repo . --prd .hal/prd-feature.md --secret-env GITHUB_TOKEN
  hal factory trigger --repo /work/hal --report .hal/reports/analysis.md --json
  hal factory trigger --repo /work/hal --discover-report --json`,
	RunE: runFactoryTrigger,
}

func configureFactoryTriggerCommand() {
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerRepoFlag, "repo", ".", "Repository path for the queued run")
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerPRDFlag, "prd", "", "Markdown PRD path for the queued run")
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerReportFlag, "report", "", "Analysis report path for the queued run")
	factoryTriggerCmd.Flags().BoolVar(&factoryTriggerDiscoverReportFlag, "discover-report", false, "Discover the latest report from the repository reports directory")
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerReportsDirFlag, "reports-dir", "", "Reports directory override for --discover-report")
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryTriggerCmd.Flags().StringVar(&factoryTriggerExecutorFlag, "executor", factory.ExecutorModeLocal, "Factory executor mode for the queued run")
	factoryTriggerCmd.Flags().StringArrayVar(&factoryTriggerSecretEnvFlags, "secret-env", nil, "Required environment variable secret for the queued run (repeatable)")
	factoryTriggerCmd.Flags().BoolVar(&factoryTriggerJSONFlag, "json", false, "Output machine-readable JSON (factory-trigger-v1 contract)")
}

func runFactoryTrigger(cmd *cobra.Command, _ []string) error {
	req, err := factoryTriggerRequestFromCommand(cmd)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	return runFactoryTriggerWithDeps(out, req, defaultFactoryTriggerDeps)
}

func factoryTriggerRequestFromCommand(cmd *cobra.Command) (factoryTriggerRequest, error) {
	secretEnv := append([]string(nil), factoryTriggerSecretEnvFlags...)
	req := factoryTriggerRequest{
		RepoPath:       factoryTriggerRepoFlag,
		MarkdownPath:   factoryTriggerPRDFlag,
		ReportPath:     factoryTriggerReportFlag,
		DiscoverReport: factoryTriggerDiscoverReportFlag,
		ReportsDir:     factoryTriggerReportsDirFlag,
		BaseBranch:     factoryTriggerBaseFlag,
		ExecutorMode:   factoryTriggerExecutorFlag,
		JSON:           factoryTriggerJSONFlag,
	}

	if cmd != nil {
		if cmd.Flags().Lookup("repo") != nil {
			value, err := cmd.Flags().GetString("repo")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.RepoPath = value
		}
		if cmd.Flags().Lookup("prd") != nil {
			value, err := cmd.Flags().GetString("prd")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.MarkdownPath = value
		}
		if cmd.Flags().Lookup("report") != nil {
			value, err := cmd.Flags().GetString("report")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.ReportPath = value
		}
		if cmd.Flags().Lookup("discover-report") != nil {
			value, err := cmd.Flags().GetBool("discover-report")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.DiscoverReport = value
		}
		if cmd.Flags().Lookup("reports-dir") != nil {
			value, err := cmd.Flags().GetString("reports-dir")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.ReportsDir = value
		}
		if cmd.Flags().Lookup("base") != nil {
			value, err := cmd.Flags().GetString("base")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.BaseBranch = value
		}
		if cmd.Flags().Lookup("executor") != nil {
			value, err := cmd.Flags().GetString("executor")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.ExecutorMode = value
		}
		if cmd.Flags().Lookup("secret-env") != nil {
			value, err := cmd.Flags().GetStringArray("secret-env")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			secretEnv = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return factoryTriggerRequest{}, err
			}
			req.JSON = value
		}
	}

	secrets, err := parseFactoryRunSecretEnvFlags(secretEnv)
	if err != nil {
		return factoryTriggerRequest{}, exitWithCode(cmd, ExitCodeValidation, err)
	}
	req.Secrets = secrets

	req, err = parseFactoryTriggerRequest(req)
	if err != nil {
		return factoryTriggerRequest{}, exitWithCode(cmd, ExitCodeValidation, err)
	}
	return req, nil
}

func runFactoryTriggerWithDeps(out io.Writer, req factoryTriggerRequest, deps factoryTriggerDeps) error {
	if out == nil {
		out = io.Discard
	}
	req, err := parseFactoryTriggerRequest(req)
	if err != nil {
		return err
	}
	deps = normalizeFactoryTriggerDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	executorMode := req.ExecutorMode

	repoPath, err := resolveFactoryTriggerRepoPath(req.RepoPath)
	if err != nil {
		return err
	}

	sourceReq, err := resolveFactoryTriggerSource(repoPath, req, deps)
	if err != nil {
		return err
	}
	sourceReq.BaseBranch = strings.TrimSpace(req.BaseBranch)
	sourceReq.Secrets = req.Secrets

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, err := newFactoryRunRecord(repoPath, sourceReq, factoryRunDeps{
		newRunID:      deps.newRunID,
		now:           deps.now,
		workingDir:    func() (string, error) { return repoPath, nil },
		currentBranch: deps.currentBranch,
		repoRemote:    deps.repoRemote,
	})
	if err != nil {
		return err
	}
	record.ExecutorMode = executorMode
	triggerRedactor := factory.NewRunSecretRedactor(resolveFactoryRunRedactionSecrets(req.Secrets, deps.lookupEnv))
	safeRecord := triggerRedactor.RedactRunRecord(record)
	safeRecord = sanitizeFactoryRunRecordCredentialedRemote(safeRecord)

	if err := createFactoryRunRecord(store, safeRecord); err != nil {
		return err
	}
	if err := recordFactoryRunTriggered(store, safeRecord, factoryTriggerKind(req)); err != nil {
		return err
	}

	entry, err := store.EnqueueQueueEntryWithLockedPostSave(record.RunID, executorMode, factory.QueueOperationOptions{
		Now:        deps.now,
		NewQueueID: deps.newQueueID,
	}, func(entry factory.QueueEntry) error {
		return recordFactoryRunQueued(store, entry, entry.CreatedAt)
	})
	if err != nil {
		enqueueErr := fmt.Errorf("enqueue triggered factory run %q: %w", record.RunID, err)
		if failErr := markTriggeredFactoryRunEnqueueFailed(store, safeRecord, enqueueErr, deps.now()); failErr != nil {
			return errors.Join(enqueueErr, fmt.Errorf("mark triggered factory run failed after enqueue failure: %w", failErr))
		}
		return enqueueErr
	}

	queuedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return fmt.Errorf("load triggered factory run %q: %w", record.RunID, err)
	}
	return renderFactoryTriggerResult(out, *queuedRecord, entry, req.JSON)
}

func parseFactoryTriggerRequest(req factoryTriggerRequest) (factoryTriggerRequest, error) {
	req.RepoPath = strings.TrimSpace(req.RepoPath)
	req.MarkdownPath = strings.TrimSpace(req.MarkdownPath)
	req.ReportPath = strings.TrimSpace(req.ReportPath)
	req.ReportsDir = strings.TrimSpace(req.ReportsDir)
	req.BaseBranch = strings.TrimSpace(req.BaseBranch)
	executorMode, err := factory.ValidateExecutorMode(req.ExecutorMode)
	if err != nil {
		return factoryTriggerRequest{}, err
	}
	req.ExecutorMode = executorMode
	if req.RepoPath == "" {
		return factoryTriggerRequest{}, fmt.Errorf("factory trigger repository path is required")
	}

	sourceCount := 0
	if req.MarkdownPath != "" {
		sourceCount++
	}
	if req.ReportPath != "" {
		sourceCount++
	}
	if req.DiscoverReport {
		sourceCount++
	}
	switch {
	case sourceCount == 0:
		return factoryTriggerRequest{}, fmt.Errorf("factory trigger payload is required: pass exactly one of --prd, --report, or --discover-report")
	case sourceCount > 1:
		return factoryTriggerRequest{}, fmt.Errorf("factory trigger accepts exactly one source: use only one of --prd, --report, or --discover-report")
	}
	if req.ReportsDir != "" && !req.DiscoverReport {
		return factoryTriggerRequest{}, fmt.Errorf("--reports-dir requires --discover-report")
	}
	if req.ExecutorMode == factory.ExecutorModeSandbox && req.BaseBranch == "" {
		return factoryTriggerRequest{}, fmt.Errorf("--base is required when --executor sandbox is set")
	}
	return req, nil
}

func normalizeFactoryTriggerDeps(deps factoryTriggerDeps) factoryTriggerDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryTriggerDeps.defaultStore
	}
	if deps.newRunID == nil {
		deps.newRunID = defaultFactoryTriggerDeps.newRunID
	}
	if deps.now == nil {
		deps.now = defaultFactoryTriggerDeps.now
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultFactoryTriggerDeps.currentBranch
	}
	if deps.repoRemote == nil {
		deps.repoRemote = defaultFactoryTriggerDeps.repoRemote
	}
	if deps.lookupEnv == nil {
		deps.lookupEnv = defaultFactoryTriggerDeps.lookupEnv
	}
	if deps.loadConfig == nil {
		deps.loadConfig = defaultFactoryTriggerDeps.loadConfig
	}
	if deps.discoverLatestReport == nil {
		deps.discoverLatestReport = defaultFactoryTriggerDeps.discoverLatestReport
	}
	return deps
}

func resolveFactoryRunRedactionSecrets(inputs []factory.RunSecretInput, lookup func(string) (string, bool)) []factory.ResolvedRunSecret {
	if len(inputs) == 0 || lookup == nil {
		return nil
	}
	resolved := make([]factory.ResolvedRunSecret, 0, len(inputs))
	for _, input := range inputs {
		secret := factory.RunSecretInput{
			Name:     strings.TrimSpace(input.Name),
			Source:   strings.TrimSpace(input.Source),
			Required: input.Required,
		}
		if secret.Name == "" || secret.Source != factory.RunSecretSourceEnv {
			continue
		}
		value, ok := lookup(secret.Name)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		resolved = append(resolved, factory.ResolvedRunSecret{
			Name:     secret.Name,
			Source:   secret.Source,
			Required: secret.Required,
			Value:    value,
		})
	}
	return resolved
}

func resolveFactoryTriggerRepoPath(repoPath string) (string, error) {
	repoPath = strings.TrimSpace(repoPath)
	if repoPath == "" {
		return "", fmt.Errorf("factory trigger repository path is required")
	}
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve factory trigger repository path %q: %w", repoPath, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("factory trigger repository path %q is not accessible: %w", repoPath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("factory trigger repository path %q is not a directory", repoPath)
	}
	return filepath.Clean(absPath), nil
}

func resolveFactoryTriggerSource(repoPath string, req factoryTriggerRequest, deps factoryTriggerDeps) (factoryRunRequest, error) {
	switch {
	case req.MarkdownPath != "":
		path, err := resolveFactoryTriggerFile(repoPath, req.MarkdownPath, "PRD")
		if err != nil {
			return factoryRunRequest{}, err
		}
		return factoryRunRequest{MarkdownPath: path}, nil
	case req.ReportPath != "":
		path, err := resolveFactoryTriggerFile(repoPath, req.ReportPath, "report")
		if err != nil {
			return factoryRunRequest{}, err
		}
		return factoryRunRequest{ReportPath: path}, nil
	default:
		reportsDir := req.ReportsDir
		if reportsDir == "" {
			config, err := deps.loadConfig(repoPath)
			if err != nil {
				return factoryRunRequest{}, fmt.Errorf("load factory trigger repo config: %w", err)
			}
			reportsDir = config.ReportsDir
		}
		reportPath, found, err := deps.discoverLatestReport(repoPath, reportsDir)
		if err != nil {
			return factoryRunRequest{}, fmt.Errorf("discover factory trigger report: %w", err)
		}
		if !found {
			if strings.TrimSpace(reportsDir) == "" {
				reportsDir = ".hal/reports"
			}
			return factoryRunRequest{}, fmt.Errorf("no report found for factory trigger in %s; pass --report <path> or add a report before scheduled enqueue", reportsDir)
		}
		return factoryRunRequest{ReportPath: displayFactoryTriggerPath(repoPath, reportPath)}, nil
	}
}

func resolveFactoryTriggerFile(repoPath, inputPath, label string) (string, error) {
	inputPath = strings.TrimSpace(inputPath)
	if inputPath == "" {
		return "", fmt.Errorf("factory trigger %s path is required", label)
	}
	resolvedPath := inputPath
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(repoPath, resolvedPath)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("factory trigger %s path %q is not accessible: %w", label, inputPath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("factory trigger %s path %q is a directory, want a file", label, inputPath)
	}
	return displayFactoryTriggerPath(repoPath, resolvedPath), nil
}

func displayFactoryTriggerPath(repoPath, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		if rel, err := filepath.Rel(repoPath, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
			return filepath.Clean(rel)
		}
	}
	return filepath.Clean(path)
}

func factoryTriggerKind(req factoryTriggerRequest) string {
	switch {
	case req.DiscoverReport:
		return "report_discovery"
	case strings.TrimSpace(req.MarkdownPath) != "":
		return factory.SourceKindMarkdown
	case strings.TrimSpace(req.ReportPath) != "":
		return factory.SourceKindReport
	default:
		return factory.SourceKindAutoDiscovery
	}
}

func recordFactoryRunTriggered(store factory.Store, record factory.RunRecord, triggerKind string) error {
	return appendFactoryRunTimelineEvent(store, record.RunID, record.CreatedAt, factoryTimelineEvent{
		EventType: factory.EventTypeRunCreated,
		Summary:   "Factory run created from trigger",
		Metadata: map[string]any{
			"executorMode": record.ExecutorMode,
			"sourceKind":   record.Source.Kind,
			"triggerKind":  triggerKind,
			"status":       record.Status,
		},
	})
}

func markTriggeredFactoryRunEnqueueFailed(store factory.Store, record factory.RunRecord, enqueueErr error, now time.Time) error {
	record.CurrentStep = factory.QueueStatusQueued
	failedRecord, err := markFactoryRunFailed(store, record, now, enqueueErr)
	if err != nil {
		return err
	}

	if err := appendFactoryRunTimelineEvent(store, failedRecord.RunID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Summary:   "Factory run enqueue failed",
		Metadata: map[string]any{
			"status": factory.RunStatusFailed,
			"error":  strings.TrimSpace(enqueueErr.Error()),
		},
	}); err != nil {
		return err
	}
	if failedRecord.Failure != nil {
		if err := recordFactoryRunFailureClassified(store, failedRecord.RunID, now, *failedRecord.Failure); err != nil {
			return err
		}
	}
	return nil
}

func renderFactoryTriggerResult(out io.Writer, record factory.RunRecord, entry factory.QueueEntry, jsonMode bool) error {
	resp := FactoryTriggerResponse{
		ContractVersion: FactoryTriggerContractVersion,
		RunID:           record.RunID,
		Run:             record,
		Entry:           entry,
		Summary:         factoryTriggerSummary(record.RunID, entry.QueueID),
	}
	if jsonMode {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal factory trigger: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintln(out, resp.Summary)
	return nil
}

func factoryTriggerSummary(runID, queueID string) string {
	return fmt.Sprintf("queued triggered run %s as %s", runID, queueID)
}
