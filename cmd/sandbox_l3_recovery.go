package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
	statuscontract "github.com/jywlabs/hal/internal/status"
	"github.com/spf13/cobra"
)

const (
	sandboxStatusContractVersion = "sandbox-status-v1"
	sandboxListLiveContract      = "sandbox-list-v2"
)

type sandboxL3Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type sandboxL3Identity struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Provider       string    `json:"provider"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	HostID         string    `json:"hostId,omitempty"`
	RuntimeDriver  string    `json:"runtimeDriver,omitempty"`
	RuntimeID      string    `json:"runtimeId,omitempty"`
	IsolationLevel string    `json:"isolationLevel,omitempty"`
}

type sandboxL3JobStatus struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	SubmittedAt time.Time  `json:"submittedAt"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	HeartbeatAt *time.Time `json:"heartbeatAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	LogCursor   uint64     `json:"logCursor"`
}

type sandboxL3ExecutionStatus struct {
	RunID             string              `json:"runId"`
	Purpose           string              `json:"purpose"`
	Status            string              `json:"status"`
	StartedAt         time.Time           `json:"startedAt"`
	FinishedAt        *time.Time          `json:"finishedAt,omitempty"`
	Active            bool                `json:"active"`
	Job               *sandboxL3JobStatus `json:"job,omitempty"`
	FinalizationState string              `json:"finalizationState,omitempty"`
	SyncOutRequested  bool                `json:"syncOutRequested,omitempty"`
	ReasonCode        string              `json:"reasonCode,omitempty"`
}

type sandboxL3StatusResponse struct {
	ContractVersion   string                    `json:"contractVersion"`
	Source            string                    `json:"source"`
	Sandbox           sandboxL3Identity         `json:"sandbox"`
	Execution         *sandboxL3ExecutionStatus `json:"execution,omitempty"`
	RecommendedAction string                    `json:"recommendedAction,omitempty"`
	Diagnostics       []sandboxL3Diagnostic     `json:"diagnostics,omitempty"`
}

type sandboxL3ListEntry struct {
	sandboxL3Identity
	Execution         *sandboxL3ExecutionStatus `json:"execution,omitempty"`
	RecommendedAction string                    `json:"recommendedAction,omitempty"`
}

type sandboxL3ListTotals struct {
	Total            int `json:"total"`
	Running          int `json:"running"`
	Stopped          int `json:"stopped"`
	ActiveExecutions int `json:"activeExecutions"`
}

type sandboxL3ListResponse struct {
	ContractVersion string                `json:"contractVersion"`
	Source          string                `json:"source"`
	Sandboxes       []sandboxL3ListEntry  `json:"sandboxes"`
	Totals          sandboxL3ListTotals   `json:"totals"`
	Diagnostics     []sandboxL3Diagnostic `json:"diagnostics,omitempty"`
}

type sandboxL3SelectionMode int

const (
	sandboxL3SelectionObserve sandboxL3SelectionMode = iota
	sandboxL3SelectionRecover
	sandboxL3SelectionSyncOut
)

var sandboxL3SensitiveAssignment = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?key|authorization|password|secret|token)=\S+`)

type sandboxL3JobClient interface {
	JobStatus(context.Context, sandboxworker.JobStatusRequest) (*sandboxworker.Job, error)
	JobLogs(context.Context, sandboxworker.JobLogsRequest) (*sandboxworker.JobLogsResponse, error)
}

var (
	sandboxL3DefaultStore    = sandboxexecution.DefaultStore
	sandboxL3LoadSandbox     = sandbox.LoadActiveInstance
	sandboxL3LoadHost        = sandbox.LoadHost
	sandboxL3NewWorkerClient = func(socketPath string) (*sandboxworker.Client, error) {
		return sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	}
)

func newSandboxLogsCommand() *cobra.Command {
	flags := struct {
		runID  string
		follow bool
	}{}
	cmd := &cobra.Command{
		Use:   "logs NAME",
		Short: "Read durable sandbox execution logs",
		Long: `Read redacted logs for one durable daemon-owned sandbox execution.

The command is observation-only. It never starts, cancels, retries, recovers, or
finalizes a job. When more than one recoverable execution exists, select one
explicitly with --run.`,
		Example: `  hal sandbox logs NAME
  hal sandbox logs NAME --run RUN_ID
  hal sandbox logs NAME --follow`,
		Args: exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxL3Cobra(cmd, "Sandbox Logs failed", func(ctx context.Context, out, errOut io.Writer) error {
				return runSandboxL3Logs(ctx, strings.TrimSpace(args[0]), strings.TrimSpace(flags.runID), flags.follow, out, errOut)
			})
		},
	}
	cmd.Flags().StringVar(&flags.runID, "run", "", "Select a durable execution by run ID")
	cmd.Flags().BoolVar(&flags.follow, "follow", false, "Follow logs until the durable job becomes terminal")
	return cmd
}

func newSandboxRecoverCommand() *cobra.Command {
	flags := struct{ runID string }{}
	cmd := &cobra.Command{
		Use:   "recover NAME",
		Short: "Recover a durable sandbox execution",
		Long: `Observe and retry finalization for one daemon-owned sandbox execution.

Recovery adopts only the durable job already linked to the selected execution.
It never relaunches the agent command and never cancels the worker job.`,
		Example: `  hal sandbox recover NAME
  hal sandbox recover NAME --run RUN_ID`,
		Args: exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxL3Cobra(cmd, "Sandbox Recover failed", func(ctx context.Context, out, _ io.Writer) error {
				return runSandboxL3RecoveryObservation(ctx, strings.TrimSpace(args[0]), strings.TrimSpace(flags.runID), false, out)
			})
		},
	}
	cmd.Flags().StringVar(&flags.runID, "run", "", "Select a durable execution by run ID")
	return cmd
}

func newSandboxRecoverySyncOutCommand() *cobra.Command {
	flags := struct{ runID string }{}
	cmd := &cobra.Command{
		Use:   "sync-out NAME",
		Short: "Recover sandbox outputs without applying them",
		Long: `Observe one durable daemon-owned sandbox execution and retry its
requested sync-out finalization.

This command never applies outputs to the host worktree, starts an agent,
cancels a job, or creates a replacement sandbox.`,
		Example: `  hal sandbox sync-out NAME
  hal sandbox sync-out NAME --run RUN_ID`,
		Args: exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxL3Cobra(cmd, "Sandbox Sync-out failed", func(ctx context.Context, out, _ io.Writer) error {
				return runSandboxL3RecoveryObservation(ctx, strings.TrimSpace(args[0]), strings.TrimSpace(flags.runID), true, out)
			})
		},
	}
	cmd.Flags().StringVar(&flags.runID, "run", "", "Select a durable execution by run ID")
	return cmd
}

func runSandboxL3Cobra(cmd *cobra.Command, title string, run func(context.Context, io.Writer, io.Writer) error) error {
	ctx := context.Background()
	out := io.Discard
	errOut := io.Discard
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()
	}
	if err := run(ctx, out, errOut); err != nil {
		if errOut != nil {
			fmt.Fprintf(errOut, "%s: %s\n", title, err.Error())
		}
		return exitWithCode(cmd, ExitCodeExpectedNonZero, err)
	}
	return nil
}

func runSandboxL3Logs(ctx context.Context, sandboxName, runID string, follow bool, out, errOut io.Writer) error {
	_, manifest, err := selectSandboxL3Execution(sandboxName, runID, sandboxL3SelectionObserve)
	if err != nil {
		return err
	}
	client, err := sandboxL3ClientForManifest(manifest)
	if err != nil {
		return err
	}
	job, err := sandboxL3JobStatusWithReconnect(ctx, client, manifest, follow)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.Join(errors.New("worker_job_status_failed"), errors.New("selected worker job is unavailable"))
	}
	if err := validateSandboxL3LiveJob(manifest, job); err != nil {
		return err
	}
	return streamSandboxL3Logs(ctx, client, manifest, job, follow, out, errOut)
}

func streamSandboxL3Logs(
	ctx context.Context,
	client sandboxL3JobClient,
	manifest *sandboxexecution.Manifest,
	job *sandboxworker.Job,
	follow bool,
	out, errOut io.Writer,
) error {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	cursor := uint64(0)
	gapReported := false
	for {
		page, err := sandboxL3JobLogsWithReconnect(ctx, client, manifest, cursor, follow)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return errors.Join(errors.New("worker_job_logs_failed"), errors.New("selected worker logs are unavailable"))
		}
		if page.JobID != manifest.WorkerJob.JobID {
			return errors.New("worker_job_identity_mismatch: selected worker log identity did not match")
		}
		if !gapReported && (page.Truncated || page.OldestCursor > cursor+1) {
			fmt.Fprintln(errOut, "warning: [redacted] logs were truncated before the retained cursor")
			gapReported = true
		}
		for _, record := range page.Records {
			writer := out
			if record.Stream == sandboxworker.JobLogStreamStderr {
				writer = errOut
			}
			fmt.Fprint(writer, sanitizeSandboxL3LogData(record.Data))
		}
		if page.NextCursor < cursor {
			return errors.New("worker_job_logs_invalid: worker log cursor moved backwards")
		}
		progressed := page.NextCursor > cursor
		cursor = page.NextCursor

		terminal := sandboxL3TerminalJobState(job.State)
		if terminal && cursor >= job.LogCursor {
			return nil
		}
		if !follow && (!progressed || cursor >= job.LogCursor) {
			return nil
		}
		if progressed {
			continue
		}

		if err := waitSandboxL3Poll(ctx); err != nil {
			return err
		}
		next, err := sandboxL3JobStatusWithReconnect(ctx, client, manifest, follow)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return errors.Join(errors.New("worker_job_status_failed"), errors.New("selected worker job is unavailable"))
		}
		if err := validateSandboxL3LiveJob(manifest, next); err != nil {
			return err
		}
		job = next
	}
}

func sandboxL3JobStatusWithReconnect(
	ctx context.Context,
	client sandboxL3JobClient,
	manifest *sandboxexecution.Manifest,
	follow bool,
) (*sandboxworker.Job, error) {
	attempt := 0
	for {
		job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           manifest.WorkerJob.JobID,
		})
		if err == nil {
			return job, nil
		}
		if !follow || !sandboxL3TransientDaemonTransportError(err) {
			return nil, err
		}
		if err := waitSandboxL3Reconnect(ctx, attempt); err != nil {
			return nil, err
		}
		attempt++
	}
}

func sandboxL3JobLogsWithReconnect(
	ctx context.Context,
	client sandboxL3JobClient,
	manifest *sandboxexecution.Manifest,
	cursor uint64,
	follow bool,
) (*sandboxworker.JobLogsResponse, error) {
	attempt := 0
	for {
		page, err := client.JobLogs(ctx, sandboxworker.JobLogsRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           manifest.WorkerJob.JobID,
			Cursor:          cursor,
			LimitBytes:      sandboxworker.DefaultJobLogReadBytes,
		})
		if err == nil {
			return page, nil
		}
		if !follow || !sandboxL3TransientDaemonTransportError(err) {
			return nil, err
		}
		if err := waitSandboxL3Reconnect(ctx, attempt); err != nil {
			return nil, err
		}
		attempt++
	}
}

func sandboxL3TransientDaemonTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var clientErr *sandboxworker.ClientError
	return errors.As(err, &clientErr) &&
		clientErr.Code == sandboxworker.ErrorCodeInternal &&
		clientErr.Err != nil
}

func waitSandboxL3Reconnect(ctx context.Context, attempt int) error {
	delay := 50 * time.Millisecond
	for index := 0; index < attempt && delay < 500*time.Millisecond; index++ {
		delay *= 2
	}
	if delay > 500*time.Millisecond {
		delay = 500 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitSandboxL3Poll(ctx context.Context) error {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sanitizeSandboxL3LogData(value string) string {
	value = sandboxL3SensitiveAssignment.ReplaceAllString(value, "[redacted]")
	value = statuscontract.SanitizePublicString(value)
	// Worker log records may contain credentials that are not part of the
	// current run-secret set, such as opaque Authorization header values.
	// Apply the shared line-aware output boundary before rendering them.
	return sanitizeSandboxOutputSummaryLines(value)
}

func runSandboxL3RecoveryObservation(ctx context.Context, sandboxName, runID string, requestSyncOut bool, out io.Writer) error {
	mode := sandboxL3SelectionRecover
	if requestSyncOut {
		mode = sandboxL3SelectionSyncOut
	}
	_, manifest, err := selectSandboxL3Execution(sandboxName, runID, mode)
	if err != nil {
		return err
	}
	store, err := sandboxL3DefaultStore()
	if err != nil {
		return errors.New("execution_store_unavailable: durable execution store is unavailable")
	}
	if err := finalizeSandboxL3Execution(
		ctx,
		store,
		manifest.ID,
		requestSyncOut,
		defaultSandboxL3FinalizationDeps(),
	); err != nil {
		return err
	}
	if out != nil {
		fmt.Fprintf(out, "execution %s finalization completed\n", manifest.ID)
	}
	return nil
}

func selectSandboxL3Execution(sandboxName, runID string, mode sandboxL3SelectionMode) (*sandbox.SandboxState, *sandboxexecution.Manifest, error) {
	sandboxName = strings.TrimSpace(sandboxName)
	runID = strings.TrimSpace(runID)
	if sandboxName == "" {
		return nil, nil, errors.New("sandbox name is required")
	}
	instance, err := sandboxL3LoadSandbox(sandboxName)
	if err != nil || instance == nil {
		return nil, nil, fmt.Errorf("sandbox_not_found: sandbox %s is unavailable", sandboxName)
	}
	store, err := sandboxL3DefaultStore()
	if err != nil {
		return nil, nil, errors.New("execution_store_unavailable: durable execution store is unavailable")
	}
	if runID != "" {
		manifest, err := store.LoadManifest(runID)
		if err != nil {
			return nil, nil, fmt.Errorf("execution_not_found: execution %s is unavailable", runID)
		}
		if manifest.SandboxName != sandboxName {
			return nil, nil, fmt.Errorf("execution_sandbox_mismatch: execution %s does not belong to sandbox %s", runID, sandboxName)
		}
		if manifest.WorkerJob == nil && !sandboxL3ExecutionAwaitingJobResolution(manifest) {
			return nil, nil, fmt.Errorf("worker_job_missing: execution %s has no durable worker job", runID)
		}
		if mode == sandboxL3SelectionRecover && !sandboxL3ExecutionRecoverable(manifest) {
			return nil, nil, fmt.Errorf("execution_not_recoverable: execution %s is already finalized", runID)
		}
		return instance, manifest, nil
	}

	manifests, err := store.ListManifests()
	if err != nil {
		return nil, nil, errors.New("execution_store_corrupt: durable execution manifests failed validation")
	}
	candidates := make([]*sandboxexecution.Manifest, 0)
	completed := make([]*sandboxexecution.Manifest, 0)
	for index := range manifests {
		manifest := &manifests[index]
		if manifest.SandboxName != sandboxName {
			continue
		}
		if manifest.WorkerJob == nil {
			if sandboxL3ExecutionAwaitingJobResolution(manifest) {
				candidates = append(candidates, manifest)
			}
			continue
		}
		if sandboxL3ExecutionRecoverable(manifest) {
			candidates = append(candidates, manifest)
			continue
		}
		if sandboxL3TerminalJobState(manifest.WorkerJob.State) {
			completed = append(completed, manifest)
		}
	}
	if len(candidates) > 1 {
		ids := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ids = append(ids, candidate.ID)
		}
		sort.Strings(ids)
		return nil, nil, fmt.Errorf("ambiguous_run: sandbox %s has multiple recoverable executions: %s", sandboxName, strings.Join(ids, ", "))
	}
	if len(candidates) == 1 {
		return instance, candidates[0], nil
	}
	if (mode == sandboxL3SelectionObserve || mode == sandboxL3SelectionSyncOut) && len(completed) > 0 {
		sort.Slice(completed, func(i, j int) bool {
			if !completed[i].StartedAt.Equal(completed[j].StartedAt) {
				return completed[i].StartedAt.After(completed[j].StartedAt)
			}
			return completed[i].ID > completed[j].ID
		})
		return instance, completed[0], nil
	}
	return nil, nil, fmt.Errorf("execution_not_found: sandbox %s has no recoverable execution", sandboxName)
}

func sandboxL3ExecutionRecoverable(manifest *sandboxexecution.Manifest) bool {
	if sandboxL3ExecutionAwaitingJobResolution(manifest) {
		return true
	}
	if manifest == nil || manifest.WorkerJob == nil {
		return false
	}
	if sandboxL3ActiveJobState(manifest.WorkerJob.State) {
		return true
	}
	return sandboxL3TerminalJobState(manifest.WorkerJob.State) &&
		(manifest.Finalization == nil || manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted)
}

func sandboxL3ExecutionAwaitingJobResolution(manifest *sandboxexecution.Manifest) bool {
	if manifest == nil ||
		manifest.WorkerJob != nil ||
		manifest.Status != sandboxexecution.StatusRunning ||
		manifest.Finalization != nil ||
		manifest.Host == nil ||
		manifest.Runtime == nil ||
		manifest.WorkerRouting == nil {
		return false
	}
	hostID := strings.TrimSpace(manifest.Host.ID)
	hostName := strings.TrimSpace(manifest.Host.Name)
	driverID := strings.TrimSpace(manifest.Runtime.Driver)
	runtimeID := strings.TrimSpace(manifest.Runtime.RuntimeID)
	workerID := strings.TrimSpace(manifest.Runtime.WorkerID)
	isolation := strings.TrimSpace(manifest.Runtime.IsolationLevel)
	routing := manifest.WorkerRouting
	return hostID != "" &&
		hostName != "" &&
		strings.TrimSpace(manifest.Host.Kind) == sandbox.SandboxHostKindWorker &&
		driverID == sandbox.SandboxRuntimeDriverRootlessPodman &&
		runtimeID != "" &&
		workerID != "" &&
		isolation == sandbox.SandboxIsolationLevelContainer &&
		strings.TrimSpace(routing.SelectedWorkerHostID) == hostID &&
		strings.TrimSpace(routing.SelectedWorkerHostName) == hostName &&
		strings.TrimSpace(routing.RuntimeDriverID) == driverID &&
		strings.TrimSpace(routing.IsolationLevel) == isolation
}

func sandboxL3ClientForManifest(manifest *sandboxexecution.Manifest) (*sandboxworker.Client, error) {
	if manifest == nil || manifest.WorkerJob == nil {
		return nil, errors.New("worker_job_missing: durable worker job identity is required")
	}
	hostID := strings.TrimSpace(manifest.WorkerJob.HostID)
	if hostID == "" && manifest.Host != nil {
		hostID = strings.TrimSpace(manifest.Host.ID)
	}
	if hostID == "" {
		return nil, errors.New("worker_host_missing: durable worker host identity is required")
	}
	return sandboxL3ClientForHostID(hostID)
}

func sandboxL3ClientForHostID(hostID string) (*sandboxworker.Client, error) {
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return nil, errors.New("worker_host_missing: durable worker host identity is required")
	}
	host, err := sandboxL3LoadHost(hostID)
	if err != nil || host == nil {
		return nil, fmt.Errorf("worker_host_unavailable: worker host %s is unavailable", hostID)
	}
	if strings.TrimSpace(host.Kind) != sandbox.SandboxHostKindWorker {
		return nil, fmt.Errorf("worker_host_invalid: host %s is not a worker", hostID)
	}
	socketPath, err := sandboxHostLocalWorkerSocketPath(host.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("worker_endpoint_invalid: worker host %s endpoint is invalid", hostID)
	}
	client, err := sandboxL3NewWorkerClient(socketPath)
	if err != nil {
		return nil, fmt.Errorf("worker_client_unavailable: worker host %s client is unavailable", hostID)
	}
	return client, nil
}

func validateSandboxL3LiveJob(manifest *sandboxexecution.Manifest, job *sandboxworker.Job) error {
	if manifest == nil || manifest.WorkerJob == nil || job == nil {
		return errors.New("worker_job_identity_mismatch: durable and live job identities are required")
	}
	if sandboxL3WorkerJobReference(job) == nil {
		return errors.New("worker_job_identity_mismatch: live job identity is invalid")
	}
	reference := manifest.WorkerJob
	mismatch := job.ContractVersion != sandboxworker.JobContractVersion ||
		job.ID != reference.JobID ||
		job.WorkerID != reference.WorkerID ||
		job.RuntimeDriver != reference.RuntimeDriver
	if reference.SubmissionKey != "" && job.SubmissionKey != reference.SubmissionKey {
		mismatch = true
	}
	if reference.HostID != "" && job.HostID != reference.HostID {
		mismatch = true
	}
	if reference.RuntimeID != "" && job.RuntimeID != reference.RuntimeID {
		mismatch = true
	}
	if mismatch {
		return fmt.Errorf("worker_job_identity_mismatch: live job did not match execution %s", manifest.ID)
	}
	if sandboxL3FinalizationProvenTerminalJobState(reference.State) && job.State != reference.State {
		return fmt.Errorf("worker_job_state_mismatch: live job contradicted terminal execution %s", manifest.ID)
	}
	if (reference.State == sandboxworker.JobStateUnknown || reference.State == sandboxworker.JobStateInterrupted) &&
		sandboxL3ActiveJobState(job.State) {
		return fmt.Errorf("worker_job_state_regression: unproven terminal execution %s cannot become active", manifest.ID)
	}
	return nil
}

func sandboxL3IdentityFromState(instance *sandbox.SandboxState) sandboxL3Identity {
	identity := sandboxL3Identity{}
	if instance == nil {
		return identity
	}
	identity.ID = strings.TrimSpace(instance.ID)
	identity.Name = strings.TrimSpace(instance.Name)
	identity.Provider = strings.TrimSpace(instance.Provider)
	identity.Status = strings.TrimSpace(instance.Status)
	identity.CreatedAt = instance.CreatedAt
	if instance.Host != nil {
		identity.HostID = strings.TrimSpace(instance.Host.ID)
	}
	if instance.Runtime != nil {
		identity.RuntimeDriver = strings.TrimSpace(instance.Runtime.Driver)
		identity.RuntimeID = strings.TrimSpace(instance.Runtime.RuntimeID)
		identity.IsolationLevel = strings.TrimSpace(instance.Runtime.IsolationLevel)
	}
	return identity
}

func sandboxL3ExecutionProjection(manifest *sandboxexecution.Manifest, liveJob *sandboxworker.Job) *sandboxL3ExecutionStatus {
	if manifest == nil {
		return nil
	}
	projection := &sandboxL3ExecutionStatus{
		RunID:      manifest.ID,
		Purpose:    string(manifest.Purpose),
		Status:     string(manifest.Status),
		StartedAt:  manifest.StartedAt,
		FinishedAt: cloneL3Time(manifest.FinishedAt),
	}
	if manifest.WorkerJob != nil {
		job := manifest.WorkerJob
		if liveJob != nil {
			projection.Job = &sandboxL3JobStatus{
				ID:          liveJob.ID,
				State:       liveJob.State,
				SubmittedAt: liveJob.SubmittedAt,
				StartedAt:   cloneL3Time(liveJob.StartedAt),
				HeartbeatAt: cloneL3Time(liveJob.HeartbeatAt),
				FinishedAt:  cloneL3Time(liveJob.FinishedAt),
				LogCursor:   liveJob.LogCursor,
			}
			projection.Active = sandboxL3ActiveJobState(liveJob.State)
		} else {
			projection.Job = &sandboxL3JobStatus{
				ID:          job.JobID,
				State:       job.State,
				SubmittedAt: job.SubmittedAt,
				StartedAt:   cloneL3Time(job.StartedAt),
				HeartbeatAt: cloneL3Time(job.HeartbeatAt),
				FinishedAt:  cloneL3Time(job.FinishedAt),
				LogCursor:   job.LogCursor,
			}
			projection.Active = sandboxL3ActiveJobState(job.State)
		}
	} else if sandboxL3ExecutionAwaitingJobResolution(manifest) {
		projection.Active = true
	}
	if manifest.Finalization != nil {
		projection.FinalizationState = string(manifest.Finalization.State)
		projection.SyncOutRequested = manifest.Finalization.SyncOutRequested
		projection.ReasonCode = manifest.Finalization.ReasonCode
	}
	return projection
}

func sandboxL3RecommendedAction(execution *sandboxL3ExecutionStatus) string {
	if execution == nil {
		return "none"
	}
	if execution.Job == nil {
		if execution.Status == string(sandboxexecution.StatusRunning) {
			return "recover"
		}
		return "none"
	}
	if execution.Active {
		return "follow_logs"
	}
	if execution.FinalizationState != string(sandboxexecution.FinalizationStateCompleted) {
		return "recover"
	}
	return "none"
}

func runSandboxL3StatusJSON(ctx context.Context, sandboxName string, live bool, out io.Writer) error {
	instance, err := sandboxL3LoadSandbox(strings.TrimSpace(sandboxName))
	if err != nil || instance == nil {
		return fmt.Errorf("sandbox_not_found: sandbox %s is unavailable", strings.TrimSpace(sandboxName))
	}
	response := sandboxL3StatusResponse{
		ContractVersion:   sandboxStatusContractVersion,
		Source:            "cached",
		Sandbox:           sandboxL3IdentityFromState(instance),
		RecommendedAction: "none",
	}
	_, manifest, selectErr := selectSandboxL3Execution(sandboxName, "", sandboxL3SelectionObserve)
	if selectErr == nil {
		var liveJob *sandboxworker.Job
		if live {
			if sandboxL3ExecutionAwaitingJobResolution(manifest) {
				response.Diagnostics = append(response.Diagnostics, sandboxL3Diagnostic{
					Code:    "worker_job_resolution_required",
					Message: "durable execution requires recovery before live observation",
				})
			} else {
				client, clientErr := sandboxL3ClientForManifest(manifest)
				if clientErr != nil {
					if !sandboxL3NamedStatusClientUnavailable(clientErr) {
						return clientErr
					}
					response.Diagnostics = append(response.Diagnostics, sandboxL3Diagnostic{
						Code:    "worker_client_unavailable",
						Message: "live execution client was unavailable; cached execution status is shown",
					})
				} else {
					liveJob, err = client.JobStatus(ctx, sandboxworker.JobStatusRequest{
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           manifest.WorkerJob.JobID,
					})
					if err != nil {
						if !sandboxL3TransientDaemonTransportError(err) {
							return errors.New("worker_job_status_failed: selected worker job response was invalid")
						}
						response.Diagnostics = append(response.Diagnostics, sandboxL3Diagnostic{
							Code:    "worker_job_status_failed",
							Message: "live execution status was unavailable; cached execution status is shown",
						})
						liveJob = nil
					} else {
						if err := validateSandboxL3LiveJob(manifest, liveJob); err != nil {
							return err
						}
						response.Source = "live"
					}
				}
			}
		}
		response.Execution = sandboxL3ExecutionProjection(manifest, liveJob)
		response.RecommendedAction = sandboxL3RecommendedAction(response.Execution)
	} else if !strings.Contains(selectErr.Error(), "execution_not_found") {
		return selectErr
	}
	return json.NewEncoder(out).Encode(response)
}

func sandboxL3NamedStatusClientUnavailable(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "worker_client_unavailable:")
}

func renderSandboxL3LiveListJSON(ctx context.Context, out io.Writer, instances []*sandbox.SandboxState) error {
	store, err := sandboxL3DefaultStore()
	if err != nil {
		return errors.New("execution_store_unavailable: durable execution store is unavailable")
	}
	manifests, err := store.ListManifests()
	if err != nil {
		return errors.New("execution_store_corrupt: durable execution manifests failed validation")
	}
	bySandbox := make(map[string][]*sandboxexecution.Manifest)
	for index := range manifests {
		manifest := &manifests[index]
		if manifest.WorkerJob != nil || sandboxL3ExecutionAwaitingJobResolution(manifest) {
			bySandbox[manifest.SandboxName] = append(bySandbox[manifest.SandboxName], manifest)
		}
	}
	sorted := append([]*sandbox.SandboxState(nil), instances...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	response := sandboxL3ListResponse{
		ContractVersion: sandboxListLiveContract,
		Source:          "live",
		Sandboxes:       make([]sandboxL3ListEntry, 0, len(sorted)),
	}
	for _, instance := range sorted {
		entry := sandboxL3ListEntry{sandboxL3Identity: sandboxL3IdentityFromState(instance)}
		candidates := bySandbox[instance.Name]
		manifest := newestSandboxL3Manifest(candidates)
		var liveJob *sandboxworker.Job
		if manifest != nil {
			if sandboxL3ExecutionAwaitingJobResolution(manifest) {
				response.Diagnostics = append(response.Diagnostics, sandboxL3Diagnostic{
					Code:    "worker_job_resolution_required",
					Message: "durable execution requires recovery before live observation",
				})
			} else {
				client, clientErr := sandboxL3ClientForManifest(manifest)
				if clientErr == nil {
					liveJob, clientErr = client.JobStatus(ctx, sandboxworker.JobStatusRequest{
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           manifest.WorkerJob.JobID,
					})
				}
				if clientErr != nil || validateSandboxL3LiveJob(manifest, liveJob) != nil {
					response.Diagnostics = append(response.Diagnostics, sandboxL3Diagnostic{
						Code:    "worker_job_status_failed",
						Message: "live execution status was unavailable",
					})
					liveJob = nil
				}
			}
			entry.Execution = sandboxL3ExecutionProjection(manifest, liveJob)
			entry.RecommendedAction = sandboxL3RecommendedAction(entry.Execution)
			if entry.Execution.Active {
				response.Totals.ActiveExecutions++
			}
		}
		response.Sandboxes = append(response.Sandboxes, entry)
		response.Totals.Total++
		switch entry.Status {
		case sandbox.StatusRunning:
			response.Totals.Running++
		case sandbox.StatusStopped:
			response.Totals.Stopped++
		}
	}
	return json.NewEncoder(out).Encode(response)
}

func newestSandboxL3Manifest(manifests []*sandboxexecution.Manifest) *sandboxexecution.Manifest {
	if len(manifests) == 0 {
		return nil
	}
	sorted := append([]*sandboxexecution.Manifest(nil), manifests...)
	sort.Slice(sorted, func(i, j int) bool {
		leftRecoverable := sandboxL3ExecutionRecoverable(sorted[i])
		rightRecoverable := sandboxL3ExecutionRecoverable(sorted[j])
		if leftRecoverable != rightRecoverable {
			return leftRecoverable
		}
		if !sorted[i].StartedAt.Equal(sorted[j].StartedAt) {
			return sorted[i].StartedAt.After(sorted[j].StartedAt)
		}
		return sorted[i].ID > sorted[j].ID
	})
	return sorted[0]
}

func sandboxL3ActiveJobState(state string) bool {
	return state == sandboxworker.JobStateQueued || state == sandboxworker.JobStateRunning
}

func sandboxL3TerminalJobState(state string) bool {
	switch state {
	case sandboxworker.JobStateSucceeded,
		sandboxworker.JobStateFailed,
		sandboxworker.JobStateCanceled,
		sandboxworker.JobStateInterrupted,
		sandboxworker.JobStateUnknown:
		return true
	default:
		return false
	}
}

func cloneL3Time(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func init() {
	sandboxCmd.AddCommand(
		newSandboxLogsCommand(),
		newSandboxRecoverCommand(),
		newSandboxRecoverySyncOutCommand(),
	)
}
