package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const sandboxWorkerJobPollInterval = 500 * time.Millisecond

// sandboxWorkerJobDriver is the optional daemon-job capability used only by
// explicitly selected worker-backed rootless runtimes. Cancellation is
// deliberately absent: command context loss must leave accepted work owned by
// the daemon and recoverable through its durable identity.
type sandboxWorkerJobDriver interface {
	JobStart(context.Context, string, sandboxruntime.ExecRequest) (*sandboxworker.Job, error)
	JobResolve(context.Context, string) (*sandboxworker.Job, error)
	JobStatus(context.Context, string) (*sandboxworker.Job, error)
	JobLogs(context.Context, string, uint64, int64) (*sandboxworker.JobLogsResponse, error)
}

type sandboxWorkerJobRunRequest struct {
	ExecutionID string
	Driver      sandboxWorkerJobDriver
	HostID      string
	Target      sandboxruntime.Target
	Command     sandboxexec.CommandRequest
	Persist     func(*sandboxexecution.WorkerJobReference) error
	Wait        func(context.Context) error
}

type sandboxWorkerJobCommandRequest struct {
	ExecutionID  string
	UseWorkerJob bool
	HostID       string
	Run          sandboxexec.RunContext
	Command      sandboxexec.CommandRequest
	Persist      func(*sandboxexecution.WorkerJobReference) error
	Wait         func(context.Context) error
}

// sandboxWorkerJobDetachedError means the daemon accepted the final command,
// but foreground observation ended before a proven terminal state.
type sandboxWorkerJobDetachedError struct {
	Cause error
}

func (err *sandboxWorkerJobDetachedError) Error() string {
	if err == nil {
		return ""
	}
	return "sandbox worker job detached after durable acceptance; recover with the execution ID"
}

func (err *sandboxWorkerJobDetachedError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func (*sandboxWorkerJobDetachedError) Recoverable() bool {
	return true
}

func (*sandboxWorkerJobDetachedError) Detached() bool {
	return true
}

func sandboxWorkerJobSubmissionID(executionID string) string {
	if strings.TrimSpace(executionID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("hal:sandbox-worker-job:v1\x00" + strings.TrimSpace(executionID)))
	return "execution-" + hex.EncodeToString(sum[:])
}

func runSandboxWorkerJobOrSync(ctx context.Context, req sandboxWorkerJobCommandRequest) error {
	jobDriver, supportsJobs := req.Run.Driver.(sandboxWorkerJobDriver)
	if !req.UseWorkerJob || !supportsJobs {
		return runSandboxRuntimeExec(ctx, req.Run, req.Command)
	}
	return runSandboxWorkerJob(ctx, sandboxWorkerJobRunRequest{
		ExecutionID: req.ExecutionID,
		Driver:      jobDriver,
		HostID:      req.HostID,
		Target:      req.Run.Target,
		Command:     req.Command,
		Persist:     req.Persist,
		Wait:        req.Wait,
	})
}

func runSandboxWorkerJob(ctx context.Context, req sandboxWorkerJobRunRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Driver == nil {
		return fmt.Errorf("sandbox worker job driver is required")
	}
	if req.Persist == nil {
		return fmt.Errorf("sandbox worker job persistence hook is required")
	}
	submissionID := sandboxWorkerJobSubmissionID(req.ExecutionID)
	if submissionID == "" {
		return fmt.Errorf("sandbox worker job execution identity is required")
	}
	execReq := sandboxruntime.ExecRequest{
		Target:  req.Target,
		Args:    runSandboxRemoteExecArgs(req.Command),
		Stdout:  io.Discard,
		Stderr:  io.Discard,
		Stdin:   req.Command.Stdin,
		Env:     cloneSandboxWorkerJobEnv(req.Command.Env),
		WorkDir: strings.TrimSpace(req.Command.WorkDir),
	}
	job, startErr := req.Driver.JobStart(ctx, submissionID, execReq)
	if startErr != nil {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		resolved, resolveErr := req.Driver.JobResolve(resolveCtx, submissionID)
		if resolveErr != nil {
			return &sandboxWorkerJobDetachedError{
				Cause: errors.Join(startErr, fmt.Errorf("resolve sandbox worker job after uncertain acceptance: %w", resolveErr)),
			}
		}
		job = resolved
	}
	if err := validateSandboxWorkerJobIdentity(job, submissionID, "", req.HostID, req.Target); err != nil {
		return &sandboxWorkerJobDetachedError{Cause: err}
	}

	reference := sandboxWorkerJobReference(*job, 0)
	if reference == nil {
		return fmt.Errorf("sandbox worker job returned unsafe durable metadata")
	}
	if err := req.Persist(reference); err != nil {
		return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("persist accepted sandbox worker job: %w", err)}
	}
	if err := ctx.Err(); err != nil {
		return &sandboxWorkerJobDetachedError{Cause: err}
	}

	wait := req.Wait
	if wait == nil {
		wait = waitForSandboxWorkerJobPoll
	}
	for {
		if err := ctx.Err(); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: err}
		}
		status, err := req.Driver.JobStatus(ctx, reference.JobID)
		if err != nil {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("fetch sandbox worker job status: %w", err)}
		}
		if err := validateSandboxWorkerJobIdentity(status, submissionID, reference.JobID, req.HostID, req.Target); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: err}
		}
		if status.LogCursor < reference.LogCursor {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("sandbox worker job log cursor regressed")}
		}
		reference = sandboxWorkerJobReference(*status, reference.LogCursor)
		if reference == nil {
			return fmt.Errorf("sandbox worker job status returned unsafe durable metadata")
		}
		if err := req.Persist(reference); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("persist sandbox worker job status: %w", err)}
		}

		if err := drainSandboxWorkerJobLogs(ctx, req, status, reference); err != nil {
			return err
		}
		if err := req.Persist(reference); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("persist sandbox worker job log cursor: %w", err)}
		}
		if sandboxWorkerJobTerminal(status.State) {
			return sandboxWorkerJobTerminalResult(*status)
		}
		if err := wait(ctx); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: err}
		}
	}
}

func drainSandboxWorkerJobLogs(
	ctx context.Context,
	req sandboxWorkerJobRunRequest,
	status *sandboxworker.Job,
	reference *sandboxexecution.WorkerJobReference,
) error {
	if status == nil || reference == nil {
		return fmt.Errorf("sandbox worker job log drain requires durable state")
	}
	for reference.LogCursor < status.LogCursor {
		logs, err := req.Driver.JobLogs(ctx, reference.JobID, reference.LogCursor, sandboxworker.DefaultJobLogReadBytes)
		if err != nil {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("fetch sandbox worker job logs: %w", err)}
		}
		if err := validateSandboxWorkerJobLogs(logs, reference.JobID, reference.LogCursor, status.LogCursor); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: err}
		}
		if err := writeSandboxWorkerJobLogs(req.Command, logs.Records); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: err}
		}
		reference.LogCursor = logs.NextCursor
		if err := req.Persist(reference); err != nil {
			return &sandboxWorkerJobDetachedError{Cause: fmt.Errorf("persist sandbox worker job log cursor: %w", err)}
		}
	}
	return nil
}

func validateSandboxWorkerJobIdentity(
	job *sandboxworker.Job,
	submissionID, jobID, hostID string,
	target sandboxruntime.Target,
) error {
	if job == nil {
		return fmt.Errorf("sandbox worker job response is required")
	}
	if err := job.Validate(); err != nil {
		return fmt.Errorf("sandbox worker job response is invalid: %w", err)
	}
	expectedSubmissionKey := sandboxWorkerJobSubmissionKey(submissionID)
	if job.SubmissionKey != expectedSubmissionKey {
		return fmt.Errorf("sandbox worker job submission identity did not match selected execution")
	}
	if jobID != "" && strings.TrimSpace(job.ID) != strings.TrimSpace(jobID) {
		return fmt.Errorf("sandbox worker job identity changed during observation")
	}
	if strings.TrimSpace(job.HostID) != strings.TrimSpace(hostID) {
		return fmt.Errorf("sandbox worker job host identity did not match selected target")
	}
	if strings.TrimSpace(job.WorkerID) != strings.TrimSpace(target.Runtime.WorkerID) {
		return fmt.Errorf("sandbox worker job worker identity did not match selected target")
	}
	if strings.TrimSpace(job.RuntimeDriver) != strings.TrimSpace(target.Runtime.Driver) {
		return fmt.Errorf("sandbox worker job runtime driver did not match selected target")
	}
	if strings.TrimSpace(job.RuntimeID) != strings.TrimSpace(target.Runtime.RuntimeID) {
		return fmt.Errorf("sandbox worker job runtime identity did not match selected target")
	}
	return nil
}

func validateSandboxWorkerJobLogs(logs *sandboxworker.JobLogsResponse, jobID string, cursor, terminalCursor uint64) error {
	if logs == nil {
		return fmt.Errorf("sandbox worker job logs response is required")
	}
	if err := logs.Validate(); err != nil {
		return fmt.Errorf("sandbox worker job logs response is invalid: %w", err)
	}
	if logs.JobID != jobID {
		return fmt.Errorf("sandbox worker job log identity did not match selected job")
	}
	if logs.NextCursor <= cursor || logs.NextCursor > terminalCursor {
		return fmt.Errorf("sandbox worker job log cursor did not make bounded progress")
	}
	var size int64
	previous := cursor
	cursorGap := false
	for _, record := range logs.Records {
		size += int64(len([]byte(record.Data)))
		if record.Cursor <= previous {
			return fmt.Errorf("sandbox worker job log record cursor did not follow requested cursor")
		}
		if record.Cursor-previous > 1 {
			cursorGap = true
		}
		previous = record.Cursor
	}
	if size > sandboxworker.DefaultJobLogReadBytes {
		return fmt.Errorf("sandbox worker job log page exceeded requested bound")
	}
	if logs.NextCursor > previous {
		cursorGap = true
	}
	if cursorGap && !logs.Truncated {
		return fmt.Errorf("sandbox worker job log cursor gap lacked truncation proof")
	}
	return nil
}

func writeSandboxWorkerJobLogs(command sandboxexec.CommandRequest, records []sandboxworker.JobLogRecord) error {
	for _, record := range records {
		writer := command.Stdout
		if record.Stream == sandboxworker.JobLogStreamStderr {
			writer = command.Stderr
		}
		if writer == nil {
			writer = io.Discard
		}
		safe := sanitizeSandboxWorkerJobLogData(record.Data)
		if safe == "" {
			continue
		}
		if _, err := io.WriteString(writer, safe); err != nil {
			return fmt.Errorf("write sandbox worker job %s log: %w", record.Stream, err)
		}
	}
	return nil
}

func sanitizeSandboxWorkerJobLogData(data string) string {
	data = strings.ToValidUTF8(data, "\uFFFD")
	if strings.TrimSpace(data) == "" {
		return data
	}
	if factoryArtifactStringNeedsRedaction(data) || factoryLogContainsSecretAssignment(data) {
		if strings.HasSuffix(data, "\n") {
			return "[redacted]\n"
		}
		return "[redacted]"
	}
	return sanitizeCredentialedRemoteReferences(data)
}

func sandboxWorkerJobReference(job sandboxworker.Job, cursor uint64) *sandboxexecution.WorkerJobReference {
	return sandboxexecution.SanitizeWorkerJobReference(&sandboxexecution.WorkerJobReference{
		ContractVersion: job.ContractVersion,
		JobID:           job.ID,
		SubmissionKey:   job.SubmissionKey,
		WorkerID:        job.WorkerID,
		HostID:          job.HostID,
		RuntimeDriver:   job.RuntimeDriver,
		RuntimeID:       job.RuntimeID,
		State:           job.State,
		SubmittedAt:     job.SubmittedAt,
		StartedAt:       job.StartedAt,
		HeartbeatAt:     job.HeartbeatAt,
		FinishedAt:      job.FinishedAt,
		LogCursor:       cursor,
	})
}

func sandboxWorkerJobSubmissionKey(submissionID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(submissionID)))
	return "submission-" + hex.EncodeToString(sum[:])
}

func sandboxWorkerJobTerminal(state string) bool {
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

func sandboxWorkerJobTerminalResult(job sandboxworker.Job) error {
	switch job.State {
	case sandboxworker.JobStateSucceeded:
		if job.ExitCode != nil && *job.ExitCode != 0 {
			return fmt.Errorf("sandbox worker job succeeded with an invalid exit status")
		}
		return nil
	case sandboxworker.JobStateFailed:
		if job.ExitCode != nil && *job.ExitCode > 0 {
			return exitWithCode(nil, *job.ExitCode, nil)
		}
		return fmt.Errorf("sandbox worker job failed")
	case sandboxworker.JobStateCanceled:
		return fmt.Errorf("sandbox worker job was canceled")
	case sandboxworker.JobStateInterrupted:
		return fmt.Errorf("sandbox worker job was interrupted")
	case sandboxworker.JobStateUnknown:
		return fmt.Errorf("sandbox worker job terminal state is unknown")
	default:
		return fmt.Errorf("sandbox worker job has not reached a terminal state")
	}
}

func waitForSandboxWorkerJobPoll(ctx context.Context) error {
	timer := time.NewTimer(sandboxWorkerJobPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cloneSandboxWorkerJobEnv(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	cloned := make(map[string]string, len(env))
	for key, value := range env {
		cloned[key] = value
	}
	return cloned
}

func isSandboxWorkerJobDetachedError(err error) bool {
	var detached *sandboxWorkerJobDetachedError
	return errors.As(err, &detached)
}
