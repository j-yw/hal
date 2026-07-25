package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

// fakeSandboxWorkerJobAdapter lets older command tests exercise the new
// daemon-job route without weakening the production fail-closed capability
// check. Each adapter owns its jobs, so parallel tests cannot share state.
type fakeSandboxWorkerJobAdapter struct {
	sandboxruntime.Driver

	mu           sync.Mutex
	bySubmission map[string]*fakeSandboxWorkerJob
	byID         map[string]*fakeSandboxWorkerJob
}

type fakeSandboxWorkerJob struct {
	job  sandboxworker.Job
	logs []sandboxworker.JobLogRecord
}

func withFakeSandboxWorkerJobs(driver sandboxruntime.Driver) sandboxruntime.Driver {
	return &fakeSandboxWorkerJobAdapter{
		Driver:       driver,
		bySubmission: make(map[string]*fakeSandboxWorkerJob),
		byID:         make(map[string]*fakeSandboxWorkerJob),
	}
}

func (adapter *fakeSandboxWorkerJobAdapter) JobStart(
	ctx context.Context,
	submissionID string,
	req sandboxruntime.ExecRequest,
) (*sandboxworker.Job, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	req.Stdout = &stdout
	req.Stderr = &stderr

	result, execErr := adapter.Driver.Exec(ctx, req)
	if execErr != nil && errors.Is(execErr, context.Canceled) {
		return nil, execErr
	}

	now := time.Now().UTC()
	exitCode := 0
	if result != nil {
		exitCode = result.ExitCode
	}
	if execErr != nil && exitCode == 0 {
		var coded interface{ ExitCode() int }
		if errors.As(execErr, &coded) {
			exitCode = coded.ExitCode()
		} else {
			exitCode = 1
		}
	}

	state := sandboxworker.JobStateSucceeded
	failureCode := ""
	if execErr != nil || exitCode != 0 {
		state = sandboxworker.JobStateFailed
		failureCode = "exec_failed"
	}
	logs := fakeSandboxWorkerJobLogs(now, stdout.String(), stderr.String())
	sum := sha256.Sum256([]byte(submissionID))
	job := sandboxworker.Job{
		ContractVersion: sandboxworker.JobContractVersion,
		ID:              "job-" + hex.EncodeToString(sum[:]),
		SubmissionKey:   sandboxWorkerJobSubmissionKey(submissionID),
		WorkerID:        req.Target.Runtime.WorkerID,
		HostID:          req.Target.Runtime.WorkerID,
		RuntimeDriver:   req.Target.Runtime.Driver,
		RuntimeID:       req.Target.Runtime.RuntimeID,
		State:           state,
		SubmittedAt:     now,
		StartedAt:       &now,
		HeartbeatAt:     &now,
		FinishedAt:      &now,
		LogCursor:       uint64(len(logs)),
		ExitCode:        &exitCode,
		FailureCode:     failureCode,
	}
	record := &fakeSandboxWorkerJob{job: job, logs: logs}

	adapter.mu.Lock()
	adapter.bySubmission[submissionID] = record
	adapter.byID[job.ID] = record
	adapter.mu.Unlock()

	return cloneFakeSandboxWorkerJob(job), nil
}

func (adapter *fakeSandboxWorkerJobAdapter) JobResolve(
	_ context.Context,
	submissionID string,
) (*sandboxworker.Job, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	record := adapter.bySubmission[submissionID]
	if record == nil {
		return nil, fmt.Errorf("fake worker job submission was not found")
	}
	return cloneFakeSandboxWorkerJob(record.job), nil
}

func (adapter *fakeSandboxWorkerJobAdapter) JobStatus(
	_ context.Context,
	jobID string,
) (*sandboxworker.Job, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	record := adapter.byID[jobID]
	if record == nil {
		return nil, fmt.Errorf("fake worker job was not found")
	}
	return cloneFakeSandboxWorkerJob(record.job), nil
}

func (adapter *fakeSandboxWorkerJobAdapter) JobLogs(
	_ context.Context,
	jobID string,
	cursor uint64,
	_ int64,
) (*sandboxworker.JobLogsResponse, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	record := adapter.byID[jobID]
	if record == nil {
		return nil, fmt.Errorf("fake worker job was not found")
	}
	if cursor > uint64(len(record.logs)) {
		return nil, fmt.Errorf("fake worker job cursor is invalid")
	}
	logs := append([]sandboxworker.JobLogRecord(nil), record.logs[cursor:]...)
	return &sandboxworker.JobLogsResponse{
		ContractVersion: sandboxworker.JobContractVersion,
		JobID:           jobID,
		Records:         logs,
		NextCursor:      uint64(len(record.logs)),
	}, nil
}

func fakeSandboxWorkerJobLogs(at time.Time, stdout, stderr string) []sandboxworker.JobLogRecord {
	logs := make([]sandboxworker.JobLogRecord, 0, 2)
	if stdout != "" {
		logs = append(logs, sandboxworker.JobLogRecord{
			Cursor:    uint64(len(logs) + 1),
			Stream:    sandboxworker.JobLogStreamStdout,
			Data:      stdout,
			Timestamp: at,
		})
	}
	if stderr != "" {
		logs = append(logs, sandboxworker.JobLogRecord{
			Cursor:    uint64(len(logs) + 1),
			Stream:    sandboxworker.JobLogStreamStderr,
			Data:      stderr,
			Timestamp: at,
		})
	}
	return logs
}

func cloneFakeSandboxWorkerJob(job sandboxworker.Job) *sandboxworker.Job {
	cloned := job
	if job.StartedAt != nil {
		value := *job.StartedAt
		cloned.StartedAt = &value
	}
	if job.HeartbeatAt != nil {
		value := *job.HeartbeatAt
		cloned.HeartbeatAt = &value
	}
	if job.FinishedAt != nil {
		value := *job.FinishedAt
		cloned.FinishedAt = &value
	}
	if job.ExitCode != nil {
		value := *job.ExitCode
		cloned.ExitCode = &value
	}
	return &cloned
}
