package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

// Worker-job executions never apply implicitly; `hal sandbox apply` stays the
// only host mutation surface. A requested --sandbox-apply must therefore name
// that handoff instead of being dropped silently after a successful job.
func TestWorkerJobSandboxApplyRequestReportsExplicitApplyHandoff(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		for _, tc := range []struct {
			name       string
			state      string
			apply      bool
			wantNotice bool
		}{
			{name: "succeeded with apply", state: sandboxworker.JobStateSucceeded, apply: true, wantNotice: true},
			{name: "succeeded without apply", state: sandboxworker.JobStateSucceeded, apply: false},
			{name: "failed with apply", state: sandboxworker.JobStateFailed, apply: true},
		} {
			t.Run(string(purpose)+"/"+tc.name, func(t *testing.T) {
				executionID := "notice-" + string(purpose) + "-" + strings.ReplaceAll(tc.name, " ", "-")
				stdout, stderr, applyCalls := runWorkerJobApplyNoticeScenario(t, purpose, executionID, tc.state, tc.apply)

				if applyCalls != 0 {
					t.Fatalf("applySyncOut calls = %d, want 0: worker jobs never apply implicitly", applyCalls)
				}
				wantCommand := "hal sandbox apply " + executionID
				if strings.Contains(stdout, wantCommand) {
					t.Fatalf("stdout carries the apply handoff; it belongs on stderr only:\n%s", stdout)
				}
				gotNotice := strings.Contains(stderr, wantCommand)
				if gotNotice != tc.wantNotice {
					t.Fatalf("stderr contains %q = %v, want %v; stderr:\n%s", wantCommand, gotNotice, tc.wantNotice, stderr)
				}
				if tc.wantNotice && !strings.Contains(stderr, "--sandbox-apply") {
					t.Fatalf("stderr notice does not name the ignored --sandbox-apply flag:\n%s", stderr)
				}
			})
		}
	}
}

func runWorkerJobApplyNoticeScenario(t *testing.T, purpose sandboxexecution.Purpose, executionID, state string, apply bool) (string, string, int) {
	t.Helper()
	now := time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)
	projectDir := t.TempDir()
	store := newPrivateSandboxExecutionTestStore(t)
	target := workerRootlessCachedSandbox("worker-rootless")
	target.Host.ID = "host-1"
	target.Runtime.RuntimeID = "runtime-1"
	target.Runtime.WorkerID = "worker-1"
	target.Lease = &sandbox.SandboxLeaseRef{ID: "lease-" + executionID, RunID: executionID, Purpose: string(purpose)}

	terminal := queuedSandboxWorkerJob(executionID)
	terminal.State = state
	startedAt := now.Add(time.Second)
	finishedAt := now.Add(2 * time.Second)
	terminal.StartedAt = &startedAt
	terminal.HeartbeatAt = &startedAt
	terminal.FinishedAt = &finishedAt
	terminal.LogCursor = 1
	stdoutData := "terminal output\n"
	if purpose == sandboxexecution.PurposeAuto {
		stdoutData = autoSandboxRemoteSuccessJSONWithArchivePath("done", ".hal/archive/2026-10-01-notice") + "\n"
	}
	exitCode := 0
	if state == sandboxworker.JobStateFailed {
		exitCode = ExitCodeExpectedNonZero
	}
	terminal.ExitCode = &exitCode
	driver := &fakeSandboxWorkerJobDriver{
		statusJobs: []sandboxworker.Job{terminal},
		logPages: []sandboxworker.JobLogsResponse{{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           terminal.ID,
			Records: []sandboxworker.JobLogRecord{{
				Cursor:    1,
				Stream:    sandboxworker.JobLogStreamStdout,
				Data:      stdoutData,
				Timestamp: finishedAt,
			}},
			NextCursor: 1,
		}},
		exec: func(sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(req sandboxruntime.CopyRequest) error {
			return os.WriteFile(req.DestinationPath, []byte("fake terminal artifact"), 0o600)
		},
	}
	workerJob := sandboxWorkerJobReference(terminal, terminal.LogCursor)
	execErr := sandboxWorkerJobTerminalResult(terminal)
	applyCalls := 0
	applySyncOut := func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		applyCalls++
		return sandboxworkspace.SafeApplyResult{}, nil
	}
	releaseLease := func(string) (*sandbox.SandboxLease, error) {
		return &sandbox.SandboxLease{Status: sandbox.SandboxLeaseStatusReleased}, nil
	}
	planWorkspace := func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
		return terminalWorkerJobWorkspacePlan(projectDir), nil
	}

	var stdout, stderr bytes.Buffer
	var err error
	switch purpose {
	case sandboxexecution.PurposeRun:
		err = runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			SandboxHostID:         "host-1",
			SandboxHostChanged:    true,
			SandboxRuntime:        sandbox.SandboxRuntimeDriverRootlessPodman,
			SandboxRuntimeChanged: true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
			SandboxApply:          apply,
			SandboxApplyChanged:   apply,
		}, &stdout, &stderr, runSandboxDeps{
			defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string { return executionID },
			now:            func() time.Time { return now },
			workingDir:     func() (string, error) { return projectDir, nil },
			planWorkspace:  planWorkspace,
			execute: func(_ context.Context, _ runSandboxRequest, _, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
				if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
					return runSandboxExecutionResult{}, err
				}
				return runSandboxExecutionResult{
					Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
					RuntimeDriver: driver,
				}, execErr
			},
			applySyncOut: applySyncOut,
			releaseLease: releaseLease,
		})
	case sandboxexecution.PurposeAuto:
		err = runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			SandboxHostID:         "host-1",
			SandboxHostChanged:    true,
			SandboxRuntime:        sandbox.SandboxRuntimeDriverRootlessPodman,
			SandboxRuntimeChanged: true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
			SandboxApply:          apply,
			SandboxApplyChanged:   apply,
		}, &stdout, &stderr, autoSandboxDeps{
			defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string { return executionID },
			now:            func() time.Time { return now },
			planWorkspace:  planWorkspace,
			execute: func(_ context.Context, _ autoSandboxRequest, foreground, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				if _, err := io.WriteString(foreground, stdoutData); err != nil {
					return autoSandboxExecutionResult{}, err
				}
				if err := hooks.OnTargetReady(target); err != nil {
					return autoSandboxExecutionResult{}, err
				}
				if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
					return autoSandboxExecutionResult{}, err
				}
				return autoSandboxExecutionResult{
					Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
					RuntimeDriver: driver,
				}, execErr
			},
			applySyncOut: applySyncOut,
			releaseLease: releaseLease,
		})
	}
	if state == sandboxworker.JobStateSucceeded && err != nil {
		t.Fatalf("succeeded worker job returned error: %v", err)
	}
	if state != sandboxworker.JobStateSucceeded && err == nil {
		t.Fatalf("%s worker job returned nil error", state)
	}
	return stdout.String(), stderr.String(), applyCalls
}
