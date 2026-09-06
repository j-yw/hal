package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestSandboxWorkerJobJSONCommandFinalization(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		for _, syncOut := range []bool{false, true} {
			for _, failure := range []bool{false, true} {
				name := string(purpose)
				if syncOut {
					name += "/sync-out"
				}
				if failure {
					name += "/release-failure"
				}
				t.Run(name, func(t *testing.T) {
					result := runWorkerJSONCommandFixture(t, purpose, workerJSONCommandCase{syncOut: syncOut, releaseFailure: failure})
					raw := decodeWorkerJSONCommandDocument(t, result.output)
					if raw["ok"] != !failure || (result.err != nil) != failure {
						t.Fatalf("ok/error = %v/%v, want ok=%v; output=%s", raw["ok"], result.err, !failure, result.output)
					}
					if raw["futureField"] != "preserved" {
						t.Fatal("validated additive field was lost")
					}
					if purpose == sandboxexecution.PurposeRun && (raw["complete"] != true || raw["storyId"] != "US-008") {
						t.Fatalf("trusted inner story facts were lost: %s", result.output)
					}
					if failure {
						if !strings.Contains(result.err.Error(), "lease_release_failed") || raw["error"] == "" || raw["summary"] == "inner success" {
							t.Fatalf("outer failure was not represented: %v / %s", result.err, result.output)
						}
						if raw["sandboxExecutionId"] != result.executionID || result.manifest.Finalization.State != sandboxexecution.FinalizationStateBlocked {
							t.Fatal("recovery identity or blocked finalization was lost")
						}
					} else if !syncOut {
						if _, present := raw["sandboxExecutionId"]; present {
							t.Fatal("default successful output gained execution identity")
						}
					}
					if _, present := raw["syncOut"]; present != syncOut {
						t.Fatalf("syncOut presence = %v, want %v", present, syncOut)
					}
					assertWorkerJSONCommandSafe(t, result.output)
				})
			}
		}
	}
}

func TestSandboxWorkerJobJSONCommandRejectsInvalidOutput(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		for _, kind := range []string{"empty", "partial", "multiple", "null", "array", "wrong-version", "missing-ok", "string-ok", "missing-fields", "stdout-truncated", "retention-gap"} {
			t.Run(string(purpose)+"/"+kind, func(t *testing.T) {
				result := runWorkerJSONCommandFixture(t, purpose, workerJSONCommandCase{invalid: kind})
				if result.err == nil {
					t.Fatalf("invalid output succeeded: %s", result.output)
				}
				raw := decodeWorkerJSONCommandDocument(t, result.output)
				if raw["ok"] != false || raw["sandboxExecutionId"] != result.executionID || raw["error"] == "" {
					t.Fatalf("invalid output did not become a recoverable typed failure: %s", result.output)
				}
				if purpose == sandboxexecution.PurposeRun && raw["complete"] != false {
					t.Fatalf("invalid output manufactured completion: %s", result.output)
				}
				assertWorkerJSONCommandSafe(t, result.output)
			})
		}
	}
}

func TestSandboxWorkerJobJSONCommandDetachDoesNotPublishInnerCompletion(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			result := runWorkerJSONCommandFixture(t, purpose, workerJSONCommandCase{detached: true})
			if !isSandboxWorkerJobDetachedError(result.err) || !errors.Is(result.err, context.Canceled) {
				t.Fatalf("detached error identity changed: %v", result.err)
			}
			raw := decodeWorkerJSONCommandDocument(t, result.output)
			if raw["ok"] != false || raw["sandboxExecutionId"] != result.executionID || raw["summary"] == "inner success" {
				t.Fatalf("detached output claimed completion: %s", result.output)
			}
			if purpose == sandboxexecution.PurposeRun && raw["complete"] != false {
				t.Fatal("detached run claimed complete")
			}
			if result.manifest.Finalization.State != sandboxexecution.FinalizationStatePending || result.manifest.FinishedAt != nil || result.releaseCalls != 0 || result.driver.copyOutCalls != 0 || result.driver.cancelCalls != 0 {
				t.Fatalf("detach performed finalization or canceled healthy work: %+v", result)
			}
		})
	}
}

func TestSandboxWorkerJobJSONCommandInnerOutcome(t *testing.T) {
	bounded := runWorkerJSONCommandFixture(t, sandboxexecution.PurposeRun, workerJSONCommandCase{invalid: "bounded-run"})
	raw := decodeWorkerJSONCommandDocument(t, bounded.output)
	if bounded.err != nil || raw["ok"] != true || raw["complete"] != false {
		t.Fatalf("successful bounded run was rejected: %v / %s", bounded.err, bounded.output)
	}
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			result := runWorkerJSONCommandFixture(t, purpose, workerJSONCommandCase{invalid: "inner-failure"})
			raw := decodeWorkerJSONCommandDocument(t, result.output)
			var exitErr *ExitCodeError
			if !errors.As(result.err, &exitErr) || exitErr.Code != ExitCodeExpectedNonZero || raw["ok"] != false {
				t.Fatalf("inner failure without execution error returned success: %v / %s", result.err, result.output)
			}
			stderrOnly := runWorkerJSONCommandFixture(t, purpose, workerJSONCommandCase{invalid: "stderr-truncated"})
			if stderrOnly.err != nil || decodeWorkerJSONCommandDocument(t, stderrOnly.output)["ok"] != true {
				t.Fatalf("stderr-only truncation rejected intact stdout: %v / %s", stderrOnly.err, stderrOnly.output)
			}
		})
	}
}

type workerJSONCommandCase struct {
	syncOut        bool
	releaseFailure bool
	detached       bool
	invalid        string
}

type workerJSONCommandResult struct {
	output       string
	err          error
	executionID  string
	manifest     *sandboxexecution.Manifest
	driver       *fakeSandboxWorkerJobDriver
	releaseCalls int
}

func runWorkerJSONCommandFixture(t *testing.T, purpose sandboxexecution.Purpose, scenario workerJSONCommandCase) workerJSONCommandResult {
	t.Helper()
	projectDir := t.TempDir()
	store := newPrivateSandboxExecutionTestStore(t)
	executionID := "worker-json-" + string(purpose)
	now := time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC)
	target := workerRootlessCachedSandbox("worker-rootless")
	target.Host.ID, target.Runtime.RuntimeID, target.Runtime.WorkerID = "host-1", "runtime-1", "worker-1"
	target.Lease = &sandbox.SandboxLeaseRef{ID: "lease-json", RunID: executionID, Purpose: string(purpose)}
	queued := queuedSandboxWorkerJob(executionID)
	terminal := queued
	startedAt, finishedAt := now.Add(-2*time.Second), now.Add(-time.Second)
	terminal.State, terminal.StartedAt, terminal.HeartbeatAt, terminal.FinishedAt = sandboxworker.JobStateSucceeded, &startedAt, &startedAt, &finishedAt
	exitCode := 0
	terminal.ExitCode = &exitCode
	data := workerJSONCommandPayload(t, purpose, scenario.invalid)
	terminal.LogCursor = 1
	if scenario.detached {
		terminal.State, terminal.FinishedAt, terminal.ExitCode = sandboxworker.JobStateRunning, nil, nil
	}
	if scenario.invalid == "stdout-truncated" {
		terminal.StdoutTruncated = true
	}
	if scenario.invalid == "stderr-truncated" {
		terminal.StderrTruncated = true
	}
	page := sandboxworker.JobLogsResponse{
		ContractVersion: sandboxworker.JobContractVersion, JobID: terminal.ID, NextCursor: 1,
		Records: []sandboxworker.JobLogRecord{{Cursor: 1, Stream: sandboxworker.JobLogStreamStdout, Data: data, Timestamp: startedAt}},
	}
	if data == "" {
		terminal.LogCursor, page.NextCursor, page.Records = 0, 0, nil
	}
	if scenario.invalid == "retention-gap" {
		terminal.LogCursor, page.NextCursor, page.Records[0].Cursor = 2, 2, 2
		page.OldestCursor = 2
		page.Truncated = true
	}
	driver := &fakeSandboxWorkerJobDriver{
		startJob: queued, statusJobs: []sandboxworker.Job{terminal, terminal},
		logPages: []sandboxworker.JobLogsResponse{page, page},
		exec: func(sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(req sandboxruntime.CopyRequest) error {
			return os.WriteFile(req.DestinationPath, []byte("fake terminal artifact"), 0o600)
		},
	}
	var output bytes.Buffer
	result := workerJSONCommandResult{executionID: executionID, driver: driver}
	plan := func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
		return terminalWorkerJobWorkspacePlan(projectDir), nil
	}
	release := func(string) (*sandbox.SandboxLease, error) {
		result.releaseCalls++
		if scenario.releaseFailure {
			return nil, errors.New("secret=raw-json-secret /private/worker.sock")
		}
		return &sandbox.SandboxLease{Status: sandbox.SandboxLeaseStatusReleased}, nil
	}
	runJob := func(ctx context.Context, out, errOut io.Writer, persist func(*sandboxexecution.WorkerJobReference) error) error {
		return runSandboxWorkerJob(ctx, sandboxWorkerJobRunRequest{
			ExecutionID: executionID, Driver: driver, HostID: "host-1", Target: sandboxRuntimeTargetFromState(target),
			Command: sandboxexec.CommandRequest{Command: []string{"hal", string(purpose), "--json"}, Stdout: out, Stderr: errOut},
			Persist: persist, Wait: func(context.Context) error { return context.Canceled },
		})
	}
	if purpose == sandboxexecution.PurposeRun {
		result.err = runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			JSON: true, Base: "main", BaseChanged: true,
			SandboxHostID: "host-1", SandboxHostChanged: true, SandboxRuntime: sandbox.SandboxRuntimeDriverRootlessPodman, SandboxRuntimeChanged: true,
			SandboxSyncOut: scenario.syncOut, SandboxSyncOutChanged: scenario.syncOut,
		}, &output, io.Discard, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil }, newExecutionID: func(time.Time) string { return executionID },
			now: func() time.Time { return now }, workingDir: func() (string, error) { return projectDir, nil }, planWorkspace: plan, releaseLease: release,
			execute: func(ctx context.Context, _ runSandboxRequest, out, errOut io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
				err := runJob(ctx, out, errOut, hooks.OnWorkerJobUpdate)
				return runSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)}, RuntimeDriver: driver, RemoteStarted: data != ""}, err
			},
		})
	} else {
		result.err = runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			JSON: true, Base: "main", BaseChanged: true,
			SandboxHostID: "host-1", SandboxHostChanged: true, SandboxRuntime: sandbox.SandboxRuntimeDriverRootlessPodman, SandboxRuntimeChanged: true,
			SandboxSyncOut: scenario.syncOut, SandboxSyncOutChanged: scenario.syncOut,
		}, &output, io.Discard, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil }, newExecutionID: func(time.Time) string { return executionID },
			now: func() time.Time { return now }, planWorkspace: plan, releaseLease: release,
			execute: func(ctx context.Context, _ autoSandboxRequest, out, errOut io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				if err := hooks.OnTargetReady(target); err != nil {
					return autoSandboxExecutionResult{}, err
				}
				err := runJob(ctx, out, errOut, hooks.OnWorkerJobUpdate)
				return autoSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)}, RuntimeDriver: driver, RemoteStarted: data != ""}, err
			},
		})
	}
	result.output = output.String()
	var err error
	result.manifest, err = store.LoadManifest(executionID)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func workerJSONCommandPayload(t *testing.T, purpose sandboxexecution.Purpose, invalid string) string {
	t.Helper()
	var payload any = RunResult{ContractVersion: 1, OK: true, Iterations: 2, Complete: true, StoryID: "US-008", Summary: "inner success"}
	if purpose == sandboxexecution.PurposeAuto {
		step := AutoStep{Status: autoStepStatusCompleted}
		payload = AutoResult{ContractVersion: 2, OK: true, EntryMode: "report_discovery", Summary: "inner success", Steps: AutoSteps{
			Analyze: step, Spec: step, Branch: step, Convert: step, Validate: step, Run: step, Review: step, CI: step, Report: step,
			Archive: AutoStep{Status: autoStepStatusCompleted, Path: ".hal/archive/worker-json"},
		}}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["futureField"] = "preserved"
	switch invalid {
	case "empty":
		return ""
	case "partial":
		return `{"ok":true,"secret":"raw-json-secret"`
	case "null":
		return "null"
	case "array":
		return "[]"
	case "wrong-version":
		raw["contractVersion"] = 99
	case "missing-ok":
		delete(raw, "ok")
	case "string-ok":
		raw["ok"] = "true"
	case "missing-fields":
		delete(raw, "summary")
	case "bounded-run":
		raw["complete"] = false
	case "inner-failure":
		raw["ok"], raw["summary"], raw["error"] = false, "inner failure", "inner failure"
	}
	data, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if invalid == "multiple" {
		return string(data) + "\n{}"
	}
	return string(data) + "\n"
}

func decodeWorkerJSONCommandDocument(t *testing.T, output string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil || raw == nil {
		t.Fatalf("expected one JSON object, got %q: %v", output, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("additional stdout document or bytes: %q", output)
	}
	return raw
}

func assertWorkerJSONCommandSafe(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{"raw-json-secret", "/private/", "worker.sock", "processGroupTerminated", "terminalPublication", `"finalization"`, "networkEnforcementMetadata"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("public output exposed %q: %s", forbidden, output)
		}
	}
}
