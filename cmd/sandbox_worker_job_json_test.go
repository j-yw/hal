package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxWorkerJobJSONRequiredTypes(t *testing.T) {
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		valid := workerJSONCommandPayload(t, purpose, "")
		raw := decodeSandboxWorkerJobJSON([]byte(valid), purpose)
		if raw == nil {
			t.Fatal("valid payload was rejected")
		}
		fields := []string{"contractVersion", "ok", "summary"}
		if purpose == sandboxexecution.PurposeRun {
			fields = append(fields, "iterations", "complete")
		} else {
			fields = append(fields, "entryMode", "resumed", "steps")
		}
		for _, field := range fields {
			for _, kind := range []string{"missing", "null", "object"} {
				t.Run(string(purpose)+"/"+field+"/"+kind, func(t *testing.T) {
					copy := decodeSandboxWorkerJobJSON([]byte(valid), purpose)
					switch kind {
					case "missing":
						delete(copy, field)
					case "null":
						copy[field] = nil
					case "object":
						copy[field] = map[string]any{"unexpected": true}
					}
					data, err := json.Marshal(copy)
					if err != nil {
						t.Fatal(err)
					}
					if decodeSandboxWorkerJobJSON(data, purpose) != nil {
						t.Fatalf("accepted invalid %s: %s", field, data)
					}
				})
			}
		}
		duplicate := strings.Replace(valid, `"ok":true`, `"ok":false,"ok":true`, 1)
		if decodeSandboxWorkerJobJSON([]byte(duplicate), purpose) != nil {
			t.Fatal("duplicate ok was accepted")
		}
	}
	for _, mutation := range []string{"missing-step", "null-step", "missing-status", "invalid-status", "wrong-telemetry"} {
		t.Run(mutation, func(t *testing.T) {
			raw := decodeSandboxWorkerJobJSON([]byte(workerJSONCommandPayload(t, sandboxexecution.PurposeAuto, "")), sandboxexecution.PurposeAuto)
			steps := raw["steps"].(map[string]any)
			switch mutation {
			case "missing-step":
				delete(steps, "run")
			case "null-step":
				steps["run"] = nil
			case "missing-status":
				steps["run"] = map[string]any{}
			case "invalid-status":
				steps["run"] = map[string]any{"status": "finished"}
			case "wrong-telemetry":
				steps["run"] = map[string]any{"status": "completed", "iterations": "lots"}
			}
			data, _ := json.Marshal(raw)
			if decodeSandboxWorkerJobJSON(data, sandboxexecution.PurposeAuto) != nil {
				t.Fatalf("accepted invalid steps: %s", data)
			}
		})
	}
}

func TestSandboxWorkerJobJSONPublicationRequiresDurableCompletion(t *testing.T) {
	for _, scenario := range []string{"success", "outer-error", "missing-manifest", "pending", "wrong-purpose", "write-error"} {
		t.Run(scenario, func(t *testing.T) {
			store, id := seedCompletedWorkerJSONPublication(t)
			var capture sandboxWorkerJobJSONCapture
			payload := workerJSONCommandPayload(t, sandboxexecution.PurposeRun, "bounded-run")
			_, _ = io.WriteString(&capture, payload)
			publication := sandboxWorkerJobJSONPublication{purpose: sandboxexecution.PurposeRun, executionID: id, store: store, capture: &capture}
			sentinel := errors.New("secret=raw-json-secret /private/worker.sock")
			switch scenario {
			case "outer-error":
				publication.commandErr = sentinel
			case "missing-manifest":
				publication.executionID = "missing-execution"
			case "pending":
				if err := store.UpdateManifest(id, func(manifest *sandboxexecution.Manifest) error { manifest.Finalization = nil; return nil }); err != nil {
					t.Fatal(err)
				}
			case "wrong-purpose":
				publication.purpose = sandboxexecution.PurposeAuto
			}
			var output bytes.Buffer
			var writer io.Writer = &output
			if scenario == "write-error" {
				writer = workerJSONErrorWriter{sentinel}
			}
			err := outputSandboxWorkerJobJSON(writer, publication)
			if scenario == "write-error" {
				if !errors.Is(err, sentinel) {
					t.Fatalf("writer cause lost: %v", err)
				}
				return
			}
			raw := decodeWorkerJSONCommandDocument(t, output.String())
			if scenario == "success" {
				if err != nil || output.String() != payload || raw["complete"] != false {
					t.Fatalf("success shape changed: %v / %s", err, output.String())
				}
			} else {
				if err == nil || raw["ok"] != false {
					t.Fatalf("unproven success: %v / %s", err, output.String())
				}
				if scenario == "outer-error" && err != sentinel {
					t.Fatalf("original error identity changed: %v", err)
				}
			}
			assertWorkerJSONCommandSafe(t, output.String())
		})
	}
}

func TestSandboxWorkerJobJSONCaptureBoundsBeforeExecutorLineBuffer(t *testing.T) {
	var capture sandboxWorkerJobJSONCapture
	ctx := context.WithValue(context.Background(), sandboxWorkerJobJSONContextKey{}, &capture)
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	queued := queuedSandboxWorkerJob("bounded-json")
	terminal := queued
	started, finished := queued.SubmittedAt.Add(time.Second), queued.SubmittedAt.Add(2*time.Second)
	code := 0
	terminal.State, terminal.StartedAt, terminal.FinishedAt, terminal.ExitCode = sandboxworker.JobStateSucceeded, &started, &finished, &code
	chunk := strings.Repeat("x", int(sandboxworker.DefaultJobLogRecordBytes))
	pageCount := sandboxWorkerJobJSONLimit/len(chunk) + 2
	terminal.LogCursor = uint64(pageCount)
	driver := &fakeSandboxWorkerJobDriver{startJob: queued, statusJobs: []sandboxworker.Job{terminal}}
	for index := 1; index <= pageCount; index++ {
		driver.logPages = append(driver.logPages, sandboxworker.JobLogsResponse{
			ContractVersion: sandboxworker.JobContractVersion, JobID: terminal.ID, NextCursor: uint64(index),
			Records: []sandboxworker.JobLogRecord{{Cursor: uint64(index), Stream: sandboxworker.JobLogStreamStdout, Data: chunk, Timestamp: started}},
		})
	}
	target := workerRootlessCachedSandbox("worker-rootless")
	target.Status = sandbox.StatusRunning
	target.Host.ID, target.Runtime.RuntimeID, target.Runtime.WorkerID = "host-1", "runtime-1", "worker-1"
	maxLine := 0
	_, err := sandboxexec.Run(ctx, sandboxexec.CommandRequest{Purpose: "run", Command: []string{"hal", "run", "--json"}, Stdout: &capture}, sandboxexec.Dependencies{
		ResolveTarget: func(context.Context, sandboxexec.TargetRequest) (*sandbox.SandboxState, error) { return target, nil },
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) { return driver, nil },
		RunCommand: func(ctx context.Context, run sandboxexec.RunContext, command sandboxexec.CommandRequest) error {
			return runSandboxWorkerJobOrSync(ctx, sandboxWorkerJobCommandRequest{
				ExecutionID: "bounded-json", UseWorkerJob: true, HostID: "host-1", Run: run, Command: command,
				Persist: func(*sandboxexecution.WorkerJobReference) error { return nil },
			})
		},
		HandleEvent: func(_ context.Context, event sandboxexec.Event) error {
			if len(event.Line) > maxLine {
				maxLine = len(event.Line)
			}
			return nil
		},
	})
	if err != nil {
		var detached *sandboxWorkerJobDetachedError
		if errors.As(err, &detached) {
			t.Fatalf("overflow detached: %v", detached.Cause)
		}
		t.Fatalf("overflow interrupted healthy daemon observation: %v", err)
	}
	if !capture.worker || !capture.truncated || len(capture.Bytes()) != sandboxWorkerJobJSONLimit || maxLine != sandboxWorkerJobJSONLimit {
		t.Fatalf("bound did not survive executor/context wrappers: worker=%v truncated=%v bytes=%d line=%d", capture.worker, capture.truncated, len(capture.Bytes()), maxLine)
	}
	if driver.logsCalls != pageCount || driver.cancelCalls != 0 {
		t.Fatalf("overflow failed to drain without cancellation: %+v", driver)
	}
}

func TestSandboxWorkerJobJSONCaptureLeavesLegacyRouteUnchanged(t *testing.T) {
	var capture sandboxWorkerJobJSONCapture
	ctx := context.WithValue(context.Background(), sandboxWorkerJobJSONContextKey{}, &capture)
	payload := "legacy malformed stdout\n" + strings.Repeat("x", sandboxWorkerJobJSONLimit+1)
	driver := &fakeSandboxWorkerJobDriver{exec: func(req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		_, err := io.WriteString(req.Stdout, payload)
		return &sandboxruntime.ExecResult{}, err
	}}
	err := runSandboxWorkerJobOrSync(ctx, sandboxWorkerJobCommandRequest{
		Run:     sandboxexec.RunContext{Driver: driver, Target: sandboxWorkerJobRuntimeTarget()},
		Command: sandboxexec.CommandRequest{Command: []string{"hal", "run", "--json"}, Stdout: &capture},
	})
	if err != nil || capture.worker || capture.truncated || string(capture.Bytes()) != payload || driver.startCalls != 0 {
		t.Fatalf("legacy capture changed: %v", err)
	}
	var output bytes.Buffer
	if err := outputSandboxAugmentedJSON(&output, capture.Bytes(), sandboxexecution.Store{}, "legacy"); err != nil || output.String() != payload {
		t.Fatalf("legacy pass-through changed: %v", err)
	}
}

func TestSandboxWorkerJobJSONCaptureBoundedWriterErrors(t *testing.T) {
	sentinel := errors.New("writer failed")
	var capture sandboxWorkerJobJSONCapture
	if _, err := capture.workerStream(workerJSONErrorWriter{sentinel}).Write([]byte("data")); !errors.Is(err, sentinel) {
		t.Fatalf("writer error lost: %v", err)
	}
	if _, err := capture.workerStream(workerJSONShortWriter{}).Write([]byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write lost: %v", err)
	}
	_, _ = io.WriteString(&capture, strings.Repeat("x", sandboxWorkerJobJSONLimit+1))
	if !capture.truncated || len(capture.Bytes()) != sandboxWorkerJobJSONLimit {
		t.Fatal("direct capture bypassed bound")
	}
}

type workerJSONErrorWriter struct{ err error }

func (writer workerJSONErrorWriter) Write([]byte) (int, error) { return 0, writer.err }

type workerJSONShortWriter struct{}

func (workerJSONShortWriter) Write([]byte) (int, error) { return 0, nil }

func seedCompletedWorkerJSONPublication(t *testing.T) (sandboxexecution.Store, string) {
	t.Helper()
	store, id, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	err := finalizeSandboxL3Execution(context.Background(), store, id, false, sandboxL3FinalizationDeps{
		now:        func() time.Time { return terminal.FinishedAt.Add(time.Second) },
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) { return terminal, nil },
		drainLogs:  func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error { return nil },
		collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			return nil
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, id
}
