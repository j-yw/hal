package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3SelectionRejectsExecutionFromReplacedSandboxInstance(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	if err := sandbox.ForceWriteInstance(&sandbox.SandboxState{
		ID:        "sandbox-alpha-replacement",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("save replacement sandbox: %v", err)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest(
		"run-alpha-stale",
		"alpha",
		now,
		"job-alpha-stale",
		sandboxworker.JobStateRunning,
		0,
	))

	t.Run("explicit run", func(t *testing.T) {
		_, manifest, err := selectSandboxL3Execution(
			"alpha",
			"run-alpha-stale",
			sandboxL3SelectionObserve,
		)
		if manifest != nil {
			t.Errorf("selected stale manifest = %q, want nil", manifest.ID)
		}
		requireL3ErrorCode(t, err, "execution_sandbox_mismatch")
	})

	t.Run("implicit run", func(t *testing.T) {
		_, manifest, err := selectSandboxL3Execution(
			"alpha",
			"",
			sandboxL3SelectionObserve,
		)
		if manifest != nil {
			t.Errorf("selected stale manifest = %q, want nil", manifest.ID)
		}
		requireL3ErrorCode(t, err, "execution_not_found")
	})
}

func TestL3LiveListDoesNotObserveExecutionFromReplacedSandboxInstance(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest(
		"run-alpha-stale",
		"alpha",
		now,
		"job-alpha-stale",
		sandboxworker.JobStateRunning,
		0,
	))
	replacement := &sandbox.SandboxState{
		ID:        "sandbox-alpha-replacement",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(time.Hour),
	}

	originalClientFactory := sandboxL3NewWorkerClient
	workerCalls := 0
	sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
		workerCalls++
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxL3NewWorkerClient = originalClientFactory
	})

	var out bytes.Buffer
	if err := renderSandboxL3LiveListJSON(context.Background(), &out, []*sandbox.SandboxState{replacement}); err != nil {
		t.Fatalf("render live list: %v", err)
	}
	if workerCalls != 0 {
		t.Fatalf("stale execution caused %d worker calls, want none", workerCalls)
	}
	payload := decodeL3JSONDocument(t, out.Bytes())
	sandboxes, ok := payload["sandboxes"].([]any)
	if !ok || len(sandboxes) != 1 {
		t.Fatalf("sandboxes = %#v, want one replacement sandbox", payload["sandboxes"])
	}
	entry, ok := sandboxes[0].(map[string]any)
	if !ok {
		t.Fatalf("sandbox entry = %#v, want object", sandboxes[0])
	}
	if _, exists := entry["execution"]; exists {
		t.Fatalf("replacement sandbox inherited stale execution: %#v", entry["execution"])
	}
}

func TestL3NamedStatusDoesNotMixSandboxReplacementSnapshots(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	original := &sandbox.SandboxState{
		ID:        "sandbox-alpha-original",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now,
	}
	replacement := &sandbox.SandboxState{
		ID:        "sandbox-alpha-replacement",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(time.Hour),
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	originalManifest := l3Manifest(
		"run-alpha-original",
		"alpha",
		now,
		"job-alpha-original",
		sandboxworker.JobStateRunning,
		0,
	)
	originalManifest.SandboxID = original.ID
	saveL3Manifest(t, store, originalManifest)
	replacementManifest := l3Manifest(
		"run-alpha-replacement",
		"alpha",
		now.Add(time.Hour),
		"job-alpha-replacement",
		sandboxworker.JobStateRunning,
		0,
	)
	replacementManifest.SandboxID = replacement.ID
	saveL3Manifest(t, store, replacementManifest)

	originalLoadSandbox := sandboxL3LoadSandbox
	loads := 0
	sandboxL3LoadSandbox = func(string) (*sandbox.SandboxState, error) {
		loads++
		if loads == 1 {
			return original, nil
		}
		return replacement, nil
	}
	t.Cleanup(func() {
		sandboxL3LoadSandbox = originalLoadSandbox
	})

	var out bytes.Buffer
	if err := runSandboxL3StatusJSON(context.Background(), "alpha", false, &out); err != nil {
		t.Fatalf("render named status: %v", err)
	}
	var response sandboxL3StatusResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode named status: %v", err)
	}
	if response.Sandbox.ID != original.ID {
		t.Fatalf("status sandbox ID = %q, want initial snapshot %q", response.Sandbox.ID, original.ID)
	}
	if response.Execution == nil || response.Execution.RunID != originalManifest.ID {
		t.Fatalf(
			"status mixed sandbox %q with execution %#v, want execution %q from the same snapshot",
			response.Sandbox.ID,
			response.Execution,
			originalManifest.ID,
		)
	}
	if loads != 1 {
		t.Fatalf("named status loaded mutable sandbox identity %d times, want one snapshot", loads)
	}
}

func TestL3LiveStatusRejectsManifestWorkerJobBindingMismatchBeforeWorkerIO(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandboxexecution.Manifest)
	}{
		{
			name: "missing submission identity",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerJob.SubmissionKey = ""
			},
		},
		{
			name: "execution submission identity",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerJob.SubmissionKey = sandboxWorkerJobSubmissionKey("run-other")
			},
		},
		{
			name: "manifest host",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.Host.ID = "worker-other"
			},
		},
		{
			name: "manifest worker",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.Runtime.WorkerID = "worker-other"
			},
		},
		{
			name: "manifest runtime driver",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.Runtime.Driver = sandbox.SandboxRuntimeDriverMicroVM
			},
		},
		{
			name: "manifest runtime",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.Runtime.RuntimeID = "runtime-other"
			},
		},
		{
			name: "missing worker routing",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerRouting = nil
			},
		},
		{
			name: "routing host",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerRouting.SelectedWorkerHostID = "worker-other"
			},
		},
		{
			name: "routing runtime driver",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerRouting.RuntimeDriverID = sandbox.SandboxRuntimeDriverMicroVM
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateRunning,
				panicOnForbidden: true,
				pages:            map[uint64]sandboxworker.JobLogsResponse{},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			manifest, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load execution manifest: %v", err)
			}
			manifest.WorkerJob.SubmissionKey = sandboxWorkerJobSubmissionKey(manifest.ID)
			tt.mutate(manifest)
			if err := store.SaveManifest(manifest); err != nil {
				t.Fatalf("save inconsistent execution manifest: %v", err)
			}

			var out bytes.Buffer
			err = runSandboxL3StatusJSON(context.Background(), "alpha", true, &out)
			requireL3ErrorCode(t, err, "worker_job_identity_mismatch")
			requests, forbidden := script.snapshot()
			if len(requests) != 0 || len(forbidden) != 0 {
				t.Fatalf("binding mismatch crossed worker boundary: requests=%#v forbidden=%#v", requests, forbidden)
			}
			if out.Len() != 0 {
				t.Fatalf("binding mismatch rendered status: %s", out.String())
			}
		})
	}
}

func TestL3FinalizationRejectsManifestWorkerJobBindingMismatchBeforeMutation(t *testing.T) {
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateSucceeded,
		panicOnForbidden: true,
		pages:            map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "job-alpha")
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load execution manifest: %v", err)
	}
	manifest.WorkerJob.SubmissionKey = sandboxWorkerJobSubmissionKey(manifest.ID)
	manifest.Host.ID = "worker-other"
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("save inconsistent execution manifest: %v", err)
	}
	before := append([]byte(nil), harness.manifestBytes()...)
	reference := manifest.WorkerJob
	job := &sandboxworker.Job{
		ContractVersion: reference.ContractVersion,
		ID:              reference.JobID,
		SubmissionKey:   reference.SubmissionKey,
		WorkerID:        reference.WorkerID,
		HostID:          reference.HostID,
		RuntimeDriver:   reference.RuntimeDriver,
		RuntimeID:       reference.RuntimeID,
		State:           reference.State,
		SubmittedAt:     reference.SubmittedAt,
		StartedAt:       cloneL3Time(reference.StartedAt),
		HeartbeatAt:     cloneL3Time(reference.HeartbeatAt),
		FinishedAt:      cloneL3Time(reference.FinishedAt),
		LogCursor:       reference.LogCursor,
	}
	observeCalls := 0
	err = finalizeSandboxL3Execution(
		context.Background(),
		store,
		manifest.ID,
		false,
		sandboxL3FinalizationDeps{
			observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
				observeCalls++
				return job, nil
			},
			drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
				return context.Canceled
			},
		},
	)
	requireL3ErrorCode(t, err, "worker_job_identity_mismatch")
	if observeCalls != 0 {
		t.Fatalf("binding mismatch made %d worker observations, want none", observeCalls)
	}
	after := harness.manifestBytes()
	if string(after) != string(before) {
		t.Fatalf("binding mismatch mutated manifest\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestL3LiveListRejectsAmbiguousRecoverableExecutionsBeforeWorkerIO(t *testing.T) {
	script := &l3WorkerScript{
		jobState: sandboxworker.JobStateRunning,
		pages:    map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha-a", "job-alpha-a")
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest(
		"run-alpha-b",
		"alpha",
		time.Date(2026, 7, 25, 8, 1, 0, 0, time.UTC),
		"job-alpha-b",
		sandboxworker.JobStateRunning,
		0,
	))
	instance, err := sandboxL3LoadSandbox("alpha")
	if err != nil {
		t.Fatalf("load sandbox: %v", err)
	}

	var out bytes.Buffer
	err = renderSandboxL3LiveListJSON(context.Background(), &out, []*sandbox.SandboxState{instance})
	requireL3ErrorCode(t, err, "ambiguous_run")
	requests, forbidden := script.snapshot()
	if len(requests) != 0 || len(forbidden) != 0 {
		t.Fatalf("ambiguous list crossed worker boundary: requests=%#v forbidden=%#v", requests, forbidden)
	}
	if out.Len() != 0 {
		t.Fatalf("ambiguous list rendered output: %s", out.String())
	}
}

func TestL3LiveListLabelsDurableFallbackCached(t *testing.T) {
	script := &l3WorkerScript{
		jobState: sandboxworker.JobStateRunning,
		pages:    map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "job-alpha")
	instance, err := sandboxL3LoadSandbox("alpha")
	if err != nil {
		t.Fatalf("load sandbox: %v", err)
	}
	originalClientFactory := sandboxL3NewWorkerClient
	sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
		return nil, errors.New("offline at token=never-render")
	}
	t.Cleanup(func() {
		sandboxL3NewWorkerClient = originalClientFactory
	})

	var out bytes.Buffer
	if err := renderSandboxL3LiveListJSON(context.Background(), &out, []*sandbox.SandboxState{instance}); err != nil {
		t.Fatalf("render cached fallback: %v", err)
	}
	var response sandboxL3ListResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode cached fallback: %v", err)
	}
	if response.Source != "cached" {
		t.Fatalf("fallback source = %q, want cached", response.Source)
	}
	if len(response.Diagnostics) != 1 || response.Diagnostics[0].Code != "worker_job_status_failed" {
		t.Fatalf("fallback diagnostics = %#v", response.Diagnostics)
	}
	if strings.Contains(out.String(), "never-render") {
		t.Fatalf("fallback output leaked worker error: %s", out.String())
	}
}

func TestL3LiveStatusRejectsUnsupportedCoherentWorkerJobRouteBeforeWorkerIO(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandboxexecution.Manifest)
	}{
		{
			name: "microvm driver",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.WorkerJob.RuntimeDriver = sandbox.SandboxRuntimeDriverMicroVM
				manifest.Runtime.Driver = sandbox.SandboxRuntimeDriverMicroVM
				manifest.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
				manifest.WorkerRouting.RuntimeDriverID = sandbox.SandboxRuntimeDriverMicroVM
				manifest.WorkerRouting.IsolationLevel = sandbox.SandboxIsolationLevelVM
			},
		},
		{
			name: "non-container isolation",
			mutate: func(manifest *sandboxexecution.Manifest) {
				manifest.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
				manifest.WorkerRouting.IsolationLevel = sandbox.SandboxIsolationLevelVM
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState: sandboxworker.JobStateRunning,
				pages:    map[uint64]sandboxworker.JobLogsResponse{},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			manifest, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load execution manifest: %v", err)
			}
			tt.mutate(manifest)
			if err := store.SaveManifest(manifest); err != nil {
				t.Fatalf("save coherent unsupported route: %v", err)
			}

			var out bytes.Buffer
			err = runSandboxL3StatusJSON(context.Background(), "alpha", true, &out)
			requireL3ErrorCode(t, err, "worker_job_identity_mismatch")
			requests, forbidden := script.snapshot()
			if len(requests) != 0 || len(forbidden) != 0 {
				t.Fatalf("unsupported route crossed worker boundary: requests=%#v forbidden=%#v", requests, forbidden)
			}
			if out.Len() != 0 {
				t.Fatalf("unsupported route rendered status: %s", out.String())
			}
		})
	}
}

func TestL3RunAndAutoManifestsPersistStableSandboxInstanceID(t *testing.T) {
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	target := &sandbox.SandboxState{
		ID:        "sandbox-stable-id",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now,
	}
	tests := []struct {
		name        string
		executionID string
		save        func(sandboxexecution.Store) error
	}{
		{
			name:        "run",
			executionID: "run-lineage",
			save: func(store sandboxexecution.Store) error {
				return saveRunSandboxManifest(store, runSandboxRequest{
					ExecutionID: "run-lineage",
					SandboxName: "alpha",
				}, sandboxexecution.StatusRunning, now, nil, target)
			},
		},
		{
			name:        "auto",
			executionID: "auto-lineage",
			save: func(store sandboxexecution.Store) error {
				return saveAutoSandboxManifest(store, autoSandboxRequest{
					ExecutionID: "auto-lineage",
					SandboxName: "alpha",
				}, sandboxexecution.StatusRunning, now, nil, target)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "store"))
			if err := tt.save(store); err != nil {
				t.Fatalf("save %s manifest: %v", tt.name, err)
			}
			path, err := store.ManifestPath(tt.executionID)
			if err != nil {
				t.Fatalf("resolve manifest path: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			var raw map[string]any
			if err := decoder.Decode(&raw); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				t.Fatalf("manifest trailing JSON: %v", err)
			}
			sandboxID, _ := raw["sandboxId"].(string)
			if got := strings.TrimSpace(sandboxID); got != target.ID {
				t.Fatalf("sandboxId = %q, want %q", got, target.ID)
			}
		})
	}
}
