package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/spf13/cobra"
)

type workerManagementRuntimeDriver struct {
	inspectFn func(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error)
	execFn    func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
}

func (d *workerManagementRuntimeDriver) ID() string { return sandboxruntime.DriverRootlessPodman }

func (d *workerManagementRuntimeDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (d *workerManagementRuntimeDriver) Start(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (d *workerManagementRuntimeDriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (d *workerManagementRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (d *workerManagementRuntimeDriver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	if d.inspectFn != nil {
		return d.inspectFn(ctx, req)
	}
	return &req.Target, nil
}

func (d *workerManagementRuntimeDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	if d.execFn != nil {
		return d.execFn(ctx, req)
	}
	return &sandboxruntime.ExecResult{}, nil
}

func (d *workerManagementRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (d *workerManagementRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func workerManagementSandbox(name, status string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:        "sandbox-" + name,
		Name:      name,
		Provider:  "local",
		Status:    status,
		CreatedAt: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Host: &sandbox.SandboxHost{
			ID:                "worker-1",
			Name:              "local-worker",
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "unix:///tmp/hal-sandboxd.sock",
			SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "container-" + name,
			Image:          "localhost/hal-worker-test:latest",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        "git",
			InputSource: "repository",
			Repo:        "github.com/example/keyboard-game",
			Branch:      "main",
			SyncRef:     "refs/heads/main",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: "default",
				PolicyEnforced:  "best_effort",
			},
		},
	}
}

func TestRunSandboxStatusWorkerUsesRuntimeInspectAndPreservesMetadata(t *testing.T) {
	setupStatusTest(t)
	target := workerManagementSandbox("worker-status", sandbox.StatusStopped)
	saveStatusTestInstance(t, target)

	wantHost := *target.Host
	wantRuntime := *target.Runtime
	wantWorkspace := *target.Workspace
	wantSecurity := *target.Security
	inspectCalls := 0
	driver := &workerManagementRuntimeDriver{inspectFn: func(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
		inspectCalls++
		if req.Target.Runtime.RuntimeID != target.Runtime.RuntimeID {
			t.Fatalf("inspect runtime ID = %q, want %q", req.Target.Runtime.RuntimeID, target.Runtime.RuntimeID)
		}
		refreshed := req.Target
		refreshed.Status = sandbox.StatusRunning
		return &refreshed, nil
	}}

	origRuntime := sandboxStatusResolveRuntime
	origProvider := sandboxStatusResolveProvider
	sandboxStatusResolveRuntime = func(got *sandbox.SandboxState) (sandboxruntime.Driver, error) {
		if got.Name != target.Name {
			t.Fatalf("resolved target = %q, want %q", got.Name, target.Name)
		}
		return driver, nil
	}
	sandboxStatusResolveProvider = func(string) (sandbox.Provider, error) {
		t.Fatal("provider resolution should not run for worker status")
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxStatusResolveRuntime = origRuntime
		sandboxStatusResolveProvider = origProvider
	})

	var out bytes.Buffer
	if err := runSandboxStatusWithDeps(target.Name, &out, nil); err != nil {
		t.Fatalf("runSandboxStatusWithDeps() error: %v", err)
	}
	if inspectCalls != 1 {
		t.Fatalf("Inspect calls = %d, want 1", inspectCalls)
	}
	if strings.Contains(out.String(), "Public SSH:") || strings.Contains(out.String(), "SSH command:") {
		t.Fatalf("worker status advertised provider SSH access:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Command transport:") || !strings.Contains(out.String(), "hal sandbox ssh worker-status -- <command>") {
		t.Fatalf("worker status missing command transport guidance:\n%s", out.String())
	}

	stored, err := sandbox.LoadInstance(target.Name)
	if err != nil {
		t.Fatalf("LoadInstance() error: %v", err)
	}
	if stored.Status != sandbox.StatusRunning {
		t.Fatalf("stored status = %q, want %q", stored.Status, sandbox.StatusRunning)
	}
	if !reflect.DeepEqual(*stored.Host, wantHost) || !reflect.DeepEqual(*stored.Runtime, wantRuntime) || !reflect.DeepEqual(*stored.Workspace, wantWorkspace) || !reflect.DeepEqual(*stored.Security, wantSecurity) {
		t.Fatalf("status refresh changed durable worker metadata: %#v", stored)
	}
}

func TestRunSandboxListLiveRefreshesMixedWorkerAndProviderTargets(t *testing.T) {
	setupListTest(t)
	worker := workerManagementSandbox("worker-live", sandbox.StatusStopped)
	cloud := &sandbox.SandboxState{
		ID:        "sandbox-cloud-live",
		Name:      "cloud-live",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: worker.CreatedAt,
	}
	writeInstance(t, worker)
	writeInstance(t, cloud)

	origRuntime := sandboxListResolveRuntime
	origProvider := sandboxListResolveProvider
	sandboxListResolveRuntime = func(got *sandbox.SandboxState) (sandboxruntime.Driver, error) {
		if got.Name != worker.Name {
			t.Fatalf("worker resolver target = %q, want %q", got.Name, worker.Name)
		}
		return &workerManagementRuntimeDriver{inspectFn: func(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
			refreshed := req.Target
			refreshed.Status = sandbox.StatusRunning
			return &refreshed, nil
		}}, nil
	}
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		if name != cloud.Provider {
			t.Fatalf("provider resolver name = %q, want %q", name, cloud.Provider)
		}
		return &liveTestProvider{statusOut: "Status: off"}, nil
	}
	t.Cleanup(func() {
		sandboxListResolveRuntime = origRuntime
		sandboxListResolveProvider = origProvider
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := runSandboxListWithWriters(&out, &errOut, true, true); err != nil {
		t.Fatalf("runSandboxListWithWriters() error: %v", err)
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected live warnings: %s", errOut.String())
	}
	var response SandboxListResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("stdout is not clean JSON: %v\n%s", err, out.String())
	}
	statuses := make(map[string]string, len(response.Sandboxes))
	for _, entry := range response.Sandboxes {
		statuses[entry.Name] = entry.Status
	}
	if statuses[worker.Name] != sandbox.StatusRunning || statuses[cloud.Name] != sandbox.StatusStopped {
		t.Fatalf("refreshed statuses = %#v", statuses)
	}
}

func TestRunSandboxListLiveWorkerFailureUsesCachedStatusAndStderrWarning(t *testing.T) {
	setupListTest(t)
	worker := workerManagementSandbox("worker-cached", sandbox.StatusStopped)
	writeInstance(t, worker)

	origRuntime := sandboxListResolveRuntime
	origProvider := sandboxListResolveProvider
	sandboxListResolveRuntime = func(*sandbox.SandboxState) (sandboxruntime.Driver, error) {
		return &workerManagementRuntimeDriver{inspectFn: func(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
			return nil, errors.New("worker socket unavailable")
		}}, nil
	}
	sandboxListResolveProvider = func(string) (sandbox.Provider, error) {
		t.Fatal("provider resolution should not run for worker live list")
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxListResolveRuntime = origRuntime
		sandboxListResolveProvider = origProvider
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := runSandboxListWithWriters(&out, &errOut, true, true); err != nil {
		t.Fatalf("runSandboxListWithWriters() error: %v", err)
	}
	var response SandboxListResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("stdout is not clean JSON: %v\n%s", err, out.String())
	}
	if len(response.Sandboxes) != 1 || response.Sandboxes[0].Status != sandbox.StatusStopped {
		t.Fatalf("cached response = %#v", response.Sandboxes)
	}
	if !strings.Contains(errOut.String(), worker.Name) || !strings.Contains(errOut.String(), "worker socket unavailable") {
		t.Fatalf("stderr warning = %q", errOut.String())
	}
}

func TestRunSandboxSSHWorkerCommandUsesRuntimeExec(t *testing.T) {
	target := workerManagementSandbox("worker-exec", sandbox.StatusRunning)
	setupSSHTest(t, target)

	var got sandboxruntime.ExecRequest
	driver := &workerManagementRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		got = req
		fmt.Fprint(req.Stdout, "worker stdout\n")
		fmt.Fprint(req.Stderr, "worker stderr\n")
		return &sandboxruntime.ExecResult{ExitCode: 0}, nil
	}}
	origRuntime := sandboxSSHResolveRuntime
	origProvider := sandboxSSHResolveProvider
	sandboxSSHResolveRuntime = func(got *sandbox.SandboxState) (sandboxruntime.Driver, error) {
		if got.Name != target.Name {
			t.Fatalf("resolved target = %q, want %q", got.Name, target.Name)
		}
		return driver, nil
	}
	sandboxSSHResolveProvider = func(string) (sandbox.Provider, error) {
		t.Fatal("provider resolution should not run for worker command")
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxSSHResolveRuntime = origRuntime
		sandboxSSHResolveProvider = origProvider
	})

	var out bytes.Buffer
	args := []string{"worker-exec", "--", "sh", "-lc", "printf ready"}
	if err := runSandboxSSHWithDeps(args, &out, nil, false); err != nil {
		t.Fatalf("runSandboxSSHWithDeps() error: %v", err)
	}
	if !reflect.DeepEqual(got.Args, []string{"sh", "-lc", "printf ready"}) {
		t.Fatalf("Exec args = %#v", got.Args)
	}
	if got.Target.Runtime.RuntimeID != target.Runtime.RuntimeID {
		t.Fatalf("Exec runtime ID = %q, want %q", got.Target.Runtime.RuntimeID, target.Runtime.RuntimeID)
	}
	if !strings.Contains(out.String(), "worker stdout") || !strings.Contains(out.String(), "worker stderr") {
		t.Fatalf("worker output was not streamed: %q", out.String())
	}
}

func TestRunSandboxSSHWorkerCommandPropagatesExitCode(t *testing.T) {
	target := workerManagementSandbox("worker-exit", sandbox.StatusRunning)
	setupSSHTest(t, target)

	origRuntime := sandboxSSHResolveRuntime
	sandboxSSHResolveRuntime = func(*sandbox.SandboxState) (sandboxruntime.Driver, error) {
		return &workerManagementRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{ExitCode: 7}, nil
		}}, nil
	}
	t.Cleanup(func() { sandboxSSHResolveRuntime = origRuntime })

	err := runSandboxSSHWithDeps([]string{target.Name, "--", "false"}, io.Discard, nil, false)
	if err == nil || !strings.Contains(err.Error(), "exited with code 7") {
		t.Fatalf("worker exit error = %v", err)
	}
}

func TestRunSandboxCobraPreservesExplicitWorkerCommandExitCode(t *testing.T) {
	cmd := &cobra.Command{}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	err := runSandboxCobra(cmd, "Sandbox SSH failed", func() error {
		return &ExitCodeError{Code: 7, Err: errors.New("sandbox command exited with code 7")}
	})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 7 {
		t.Fatalf("runSandboxCobra() error = %#v, want exit code 7", err)
	}
	if !strings.Contains(errOut.String(), "sandbox command exited with code 7") {
		t.Fatalf("rendered error = %q", errOut.String())
	}
}

func TestRunSandboxSSHWorkerInteractiveReturnsPassCommandGuidance(t *testing.T) {
	target := workerManagementSandbox("worker-interactive", sandbox.StatusRunning)
	setupSSHTest(t, target)

	origRuntime := sandboxSSHResolveRuntime
	origProvider := sandboxSSHResolveProvider
	sandboxSSHResolveRuntime = func(*sandbox.SandboxState) (sandboxruntime.Driver, error) {
		t.Fatal("runtime resolution should not run for unsupported interactive worker shell")
		return nil, nil
	}
	sandboxSSHResolveProvider = func(string) (sandbox.Provider, error) {
		t.Fatal("provider resolution should not run for unsupported interactive worker shell")
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxSSHResolveRuntime = origRuntime
		sandboxSSHResolveProvider = origProvider
	})

	err := runSandboxSSHWithDeps([]string{target.Name}, io.Discard, nil, false)
	if err == nil {
		t.Fatal("expected unsupported interactive worker shell error")
	}
	for _, want := range []string{"interactive shell is not supported", "pass a command after --", "hal sandbox ssh worker-interactive -- sh"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestSandboxWorkerManagementHelpDocumentsRuntimeRouting(t *testing.T) {
	checks := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "status",
			text: sandboxStatusCmd.Long,
			want: []string{"provider or worker runtime"},
		},
		{
			name: "list",
			text: sandboxListCmd.Long,
			want: []string{"provider or worker runtime"},
		},
		{
			name: "ssh",
			text: sandboxSSHCmd.Long + "\n" + sandboxSSHCmd.Example,
			want: []string{"Worker-backed sandboxes require a command", "does not provide an interactive PTY", "hal sandbox ssh local-worker-check -- sh"},
		},
	}
	for _, check := range checks {
		for _, want := range check.want {
			if !strings.Contains(check.text, want) {
				t.Errorf("%s help does not contain %q", check.name, want)
			}
		}
	}
}
