package sshmachine_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"
)

func TestDriverIdentifiesSSHMachineRuntime(t *testing.T) {
	driver := sshmachine.New(&recordingProvider{})

	if got := driver.ID(); got != sandboxruntime.DriverSSHMachine {
		t.Fatalf("ID() = %q, want %q", got, sandboxruntime.DriverSSHMachine)
	}
}

func TestLifecycleDelegatesToSandboxProvider(t *testing.T) {
	ctx := context.Background()
	stdout := &bytes.Buffer{}
	env := map[string]string{"HAL_TEST": "1"}
	provider := &recordingProvider{
		createResult: &sandbox.SandboxResult{
			ID:          "runtime-created",
			Name:        "created-dev",
			IP:          "203.0.113.20",
			TailscaleIP: "100.64.0.20",
		},
		startResult:  &sandbox.LifecycleResult{Status: sandbox.StatusRunning, IP: "203.0.113.21"},
		statusOutput: "Status: stopped\nPublic IP: 203.0.113.22\n",
		onStart: func(info *sandbox.ConnectInfo) {
			info.WorkspaceID = "runtime-started"
		},
	}
	driver := sshmachine.New(provider)

	created, err := driver.Create(ctx, sandboxruntime.CreateRequest{
		Name:   "created-dev",
		Env:    env,
		Stdout: stdout,
	})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if created.ID != "runtime-created" || created.Name != "created-dev" || created.Status != sandbox.StatusRunning {
		t.Fatalf("Create() target = %#v, want created running target", created)
	}
	if created.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("Create() runtime driver = %q, want %q", created.Runtime.Driver, sandboxruntime.DriverSSHMachine)
	}
	if created.Connection.Address != "100.64.0.20" || created.Connection.PublicIP != "203.0.113.20" || created.Connection.TailscaleIP != "100.64.0.20" {
		t.Fatalf("Create() connection = %#v, want preferred tailscale address with public IP preserved", created.Connection)
	}

	target := sandboxruntime.Target{
		ID:       "runtime-existing",
		Name:     "dev",
		Provider: "digitalocean",
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverSSHMachine,
			RuntimeID:      "runtime-existing",
			Image:          "ubuntu-22.04",
			WorkerID:       "worker-1",
			IsolationLevel: "vm",
		},
		Connection: sandboxruntime.ConnectionInfo{
			PublicIP:          "203.0.113.10",
			TailscaleIP:       "100.64.0.10",
			TailscaleHostname: "dev.tailnet.test",
			TailscaleLockdown: true,
			WorkspaceID:       "runtime-existing",
		},
	}

	started, err := driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: target, Stdout: stdout})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if started.Status != sandbox.StatusRunning {
		t.Fatalf("Start() status = %q, want running", started.Status)
	}
	if started.Connection.WorkspaceID != "runtime-started" {
		t.Fatalf("Start() workspace ID = %q, want resolved provider workspace ID", started.Connection.WorkspaceID)
	}
	if started.Connection.Address != "100.64.0.10" || started.Connection.PublicIP != "203.0.113.21" {
		t.Fatalf("Start() connection = %#v, want lifecycle public IP refreshed without changing preferred address semantics", started.Connection)
	}

	stopped, err := driver.Stop(ctx, sandboxruntime.LifecycleRequest{Target: target, Stdout: stdout})
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	if stopped.Status != sandbox.StatusStopped {
		t.Fatalf("Stop() status = %q, want stopped", stopped.Status)
	}

	inspected, err := driver.Inspect(ctx, sandboxruntime.InspectRequest{Target: target})
	if err != nil {
		t.Fatalf("Inspect() unexpected error: %v", err)
	}
	if inspected.Status != sandbox.StatusStopped || inspected.Connection.PublicIP != "203.0.113.22" {
		t.Fatalf("Inspect() target = %#v, want provider status details applied", inspected)
	}

	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: target, Stdout: stdout}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	wantOps := []string{"create", "start", "stop", "status", "delete"}
	if gotOps := provider.operations(); !reflect.DeepEqual(gotOps, wantOps) {
		t.Fatalf("provider operations = %v, want %v", gotOps, wantOps)
	}
	if provider.calls[0].name != "created-dev" || !reflect.DeepEqual(provider.calls[0].env, env) || provider.calls[0].out != stdout {
		t.Fatalf("Create provider call = %#v, want name/env/stdout delegated", provider.calls[0])
	}
	wantInfo := &sandbox.ConnectInfo{
		Name:              "dev",
		IP:                "100.64.0.10",
		PublicIP:          "203.0.113.10",
		TailscaleIP:       "100.64.0.10",
		TailscaleHostname: "dev.tailnet.test",
		TailscaleLockdown: true,
		WorkspaceID:       "runtime-existing",
	}
	for _, call := range provider.calls[1:] {
		if call.info == nil {
			t.Fatalf("%s provider call ConnectInfo = nil, want %#v", call.operation, wantInfo)
		}
		if !reflect.DeepEqual(call.info, wantInfo) {
			t.Fatalf("%s provider call ConnectInfo = %#v, want %#v", call.operation, call.info, wantInfo)
		}
	}
}

func TestLifecycleErrorsWrapProviderErrorsWithOperationAndDriver(t *testing.T) {
	for _, tt := range []struct {
		operation string
		run       func(*sshmachine.Driver) error
	}{
		{
			operation: "create",
			run: func(driver *sshmachine.Driver) error {
				_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "dev"})
				return err
			},
		},
		{
			operation: "start",
			run: func(driver *sshmachine.Driver) error {
				_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: sandboxruntime.Target{Name: "dev"}})
				return err
			},
		},
		{
			operation: "stop",
			run: func(driver *sshmachine.Driver) error {
				_, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: sandboxruntime.Target{Name: "dev"}})
				return err
			},
		},
		{
			operation: "delete",
			run: func(driver *sshmachine.Driver) error {
				return driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: sandboxruntime.Target{Name: "dev"}})
			},
		},
		{
			operation: "inspect",
			run: func(driver *sshmachine.Driver) error {
				_, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: sandboxruntime.Target{Name: "dev"}})
				return err
			},
		},
	} {
		t.Run(tt.operation, func(t *testing.T) {
			providerErr := errors.New("provider failed")
			provider := &recordingProvider{errByOperation: map[string]error{tt.operation: providerErr}}
			driver := sshmachine.New(provider)

			err := tt.run(driver)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, providerErr) {
				t.Fatalf("errors.Is(%v, providerErr) = false, want true", err)
			}
			var opErr *sshmachine.OperationError
			if !errors.As(err, &opErr) {
				t.Fatalf("errors.As(%T) = false, want true", opErr)
			}
			if opErr.Driver != sandboxruntime.DriverSSHMachine || opErr.Operation != tt.operation {
				t.Fatalf("OperationError = %#v, want driver %q operation %q", opErr, sandboxruntime.DriverSSHMachine, tt.operation)
			}
			message := err.Error()
			if !strings.Contains(message, sandboxruntime.DriverSSHMachine) || !strings.Contains(message, tt.operation) {
				t.Fatalf("error message %q does not include driver and operation", message)
			}
		})
	}
}

type lifecycleCall struct {
	operation string
	name      string
	env       map[string]string
	info      *sandbox.ConnectInfo
	out       io.Writer
}

type recordingProvider struct {
	calls          []lifecycleCall
	createResult   *sandbox.SandboxResult
	startResult    *sandbox.LifecycleResult
	statusOutput   string
	errByOperation map[string]error
	onStart        func(*sandbox.ConnectInfo)
}

func (p *recordingProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	p.calls = append(p.calls, lifecycleCall{operation: "create", name: name, env: env, out: out})
	if err := p.errByOperation["create"]; err != nil {
		return nil, err
	}
	return p.createResult, nil
}

func (p *recordingProvider) Start(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) (*sandbox.LifecycleResult, error) {
	p.calls = append(p.calls, lifecycleCall{operation: "start", info: cloneConnectInfo(info), out: out})
	if err := p.errByOperation["start"]; err != nil {
		return nil, err
	}
	if p.onStart != nil {
		p.onStart(info)
	}
	return p.startResult, nil
}

func (p *recordingProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	p.calls = append(p.calls, lifecycleCall{operation: "stop", info: cloneConnectInfo(info), out: out})
	return p.errByOperation["stop"]
}

func (p *recordingProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	p.calls = append(p.calls, lifecycleCall{operation: "delete", info: cloneConnectInfo(info), out: out})
	return p.errByOperation["delete"]
}

func (p *recordingProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, errors.New("not implemented")
}

func (p *recordingProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, errors.New("not implemented")
}

func (p *recordingProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	p.calls = append(p.calls, lifecycleCall{operation: "status", info: cloneConnectInfo(info), out: out})
	if err := p.errByOperation["inspect"]; err != nil {
		return err
	}
	if out != nil {
		_, _ = io.WriteString(out, p.statusOutput)
	}
	return nil
}

func (p *recordingProvider) operations() []string {
	operations := make([]string, 0, len(p.calls))
	for _, call := range p.calls {
		operations = append(operations, call.operation)
	}
	return operations
}

func cloneConnectInfo(info *sandbox.ConnectInfo) *sandbox.ConnectInfo {
	if info == nil {
		return nil
	}
	cloned := *info
	return &cloned
}
