package sshmachine_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"
)

var _ sandboxruntime.Driver = (*sshmachine.Driver)(nil)

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

func TestExecDelegatesArgsAndStreamsIO(t *testing.T) {
	ctx := context.Background()
	provider := &recordingProvider{
		execCommand: func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
			return helperCommand("stdio"), nil
		},
	}
	driver := sshmachine.New(provider)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	workDir := t.TempDir()
	resolvedWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", workDir, err)
	}
	args := []string{"codex", "exec", "--json"}

	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{
			ID:       "runtime-existing",
			Name:     "dev",
			Provider: "digitalocean",
			Connection: sandboxruntime.ConnectionInfo{
				PublicIP:    "203.0.113.10",
				TailscaleIP: "100.64.0.10",
			},
		},
		Args:    args,
		Stdout:  stdout,
		Stderr:  stderr,
		Stdin:   strings.NewReader("input-data"),
		Env:     map[string]string{"HAL_EXEC_TEST": "env-value"},
		WorkDir: workDir,
	})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	if result == nil || result.ExitCode != 0 {
		t.Fatalf("Exec() result = %#v, want exit code 0", result)
	}

	if got := stdout.String(); got != "stdout:input-data" {
		t.Fatalf("stdout = %q, want helper stdout with forwarded stdin", got)
	}
	if got, want := stderr.String(), fmt.Sprintf("stderr:env-value:%s", resolvedWorkDir); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if len(provider.calls) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(provider.calls))
	}
	call := provider.calls[0]
	if call.operation != "exec" {
		t.Fatalf("provider operation = %q, want exec", call.operation)
	}
	if !reflect.DeepEqual(call.args, args) {
		t.Fatalf("provider Exec args = %#v, want unchanged %#v", call.args, args)
	}
	if call.info == nil || call.info.IP != "100.64.0.10" || call.info.PublicIP != "203.0.113.10" {
		t.Fatalf("provider Exec ConnectInfo = %#v, want preferred connection info", call.info)
	}
}

func TestExecDefaultsStderrToStdout(t *testing.T) {
	provider := &recordingProvider{
		execCommand: func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
			return helperCommand("stdio"), nil
		},
	}
	driver := sshmachine.New(provider)
	stdout := &bytes.Buffer{}

	_, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "dev", Connection: sandboxruntime.ConnectionInfo{Address: "203.0.113.10"}},
		Args:   []string{"echo", "combined"},
		Stdout: stdout,
		Stdin:  strings.NewReader("input-data"),
		Env:    map[string]string{"HAL_EXEC_TEST": "env-value"},
	})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "stdout:input-data") || !strings.Contains(got, "stderr:env-value:") {
		t.Fatalf("combined output = %q, want stdout and stderr routed to stdout", got)
	}
}

func TestExecCancellationUnwrapsContextErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		trigger func(context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			trigger: func(cancel context.CancelFunc) {
				cancel()
			},
			want: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			trigger: func(context.CancelFunc) {},
			want:    context.DeadlineExceeded,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider := &recordingProvider{
				execCommand: func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
					return helperCommand("wait"), nil
				},
			}
			driver := sshmachine.New(provider)
			ctx, cancel := tt.context()
			defer cancel()
			stdout := newNotifyingBuffer("started")
			done := make(chan error, 1)

			go func() {
				_, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
					Target: sandboxruntime.Target{Name: "dev", Connection: sandboxruntime.ConnectionInfo{Address: "203.0.113.10"}},
					Args:   []string{"sleep", "forever"},
					Stdout: stdout,
				})
				done <- err
			}()

			select {
			case <-stdout.seen:
			case <-time.After(2 * time.Second):
				t.Fatal("Exec() helper did not start")
			}
			tt.trigger(cancel)

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Exec() error = nil, want cancellation error")
				}
				if !errors.Is(err, tt.want) {
					t.Fatalf("Exec() error = %v, want errors.Is %v", err, tt.want)
				}
				var opErr *sshmachine.OperationError
				if !errors.As(err, &opErr) {
					t.Fatalf("errors.As(%T) = false, want true", opErr)
				}
				if opErr.Driver != sandboxruntime.DriverSSHMachine || opErr.Operation != "exec" {
					t.Fatalf("OperationError = %#v, want exec error for ssh_machine", opErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Exec() did not return after context cancellation")
			}
		})
	}
}

func TestCopyInDelegatesToProviderExecAndStreamsSource(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "input with spaces.txt")
	if err := os.WriteFile(sourcePath, []byte("copy-in payload"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	capturedPath := filepath.Join(t.TempDir(), "captured.txt")
	provider := &recordingProvider{
		execCommand: func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
			return helperCommand("copy-in", capturedPath), nil
		},
	}
	driver := sshmachine.New(provider)
	remoteDestination := "/workspace/project/input with spaces.txt"

	err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target: sandboxruntime.Target{
			Name: "dev",
			Connection: sandboxruntime.ConnectionInfo{
				PublicIP:    "203.0.113.10",
				TailscaleIP: "100.64.0.10",
			},
		},
		SourcePath:      sourcePath,
		DestinationPath: remoteDestination,
	})
	if err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}

	captured, err := os.ReadFile(capturedPath)
	if err != nil {
		t.Fatalf("read captured copy-in payload: %v", err)
	}
	if string(captured) != "copy-in payload" {
		t.Fatalf("captured copy-in payload = %q, want source content", captured)
	}
	if len(provider.calls) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(provider.calls))
	}
	call := provider.calls[0]
	if call.operation != "exec" {
		t.Fatalf("provider operation = %q, want exec", call.operation)
	}
	if got := call.args[len(call.args)-1]; got != remoteDestination {
		t.Fatalf("provider CopyIn destination arg = %q, want %q", got, remoteDestination)
	}
	if call.info == nil || call.info.IP != "100.64.0.10" || call.info.PublicIP != "203.0.113.10" {
		t.Fatalf("provider CopyIn ConnectInfo = %#v, want preferred connection info", call.info)
	}
}

func TestCopyOutDelegatesToProviderExecAndWritesDestination(t *testing.T) {
	provider := &recordingProvider{
		execCommand: func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
			return helperCommand("copy-out", "copy-out payload"), nil
		},
	}
	driver := sshmachine.New(provider)
	destinationPath := filepath.Join(t.TempDir(), "nested", "output.txt")
	remoteSource := "/workspace/project/output.txt"

	err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target: sandboxruntime.Target{
			Name:       "dev",
			Connection: sandboxruntime.ConnectionInfo{Address: "203.0.113.10"},
		},
		SourcePath:      remoteSource,
		DestinationPath: destinationPath,
	})
	if err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}

	content, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatalf("read copy-out destination: %v", err)
	}
	if string(content) != "copy-out payload" {
		t.Fatalf("copy-out destination = %q, want provider stdout payload", content)
	}
	if len(provider.calls) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(provider.calls))
	}
	call := provider.calls[0]
	if call.operation != "exec" {
		t.Fatalf("provider operation = %q, want exec", call.operation)
	}
	if got := call.args[len(call.args)-1]; got != remoteSource {
		t.Fatalf("provider CopyOut source arg = %q, want %q", got, remoteSource)
	}
	if call.info == nil || call.info.IP != "203.0.113.10" {
		t.Fatalf("provider CopyOut ConnectInfo = %#v, want runtime connection info", call.info)
	}
}

func TestCopyErrorsWrapProviderFailuresWithOperationAndDriver(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(sourcePath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	providerErr := errors.New("provider copy failed")

	for _, tt := range []struct {
		operation string
		run       func(*sshmachine.Driver) error
	}{
		{
			operation: "copy_in",
			run: func(driver *sshmachine.Driver) error {
				return driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
					Target:          sandboxruntime.Target{Name: "dev", Connection: sandboxruntime.ConnectionInfo{Address: "203.0.113.10"}},
					SourcePath:      sourcePath,
					DestinationPath: "/workspace/input.txt",
				})
			},
		},
		{
			operation: "copy_out",
			run: func(driver *sshmachine.Driver) error {
				return driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
					Target:          sandboxruntime.Target{Name: "dev", Connection: sandboxruntime.ConnectionInfo{Address: "203.0.113.10"}},
					SourcePath:      "/workspace/output.txt",
					DestinationPath: filepath.Join(t.TempDir(), "output.txt"),
				})
			},
		},
	} {
		t.Run(tt.operation, func(t *testing.T) {
			provider := &recordingProvider{errByOperation: map[string]error{"exec": providerErr}}
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
		})
	}
}

type lifecycleCall struct {
	operation string
	name      string
	env       map[string]string
	info      *sandbox.ConnectInfo
	args      []string
	out       io.Writer
}

type recordingProvider struct {
	calls          []lifecycleCall
	createResult   *sandbox.SandboxResult
	startResult    *sandbox.LifecycleResult
	statusOutput   string
	errByOperation map[string]error
	onStart        func(*sandbox.ConnectInfo)
	execCommand    func(*sandbox.ConnectInfo, []string) (*exec.Cmd, error)
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
	p.calls = append(p.calls, lifecycleCall{operation: "exec", info: cloneConnectInfo(info), args: append([]string(nil), args...)})
	if err := p.errByOperation["exec"]; err != nil {
		return nil, err
	}
	if p.execCommand == nil {
		return nil, errors.New("not implemented")
	}
	return p.execCommand(info, args)
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

func helperCommand(mode string, args ...string) *exec.Cmd {
	commandArgs := []string{"-test.run=TestSSHMachineExecHelper", "--", mode}
	commandArgs = append(commandArgs, args...)
	cmd := exec.Command(os.Args[0], commandArgs...)
	cmd.Env = append(os.Environ(), "HAL_SSHMACHINE_EXEC_HELPER=1")
	return cmd
}

func TestSSHMachineExecHelper(t *testing.T) {
	if os.Getenv("HAL_SSHMACHINE_EXEC_HELPER") != "1" {
		return
	}
	mode := ""
	helperArgs := []string(nil)
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			helperArgs = os.Args[i+2:]
			break
		}
	}
	switch mode {
	case "stdio":
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v", err)
			os.Exit(2)
		}
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "get cwd: %v", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stdout, "stdout:%s", input)
		fmt.Fprintf(os.Stderr, "stderr:%s:%s", os.Getenv("HAL_EXEC_TEST"), cwd)
		os.Exit(0)
	case "wait":
		fmt.Fprintln(os.Stdout, "started")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "copy-in":
		if len(helperArgs) != 1 {
			fmt.Fprintf(os.Stderr, "copy-in helper args = %v, want capture path", helperArgs)
			os.Exit(2)
		}
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read copy-in stdin: %v", err)
			os.Exit(2)
		}
		if err := os.WriteFile(helperArgs[0], input, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write copy-in capture: %v", err)
			os.Exit(2)
		}
		os.Exit(0)
	case "copy-out":
		if len(helperArgs) != 1 {
			fmt.Fprintf(os.Stderr, "copy-out helper args = %v, want payload", helperArgs)
			os.Exit(2)
		}
		fmt.Fprint(os.Stdout, helperArgs[0])
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q", mode)
		os.Exit(2)
	}
}

type notifyingBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	pattern string
	seen    chan struct{}
	once    sync.Once
}

func newNotifyingBuffer(pattern string) *notifyingBuffer {
	return &notifyingBuffer{pattern: pattern, seen: make(chan struct{})}
}

func (b *notifyingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	text := b.buf.String()
	b.mu.Unlock()
	if strings.Contains(text, b.pattern) {
		b.once.Do(func() {
			close(b.seen)
		})
	}
	return n, err
}
