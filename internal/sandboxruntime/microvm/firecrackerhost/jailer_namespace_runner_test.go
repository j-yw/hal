package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestStrictJailerNamespaceRunnerUsesOnlyUserAndNetworkDescriptors(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	process := newAtomicJailerTestProcess()
	runner, starter, provider := atomicJailerTestRunner(t, process, nil)

	got, err := runner.StartHostProcess(context.Background(), plan.processRequest())
	if err != nil || got != process {
		t.Fatalf("StartHostProcess() = %#v, %v, want exact process", got, err)
	}
	if provider.calls != 1 || starter.calls != 1 {
		t.Fatalf("namespace/start calls = %d/%d, want 1/1", provider.calls, starter.calls)
	}
	wantArgs := []string{
		"--preserve-credentials", "--keep-caps", "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--",
		plan.processRequest().Executable,
	}
	wantArgs = append(wantArgs, plan.processRequest().Args...)
	if starter.request.Executable != "/usr/bin/nsenter" || !reflect.DeepEqual(starter.request.Args, wantArgs) {
		t.Fatalf("namespace request = %#v, want exact foreground Jailer wrapper", starter.request)
	}
	if len(starter.request.InheritedFiles) != 2 {
		t.Fatalf("namespace descriptors = %d, want user+network only", len(starter.request.InheritedFiles))
	}
	for _, file := range provider.files {
		if _, statErr := file.Stat(); statErr == nil {
			t.Fatal("namespace descriptor remained open after start handoff")
		}
	}
	for _, arg := range plan.processRequest().Args {
		if arg == "--daemonize" || arg == "--new-pid-ns" {
			t.Fatalf("foreground Jailer request contains %q", arg)
		}
	}
}

func TestStrictJailerNamespaceRunnerRejectsAssetsEnvironmentAndDetachedJailer(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	asset, assetWriter := atomicJailerTestPipe(t)
	defer asset.Close()
	defer assetWriter.Close()
	tests := []struct {
		name string
		edit func(*firecracker.ProcessRunnerStartRequest)
	}{
		{name: "asset descriptor", edit: func(req *firecracker.ProcessRunnerStartRequest) { req.InheritedFiles = []*os.File{asset} }},
		{name: "environment", edit: func(req *firecracker.ProcessRunnerStartRequest) { req.Environment = []string{"SECRET=value"} }},
		{name: "daemonize", edit: func(req *firecracker.ProcessRunnerStartRequest) {
			req.Args = atomicJailerInsertBeforeSeparator(req.Args, "--daemonize")
		}},
		{name: "new pid namespace", edit: func(req *firecracker.ProcessRunnerStartRequest) {
			req.Args = atomicJailerInsertBeforeSeparator(req.Args, "--new-pid-ns")
		}},
		{name: "runtime whitespace", edit: func(req *firecracker.ProcessRunnerStartRequest) { req.Args[1] = " run-alpha " }},
		{name: "noncanonical uid", edit: func(req *firecracker.ProcessRunnerStartRequest) { req.Args[5] = "01001" }},
		{name: "noncanonical jail path", edit: func(req *firecracker.ProcessRunnerStartRequest) {
			req.Args[12] = "/run/fc-run-alpha/./firecracker.sock"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, starter, provider := atomicJailerTestRunner(t, newAtomicJailerTestProcess(), nil)
			request := plan.processRequest()
			tt.edit(&request)
			_, err := runner.StartHostProcess(context.Background(), request)
			if !errors.Is(err, errStrictJailerNamespaceRequestInvalid) {
				t.Fatalf("StartHostProcess() error = %v, want invalid", err)
			}
			if starter.calls != 0 || provider.calls != 0 {
				t.Fatalf("invalid request crossed live boundary: namespace/start = %d/%d", provider.calls, starter.calls)
			}
		})
	}
}

func TestStrictJailerNamespaceRunnerRejectsAndClosesNilOrDuplicateNamespaceDescriptors(t *testing.T) {
	tests := []struct {
		name  string
		files func(*testing.T) (*os.File, *os.File, []*os.File)
	}{
		{name: "nil network", files: func(t *testing.T) (*os.File, *os.File, []*os.File) {
			user, writer := atomicJailerTestPipe(t)
			writer.Close()
			return user, nil, []*os.File{user}
		}},
		{name: "duplicate", files: func(t *testing.T) (*os.File, *os.File, []*os.File) {
			user, writer := atomicJailerTestPipe(t)
			writer.Close()
			return user, user, []*os.File{user}
		}},
		{name: "closed user", files: func(t *testing.T) (*os.File, *os.File, []*os.File) {
			user, network := atomicJailerTestDescriptorPair(t)
			user.Close()
			return user, network, []*os.File{user, network}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, network, owned := tt.files(t)
			provider := &atomicJailerNamespaceProvider{nextUser: user, nextNetwork: network}
			starter := &atomicJailerNamespaceStarter{process: newAtomicJailerTestProcess()}
			runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{
				namespace: provider, starter: starter, nsenterPath: "/usr/bin/nsenter",
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = runner.StartHostProcess(context.Background(), atomicJailerTestPlan(t, "run-alpha").processRequest())
			if !errors.Is(err, errStrictJailerNamespaceInvalid) {
				t.Fatalf("StartHostProcess() error = %v, want namespace invalid", err)
			}
			if starter.calls != 0 {
				t.Fatalf("starter calls = %d, want zero", starter.calls)
			}
			for _, file := range owned {
				if _, statErr := file.Stat(); statErr == nil {
					t.Fatal("invalid namespace descriptor remained open")
				}
			}
		})
	}
}

func TestStrictJailerNamespaceRunnerContainsPartialStartFailure(t *testing.T) {
	process := newAtomicJailerTestProcess()
	startErr := errors.New("unsafe /Users/alice/private starter failure")
	runner, _, _ := atomicJailerTestRunner(t, process, startErr)

	_, err := runner.StartHostProcess(context.Background(), atomicJailerTestPlan(t, "run-alpha").processRequest())
	if !errors.Is(err, errStrictJailerNamespaceStartFailed) {
		t.Fatalf("StartHostProcess() error = %v, want contained start failure", err)
	}
	if process.killCalls != 1 || process.waitCalls != 1 {
		t.Fatalf("partial process kill/wait = %d/%d, want 1/1", process.killCalls, process.waitCalls)
	}
	if err != nil && (containsAny(err.Error(), "/Users/alice", "private", "starter failure")) {
		t.Fatalf("partial start error leaked cause: %q", err)
	}
	if strictJailerLifecycleStartCleanupUncertain(err) {
		t.Fatal("contained partial start was classified cleanup-uncertain")
	}
}

func TestStrictJailerNamespaceRunnerRetainsAndRetriesCleanupUncertainProcess(t *testing.T) {
	process := newAtomicJailerTestProcess()
	process.killErr = errors.New("kill failed")
	process.waitErr = errors.New("wait failed")
	runner, _, _ := atomicJailerTestRunner(t, process, errors.New("start failed"))
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatal(err)
	}
	plan := atomicJailerTestPlan(t, "run-alpha")

	_, err = lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{
		launchPlan: plan, hostPaths: plan.hostPathPlan(),
	})
	if !strictJailerLifecycleStartCleanupUncertain(err) {
		t.Fatalf("start() error = %v, want cleanup-uncertain classification", err)
	}
	process.mu.Lock()
	process.killErr = nil
	process.waitErr = nil
	process.mu.Unlock()
	if err := lifecycle.retryUncertainStartCleanup(context.Background()); err != nil {
		t.Fatalf("retryUncertainStartCleanup() error = %v", err)
	}
}

func TestStrictJailerNamespaceRunnerLeavesLegacyAssetRunnerUnchanged(t *testing.T) {
	user, network := atomicJailerTestDescriptorPair(t)
	provider := &atomicJailerNamespaceProvider{nextUser: user, nextNetwork: network}
	starter := &atomicJailerNamespaceStarter{process: newAtomicJailerTestProcess()}
	legacy, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace: provider, Starter: starter, NSenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatal(err)
	}
	kernel, kernelWriter := atomicJailerTestPipe(t)
	rootfs, rootfsWriter := atomicJailerTestPipe(t)
	defer kernel.Close()
	defer kernelWriter.Close()
	defer rootfs.Close()
	defer rootfsWriter.Close()

	_, err = legacy.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "/usr/bin/firecracker", Args: []string{"--api-sock", "/run/fc-legacy/firecracker.sock"},
		Environment: []string{}, InheritedFiles: []*os.File{kernel, rootfs},
	})
	if err != nil {
		t.Fatalf("legacy StartHostProcess() error = %v", err)
	}
	if len(starter.request.InheritedFiles) != 4 || starter.request.InheritedFiles[2] != kernel || starter.request.InheritedFiles[3] != rootfs {
		t.Fatalf("legacy descriptors = %#v, want namespace+kernel+rootfs", starter.request.InheritedFiles)
	}
}

type atomicJailerNamespaceProvider struct {
	nextUser    *os.File
	nextNetwork *os.File
	files       []*os.File
	calls       int
}

func (provider *atomicJailerNamespaceProvider) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	provider.calls++
	provider.files = []*os.File{provider.nextUser, provider.nextNetwork}
	return provider.nextUser, provider.nextNetwork, nil
}

type atomicJailerNamespaceStarter struct {
	request NamespaceProcessStartRequest
	process HostProcess
	err     error
	calls   int
}

func (starter *atomicJailerNamespaceStarter) StartNamespaceProcess(_ context.Context, request NamespaceProcessStartRequest) (HostProcess, error) {
	starter.calls++
	starter.request = NamespaceProcessStartRequest{
		Executable: request.Executable, Args: append([]string(nil), request.Args...),
		InheritedFiles: append([]*os.File(nil), request.InheritedFiles...),
	}
	return starter.process, starter.err
}

func (starter *atomicJailerNamespaceStarter) startStrictJailerNamespaceProcess(
	_ context.Context,
	request strictJailerNamespaceProcessStartRequest,
) (HostProcess, error) {
	starter.calls++
	starter.request = NamespaceProcessStartRequest{
		Executable: request.executable, Args: append([]string(nil), request.args...),
		InheritedFiles: append([]*os.File(nil), request.inheritedFiles...),
	}
	return starter.process, starter.err
}

type atomicJailerTestProcess struct {
	mu          sync.Mutex
	done        chan struct{}
	signalCalls int
	waitCalls   int
	killCalls   int
	signalErr   error
	waitErr     error
	killErr     error
	closed      bool
}

func newAtomicJailerTestProcess() *atomicJailerTestProcess {
	return &atomicJailerTestProcess{done: make(chan struct{})}
}

func (process *atomicJailerTestProcess) Wait(ctx context.Context) error {
	process.mu.Lock()
	process.waitCalls++
	err := process.waitErr
	done := process.done
	process.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (process *atomicJailerTestProcess) Signal(context.Context, ProcessSignal) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.signalCalls++
	if process.signalErr == nil {
		process.closeLocked()
	}
	return process.signalErr
}

func (process *atomicJailerTestProcess) Kill(context.Context) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.killCalls++
	if process.killErr == nil {
		process.closeLocked()
	}
	return process.killErr
}

func (process *atomicJailerTestProcess) HostPID() int          { return 4242 }
func (process *atomicJailerTestProcess) Done() <-chan struct{} { return process.done }

func (process *atomicJailerTestProcess) closeLocked() {
	if !process.closed {
		close(process.done)
		process.closed = true
	}
}

func atomicJailerTestRunner(t *testing.T, process HostProcess, startErr error) (*strictJailerNamespaceRunner, *atomicJailerNamespaceStarter, *atomicJailerNamespaceProvider) {
	t.Helper()
	user, network := atomicJailerTestDescriptorPair(t)
	provider := &atomicJailerNamespaceProvider{nextUser: user, nextNetwork: network}
	starter := &atomicJailerNamespaceStarter{process: process, err: startErr}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{
		namespace: provider, starter: starter, nsenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatalf("newStrictJailerNamespaceRunner() error = %v", err)
	}
	return runner, starter, provider
}

func atomicJailerTestDescriptorPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	user, userWriter := atomicJailerTestPipe(t)
	network, networkWriter := atomicJailerTestPipe(t)
	userWriter.Close()
	networkWriter.Close()
	return user, network
}

func atomicJailerTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	return reader, writer
}

func atomicJailerInsertBeforeSeparator(args []string, value string) []string {
	for index, arg := range args {
		if arg == "--" {
			result := append([]string(nil), args[:index]...)
			result = append(result, value)
			return append(result, args[index:]...)
		}
	}
	return append(args, value)
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
