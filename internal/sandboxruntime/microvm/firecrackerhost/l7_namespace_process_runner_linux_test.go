//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestL7NamespaceProcessRunnerMapsNamespaceAndAssetFilesDeterministically(t *testing.T) {
	user := l7OpenProcessFile(t, "user-namespace")
	network := l7OpenProcessFile(t, "network-namespace")
	kernel := l7OpenProcessFile(t, "kernel")
	rootfs := l7OpenProcessFile(t, "rootfs")
	provider := &l7NamespaceFileProvider{user: user, network: network}
	starter := &l7NamespaceProcessStarter{start: func(_ context.Context, request NamespaceProcessStartRequest) (HostProcess, error) {
		if request.Executable != "/usr/bin/nsenter" {
			t.Fatalf("wrapper executable = %q", request.Executable)
		}
		wantArgs := []string{
			"--user=/proc/self/fd/3",
			"--net=/proc/self/fd/4",
			"--",
			"/usr/bin/firecracker",
			"--api-sock", "/owned/firecracker.sock",
		}
		if !reflect.DeepEqual(request.Args, wantArgs) {
			t.Fatalf("wrapper args = %#v, want %#v", request.Args, wantArgs)
		}
		wantFiles := []*os.File{user, network, kernel, rootfs}
		if !reflect.DeepEqual(request.InheritedFiles, wantFiles) {
			t.Fatalf("wrapper files = %#v, want user/net/kernel/rootfs order", request.InheritedFiles)
		}
		for index, file := range request.InheritedFiles {
			if _, err := file.Stat(); err != nil {
				t.Fatalf("wrapper file %d was closed before synchronous start: %v", index, err)
			}
		}
		return &l7NamespaceHostProcess{}, nil
	}}
	runner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace:   provider,
		Starter:     starter,
		NSenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatalf("NewNamespaceProcessRunner() error = %v", err)
	}

	process, err := runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable:     "/usr/bin/firecracker",
		Args:           []string{"--api-sock", "/owned/firecracker.sock"},
		Environment:    []string{},
		InheritedFiles: []*os.File{kernel, rootfs},
	})
	if err != nil {
		t.Fatalf("StartHostProcess() error = %v", err)
	}
	if process == nil || provider.calls != 1 || starter.calls != 1 {
		t.Fatalf("process/calls = %#v/%d/%d, want one namespace borrow and one start", process, provider.calls, starter.calls)
	}
	for label, file := range map[string]*os.File{"user": user, "network": network} {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("%s namespace duplicate remained open after start", label)
		}
	}
	for label, file := range map[string]*os.File{"kernel": kernel, "rootfs": rootfs} {
		if _, err := file.Stat(); err != nil {
			t.Fatalf("%s asset ownership was consumed by wrapper: %v", label, err)
		}
	}
}

func TestL7NamespaceProcessRunnerPreservesTwoAssetFileInvariant(t *testing.T) {
	for _, count := range []int{0, 1, 3, 4} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			provider := &l7NamespaceFileProvider{}
			starter := &l7NamespaceProcessStarter{}
			runner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
				Namespace: provider, Starter: starter, NSenterPath: "/usr/bin/nsenter",
			})
			if err != nil {
				t.Fatal(err)
			}
			files := make([]*os.File, count)
			for index := range files {
				files[index] = l7OpenProcessFile(t, "asset")
			}
			_, err = runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
				Executable: "/usr/bin/firecracker", InheritedFiles: files,
			})
			if !errors.Is(err, ErrNamespaceProcessAssetsInvalid) {
				t.Fatalf("StartHostProcess() error = %v, want ErrNamespaceProcessAssetsInvalid", err)
			}
			if provider.calls != 0 || starter.calls != 0 {
				t.Fatalf("invalid asset count crossed boundary: provider=%d starter=%d", provider.calls, starter.calls)
			}
		})
	}
}

func TestL7NamespaceProcessRunnerClosesOnlyOwnedNamespaceFilesOnStartFailure(t *testing.T) {
	user := l7OpenProcessFile(t, "user-namespace")
	network := l7OpenProcessFile(t, "network-namespace")
	kernel := l7OpenProcessFile(t, "kernel")
	rootfs := l7OpenProcessFile(t, "rootfs")
	privateFailure := errors.New("pid=4242 socket=/private/owned/firecracker.sock")
	runner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace: &l7NamespaceFileProvider{user: user, network: network},
		Starter: &l7NamespaceProcessStarter{start: func(context.Context, NamespaceProcessStartRequest) (HostProcess, error) {
			return nil, privateFailure
		}},
		NSenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "/usr/bin/firecracker", InheritedFiles: []*os.File{kernel, rootfs},
	})
	if !errors.Is(err, ErrNamespaceProcessStartFailed) || errors.Is(err, privateFailure) {
		t.Fatalf("StartHostProcess() error = %v, want sanitized namespace start failure", err)
	}
	for _, file := range []*os.File{user, network} {
		if _, statErr := file.Stat(); statErr == nil {
			t.Fatal("owned namespace duplicate remained open after failed start")
		}
	}
	for _, file := range []*os.File{kernel, rootfs} {
		if _, statErr := file.Stat(); statErr != nil {
			t.Fatalf("borrowed asset was closed after failed wrapper start: %v", statErr)
		}
	}
}

func TestL7NamespaceProcessRunnerReapsPartialProcessBeforeReturningStartError(t *testing.T) {
	user := l7OpenProcessFile(t, "user-namespace")
	network := l7OpenProcessFile(t, "network-namespace")
	kernel := l7OpenProcessFile(t, "kernel")
	rootfs := l7OpenProcessFile(t, "rootfs")
	partial := &l7NamespaceHostProcess{}
	runner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace: &l7NamespaceFileProvider{user: user, network: network},
		Starter: &l7NamespaceProcessStarter{start: func(context.Context, NamespaceProcessStartRequest) (HostProcess, error) {
			return partial, errors.New("pid=4242 private partial start")
		}},
		NSenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatal(err)
	}
	process, err := runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "/usr/bin/firecracker", InheritedFiles: []*os.File{kernel, rootfs},
	})
	if process != nil || !errors.Is(err, ErrNamespaceProcessStartFailed) {
		t.Fatalf("StartHostProcess() = %#v, %v, want contained start failure", process, err)
	}
	if partial.killCalls != 1 || partial.waitCalls != 1 {
		t.Fatalf("partial process kill/wait = %d/%d, want exact termination and reap", partial.killCalls, partial.waitCalls)
	}
}

func TestL7NamespaceProcessRunnerReapsStartedProcessWhenNamespaceFileCloseIsUncertain(t *testing.T) {
	user := l7OpenProcessFile(t, "user-namespace")
	network := l7OpenProcessFile(t, "network-namespace")
	kernel := l7OpenProcessFile(t, "kernel")
	rootfs := l7OpenProcessFile(t, "rootfs")
	partial := &l7NamespaceHostProcess{}
	runner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace: &l7NamespaceFileProvider{user: user, network: network},
		Starter: &l7NamespaceProcessStarter{start: func(_ context.Context, request NamespaceProcessStartRequest) (HostProcess, error) {
			if err := request.InheritedFiles[0].Close(); err != nil {
				t.Fatal(err)
			}
			return partial, nil
		}},
		NSenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatal(err)
	}
	process, err := runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "/usr/bin/firecracker", InheritedFiles: []*os.File{kernel, rootfs},
	})
	if process != nil || !errors.Is(err, ErrNamespaceProcessCleanupIncomplete) {
		t.Fatalf("StartHostProcess() = %#v, %v, want contained close uncertainty", process, err)
	}
	if partial.killCalls != 1 || partial.waitCalls != 1 {
		t.Fatalf("started process kill/wait = %d/%d, want exact termination and reap", partial.killCalls, partial.waitCalls)
	}
}

func TestOSExecNamespaceProcessStarterRejectsCanceledContextBeforeLaunch(t *testing.T) {
	files := l7NamespaceStarterFiles(t)
	startCalls := 0
	starter := OSExecNamespaceProcessStarter{startCommand: func(*exec.Cmd) error {
		startCalls++
		return errors.New("start must not be reached")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	process, err := starter.StartNamespaceProcess(ctx, l7NamespaceStarterRequest(files))
	if process != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("StartNamespaceProcess(canceled) = %#v, %v, want context cancellation", process, err)
	}
	if startCalls != 0 {
		t.Fatalf("canceled namespace process start calls = %d, want 0", startCalls)
	}
}

func TestOSExecNamespaceProcessStarterNormalizesNilContext(t *testing.T) {
	files := l7NamespaceStarterFiles(t)
	privateFailure := errors.New("private injected start failure")
	startCalls := 0
	starter := OSExecNamespaceProcessStarter{startCommand: func(*exec.Cmd) error {
		startCalls++
		return privateFailure
	}}

	//nolint:staticcheck // This compatibility test deliberately exercises nil-context normalization.
	process, err := starter.StartNamespaceProcess(nil, l7NamespaceStarterRequest(files))
	if process != nil || !errors.Is(err, ErrNamespaceProcessStartFailed) || errors.Is(err, privateFailure) {
		t.Fatalf("StartNamespaceProcess(nil) = %#v, %v, want sanitized start failure", process, err)
	}
	if startCalls != 1 {
		t.Fatalf("nil-context namespace process start calls = %d, want 1", startCalls)
	}
}

func TestOSExecNamespaceProcessStarterRejectsNilAndDuplicateFileHandlesBeforeLaunch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]*os.File) []*os.File
	}{
		{name: "nil", mutate: func(files []*os.File) []*os.File {
			files[2] = nil
			return files
		}},
		{name: "duplicate pointer", mutate: func(files []*os.File) []*os.File {
			files[3] = files[2]
			return files
		}},
		{name: "duplicate descriptor", mutate: func(files []*os.File) []*os.File {
			alias := *files[2]
			files[3] = &alias
			return files
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := tt.mutate(l7NamespaceStarterFiles(t))
			startCalls := 0
			starter := OSExecNamespaceProcessStarter{startCommand: func(*exec.Cmd) error {
				startCalls++
				return nil
			}}
			process, err := starter.StartNamespaceProcess(context.Background(), l7NamespaceStarterRequest(files))
			if process != nil || !errors.Is(err, ErrNamespaceProcessRequestInvalid) {
				t.Fatalf("StartNamespaceProcess(invalid files) = %#v, %v", process, err)
			}
			if startCalls != 0 {
				t.Fatalf("invalid file request start calls = %d, want 0", startCalls)
			}
		})
	}
}

func l7NamespaceStarterFiles(t *testing.T) []*os.File {
	t.Helper()
	return []*os.File{
		l7OpenProcessFile(t, "user-namespace"),
		l7OpenProcessFile(t, "network-namespace"),
		l7OpenProcessFile(t, "kernel"),
		l7OpenProcessFile(t, "rootfs"),
	}
}

func l7NamespaceStarterRequest(files []*os.File) NamespaceProcessStartRequest {
	return NamespaceProcessStartRequest{
		Executable: "/usr/bin/nsenter",
		Args: []string{
			"--user=/proc/self/fd/3",
			"--net=/proc/self/fd/4",
			"--",
			"/usr/bin/firecracker",
		},
		InheritedFiles: files,
	}
}

func l7OpenProcessFile(t *testing.T, name string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

type l7NamespaceFileProvider struct {
	user    *os.File
	network *os.File
	calls   int
}

func (provider *l7NamespaceFileProvider) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	provider.calls++
	return provider.user, provider.network, nil
}

type l7NamespaceProcessStarter struct {
	start func(context.Context, NamespaceProcessStartRequest) (HostProcess, error)
	calls int
}

func (starter *l7NamespaceProcessStarter) StartNamespaceProcess(ctx context.Context, request NamespaceProcessStartRequest) (HostProcess, error) {
	starter.calls++
	if starter.start == nil {
		return &l7NamespaceHostProcess{}, nil
	}
	return starter.start(ctx, request)
}

type l7NamespaceHostProcess struct {
	waitCalls int
	killCalls int
}

func (process *l7NamespaceHostProcess) Wait(context.Context) error {
	process.waitCalls++
	return nil
}
func (*l7NamespaceHostProcess) Signal(context.Context, ProcessSignal) error { return nil }
func (process *l7NamespaceHostProcess) Kill(context.Context) error {
	process.killCalls++
	return nil
}
