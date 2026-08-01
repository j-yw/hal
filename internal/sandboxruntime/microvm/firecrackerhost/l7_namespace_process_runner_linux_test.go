//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
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

type l7NamespaceHostProcess struct{}

func (*l7NamespaceHostProcess) Wait(context.Context) error                  { return nil }
func (*l7NamespaceHostProcess) Signal(context.Context, ProcessSignal) error { return nil }
func (*l7NamespaceHostProcess) Kill(context.Context) error                  { return nil }
