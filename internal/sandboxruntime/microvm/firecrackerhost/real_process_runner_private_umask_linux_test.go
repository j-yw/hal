//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"golang.org/x/sys/unix"
)

const (
	privateUmaskHarnessMarker = "--hal-private-umask-harness"
	privateUmaskSocketMarker  = "--hal-private-umask-socket"
)

func TestOSExecProcessRunnerFailsClosedWhenFilesystemIsolationFails(t *testing.T) {
	started := false
	err := startPrivateOSExecLaunch(privateOSExecLaunchOps{
		unshare: func(int) error { return errors.New("injected unshare failure") },
		umask:   unix.Umask,
		start: func() error {
			started = true
			return nil
		},
	})
	if !errors.Is(err, errHostProcessPrivateLaunch) {
		t.Fatalf("startPrivateOSExecLaunch() error = %v, want private launch failure", err)
	}
	if started {
		t.Fatal("process start ran after filesystem isolation failure")
	}
}

func TestOSExecProcessRunnerUsesPrivateChildUmask(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "firecracker.sock")
	command := exec.Command(
		executable,
		"-test.run=^TestOSExecProcessRunnerPrivateUmaskHarness$",
		"--",
		privateUmaskHarnessMarker,
		socketPath,
	)
	command.Env = []string{}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("private umask harness failed: %v\n%s", err, output)
	}
}

func TestOSExecProcessRunnerPrivateUmaskHarness(t *testing.T) {
	socketPath, ok := privateUmaskTestPath(privateUmaskHarnessMarker)
	if !ok {
		t.Skip("private umask subprocess harness")
	}

	previous := unix.Umask(0)
	defer unix.Umask(previous)

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process, err := NewOSExecProcessRunner().StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: executable,
		Args: []string{
			"-test.run=^TestOSExecProcessRunnerPrivateUmaskSocketHelper$",
			"--",
			privateUmaskSocketMarker,
			socketPath,
		},
	})
	if err != nil {
		t.Fatalf("StartHostProcess() error = %v", err)
	}
	if inherited := unix.Umask(0); inherited != 0 {
		t.Fatalf("launcher umask changed to %#o, want inherited %#o", inherited, 0)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = process.Kill(cleanupCtx)
		_ = process.Wait(cleanupCtx)
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		info, statErr := os.Lstat(socketPath)
		if statErr == nil {
			if info.Mode()&os.ModeSocket == 0 {
				t.Fatalf("child endpoint mode = %v, want Unix socket", info.Mode())
			}
			if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
				t.Fatalf("child endpoint permissions = %o, want %o", got, want)
			}
			return
		}
		if !os.IsNotExist(statErr) {
			t.Fatal(statErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for child Unix socket")
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOSExecProcessRunnerPrivateUmaskSocketHelper(t *testing.T) {
	socketPath, ok := privateUmaskTestPath(privateUmaskSocketMarker)
	if !ok {
		t.Skip("private umask socket subprocess")
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	select {}
}

func privateUmaskTestPath(marker string) (string, bool) {
	for i := 0; i+1 < len(os.Args); i++ {
		if os.Args[i] == marker {
			return os.Args[i+1], true
		}
	}
	return "", false
}
