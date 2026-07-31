//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	sealedAssetHarnessMarker  = "--hal-sealed-asset-harness"
)

func TestOSExecProcessRunnerPassesOnlyExplicitInheritedFiles(t *testing.T) {
	first, err := os.CreateTemp(t.TempDir(), "kernel-")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.CreateTemp(t.TempDir(), "rootfs-")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	wantErr := errors.New("stop before process start")
	runner := OSExecProcessRunner{startCommand: func(command *exec.Cmd) error {
		if len(command.ExtraFiles) != 2 || command.ExtraFiles[0] != first || command.ExtraFiles[1] != second {
			t.Fatalf("command ExtraFiles = %#v, want exact explicit file set", command.ExtraFiles)
		}
		return wantErr
	}}
	process, err := runner.StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable:     "firecracker",
		InheritedFiles: []*os.File{first, second},
	})
	if process != nil {
		t.Fatalf("process = %#v, want nil", process)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("StartHostProcess() error = %v, want injected stop", err)
	}
}

func TestOSExecProcessRunnerMapsSealedAssetsToChildFDThreeAndFour(t *testing.T) {
	kernel := sealedAssetFile(t, "hal-l7-kernel", []byte("verified-l7-kernel"))
	rootfs := sealedAssetFile(t, "hal-l7-rootfs", []byte("verified-l7-rootfs"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process, err := NewOSExecProcessRunner().StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: executable,
		Args: []string{
			"-test.run=^TestOSExecProcessRunnerSealedAssetChildHarness$",
			"--",
			sealedAssetHarnessMarker,
		},
		InheritedFiles: []*os.File{kernel, rootfs},
	})
	if err != nil {
		t.Fatalf("StartHostProcess() error = %v", err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Wait(waitCtx); err != nil {
		t.Fatalf("sealed asset child failed: %v", err)
	}
}

func TestOSExecProcessRunnerSealedAssetChildHarness(t *testing.T) {
	if !hasPrivateUmaskMarker(sealedAssetHarnessMarker) {
		t.Skip("sealed asset subprocess harness")
	}
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for index, want := range [][]byte{[]byte("verified-l7-kernel"), []byte("verified-l7-rootfs")} {
		fd := 3 + index
		seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
		if err != nil || seals&wantSeals != wantSeals {
			t.Fatalf("child fd %d seals = %x, error = %v", fd, seals, err)
		}
		got, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			t.Fatalf("read child fd %d: %v", fd, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("child fd %d bytes = %q, want verified asset", fd, got)
		}
		file := os.NewFile(uintptr(fd), "sealed-child-asset")
		if _, err := file.WriteAt([]byte("x"), 0); err == nil {
			t.Fatalf("child fd %d accepted a write", fd)
		}
	}
	if seals, err := unix.FcntlInt(5, unix.F_GET_SEALS, 0); err == nil && seals&wantSeals == wantSeals {
		t.Fatal("unexpected third sealed launch asset inherited at child fd 5")
	}
}

func sealedAssetFile(t *testing.T, name string, contents []byte) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(contents); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
	}
	return file
}

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

func hasPrivateUmaskMarker(marker string) bool {
	for _, value := range os.Args {
		if value == marker {
			return true
		}
	}
	return false
}
