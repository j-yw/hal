//go:build firecracker_live

package firecrackerhost

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	firecrackerHostLiveEnvEnabled    = "HAL_FIRECRACKER_LIVE"
	firecrackerHostLiveEnvExecutable = "HAL_FIRECRACKER_LIVE_FIRECRACKER"
	firecrackerHostLiveTimeout       = 5 * time.Second
	firecrackerHostLiveStopTimeout   = 2 * time.Second
)

func TestOSExecProcessRunnerLiveStartsFirecrackerAPISocket(t *testing.T) {
	prereqs, skip := firecrackerHostLivePrerequisitesFromEnv(os.Getenv)
	if skip != "" {
		t.Skip(skip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), firecrackerHostLiveTimeout)
	defer cancel()

	socketPath := filepath.Join(t.TempDir(), firecracker.DefaultAPISocketPath)
	process, err := NewOSExecProcessRunner().StartHostProcess(ctx, firecracker.ProcessRunnerStartRequest{
		Executable:  prereqs.executable,
		Args:        []string{"--api-sock", socketPath},
		Environment: []string{},
	})
	if err != nil {
		t.Fatalf("StartHostProcess() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), firecrackerHostLiveStopTimeout)
		defer cleanupCancel()
		_ = process.Kill(cleanupCtx)
		_ = process.Wait(cleanupCtx)
	})

	if err := firecrackerHostLiveWaitForAPISocket(ctx, socketPath); err != nil {
		t.Fatalf("Firecracker API socket was not accepted: %v", err)
	}
	if err := process.Kill(ctx); err != nil {
		t.Fatalf("Kill() error = %v, want nil", err)
	}
	if err := process.Wait(ctx); err != nil {
		t.Fatalf("Wait() after Kill() error = %v, want nil", err)
	}
}

type firecrackerHostLivePrerequisites struct {
	executable string
}

func firecrackerHostLivePrerequisitesFromEnv(getenv func(string) string) (firecrackerHostLivePrerequisites, string) {
	if strings.TrimSpace(getenv(firecrackerHostLiveEnvEnabled)) != "1" {
		return firecrackerHostLivePrerequisites{}, fmt.Sprintf("%s=1 is required for Firecracker host live tests", firecrackerHostLiveEnvEnabled)
	}
	if runtime.GOOS != "linux" {
		return firecrackerHostLivePrerequisites{}, "Firecracker host live tests require Linux"
	}

	executable := strings.TrimSpace(getenv(firecrackerHostLiveEnvExecutable))
	if executable == "" {
		return firecrackerHostLivePrerequisites{}, fmt.Sprintf("%s is required for Firecracker host live tests", firecrackerHostLiveEnvExecutable)
	}
	if hasOSExecProcessControl(executable) {
		return firecrackerHostLivePrerequisites{}, fmt.Sprintf("%s is invalid", firecrackerHostLiveEnvExecutable)
	}
	info, err := os.Stat(executable)
	switch {
	case err != nil:
		return firecrackerHostLivePrerequisites{}, fmt.Sprintf("%s must point to an executable regular file", firecrackerHostLiveEnvExecutable)
	case info == nil || info.IsDir() || info.Mode()&0o111 == 0:
		return firecrackerHostLivePrerequisites{}, fmt.Sprintf("%s must point to an executable regular file", firecrackerHostLiveEnvExecutable)
	default:
		return firecrackerHostLivePrerequisites{executable: executable}, ""
	}
}

func firecrackerHostLiveWaitForAPISocket(ctx context.Context, path string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		available, err := firecrackerHostLiveAPISocketAvailable(path)
		if err != nil {
			return err
		}
		if available {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func firecrackerHostLiveAPISocketAvailable(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return info != nil && info.Mode()&os.ModeSocket != 0, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}
