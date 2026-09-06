package cmd

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestFactoryRootlessBundleDoesNotCloneRemote(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	target := workerRootlessCachedSandbox("factory-local")
	store := factory.NewStore(t.TempDir())
	cloneCalls := 0
	driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
		exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: t.TempDir(), SandboxName: target.Name, SandboxHostID: target.Host.ID,
		SandboxRuntime: sandboxruntime.DriverRootlessPodman, RemoteOutput: io.Discard, DeferSuccessCleanup: true,
		RunRecord: factory.RunRecord{RunID: "factory-local", RepoRemote: "https://example.invalid/private/repo.git", BaseBranch: "local-base", BranchName: "hal/factory-output"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil }, now: time.Now,
		loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
		listHosts: func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil },
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) { return driver, nil },
		persistSandboxState: func(*sandbox.SandboxState) error { return nil },
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			cloneCalls++
			return factory.BootstrapResult{}, errors.New("private remote clone is unavailable")
		},
	})
	if err != nil || cloneCalls != 0 {
		t.Fatalf("local factory input attempted remote bootstrap: calls=%d error=%v", cloneCalls, err)
	}
}

func TestFactoryRootlessBundleUsesImageHal(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	target := workerRootlessCachedSandbox("image-hal")
	driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if strings.Contains(strings.Join(req.Args, " "), `exec "$HOME/.local/bin/hal"`) {
				return &sandboxruntime.ExecResult{ExitCode: 127}, errors.New("image has no per-user Hal installation")
			}
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	if err := executeWorkerGitIdentityFixture(t, "factory", t.TempDir(), target, driver); err != nil {
		t.Fatalf("rootless factory did not use image Hal: %v", err)
	}
}
