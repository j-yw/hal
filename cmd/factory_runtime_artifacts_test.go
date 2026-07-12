package cmd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/verify"
)

func TestFactoryRuntimeSandboxArtifactCopierCopiesFilesAndDirectories(t *testing.T) {
	var execArgs [][]string
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execArgs = append(execArgs, append([]string(nil), req.Args...))
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			if strings.HasSuffix(req.SourcePath, ".tar") {
				return writeFactoryRuntimeArtifactTestTar(req.DestinationPath, "result.txt", "directory payload\n")
			}
			return os.WriteFile(req.DestinationPath, []byte("file payload\n"), 0o600)
		},
	}
	copier := factoryRuntimeSandboxArtifactCopier{
		driver:  driver,
		target:  sandboxruntime.Target{ID: "container-1", Name: "worker-rootless"},
		baseDir: "/root/workspace/game",
	}

	fileDestination := filepath.Join(t.TempDir(), "progress.txt")
	if err := copier.CopyFile(context.Background(), ".hal/progress.txt", fileDestination); err != nil {
		t.Fatalf("CopyFile() error: %v", err)
	}
	if data, err := os.ReadFile(fileDestination); err != nil || string(data) != "file payload\n" {
		t.Fatalf("copied file = %q, err=%v", data, err)
	}

	dirDestination := filepath.Join(t.TempDir(), "reports")
	if err := copier.CopyDir(context.Background(), ".hal/reports", dirDestination); err != nil {
		t.Fatalf("CopyDir() error: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dirDestination, "result.txt")); err != nil || string(data) != "directory payload\n" {
		t.Fatalf("copied directory file = %q, err=%v", data, err)
	}
	joined := make([]string, 0, len(execArgs))
	for _, args := range execArgs {
		joined = append(joined, strings.Join(args, " "))
	}
	if !strings.Contains(strings.Join(joined, "\n"), "tar -C '/root/workspace/game/.hal/reports'") {
		t.Fatalf("runtime exec calls = %#v, want in-target directory archive", execArgs)
	}
}

func TestFactoryRuntimeSandboxArtifactCopierMapsMissingOptionalPath(t *testing.T) {
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if len(req.Args) > 0 && req.Args[0] == "test" {
				return &sandboxruntime.ExecResult{ExitCode: 1}, errors.New("path missing")
			}
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	copier := factoryRuntimeSandboxArtifactCopier{
		driver:  driver,
		target:  sandboxruntime.Target{ID: "container-1"},
		baseDir: "/root/workspace/game",
	}

	err := copier.CopyFile(context.Background(), ".hal/missing.json", filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, factory.ErrSandboxArtifactNotFound) {
		t.Fatalf("CopyFile() error = %v, want ErrSandboxArtifactNotFound", err)
	}
}

func TestCollectFactorySandboxArtifactsRoutesWorkerTargetThroughRuntime(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := store.Ensure(); err != nil {
		t.Fatalf("store.Ensure() error: %v", err)
	}
	record := factory.RunRecord{
		RunID:        "worker-runtime-artifacts",
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:example/game.git",
		SandboxName:  "worker-rootless",
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	target := workerRootlessCachedSandbox("worker-rootless")
	var resolvedRuntime bool
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			return os.WriteFile(req.DestinationPath, []byte("runtime artifact\n"), 0o600)
		},
	}

	err := collectAndStoreFactorySandboxArtifacts(context.Background(), store, t.TempDir(), factoryRunRequest{}, record, factoryRunDeps{
		now: func() time.Time { return time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC) },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveSandboxRuntime: func(_ string, got *sandbox.SandboxState) (sandboxruntime.Driver, error) {
			resolvedRuntime = true
			if got != target {
				t.Fatalf("runtime target = %#v, want loaded worker target", got)
			}
			return driver, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			t.Fatal("provider resolution should not run for worker artifact collection")
			return nil, nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{{
				ID:         "progress",
				Name:       "progress",
				Type:       "text",
				RemotePath: ".hal/progress.txt",
				Path:       ".hal/progress.txt",
			}}
		},
	})
	if err != nil {
		t.Fatalf("collectAndStoreFactorySandboxArtifacts() error: %v", err)
	}
	if !resolvedRuntime {
		t.Fatal("worker runtime resolver was not called")
	}
	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if len(loaded.Artifacts) != 1 || loaded.Artifacts[0].StoredPath == "" {
		t.Fatalf("stored artifacts = %#v, want runtime-collected artifact", loaded.Artifacts)
	}
}

func TestCleanupFactoryRunDeferredWorkerSandboxUsesRuntimeDelete(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := store.Ensure(); err != nil {
		t.Fatalf("store.Ensure() error: %v", err)
	}
	record := factory.RunRecord{
		RunID:        "worker-runtime-cleanup",
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:example/game.git",
		SandboxName:  "worker-rootless",
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	target := workerRootlessCachedSandbox("worker-rootless")
	var deleted sandboxruntime.Target
	driver := fakeFactorySandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		deleteFn: func(_ context.Context, req sandboxruntime.LifecycleRequest) error {
			deleted = req.Target
			return nil
		},
	}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorAlways

	updated, cleaned, err := cleanupFactoryRunDeferredWorkerSandbox(context.Background(), store, t.TempDir(), factoryRunRequest{}, record, factoryRunDeps{
		now: func() time.Time { return time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC) },
		resolveSandboxRuntime: func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			t.Fatal("provider resolution should not run for worker cleanup")
			return nil, nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return nil
		},
	}, policy, "success", target)
	if err != nil {
		t.Fatalf("cleanupFactoryRunDeferredWorkerSandbox() error: %v", err)
	}
	if !cleaned || updated.Sandbox == nil || updated.Sandbox.Status != sandbox.StatusUnknown || updated.Sandbox.Connection != nil {
		t.Fatalf("cleaned record = %#v, cleaned=%t", updated.Sandbox, cleaned)
	}
	if deleted.Runtime.RuntimeID != target.Runtime.RuntimeID {
		t.Fatalf("deleted target = %#v, want worker runtime target", deleted)
	}
}

func TestRunFactorySandboxRemoteVerificationUsesWorkerRuntime(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	record := factory.RunRecord{
		RunID:        "worker-runtime-verify",
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:example/game.git",
		SandboxName:  "worker-rootless",
		Sandbox:      &factory.SandboxMetadata{Name: "worker-rootless"},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	target := workerRootlessCachedSandbox(record.SandboxName)
	secret := "worker-verify-secret"
	var gotEnv map[string]string
	driver := fakeFactorySandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			gotEnv = req.Env
			if err := json.NewEncoder(req.Stdout).Encode(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{Total: 1, Passed: 1},
			}); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	resolvedSecrets := []factory.ResolvedRunSecret{{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Value: secret}}
	result, _, err := runFactorySandboxRemoteVerification(context.Background(), store, t.TempDir(), record, factoryRunDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveSandboxRuntime: func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			t.Fatal("provider resolution should not run for worker verification")
			return nil, nil
		},
		runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
			t.Fatal("provider exec should not run for worker verification")
			return nil
		},
	}, resolvedSecrets, factory.NewRunSecretRedactor(resolvedSecrets))
	if err != nil {
		t.Fatalf("runFactorySandboxRemoteVerification() error: %v", err)
	}
	if result == nil || result.Status != verify.StatusPass || gotEnv["GITHUB_TOKEN"] != secret {
		t.Fatalf("result = %#v, env = %#v", result, gotEnv)
	}
}

func TestPublishFactoryRunWithSandboxRunnerUsesWorkerRuntime(t *testing.T) {
	target := workerRootlessCachedSandbox("worker-rootless")
	record := factory.RunRecord{
		RunID:        "worker-runtime-publish",
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:example/game.git",
		BranchName:   "hal/worker-runtime-publish",
		BaseBranch:   "main",
		SandboxName:  target.Name,
		Sandbox:      &factory.SandboxMetadata{Name: target.Name},
	}
	secret := "worker-publish-secret"
	var gotEnv map[string]string
	driver := fakeFactorySandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			gotEnv = req.Env
			if err := json.NewEncoder(req.Stdout).Encode(factorySandboxPublishResult{
				ContractVersion: "factory-publish-branch-v1",
				OK:              true,
				Commit:          "abc123",
				Push: ci.PushResult{
					ContractVersion: ci.PushContractVersion,
					Branch:          record.BranchName,
					Pushed:          true,
				},
			}); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	resolvedSecrets := []factory.ResolvedRunSecret{{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Value: secret}}
	result, err := publishFactoryRunWithSandboxRunner(context.Background(), t.TempDir(), factoryRunRequest{
		Sandbox:         true,
		SandboxName:     target.Name,
		PublishFrom:     factory.PublishRunnerSandbox,
		ResolvedSecrets: resolvedSecrets,
	}, record, factoryRunDeps{
		now:         time.Now,
		loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveSandboxRuntime: func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			t.Fatal("provider resolution should not run for worker publish")
			return nil, nil
		},
		runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
			t.Fatal("provider exec should not run for worker publish")
			return nil
		},
	}, factory.PublishPolicyPush, nil)
	if err != nil {
		t.Fatalf("publishFactoryRunWithSandboxRunner() error: %v", err)
	}
	if result.Runner != factory.PublishRunnerSandbox || result.Commit != "abc123" || gotEnv["GITHUB_TOKEN"] != secret {
		t.Fatalf("result = %#v, env = %#v", result, gotEnv)
	}
}

func writeFactoryRuntimeArtifactTestTar(path, name, content string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(file)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		_ = file.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
