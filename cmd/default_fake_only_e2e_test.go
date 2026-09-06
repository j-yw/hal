package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestUS006DefaultFakeOnlyE2ERunAutoAndFactoryPaths(t *testing.T) {
	t.Run("run sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		startedAt := time.Date(2026, 7, 4, 2, 5, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(root, "repo")
		store := sandboxexecution.NewStore(filepath.Join(root, "run-executions"))
		target := us006DefaultWorkerBackedTarget("us006-run-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := &us006DefaultFakeOnlyProbe{t: t, lane: "run", output: `{"contractVersion":1,"ok":true,"iterations":1,"complete":true,"summary":"us006 run fake-only"}` + "\n"}

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "run-us006-default-fake-only-e2e"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us006BundleWorkspacePlan(projectDir), nil
			},
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              probe.forbiddenBootstrap,
			materializeWorkspace:   probe.materializeWorkspace,
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		if resolver.calls != 1 {
			t.Fatalf("run default resolver calls = %d, want 1", resolver.calls)
		}
		probe.requireRunAutoPath(t, "run")
		if !strings.Contains(out.String(), "us006 run fake-only") {
			t.Fatalf("run stdout = %q, want fake-only command output", out.String())
		}
		manifest := us006LoadExecutionManifest(t, store, "run-us006-default-fake-only-e2e")
		us006RequireExecutionManifestFakeOnly(t, manifest, sandboxexecution.PurposeRun, target.Name, store.Root(), root)
	})

	t.Run("auto sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		startedAt := time.Date(2026, 7, 4, 2, 6, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(root, "repo")
		store := sandboxexecution.NewStore(filepath.Join(root, "auto-executions"))
		target := us006DefaultWorkerBackedTarget("us006-auto-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := &us006DefaultFakeOnlyProbe{t: t, lane: "auto", output: autoSandboxRemoteSuccessJSON("us006 auto fake-only") + "\n"}

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "auto-us006-default-fake-only-e2e"
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us006BundleWorkspacePlan(projectDir), nil
			},
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              probe.forbiddenBootstrap,
			materializeWorkspace:   probe.materializeWorkspace,
		})
		if err != nil {
			t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		if resolver.calls != 1 {
			t.Fatalf("auto default resolver calls = %d, want 1", resolver.calls)
		}
		probe.requireRunAutoPath(t, "auto")
		if !strings.Contains(out.String(), "us006 auto fake-only") {
			t.Fatalf("auto stdout = %q, want fake-only command output", out.String())
		}
		manifest := us006LoadExecutionManifest(t, store, "auto-us006-default-fake-only-e2e")
		us006RequireExecutionManifestFakeOnly(t, manifest, sandboxexecution.PurposeAuto, target.Name, store.Root(), root)
	})

	t.Run("factory sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		now := runSandboxTestClock(
			time.Date(2026, 7, 4, 2, 7, 0, 0, time.UTC),
			time.Date(2026, 7, 4, 2, 7, 1, 0, time.UTC),
		)
		store := factory.NewStore(filepath.Join(root, "factory-store"))
		target := us006DefaultWorkerBackedTarget("us006-factory-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := &us006DefaultFakeOnlyProbe{t: t, lane: "factory", output: "us006 factory fake-only\n"}

		var out bytes.Buffer
		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir: filepath.Join(root, "repo"),
			RunRecord: factory.RunRecord{
				RunID:      "factory-us006-default-fake-only-e2e",
				RepoPath:   "/workspace/us006-factory-repo",
				BranchName: "feature/us006-default-fake-only",
				BaseBranch: "main",
				Status:     factory.RunStatusRunning,
			},
			RemoteAuto:          factoryRunAutoRequest{BaseBranch: "main"},
			RemoteOutput:        &out,
			DeferSuccessCleanup: true,
		}, factorySandboxExecutorDeps{
			defaultStore:           func() (factory.Store, error) { return store, nil },
			now:                    now,
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExec:        probe.forbiddenProviderExec,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              probe.forbiddenBootstrap,
			cleanupSandbox:         probe.cleanupSandbox,
		})
		if err != nil {
			t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
		}
		if resolver.calls != 1 {
			t.Fatalf("factory default resolver calls = %d, want 1", resolver.calls)
		}
		probe.requireFactoryPath(t)
		if !strings.Contains(out.String(), "us006 factory fake-only") {
			t.Fatalf("factory output = %q, want fake-only command output", out.String())
		}
		storedRun, err := store.LoadRun("factory-us006-default-fake-only-e2e")
		if err != nil {
			t.Fatalf("LoadRun() error = %v", err)
		}
		if storedRun.Sandbox == nil || storedRun.Sandbox.Name != target.Name {
			t.Fatalf("factory stored sandbox = %#v, want %q", storedRun.Sandbox, target.Name)
		}
		if storedRun.Sandbox.WorkerRouting != nil {
			t.Fatalf("factory WorkerRouting = %#v, want nil for default fake-only path", storedRun.Sandbox.WorkerRouting)
		}
		if storedRun.Sandbox.Runtime == nil || storedRun.Sandbox.Runtime.Driver != sandboxruntime.DriverSSHMachine {
			t.Fatalf("factory stored runtime = %#v, want SSH-machine-compatible default runtime", storedRun.Sandbox.Runtime)
		}
		if storedRun.Sandbox.Runtime.WorkerID != "" || storedRun.Sandbox.Runtime.RuntimeID != "" || storedRun.Sandbox.Runtime.Image != "" {
			t.Fatalf("factory stored runtime metadata = %#v, want no worker-backed runtime metadata on default path", storedRun.Sandbox.Runtime)
		}
		if !strings.HasPrefix(store.Root(), root) {
			t.Fatalf("factory store root = %q, want under temp root %q", store.Root(), root)
		}
	})
}

type us006DefaultFakeOnlyProbe struct {
	t                   *testing.T
	lane                string
	output              string
	providerResolutions int
	runtimeResolutions  int
	execCalls           int
	commandExecCalls    int
	copyOutCalls        int
	authFileChecks      int
	materializeCalls    int
	persistCalls        int
	cleanupCalls        int
}

func (p *us006DefaultFakeOnlyProbe) resolveProvider(providerName string) (sandbox.Provider, error) {
	p.providerResolutions++
	if strings.TrimSpace(providerName) != "test-provider" {
		p.t.Fatalf("%s provider name = %q, want test-provider", p.lane, providerName)
	}
	return fakeFactorySandboxProvider{}, nil
}

func (p *us006DefaultFakeOnlyProbe) resolveRuntimeDriver(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
	p.runtimeResolutions++
	if target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		p.t.Fatalf("%s runtime driver = %q, want SSH-machine compatibility", p.lane, target.Runtime.Driver)
	}
	if target.Runtime.WorkerID != "" || target.Runtime.RuntimeID != "" || target.Runtime.Image != "" {
		p.t.Fatalf("%s runtime metadata = %#v, want no worker metadata on default path", p.lane, target.Runtime)
	}
	return fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			p.execCalls++
			joinedArgs := strings.Join(req.Args, " ")
			if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				p.t.Fatalf("%s exec runtime driver = %q, want SSH-machine compatibility", p.lane, req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
				p.t.Fatalf("%s exec runtime metadata = %#v, want no worker metadata on default path", p.lane, req.Target.Runtime)
			}
			if !strings.Contains(joinedArgs, "hal") {
				p.t.Fatalf("%s exec args = %#v, want hal command", p.lane, req.Args)
			}
			if strings.Contains(joinedArgs, "exec 'hal'") || strings.Contains(joinedArgs, `exec "$HOME/.local/bin/hal"`) || (len(req.Args) > 0 && req.Args[0] == "hal") {
				p.commandExecCalls++
				if _, err := io.WriteString(req.Stdout, p.output); err != nil {
					return nil, err
				}
			}
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(ctx context.Context, req sandboxruntime.CopyRequest) error {
			p.copyOutCalls++
			return fakeRunSandboxRuntimeDriver{}.CopyOut(ctx, req)
		},
	}, nil
}

func (p *us006DefaultFakeOnlyProbe) materializeWorkspace(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
	p.materializeCalls++
	return sandboxworkspace.MaterializationResult{}, nil
}

func (p *us006DefaultFakeOnlyProbe) engineAuthFiles() []factorySandboxAuthFile {
	p.authFileChecks++
	return nil
}

func (p *us006DefaultFakeOnlyProbe) persistSandboxState(*sandbox.SandboxState) error {
	p.persistCalls++
	return nil
}

func (p *us006DefaultFakeOnlyProbe) cleanupSandbox(context.Context, factorySandboxCleanupRequest) error {
	p.cleanupCalls++
	return nil
}

func (p *us006DefaultFakeOnlyProbe) requireRunAutoPath(t *testing.T, lane string) {
	t.Helper()
	if p.materializeCalls != 1 {
		t.Fatalf("%s materialize workspace calls = %d, want 1 fake materialization", lane, p.materializeCalls)
	}
	if p.providerResolutions != 1 {
		t.Fatalf("%s provider resolutions = %d, want one fake provider resolution for inert auth prep", lane, p.providerResolutions)
	}
	if p.runtimeResolutions != 1 {
		t.Fatalf("%s runtime resolutions = %d, want 1", lane, p.runtimeResolutions)
	}
	if p.commandExecCalls != 1 {
		t.Fatalf("%s command exec calls = %d, want 1 fake remote hal command", lane, p.commandExecCalls)
	}
	if p.execCalls < p.commandExecCalls {
		t.Fatalf("%s exec calls = %d, command exec calls = %d", lane, p.execCalls, p.commandExecCalls)
	}
	if p.authFileChecks != 1 {
		t.Fatalf("%s auth file checks = %d, want one inert auth check", lane, p.authFileChecks)
	}
	if p.copyOutCalls == 0 {
		t.Fatalf("%s copy-out calls = 0, want artifact collection through fake runtime transport", lane)
	}
}

func (p *us006DefaultFakeOnlyProbe) requireFactoryPath(t *testing.T) {
	t.Helper()
	if p.materializeCalls != 0 {
		t.Fatalf("factory materialize workspace calls = %d, want none for existing /workspace repo", p.materializeCalls)
	}
	if p.providerResolutions != 1 {
		t.Fatalf("factory provider resolutions = %d, want one fake provider resolution for inert prep", p.providerResolutions)
	}
	if p.runtimeResolutions != 1 {
		t.Fatalf("factory runtime resolutions = %d, want 1", p.runtimeResolutions)
	}
	if p.commandExecCalls != 1 {
		t.Fatalf("factory command exec calls = %d, want 1 fake remote hal command", p.commandExecCalls)
	}
	if p.execCalls < p.commandExecCalls {
		t.Fatalf("factory exec calls = %d, command exec calls = %d", p.execCalls, p.commandExecCalls)
	}
	if p.authFileChecks != 1 {
		t.Fatalf("factory auth file checks = %d, want one inert auth check", p.authFileChecks)
	}
	if p.cleanupCalls != 0 {
		t.Fatalf("factory cleanup calls = %d, want no cleanup for preserve/default fake path", p.cleanupCalls)
	}
}

func (p *us006DefaultFakeOnlyProbe) forbiddenLoadSandbox(string) (*sandbox.SandboxState, error) {
	p.t.Fatalf("%s loadSandbox should not run without explicit sandbox name", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenListSandboxes() ([]*sandbox.SandboxState, error) {
	p.t.Fatalf("%s listSandboxes should not run when injected default resolver owns selection", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenListHosts() ([]*sandbox.SandboxHost, error) {
	p.t.Fatalf("%s listHosts should not run without explicit host/runtime scheduling", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenListLeases() ([]*sandbox.SandboxLease, error) {
	p.t.Fatalf("%s listLeases should not run without explicit host/runtime scheduling", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenProvision(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
	p.t.Fatalf("%s provision should not run for cached default fake-only path", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenAcquireLease(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
	p.t.Fatalf("%s acquireLease should not run without explicit scheduler target", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenWorkerRuntime(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
	p.t.Fatalf("%s worker runtime resolver should not run without explicit worker routing flags", p.lane)
	return nil, nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenProviderExec(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
	p.t.Fatalf("%s provider exec should not run in default fake-only E2E path", p.lane)
	return nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenProviderExecWithEnv(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
	p.t.Fatalf("%s provider exec with env should not run in default fake-only E2E path", p.lane)
	return nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenProviderScript(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
	p.t.Fatalf("%s provider script should not run in default fake-only E2E path", p.lane)
	return nil
}

func (p *us006DefaultFakeOnlyProbe) forbiddenBootstrap(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
	p.t.Fatalf("%s bootstrap should not run in default fake-only E2E path", p.lane)
	return factory.BootstrapResult{}, nil
}

func us006PrepareFakeOnlyTestEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{
		filepath.Join(root, "hal-config"),
		filepath.Join(root, "repo"),
		filepath.Join(root, "codex-home"),
		filepath.Join(root, "pi-home", "agent"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", dir, err)
		}
	}
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(root, "hal-config"))
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex-home"))
	t.Setenv("PI_HOME", filepath.Join(root, "pi-home"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	for path, payload := range map[string]string{
		filepath.Join(root, "codex-home", "auth.json"):           `{"token":"should-not-be-read"}`,
		filepath.Join(root, "pi-home", "agent", "auth.json"):     `{"token":"should-not-be-read"}`,
		filepath.Join(root, "pi-home", "agent", "settings.json"): `{"setting":"should-not-be-read"}`,
	} {
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	return root
}

func us006DefaultWorkerBackedTarget(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name + "-id",
		Name:     name,
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-" + name,
			Image:          "localhost/hal:" + name,
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repo:        "git@example.com:org/us006.git",
			Branch:      "feature/us006-default-fake-only",
			SyncRef:     "bundle:us006-default-fake-only",
		},
	}
}

func us006BundleWorkspacePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		RequiresBundle: true,
		ProjectDir:     projectDir,
		Repository:     "git@example.com:org/us006.git",
		Branch:         "feature/us006-default-fake-only",
		Upstream:       "origin/feature/us006-default-fake-only",
		SyncRef:        "bundle:us006-default-fake-only",
	}
}

func us006LoadExecutionManifest(t *testing.T, store sandboxexecution.Store, executionID string) *sandboxexecution.Manifest {
	t.Helper()
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest(%s) error = %v", executionID, err)
	}
	return manifest
}

func us006RequireExecutionManifestFakeOnly(t *testing.T, manifest *sandboxexecution.Manifest, purpose sandboxexecution.Purpose, sandboxName, storeRoot, tempRoot string) {
	t.Helper()
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("%s manifest status = %q, want succeeded", purpose, manifest.Status)
	}
	if manifest.Purpose != purpose {
		t.Fatalf("manifest purpose = %q, want %q", manifest.Purpose, purpose)
	}
	if manifest.SandboxName != sandboxName {
		t.Fatalf("manifest sandboxName = %q, want %q", manifest.SandboxName, sandboxName)
	}
	if manifest.WorkerRouting != nil {
		t.Fatalf("%s WorkerRouting = %#v, want nil for default fake-only path", purpose, manifest.WorkerRouting)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("%s runtime = %#v, want SSH-machine-compatible default runtime", purpose, manifest.Runtime)
	}
	if manifest.Runtime.WorkerID != "" || manifest.Runtime.RuntimeID != "" || manifest.Runtime.Image != "" {
		t.Fatalf("%s runtime metadata = %#v, want no worker-backed runtime metadata on default path", purpose, manifest.Runtime)
	}
	if !strings.HasPrefix(storeRoot, tempRoot) {
		t.Fatalf("%s store root = %q, want under temp root %q", purpose, storeRoot, tempRoot)
	}
	if manifest.ArtifactMetadata == nil || len(manifest.ArtifactMetadata.Collected) == 0 {
		t.Fatalf("%s artifact metadata = %#v, want fake runtime artifacts persisted through sandbox execution store", purpose, manifest.ArtifactMetadata)
	}
}
