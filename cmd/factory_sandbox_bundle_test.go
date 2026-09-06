package cmd

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
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
		loadSandbox:           func(string) (*sandbox.SandboxState, error) { return target, nil },
		listHosts:             func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil },
		resolveWorkerRuntime:  func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) { return driver, nil },
		persistSandboxState:   func(*sandbox.SandboxState) error { return nil },
		engineAuthFiles:       func() []factorySandboxAuthFile { return nil },
		planBundle:            fakeFactoryBundlePlan,
		materializeWorkspace:  fakeFactoryBundleMaterialize,
		prepareCommandContext: fakeFactoryBundleCommandContext,
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			cloneCalls++
			return factory.BootstrapResult{}, errors.New("private remote clone is unavailable")
		},
	})
	if err != nil || cloneCalls != 0 {
		t.Fatalf("local factory input attempted remote bootstrap: calls=%d error=%v", cloneCalls, err)
	}
}

func fakeFactoryBundlePlan(_ context.Context, projectDir string, record factory.RunRecord) (*factorySandboxBundlePlan, error) {
	return &factorySandboxBundlePlan{
		Workspace:  sandboxworkspace.Plan{ProjectDir: projectDir, Repository: record.RepoRemote, Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle, RequiresBundle: true, Branch: "local-source", SyncRef: strings.Repeat("a", 40)},
		BaseBranch: record.BaseBranch, BaseCommit: strings.Repeat("b", 40), RunBranch: record.BranchName,
	}, nil
}

func fakeFactoryBundleMaterialize(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
	return sandboxworkspace.MaterializationResult{}, nil
}

func fakeFactoryBundleCommandContext(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
	return sandboxworkspace.MaterializationOperation{}, nil
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

func TestFactoryRootlessBundlePhaseFailuresAndMetadata(t *testing.T) {
	for _, phase := range []string{"success", "plan", "nil_plan", "materialize", "branches", "context"} {
		t.Run(phase, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())
			target := workerRootlessCachedSandbox("phase-factory")
			store := factory.NewStore(t.TempDir())
			var calls []string
			var persisted []*sandbox.SandboxWorkspace
			phaseErr := errors.New("injected phase failure")
			driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
				exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					joined := strings.Join(req.Args, " ")
					if strings.Contains(joined, "git update-ref") {
						calls = append(calls, "branches")
						if phase == "branches" {
							return &sandboxruntime.ExecResult{ExitCode: 128}, phaseErr
						}
					} else if strings.Contains(joined, "exec hal") {
						calls = append(calls, "final")
					}
					return &sandboxruntime.ExecResult{}, nil
				},
			}
			record := factory.RunRecord{RunID: "phase-factory", RepoRemote: "https://example.invalid/repo.git", BaseBranch: "local-base", BranchName: "hal/output"}
			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir: t.TempDir(), SandboxName: target.Name, SandboxHostID: target.Host.ID, SandboxRuntime: sandboxruntime.DriverRootlessPodman,
				RunRecord: record, RemoteOutput: io.Discard, DeferSuccessCleanup: true,
			}, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil }, now: time.Now,
				loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
				listHosts:   func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil },
				resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
					calls = append(calls, "driver")
					return driver, nil
				},
				persistSandboxState: func(state *sandbox.SandboxState) error { persisted = append(persisted, state.Workspace); return nil },
				engineAuthFiles:     func() []factorySandboxAuthFile { calls = append(calls, "auth"); return nil },
				planBundle: func(ctx context.Context, dir string, record factory.RunRecord) (*factorySandboxBundlePlan, error) {
					calls = append(calls, "plan")
					if phase == "plan" {
						return nil, phaseErr
					}
					if phase == "nil_plan" {
						return nil, nil
					}
					return fakeFactoryBundlePlan(ctx, dir, record)
				},
				materializeWorkspace: func(_ context.Context, _ sandboxexec.PrepareContext, req sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
					calls = append(calls, "materialize")
					if req.Plan.Branch != "local-source" || req.Plan.SyncRef != strings.Repeat("a", 40) || req.LocalGit == nil {
						t.Fatal("source identity was replaced by uncreated run branch")
					}
					if phase == "materialize" {
						return sandboxworkspace.MaterializationResult{}, phaseErr
					}
					return sandboxworkspace.MaterializationResult{}, nil
				},
				prepareCommandContext: func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
					calls = append(calls, "context")
					if phase == "context" {
						return sandboxworkspace.MaterializationOperation{}, phaseErr
					}
					return sandboxworkspace.MaterializationOperation{}, nil
				},
				bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
					t.Fatal("local path called remote bootstrap")
					return factory.BootstrapResult{}, nil
				},
			})
			want := []string{"plan", "driver", "materialize", "branches", "context", "auth", "final"}
			if phase != "success" {
				if err == nil {
					t.Fatal("phase failure returned success")
				}
				end := map[string]int{"plan": 1, "nil_plan": 1, "materialize": 3, "branches": 4, "context": 5}[phase]
				want = want[:end]
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls=%v want=%v", calls, want)
			}
			for index, workspace := range persisted {
				if workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || workspace.SyncRef != strings.Repeat("a", 40) || workspace.Repo != "" {
					t.Fatalf("unsafe or incorrect workspace: %#v", workspace)
				}
				if index == 0 && workspace.Branch != "" {
					t.Fatal("run branch claimed before materialization")
				}
				if index > 0 && workspace.Branch != record.BranchName {
					t.Fatal("completed workspace did not preserve factory run branch")
				}
			}
			if phase == "success" && len(persisted) != 2 {
				t.Fatalf("workspace updates=%d", len(persisted))
			}
		})
	}
}

func TestFactoryRootlessBundleImageHalRetriesAndLegacy(t *testing.T) {
	for _, imageHal := range []bool{false, true} {
		record := factory.RunRecord{RepoPath: "/workspace/test"}
		req := factoryRunAutoRequest{MaxCommandRetries: 1}
		command := sandboxexec.CommandRequest{Command: factorySandboxRemoteCommandArgs(record, req), WorkDir: "/workspace/test", Env: map[string]string{"GIT_AUTHOR_NAME": "fixture"}}
		if imageHal {
			command.Command = factorySandboxImageCommandArgs(record, req)
		}
		calls := 0
		driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman, exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			calls++
			if calls == 2 {
				return &sandboxruntime.ExecResult{}, nil
			}
			joined := strings.Join(got.Args, " ")
			if strings.Contains(joined, `exec "$HOME/.local/bin/hal"`) == imageHal || !reflect.DeepEqual(got.Env, command.Env) {
				t.Fatal("retry changed executable selection or identity snapshot")
			}
			if calls == 1 {
				return &sandboxruntime.ExecResult{}, errors.New("transient failure")
			}
			if !strings.Contains(joined, "--resume") {
				t.Fatal("retry did not resume")
			}
			return &sandboxruntime.ExecResult{}, nil
		}}
		if err := runFactorySandboxRuntimeExecWithRetriesForImage(context.Background(), sandboxexec.RunContext{Driver: driver}, command, record, req, nil, imageHal); err != nil || calls != 3 {
			t.Fatalf("retry calls=%d err=%v", calls, err)
		}
	}
}
