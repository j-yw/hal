package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
)

func TestWorkerGitIdentityDeliveredPerCommandForRunAutoFactory(t *testing.T) {
	for _, purpose := range []string{"run", "auto", "factory"} {
		t.Run(purpose, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())
			t.Setenv("GIT_USER_NAME", "host-must-not-leak")
			t.Setenv("GIT_USER_EMAIL", "host-must-not-leak@example.invalid")
			target := workerRootlessCachedSandbox("identity-worker")
			for _, identity := range []struct{ name, email string }{
				{"Zoë O'Connor 李", "first@example.invalid"},
				{"Second User", "second@example.invalid"},
				{},
			} {
				projectDir := t.TempDir()
				if identity.name != "" {
					writeWorkerGitIdentityConfig(t, projectDir, map[string]string{
						"GIT_USER_NAME": identity.name, "GIT_USER_EMAIL": identity.email,
						"GITHUB_TOKEN": "not-an-identity-secret", "GIT_CONFIG_COUNT": "100",
					})
				}
				var finalEnvs []map[string]string
				driver := fakeRunSandboxRuntimeDriver{
					id: sandboxruntime.DriverRootlessPodman,
					exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						joined := strings.Join(req.Args, " ")
						if strings.Contains(joined, "'hal' 'run'") || strings.Contains(joined, "'hal' 'auto'") ||
							strings.Contains(joined, `exec "$HOME/.local/bin/hal"`) {
							finalEnvs = append(finalEnvs, req.Env)
							for _, value := range []string{identity.name, identity.email, "not-an-identity-secret"} {
								if value != "" && strings.Contains(joined, value) {
									t.Fatal("identity/config value entered command argv")
								}
							}
						} else if len(req.Env) != 0 {
							t.Fatal("identity was delivered outside the final command")
						}
						return &sandboxruntime.ExecResult{}, nil
					},
				}
				if err := executeWorkerGitIdentityFixture(t, purpose, projectDir, target, driver); err != nil {
					t.Fatalf("execute %s: %v", purpose, err)
				}
				if len(finalEnvs) != 1 {
					t.Fatalf("final commands = %d, want one", len(finalEnvs))
				}
				var expected map[string]string
				if identity.name != "" {
					expected = map[string]string{
						"GIT_AUTHOR_NAME": identity.name, "GIT_COMMITTER_NAME": identity.name,
						"GIT_AUTHOR_EMAIL": identity.email, "GIT_COMMITTER_EMAIL": identity.email,
					}
				}
				if !reflect.DeepEqual(finalEnvs[0], expected) {
					t.Fatalf("final identity env = %#v, want %#v", finalEnvs[0], expected)
				}
			}
		})
	}
}

func writeWorkerGitIdentityConfig(t *testing.T, dir string, env map[string]string) {
	t.Helper()
	// JSON is a YAML subset and avoids ad hoc quoting of Unicode/control fixtures.
	payload, err := json.Marshal(map[string]any{"sandbox": map[string]any{"env": env}})
	if err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, template.ConfigFile), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func executeWorkerGitIdentityFixture(t *testing.T, purpose, projectDir string, target *sandbox.SandboxState, driver sandboxruntime.Driver) error {
	t.Helper()
	load := func(string) (*sandbox.SandboxState, error) { return target, nil }
	hosts := func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil }
	resolve := func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
		return withFakeSandboxWorkerJobs(driver), nil
	}
	materialize := func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
		return sandboxworkspace.MaterializationResult{}, nil
	}
	commandContext := func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
		return sandboxworkspace.MaterializationOperation{}, nil
	}
	auth := func() []factorySandboxAuthFile { return nil }
	workspace := &sandbox.SandboxWorkspace{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle}
	jobUpdate := func(*sandboxexecution.WorkerJobReference) error { return nil }
	switch purpose {
	case "run":
		deps := normalizeRunSandboxDeps(runSandboxDeps{
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve,
			materializeWorkspace: materialize, prepareCommandContext: commandContext, engineAuthFiles: auth,
		})
		_, err := deps.executeRunSandbox(context.Background(), runSandboxRequest{
			ExecutionID: "identity-run", ProjectDir: projectDir, SandboxName: target.Name,
			SandboxHostID: target.Host.ID, SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			Workspace: workspace, WorkDir: "/workspace/identity", RemoteCommand: []string{"hal", "run"},
		}, io.Discard, io.Discard, runSandboxExecutionHooks{OnWorkerJobUpdate: jobUpdate})
		return err
	case "auto":
		deps := normalizeAutoSandboxDeps(autoSandboxDeps{
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve,
			materializeWorkspace: materialize, prepareCommandContext: commandContext, engineAuthFiles: auth,
		})
		_, err := deps.executeAutoSandbox(context.Background(), autoSandboxRequest{
			ExecutionID: "identity-auto", ProjectDir: projectDir, SandboxName: target.Name,
			SandboxHostID: target.Host.ID, SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			Workspace: workspace, WorkDir: "/workspace/identity", RemoteCommand: []string{"hal", "auto"},
		}, io.Discard, io.Discard, autoSandboxExecutionHooks{OnWorkerJobUpdate: jobUpdate})
		return err
	case "factory":
		store := factory.NewStore(t.TempDir())
		now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
		return runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir: projectDir, SandboxName: target.Name, SandboxHostID: target.Host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman, RemoteOutput: io.Discard, DeferSuccessCleanup: true,
			RunRecord: factory.RunRecord{
				RunID: "identity-factory", RepoPath: projectDir, RepoRemote: "git@example.invalid:org/repo.git",
				BranchName: "feature/identity", BaseBranch: "main", CreatedAt: now, UpdatedAt: now,
			},
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil }, now: func() time.Time { return now },
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve, engineAuthFiles: auth,
			persistSandboxState: func(*sandbox.SandboxState) error { return nil },
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				return factory.BootstrapResult{}, nil
			},
			generateRecovery: func(context.Context, factorySandboxRecoveryArtifactRequest) error { return nil },
		})
	default:
		t.Fatalf("unknown fixture purpose %q", purpose)
		return nil
	}
}
