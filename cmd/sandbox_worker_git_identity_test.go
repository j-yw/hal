package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
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

func TestWorkerGitIdentityValidationAndConflicts(t *testing.T) {
	valid := map[string]string{"GIT_USER_NAME": "Zoë O'Connor 李", "GIT_USER_EMAIL": "user@example.invalid"}
	tests := []struct {
		name, key, value string
	}{
		{"empty name", "GIT_USER_NAME", ""},
		{"blank name", "GIT_USER_NAME", "   "},
		{"empty email", "GIT_USER_EMAIL", ""},
		{"newline injection", "GIT_USER_NAME", "Name\nGIT_CONFIG_COUNT=1"},
		{"nul injection", "GIT_USER_EMAIL", "user@example.invalid\x00GIT_CONFIG_COUNT=1"},
		{"carriage return", "GIT_USER_NAME", "Name\rInjected"},
		{"terminal escape", "GIT_USER_NAME", "Name\x1b[2J"},
		{"unicode control", "GIT_USER_NAME", "Name\u0085Injected"},
		{"invalid utf8", "GIT_USER_NAME", "Name\xff"},
		{"git delimiter", "GIT_USER_NAME", "Name <different@example.invalid>"},
		{"email whitespace", "GIT_USER_EMAIL", "user @example.invalid"},
		{"oversized", "GIT_USER_NAME", strings.Repeat("x", sandboxWorkerGitIdentityMaxBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := cloneRuntimeStringMap(valid)
			config[tt.key] = tt.value
			if _, err := sandboxWorkerGitIdentityEnv(config, nil); err == nil {
				t.Fatal("invalid identity was accepted")
			} else if strings.Contains(err.Error(), tt.value) && tt.value != "" && strings.TrimSpace(tt.value) != "" {
				t.Fatal("validation error contains raw identity")
			}
		})
	}
	for _, missing := range []string{"GIT_USER_NAME", "GIT_USER_EMAIL"} {
		config := cloneRuntimeStringMap(valid)
		delete(config, missing)
		if _, err := sandboxWorkerGitIdentityEnv(config, nil); err == nil {
			t.Fatalf("missing %s was accepted", missing)
		}
	}
	for _, key := range []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"} {
		existing := map[string]string{key: "explicit-secret-must-not-change", "UNCHANGED_SECRET": "kept"}
		if _, err := sandboxWorkerGitIdentityEnv(valid, existing); err == nil || strings.Contains(err.Error(), existing[key]) {
			t.Fatalf("conflict error = %v", err)
		}
		if existing[key] != "explicit-secret-must-not-change" || len(existing) != 2 {
			t.Fatal("conflicting command environment was modified")
		}
	}
	existing := map[string]string{"UNCHANGED_SECRET": "kept", "GIT_AUTHOR_NAME": valid["GIT_USER_NAME"]}
	merged, err := sandboxWorkerGitIdentityEnv(valid, existing)
	if err != nil || merged["UNCHANGED_SECRET"] != "kept" {
		t.Fatalf("nonconflicting environment was not retained: %v", err)
	}
	merged["UNCHANGED_SECRET"] = "changed"
	if existing["UNCHANGED_SECRET"] != "kept" || len(existing) != 2 {
		t.Fatal("identity mapping mutated the caller's environment")
	}
}

func TestWorkerGitIdentityRejectsInvalidConfigBeforeDispatch(t *testing.T) {
	for _, purpose := range []string{"run", "auto", "factory"} {
		t.Run(purpose, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())
			projectDir := t.TempDir()
			writeWorkerGitIdentityConfig(t, projectDir, map[string]string{"GIT_USER_NAME": "private-config-value"})
			driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
				exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					joined := strings.Join(req.Args, " ")
					if strings.Contains(joined, "'hal' 'run'") || strings.Contains(joined, "'hal' 'auto'") ||
						strings.Contains(joined, `exec "$HOME/.local/bin/hal"`) || len(req.Env) != 0 {
						t.Fatal("invalid identity reached final command dispatch")
					}
					// Factory retains its existing best-effort recovery on failure.
					return &sandboxruntime.ExecResult{}, nil
				},
			}
			err := executeWorkerGitIdentityFixture(t, purpose, projectDir, workerRootlessCachedSandbox("identity-worker"), driver)
			if err == nil || strings.Contains(err.Error(), "private-config-value") || strings.Contains(err.Error(), projectDir) {
				t.Fatalf("invalid config error = %v", err)
			}
		})
	}
}

func TestWorkerGitIdentityConfigErrorsAreSafeAndOtherRuntimesUnchanged(t *testing.T) {
	projectDir := t.TempDir()
	writeWorkerGitIdentityConfig(t, projectDir, nil)
	configPath := filepath.Join(projectDir, template.HalDir, template.ConfigFile)
	if err := os.WriteFile(configPath, []byte("sandbox:\n  env: private-invalid-config-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, driver := range []string{"", sandboxruntime.DriverSSHMachine, sandboxruntime.DriverMicroVM} {
		command := sandboxexec.CommandRequest{Env: map[string]string{"EXISTING": "kept"}}
		err := prepareSandboxWorkerGitIdentity(projectDir, sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: driver}}, &command)
		if err != nil || !reflect.DeepEqual(command.Env, map[string]string{"EXISTING": "kept"}) {
			t.Fatalf("runtime %q read identity config or changed env: %v", driver, err)
		}
	}
	command := sandboxexec.CommandRequest{}
	err := prepareSandboxWorkerGitIdentity(projectDir, sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman}}, &command)
	if err == nil || errors.Unwrap(err) == nil || strings.Contains(err.Error(), "private-invalid-config-value") || strings.Contains(err.Error(), projectDir) {
		t.Fatalf("config parse error failed safe wrapping: %v", err)
	}
	readCause := &os.PathError{Op: "open", Path: "private-host-path", Err: os.ErrPermission}
	wrapped := sandboxWorkerGitIdentityConfigError{cause: readCause}
	if !errors.Is(wrapped, os.ErrPermission) || strings.Contains(wrapped.Error(), readCause.Path) {
		t.Fatal("config read error lost its cause or leaked a host path")
	}
}

func TestWorkerGitIdentityProducesRealCommitsWithoutPersistentConfig(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	isolatedHome := t.TempDir()
	baseEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + isolatedHome, "XDG_CONFIG_HOME=" + isolatedHome,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_PARAMETERS='commit.gpgsign=false'"}
	runGit := func(env []string, args ...string) []byte {
		t.Helper()
		command := exec.Command(git, args...)
		command.Dir, command.Env = repo, env
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git %s: %v\n%s", args[0], err, output)
		}
		return output
	}
	runGit(baseEnv, "init", "-q")
	configPath := filepath.Join(repo, ".git", "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Zoë O'Connor 李", "Literal $(touch injected) ; name"} {
		identity, err := sandboxWorkerGitIdentityEnv(map[string]string{"GIT_USER_NAME": name, "GIT_USER_EMAIL": "author@example.invalid"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		env := append([]string(nil), baseEnv...)
		for key, value := range identity {
			env = append(env, key+"="+value)
		}
		runGit(env, "commit", "--allow-empty", "-q", "-m", "identity fixture")
		got := strings.TrimSpace(string(runGit(baseEnv, "log", "-1", "--format=%an%n%ae%n%cn%n%ce")))
		want := strings.Join([]string{name, "author@example.invalid", name, "author@example.invalid"}, "\n")
		if got != want {
			t.Fatalf("commit identity = %q, want %q", got, want)
		}
	}
	after, err := os.ReadFile(configPath)
	if err != nil || string(after) != string(before) {
		t.Fatal("per-command identity changed repository Git configuration")
	}
	if _, err := os.Stat(filepath.Join(repo, "injected")); !os.IsNotExist(err) {
		t.Fatal("identity shell text was evaluated")
	}
	command := exec.Command(git, "-c", "user.useConfigOnly=true", "var", "GIT_AUTHOR_IDENT")
	command.Dir, command.Env = repo, baseEnv
	if err := command.Run(); err == nil {
		t.Fatal("a later command inherited a previous command's identity")
	}
}

func TestWorkerGitIdentityFactoryRetriesKeepCommandSnapshot(t *testing.T) {
	projectDir := t.TempDir()
	writeWorkerGitIdentityConfig(t, projectDir, map[string]string{"GIT_USER_NAME": "First User", "GIT_USER_EMAIL": "first@example.invalid"})
	target := sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman}}
	command := sandboxexec.CommandRequest{Command: []string{"hal", "auto"}, WorkDir: "/workspace/identity"}
	if err := prepareSandboxWorkerGitIdentity(projectDir, target, &command); err != nil {
		t.Fatal(err)
	}
	expected := cloneRuntimeStringMap(command.Env)
	calls := 0
	driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			calls++
			if calls == 2 {
				if len(req.Env) != 0 || !strings.Contains(strings.Join(req.Args, " "), "test -f .hal/auto-state.json") {
					t.Fatal("retry probe inherited identity or changed command")
				}
				return &sandboxruntime.ExecResult{}, nil
			}
			if !reflect.DeepEqual(req.Env, expected) {
				t.Fatal("retry did not retain the original per-command identity")
			}
			if calls == 1 {
				writeWorkerGitIdentityConfig(t, projectDir, map[string]string{"GIT_USER_NAME": "Next User", "GIT_USER_EMAIL": "next@example.invalid"})
				return &sandboxruntime.ExecResult{}, errors.New("transient failure")
			}
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	err := runFactorySandboxRuntimeExecWithRetries(context.Background(), sandboxexec.RunContext{Target: target, Driver: driver}, command,
		factory.RunRecord{RepoPath: "/workspace/identity"}, factoryRunAutoRequest{MaxCommandRetries: 1}, nil)
	if err != nil || calls != 3 {
		t.Fatalf("retry calls/error = %d/%v", calls, err)
	}
}

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

func TestWorkerGitIdentityLegacyRoutesIgnoreProjectIdentity(t *testing.T) {
	for _, purpose := range []string{"run", "auto", "factory"} {
		for _, driverID := range []string{sandboxruntime.DriverSSHMachine, sandboxruntime.DriverRootlessPodman} {
			t.Run(purpose+"/"+driverID, func(t *testing.T) {
				t.Setenv("HAL_CONFIG_HOME", t.TempDir())
				projectDir := t.TempDir()
				// Invalid identity would block a worker route, but must not be
				// read by legacy SSH or non-worker local-rootless execution.
				writeWorkerGitIdentityConfig(t, projectDir, map[string]string{"GIT_USER_NAME": "partial-identity"})
				target := workerRootlessCachedSandbox("legacy-identity")
				target.Host = nil
				target.Runtime.Driver = driverID
				calls := 0
				driver := fakeRunSandboxRuntimeDriver{id: driverID,
					exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						calls++
						if len(req.Env) != 0 {
							t.Fatal("legacy route received new environment values")
						}
						return &sandboxruntime.ExecResult{}, nil
					},
				}
				if err := executeWorkerGitIdentityFixture(t, purpose, projectDir, target, driver); err != nil || calls != 1 {
					t.Fatalf("legacy dispatch calls/error = %d/%v", calls, err)
				}
			})
		}
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
	hostID, runtimeID := "", ""
	if target.Host != nil {
		hostID, runtimeID = target.Host.ID, sandboxruntime.DriverRootlessPodman
	}
	load := func(string) (*sandbox.SandboxState, error) { return target, nil }
	hosts := func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil }
	provider := func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil }
	legacyDriver := func(sandboxruntime.Target) (sandboxruntime.Driver, error) { return driver, nil }
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
	executionStore := newPrivateSandboxExecutionTestStore(t)
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	switch purpose {
	case "run":
		deps := normalizeRunSandboxDeps(runSandboxDeps{
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve,
			resolveProvider: provider, resolveRuntimeDriver: legacyDriver,
			materializeWorkspace: materialize, prepareCommandContext: commandContext, engineAuthFiles: auth,
		})
		req := runSandboxRequest{
			ExecutionID: "identity-run", ProjectDir: projectDir, SandboxName: target.Name,
			SandboxHostID: hostID, SandboxRuntime: runtimeID,
			Workspace: workspace, WorkDir: "/workspace/identity", RemoteCommand: []string{"hal", "run"},
		}
		_, err := deps.executeRunSandbox(context.Background(), req, io.Discard, io.Discard, runSandboxExecutionHooks{
			OnWorkerJobUpdate: jobUpdate,
			OnTargetReady: func(ready *sandbox.SandboxState) error {
				return saveRunSandboxManifest(executionStore, req, sandboxexecution.StatusRunning, now, nil, ready)
			},
		})
		manifest, loadErr := executionStore.LoadManifest(req.ExecutionID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		assertWorkerGitIdentityNotPersisted(t, manifest)
		return err
	case "auto":
		deps := normalizeAutoSandboxDeps(autoSandboxDeps{
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve,
			resolveProvider: provider, resolveRuntimeDriver: legacyDriver,
			materializeWorkspace: materialize, prepareCommandContext: commandContext, engineAuthFiles: auth,
		})
		req := autoSandboxRequest{
			ExecutionID: "identity-auto", ProjectDir: projectDir, SandboxName: target.Name,
			SandboxHostID: hostID, SandboxRuntime: runtimeID,
			Workspace: workspace, WorkDir: "/workspace/identity", RemoteCommand: []string{"hal", "auto"},
		}
		_, err := deps.executeAutoSandbox(context.Background(), req, io.Discard, io.Discard, autoSandboxExecutionHooks{
			OnWorkerJobUpdate: jobUpdate,
			OnTargetReady: func(ready *sandbox.SandboxState) error {
				return saveAutoSandboxManifest(executionStore, req, sandboxexecution.StatusRunning, now, nil, ready)
			},
		})
		manifest, loadErr := executionStore.LoadManifest(req.ExecutionID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		assertWorkerGitIdentityNotPersisted(t, manifest)
		return err
	case "factory":
		store := factory.NewStore(t.TempDir())
		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir: projectDir, SandboxName: target.Name, SandboxHostID: hostID,
			SandboxRuntime: runtimeID, RemoteOutput: io.Discard, DeferSuccessCleanup: true,
			RunRecord: factory.RunRecord{
				RunID: "identity-factory", RepoPath: projectDir, RepoRemote: "git@example.invalid:org/repo.git",
				BranchName: "feature/identity", BaseBranch: "main", CreatedAt: now, UpdatedAt: now,
			},
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil }, now: func() time.Time { return now },
			loadSandbox: load, listHosts: hosts, resolveWorkerRuntime: resolve, engineAuthFiles: auth,
			resolveProvider: provider, resolveRuntimeDriver: legacyDriver,
			persistSandboxState: func(*sandbox.SandboxState) error { return nil },
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				return factory.BootstrapResult{}, nil
			},
			generateRecovery: func(context.Context, factorySandboxRecoveryArtifactRequest) error { return nil },
		})
		record, loadErr := store.LoadRun("identity-factory")
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		assertWorkerGitIdentityNotPersisted(t, record)
		events, loadErr := store.LoadEvents(record.RunID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		assertWorkerGitIdentityNotPersisted(t, events)
		return err
	default:
		t.Fatalf("unknown fixture purpose %q", purpose)
		return nil
	}
}

func assertWorkerGitIdentityNotPersisted(t *testing.T, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"GIT_USER_NAME":`, `"GIT_USER_EMAIL":`, `"GIT_AUTHOR_NAME":`, `"GIT_AUTHOR_EMAIL":`, `"GIT_COMMITTER_NAME":`, `"GIT_COMMITTER_EMAIL":`, "Zoë O'Connor 李", "first@example.invalid", "Second User", "second@example.invalid", "not-an-identity-secret", "private-config-value"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("configured identity/environment leaked to durable metadata: %q", forbidden)
		}
	}
}
