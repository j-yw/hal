package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/verify"
)

// The transports execute copy scripts in a test-owned workspace, while Hal init
// and verify use their real command handlers. No container, provider, or network
// is needed to observe the delivered bytes and required-check outcome.
func TestFactorySandboxHostVerifyConfig(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("local shell is unavailable")
	}
	for _, worker := range []bool{false, true} {
		for _, scenario := range []string{"host_pass", "host_fail", "host_overrides_committed", "absent", "absent_keeps_committed"} {
			t.Run(fmt.Sprintf("worker=%t/%s", worker, scenario), func(t *testing.T) {
				t.Setenv("HAL_CONFIG_HOME", t.TempDir())
				projectDir, workspaceDir, stagingDir := t.TempDir(), t.TempDir(), t.TempDir()
				setIsolatedCodexHomeFallback(t, projectDir)
				hostPresent := !strings.HasPrefix(scenario, "absent")
				committed := strings.Contains(scenario, "committed")
				wantFailure := scenario == "host_fail"
				code := 0
				if wantFailure {
					code = 1
				}
				hostConfig := []byte(fmt.Sprintf("# host-owned config\nengine: pi\nverify:\n  checks:\n    - id: host-check\n      name: Host check\n      command: 'printf checked > verify-marker; exit %d'\n      required: true\n", code))
				committedConfig := []byte("# committed config\nengine: pi\nverify:\n  checks:\n    - id: committed-check\n      name: Committed check\n      command: 'exit 0'\n      required: true\n")
				writeFile := func(path string, content []byte) {
					t.Helper()
					if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, content, 0600); err != nil {
						t.Fatal(err)
					}
				}
				// Other host context must not cause an absent config to remove a
				// committed config on the bundle route.
				writeFile(filepath.Join(projectDir, ".hal", "prompt.md"), []byte("fixture prompt\n"))
				if hostPresent {
					writeFile(filepath.Join(projectDir, ".hal", "config.yaml"), hostConfig)
				}
				materialized, initialized, verified := false, false, false
				materialize := func() {
					materialized = true
					if committed {
						writeFile(filepath.Join(workspaceDir, ".hal", "config.yaml"), committedConfig)
					}
				}
				assertConfig := func() {
					t.Helper()
					if !materialized {
						t.Fatal("config delivery occurred before workspace materialization")
					}
					path := filepath.Join(workspaceDir, ".hal", "config.yaml")
					got, err := os.ReadFile(path)
					if hostPresent || committed {
						want := committedConfig
						if hostPresent {
							want = hostConfig
						}
						if err != nil || !bytes.Equal(got, want) {
							t.Fatalf("remote config bytes differ: read error=%v", err)
						}
						if hostPresent {
							info, err := os.Stat(path)
							if err != nil || info.Mode().Perm() != 0644 {
								t.Fatalf("remote config mode must be 0644: info=%v error=%v", info, err)
							}
						}
					} else if !initialized && !os.IsNotExist(err) {
						t.Fatal("absent host config was copied")
					}
				}
				initialize := func() error {
					assertConfig()
					previousDir, err := os.Getwd()
					if err != nil {
						return err
					}
					if err := os.Chdir(workspaceDir); err != nil {
						return err
					}
					defer func() {
						if err := os.Chdir(previousDir); err != nil {
							t.Fatal(err)
						}
					}()
					if err := runInitWithWriters(nil, nil, io.Discard, io.Discard); err != nil {
						return err
					}
					initialized = true
					return nil
				}
				transport := func(ctx context.Context, args []string, out io.Writer) (*sandboxruntime.ExecResult, error) {
					joined := strings.Join(args, " ")
					if strings.Contains(joined, "'verify'") {
						assertConfig()
						verified = true
						var output bytes.Buffer
						// Only verification artifacts are omitted at the fake transport
						// boundary; the real config loader and check runner are used.
						err := runVerifyWithDeps(ctx, workspaceDir, true, &output, io.Discard, verifyDeps{
							run: func(ctx context.Context, cfg *verify.Config) (*verify.Result, error) {
								result, err := verify.Run(ctx, cfg)
								if result != nil {
									result.Artifacts = nil
								}
								return result, err
							},
						}, nil)
						_, _ = out.Write(output.Bytes())
						code := 0
						if err != nil {
							code = ExitCodeExpectedNonZero
						}
						if worker {
							_, _ = fmt.Fprintf(out, "\nHAL_FACTORY_VERIFY_EXIT=%d\n", code)
							return &sandboxruntime.ExecResult{}, nil
						}
						if code != 0 {
							return &sandboxruntime.ExecResult{ExitCode: code}, factoryVerificationSafetyExit(code)
						}
						return &sandboxruntime.ExecResult{}, nil
					}
					if strings.Contains(joined, "exec hal init") || strings.Contains(joined, "'init'") {
						return &sandboxruntime.ExecResult{}, initialize()
					}
					if strings.Contains(joined, "git update-ref") || strings.Contains(joined, "'auto'") {
						return &sandboxruntime.ExecResult{}, nil
					}
					localArgs := append([]string(nil), args...)
					for i := range localArgs {
						localArgs[i] = strings.ReplaceAll(localArgs[i], factorySandboxRemoteWorkspaceDir(factory.RunRecord{RepoRemote: "https://example.invalid/repo.git"}), filepath.ToSlash(workspaceDir))
						localArgs[i] = strings.ReplaceAll(localArgs[i], "/tmp/hal-command-context-", filepath.ToSlash(stagingDir)+"/hal-command-context-")
					}
					command := exec.CommandContext(ctx, localArgs[0], localArgs[1:]...)
					command.Stdout, command.Stderr = out, out
					err := command.Run()
					result := &sandboxruntime.ExecResult{}
					if command.ProcessState != nil {
						result.ExitCode = command.ProcessState.ExitCode()
					}
					return result, err
				}
				driver := fakeRunSandboxRuntimeDriver{
					id: sandboxruntime.DriverRootlessPodman,
					exec: func(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						return transport(ctx, req.Args, req.Stdout)
					},
					copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
						if !materialized {
							t.Fatal("CopyIn before materialization")
						}
						content, err := os.ReadFile(req.SourcePath)
						if err != nil {
							return err
						}
						destination := strings.ReplaceAll(req.DestinationPath, "/tmp/hal-command-context-", filepath.ToSlash(stagingDir)+"/hal-command-context-")
						writeFile(destination, content)
						return nil
					},
				}
				target := &sandbox.SandboxState{Name: "config-fixture", Provider: "legacy-provider", Status: sandbox.StatusRunning}
				if worker {
					target = workerRootlessCachedSandbox(target.Name)
				}
				store := factory.NewStore(t.TempDir())
				request := factorySandboxExecutorRequest{
					ProjectDir: projectDir, SandboxName: target.Name, RemoteOutput: io.Discard, DeferSuccessCleanup: true,
					RunRecord: factory.RunRecord{RunID: "config-fixture", RepoPath: workspaceDir, RepoRemote: "https://example.invalid/repo.git", BaseBranch: "main", BranchName: "hal/config-fixture"},
				}
				if worker {
					request.SandboxHostID, request.SandboxRuntime = target.Host.ID, sandboxruntime.DriverRootlessPodman
				}
				providerExec := func(ctx context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ map[string]string, out io.Writer) error {
					_, err := transport(ctx, args, out)
					return err
				}
				err := runFactorySandboxExecutorWithDeps(context.Background(), request, factorySandboxExecutorDeps{
					defaultStore:         func() (factory.Store, error) { return store, nil },
					now:                  time.Now,
					loadSandbox:          func(string) (*sandbox.SandboxState, error) { return target, nil },
					listHosts:            func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{target.Host}, nil },
					resolveProvider:      func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
					resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) { return driver, nil },
					resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) { return driver, nil },
					persistSandboxState:  func(*sandbox.SandboxState) error { return nil },
					engineAuthFiles:      func() []factorySandboxAuthFile { return nil },
					generateRecovery:     func(context.Context, factorySandboxRecoveryArtifactRequest) error { return nil },
					planBundle:           fakeFactoryBundlePlan,
					materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
						materialize()
						return sandboxworkspace.MaterializationResult{}, nil
					},
					bootstrap: func(ctx context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
						materialize()
						_, err := deps.Executor.Run(ctx, factory.BootstrapCommand{Name: "hal", Args: []string{"init"}, Dir: req.WorkspaceDir})
						return factory.BootstrapResult{}, err
					},
					runProviderExecWithEnv: providerExec,
					runProviderScript: func(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, script string, out io.Writer) error {
						return providerExec(ctx, provider, info, []string{"sh", "-c", script}, nil, out)
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !initialized {
					t.Fatal("workspace was not initialized")
				}
				record, err := store.LoadRun(request.RunRecord.RunID)
				if err != nil {
					t.Fatal(err)
				}
				policy := factory.DefaultFactoryPolicy()
				policy.VerificationRequired = hostPresent || committed
				verifiedRecord, _, err := recordFactoryRunVerification(context.Background(), store, *record, projectDir, factoryRunDeps{
					now:                    time.Now,
					loadSandbox:            func(string) (*sandbox.SandboxState, error) { return target, nil },
					resolveSandboxRuntime:  func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) { return driver, nil },
					resolveProvider:        func(string, string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
					runProviderExecWithEnv: providerExec,
				}, policy, nil, factory.RunSecretRedactor{})
				if (err != nil) != wantFailure || !verified {
					t.Fatalf("required verification failure=%t: error=%v verified=%t", wantFailure, err, verified)
				}
				wantTotal := 0
				if hostPresent || committed {
					wantTotal = 1
				}
				if (wantTotal > 0 && verifiedRecord.Verification == nil) || (verifiedRecord.Verification != nil && verifiedRecord.Verification.Summary.Total != wantTotal) {
					t.Fatalf("verification summary=%v, want total=%d", verifiedRecord.Verification, wantTotal)
				}
				if wantFailure && (verifiedRecord.Verification.Summary.Failed != 1 || err.Error() != "verification failed: 1 failed, 0 timed out, 0 missing") {
					t.Fatalf("required check failure was not propagated: summary=%v error=%v", verifiedRecord.Verification.Summary, err)
				}
				if hostPresent {
					marker, err := os.ReadFile(filepath.Join(workspaceDir, "verify-marker"))
					if err != nil || string(marker) != "checked" {
						t.Fatal("host-only check did not execute in the remote workspace")
					}
				}
				events, err := store.LoadEvents(record.RunID)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := json.Marshal([]any{verifiedRecord, events})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(stored), projectDir) {
					t.Fatal("host project path leaked into persisted records")
				}
			})
		}
	}
}

func TestFactorySandboxConfigCopyFailures(t *testing.T) {
	for _, worker := range []bool{false, true} {
		for _, invalidFile := range []bool{false, true} {
			t.Run(fmt.Sprintf("worker=%t/invalid=%t", worker, invalidFile), func(t *testing.T) {
				projectDir := t.TempDir()
				configPath := filepath.Join(projectDir, ".hal", "config.yaml")
				if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
					t.Fatal(err)
				}
				if invalidFile {
					if err := os.Mkdir(configPath, 0755); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(configPath, []byte("engine: pi\n"), 0600); err != nil {
					t.Fatal(err)
				}
				copyErr := errors.New("config transfer failed")
				copies := 0
				var err error
				if worker {
					err = factorySandboxCopyConfigRuntime(context.Background(), sandboxexec.PrepareContext{Driver: fakeRunSandboxRuntimeDriver{
						copyIn: func(context.Context, sandboxruntime.CopyRequest) error { copies++; return copyErr },
					}}, projectDir, "/workspace/repo")
				} else {
					err = factorySandboxCopyConfigToRemote(context.Background(), projectDir, "/workspace/repo", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{}, io.Discard, factorySandboxExecutorDeps{
						runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
							copies++
							return copyErr
						},
					})
				}
				if err == nil {
					t.Fatal("invalid config or failed transfer was ignored")
				}
				if invalidFile && copies != 0 {
					t.Fatal("non-regular host config was copied")
				}
				if !invalidFile && (copies != 1 || !errors.Is(err, copyErr)) {
					t.Fatalf("copy failure not propagated: copies=%d error=%v", copies, err)
				}
			})
		}
	}
}
