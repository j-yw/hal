package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestNormalizeFactorySandboxExecutorDepsFillsProductionDefaults(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{})

	checks := map[string]any{
		"defaultStore":           deps.defaultStore,
		"now":                    deps.now,
		"resolveDefault":         deps.resolveDefault,
		"loadSandbox":            deps.loadSandbox,
		"provision":              deps.provision,
		"resolveProvider":        deps.resolveProvider,
		"resolveRuntimeDriver":   deps.resolveRuntimeDriver,
		"runProviderExec":        deps.runProviderExec,
		"runProviderScript":      deps.runProviderScript,
		"runProviderExecWithEnv": deps.runProviderExecWithEnv,
		"engineAuthFiles":        deps.engineAuthFiles,
		"bootstrap":              deps.bootstrap,
		"cleanupSandbox":         deps.cleanupSandbox,
		"saveRun":                deps.saveRun,
		"appendEvent":            deps.appendEvent,
		"appendLog":              deps.appendLog,
	}
	for name, fn := range checks {
		if reflect.ValueOf(fn).IsNil() {
			t.Fatalf("%s dependency was not defaulted", name)
		}
	}
}

func TestFactorySandboxExecutorDepsExposeRuntimeDriverResolver(t *testing.T) {
	field, ok := reflect.TypeOf(factorySandboxExecutorDeps{}).FieldByName("resolveRuntimeDriver")
	if !ok {
		t.Fatal("factorySandboxExecutorDeps missing resolveRuntimeDriver")
	}
	want := reflect.TypeOf((func(sandboxruntime.Target) (sandboxruntime.Driver, error))(nil))
	if field.Type != want {
		t.Fatalf("resolveRuntimeDriver type = %v, want %v", field.Type, want)
	}
}

func TestFactorySandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("resolveProvider should not run for explicit rootless Podman runtime metadata")
			return nil, nil
		},
	})
	driver, err := deps.resolveRuntimeDriver(sandboxruntime.Target{
		Provider: "local",
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxruntime.DriverRootlessPodman,
		},
	})
	if err != nil {
		t.Fatalf("resolveRuntimeDriver() error = %v", err)
	}
	if driver == nil || driver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver = %#v, want rootless Podman driver", driver)
	}
}

func TestFactorySandboxDefaultRuntimeDriverResolverKeepsSSHMachineForAbsentOrExplicitSSHMetadata(t *testing.T) {
	tests := []struct {
		name          string
		runtimeDriver string
	}{
		{name: "absent runtime driver"},
		{name: "explicit SSH-machine runtime driver", runtimeDriver: sandboxruntime.DriverSSHMachine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var providerName string
			deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
				resolveProvider: func(name string) (sandbox.Provider, error) {
					providerName = name
					return fakeFactorySandboxProvider{}, nil
				},
			})
			driver, err := deps.resolveRuntimeDriver(sandboxruntime.Target{
				Provider: "test-provider",
				Runtime: sandboxruntime.RuntimeState{
					Driver: tt.runtimeDriver,
				},
			})
			if err != nil {
				t.Fatalf("resolveRuntimeDriver() error = %v", err)
			}
			if providerName != "test-provider" {
				t.Fatalf("providerName = %q, want test-provider", providerName)
			}
			if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
				t.Fatalf("driver = %#v, want SSH-machine driver", driver)
			}
		})
	}
}

func TestFactorySandboxConnectionMetadataFromStatePrefersTailscaleAddress(t *testing.T) {
	tests := []struct {
		name        string
		instance    *sandbox.SandboxState
		wantAddress string
		wantPublic  string
	}{
		{
			name: "tailscale ip preferred over public ip",
			instance: &sandbox.SandboxState{
				IP:                "203.0.113.42",
				TailscaleIP:       "100.64.0.9",
				TailscaleHostname: "hal-factory-dev",
				TailscaleLockdown: true,
			},
			wantAddress: "100.64.0.9",
			wantPublic:  "203.0.113.42",
		},
		{
			name: "lockdown hostname fallback without public ip",
			instance: &sandbox.SandboxState{
				TailscaleHostname: "hal-factory-dev",
				TailscaleLockdown: true,
			},
			wantAddress: "hal-factory-dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factorySandboxConnectionMetadataFromState(tt.instance)
			if got == nil {
				t.Fatal("factorySandboxConnectionMetadataFromState() = nil")
			}
			if got.Address != tt.wantAddress {
				t.Fatalf("Address = %q, want %q", got.Address, tt.wantAddress)
			}
			if got.PublicIP != tt.wantPublic {
				t.Fatalf("PublicIP = %q, want %q", got.PublicIP, tt.wantPublic)
			}
		})
	}
}

func TestFactorySandboxMetadataFromStateIncludesSecurityMetadata(t *testing.T) {
	_, got := factorySandboxMetadataFromState(&sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		Security: sandbox.EvaluateSSHMachineCompatibilitySecurity(sandbox.SecurityEvaluationRequest{
			RuntimeDriver:          sandbox.SandboxRuntimeDriverSSHMachine,
			RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
			RequestedSecretModes:   []string{sandbox.SandboxSecretModeHTTPProxy},
			ActiveSecretModes:      []string{sandbox.SandboxSecretModeEnv},
			CompatibilityAuthSync:  true,
		}),
	})
	if got == nil {
		t.Fatal("factorySandboxMetadataFromState() = nil")
	}
	requireFactorySandboxSecurityMetadata(t, got.Security, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync})
}

func TestFactorySandboxMetadataFromStateIncludesRootlessRuntimeV2Metadata(t *testing.T) {
	expiresAt := time.Date(2026, 7, 1, 2, 30, 0, 0, time.UTC)
	acquiredAt := expiresAt.Add(-30 * time.Minute)
	_, got := factorySandboxMetadataFromState(&sandbox.SandboxState{
		Name:     "factory-rootless",
		Provider: "local",
		Size:     "podman",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "host-local",
			Name:     "developer-workstation",
			Kind:     sandbox.SandboxHostKindLocal,
			Endpoint: "unix:///run/user/501/podman/podman.sock",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "container-123",
			Image:          "localhost/hal-test:latest",
			WorkerID:       "local-worker",
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repo:        "/Users/v/work/private/repo",
			Branch:      "hal/rootless-runtime",
			SyncRef:     "bundle:abc123",
		},
		Security: sandbox.EvaluateSandboxSecurity(sandbox.SecurityEvaluationRequest{
			RuntimeDriver:          sandbox.SandboxRuntimeDriverRootlessPodman,
			RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
			RequestedSecretModes:   []string{sandbox.SandboxSecretModeHTTPProxy},
			ActiveSecretModes:      []string{sandbox.SandboxSecretModeEnv},
			CompatibilityAuthSync:  true,
		}),
		Lease: &sandbox.SandboxLeaseRef{
			ID:            "lease-rootless",
			HostID:        "host-local",
			HostName:      "developer-workstation",
			RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
			ResourceKey:   "runtime:container-123",
			Holder:        "local-user",
			Purpose:       sandbox.SandboxLeasePurposeFactory,
			RunID:         "run-rootless",
			AcquiredAt:    acquiredAt,
			ExpiresAt:     expiresAt,
		},
	})
	if got == nil {
		t.Fatal("factorySandboxMetadataFromState() = nil")
	}
	if got.Host == nil || got.Host.ID != "host-local" || got.Host.Kind != sandbox.SandboxHostKindLocal {
		t.Fatalf("host metadata = %#v", got.Host)
	}
	if got.Runtime == nil {
		t.Fatal("runtime metadata = nil")
	}
	if got.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("runtime driver = %q, want %q", got.Runtime.Driver, sandbox.SandboxRuntimeDriverRootlessPodman)
	}
	if got.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime isolationLevel = %q, want %q", got.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if got.Runtime.IsolationLevel == sandbox.SandboxIsolationLevelVM {
		t.Fatalf("rootless Podman runtime must not report VM isolation: %#v", got.Runtime)
	}
	if got.Workspace == nil || got.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || got.Workspace.Branch != "hal/rootless-runtime" {
		t.Fatalf("workspace metadata = %#v", got.Workspace)
	}
	requireFactorySandboxSecurityMetadata(t, got.Security, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync})
	if got.Lease == nil ||
		got.Lease.ID != "lease-rootless" ||
		got.Lease.HostID != "host-local" ||
		got.Lease.HostName != "developer-workstation" ||
		got.Lease.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		got.Lease.ResourceKey != "runtime:container-123" ||
		!got.Lease.AcquiredAt.Equal(acquiredAt) ||
		!got.Lease.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("lease metadata = %#v", got.Lease)
	}

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(metadata) error: %v", err)
	}
	for _, forbidden := range []string{"/Users/v/work/private/repo", "local-user", "endpoint", "holder"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("factory sandbox metadata leaked %q:\n%s", forbidden, string(data))
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsAppliesCleanupPolicy(t *testing.T) {
	tests := []struct {
		name        string
		behavior    string
		execErr     error
		wantCleanup bool
		wantErr     bool
	}{
		{
			name:     "preserve leaves successful sandbox available",
			behavior: factory.CleanupBehaviorPreserve,
		},
		{
			name:        "on success cleans up successful sandbox",
			behavior:    factory.CleanupBehaviorOnSuccess,
			wantCleanup: true,
		},
		{
			name:        "on success preserves failed sandbox",
			behavior:    factory.CleanupBehaviorOnSuccess,
			execErr:     fmt.Errorf("remote failed"),
			wantCleanup: false,
			wantErr:     true,
		},
		{
			name:        "always cleans up successful sandbox",
			behavior:    factory.CleanupBehaviorAlways,
			wantCleanup: true,
		},
		{
			name:        "always cleans up failed sandbox",
			behavior:    factory.CleanupBehaviorAlways,
			execErr:     fmt.Errorf("remote failed"),
			wantCleanup: true,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			projectDir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0755); err != nil {
				t.Fatalf("MkdirAll() error: %v", err)
			}
			if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0644); err != nil {
				t.Fatalf("WriteFile() error: %v", err)
			}
			policy := factory.DefaultFactoryPolicy()
			policy.CleanupBehavior = tt.behavior
			target := &sandbox.SandboxState{
				Name:     "factory-dev",
				Provider: "daytona",
				Status:   sandbox.StatusRunning,
				IP:       "127.0.0.1",
			}

			var execCalls int
			var cleanupCalls int
			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir:  projectDir,
				SandboxName: "factory-dev",
				RunRecord: factory.RunRecord{
					RunID:      "run-sandbox",
					RepoRemote: "git@github.com:example/repo.git",
					Policy:     &policy,
				},
				RemoteAuto:   factoryRunAutoRequest{Args: []string{".hal/prd.md"}},
				RemoteOutput: io.Discard,
			}, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) {
					return store, nil
				},
				now: func() time.Time {
					return time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
				},
				loadSandbox: func(string) (*sandbox.SandboxState, error) {
					return target, nil
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					return fakeFactorySandboxProvider{}, nil
				},
				runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
					execCalls++
					if execCalls == 2 {
						return tt.execErr
					}
					return nil
				},
				cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
					cleanupCalls++
					if req.Target == nil || req.Target.Name != "factory-dev" {
						t.Fatalf("cleanup target = %#v, want factory-dev", req.Target)
					}
					if req.Provider == nil {
						t.Fatalf("cleanup provider = nil")
					}
					return nil
				},
			})
			if tt.wantErr && err == nil {
				t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
			}
			wantCleanupCalls := 0
			if tt.wantCleanup {
				wantCleanupCalls = 1
			}
			if cleanupCalls != wantCleanupCalls {
				t.Fatalf("cleanup calls = %d, want %d", cleanupCalls, wantCleanupCalls)
			}
			saved, err := store.LoadRun("run-sandbox")
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			if tt.wantCleanup {
				if saved.Sandbox == nil {
					t.Fatal("saved sandbox metadata = nil, want cleaned metadata")
				}
				if saved.Sandbox.Status != sandbox.StatusUnknown {
					t.Fatalf("saved sandbox status = %q, want unknown after cleanup", saved.Sandbox.Status)
				}
				if saved.Sandbox.Connection != nil || saved.Sandbox.SSHCommand != "" || saved.Sandbox.CleanupCommand != "" || saved.Sandbox.Handoff != "" {
					t.Fatalf("saved sandbox handoff metadata = %#v, want cleared after cleanup", saved.Sandbox)
				}
				if tt.wantErr {
					if saved.Failure == nil {
						t.Fatal("saved failure = nil, want sandbox failure")
					}
					if saved.Failure.SuggestedCommand != factoryRunInspectCommand(saved.RunID) {
						t.Fatalf("failure suggested command = %q, want inspect command", saved.Failure.SuggestedCommand)
					}
				}
			}
		})
	}
}

func TestCleanupFactorySandboxAfterRunSkipsCleanupAfterBeforeCleanupError(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	beforeErr := fmt.Errorf("copy artifacts failed")
	cleanupCalls := 0

	cleaned, err := cleanupFactorySandboxAfterRun(context.Background(), factorySandboxExecutorDeps{
		cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
	}, factorySandboxExecutorRequest{
		BeforeCleanup: func(context.Context, factory.RunRecord) error {
			return beforeErr
		},
	}, factory.RunRecord{}, target, fakeFactorySandboxProvider{}, io.Discard, factory.CleanupBehaviorAlways, false)

	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 after BeforeCleanup error", cleanupCalls)
	}
	if cleaned {
		t.Fatal("cleanupFactorySandboxAfterRun() cleaned = true, want false after BeforeCleanup error")
	}
	if err == nil {
		t.Fatal("cleanupFactorySandboxAfterRun() error = nil, want preparation error")
	}
	if want := "prepare factory sandbox cleanup: copy artifacts failed"; !strings.Contains(err.Error(), want) {
		t.Fatalf("cleanupFactorySandboxAfterRun() error = %q, want containing %q", err.Error(), want)
	}
}

func TestRunFactorySandboxExecutorWithDepsDefersOnSuccessCleanup(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var cleanupCalls int
	var beforeCleanupCalls int
	if err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:          projectDir,
		SandboxName:         "factory-dev",
		RunRecord:           factory.RunRecord{RunID: "run-sandbox-defer-cleanup", RepoRemote: "git@github.com:example/repo.git", Policy: &policy},
		RemoteAuto:          factoryRunAutoRequest{Args: []string{".hal/prd.md"}},
		RemoteOutput:        io.Discard,
		DeferSuccessCleanup: true,
		BeforeCleanup: func(context.Context, factory.RunRecord) error {
			beforeCleanupCalls++
			return nil
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return store, nil
		},
		now: func() time.Time {
			return time.Date(2026, 6, 21, 9, 35, 0, 0, time.UTC)
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
	}); err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when success cleanup is deferred", cleanupCalls)
	}
	if beforeCleanupCalls != 0 {
		t.Fatalf("BeforeCleanup calls = %d, want 0 when cleanup is deferred", beforeCleanupCalls)
	}
}

func TestRunFactorySandboxExecutorWithDepsDefersAlwaysCleanupAfterSuccess(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorAlways
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var cleanupCalls int
	var beforeCleanupCalls int
	if err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:          projectDir,
		SandboxName:         "factory-dev",
		RunRecord:           factory.RunRecord{RunID: "run-sandbox-defer-always-cleanup", RepoRemote: "git@github.com:example/repo.git", Policy: &policy},
		RemoteAuto:          factoryRunAutoRequest{Args: []string{".hal/prd.md"}},
		RemoteOutput:        io.Discard,
		DeferSuccessCleanup: true,
		BeforeCleanup: func(context.Context, factory.RunRecord) error {
			beforeCleanupCalls++
			return nil
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return store, nil
		},
		now: func() time.Time {
			return time.Date(2026, 6, 21, 9, 36, 0, 0, time.UTC)
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
	}); err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when always cleanup is deferred after successful execution", cleanupCalls)
	}
	if beforeCleanupCalls != 0 {
		t.Fatalf("BeforeCleanup calls = %d, want 0 when always cleanup is deferred after successful execution", beforeCleanupCalls)
	}
}

func TestRunFactorySandboxExecutorWithDepsCleansUpEarlyFailureWhenPolicyAlways(t *testing.T) {
	tests := []struct {
		name       string
		record     factory.RunRecord
		remoteAuto factoryRunAutoRequest
		bootstrap  func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
		wantErr    string
	}{
		{
			name: "bootstrap failure",
			record: factory.RunRecord{
				RunID:      "run-bootstrap-cleanup",
				RepoRemote: "git@github.com:example/repo.git",
				BaseBranch: "main",
				BranchName: "hal/feature",
			},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				return factory.BootstrapResult{}, fmt.Errorf("bootstrap failed")
			},
			wantErr: "bootstrap factory sandbox workspace: bootstrap failed",
		},
		{
			name: "prepare inputs failure",
			record: factory.RunRecord{
				RunID:      "run-prepare-cleanup",
				RepoRemote: "git@github.com:example/repo.git",
			},
			remoteAuto: factoryRunAutoRequest{Args: []string{".hal/missing.md"}},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				t.Fatalf("bootstrap should not run without a base branch")
				return factory.BootstrapResult{}, nil
			},
			wantErr: "prepare factory sandbox inputs: read sandbox input \".hal/missing.md\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			projectDir := t.TempDir()
			policy := factory.DefaultFactoryPolicy()
			policy.CleanupBehavior = factory.CleanupBehaviorAlways
			record := tt.record
			record.Policy = &policy
			target := &sandbox.SandboxState{
				Name:     "factory-dev",
				Provider: "daytona",
				Status:   sandbox.StatusRunning,
			}

			var beforeCleanupCalls int
			var cleanupCalls int
			var execCalls int
			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir:   projectDir,
				SandboxName:  "factory-dev",
				RunRecord:    record,
				RemoteAuto:   tt.remoteAuto,
				RemoteOutput: io.Discard,
				BeforeCleanup: func(context.Context, factory.RunRecord) error {
					beforeCleanupCalls++
					return nil
				},
			}, factorySandboxExecutorDeps{
				defaultStore:    func() (factory.Store, error) { return store, nil },
				loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
				resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
				bootstrap:       tt.bootstrap,
				runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
					execCalls++
					return nil
				},
				cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
					cleanupCalls++
					if beforeCleanupCalls != cleanupCalls {
						t.Fatalf("cleanup ran before BeforeCleanup")
					}
					if req.Target == nil || req.Target.Name != "factory-dev" {
						t.Fatalf("cleanup target = %#v, want factory-dev", req.Target)
					}
					if req.Provider == nil {
						t.Fatalf("cleanup provider = nil")
					}
					return nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want containing %q", err, tt.wantErr)
			}
			if beforeCleanupCalls != 1 || cleanupCalls != 1 {
				t.Fatalf("BeforeCleanup/cleanup calls = %d/%d, want 1/1", beforeCleanupCalls, cleanupCalls)
			}
			if execCalls != 0 {
				t.Fatalf("remote execution calls = %d, want 0", execCalls)
			}
		})
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesFakeSideEffectBoundaries(t *testing.T) {
	now := time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var calls []string
	var savedRecords []factory.RunRecord
	var appendedEvent factory.EventRecord
	var gotExecArgs []string
	var gotExecTarget sandboxruntime.Target
	var execCalls int
	record := factory.RunRecord{
		RunID:        "run-sandbox",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeLocal,
		RepoRemote:   "git@github.com:example/repo.git",
	}
	remoteAuto := factoryRunAutoRequest{Args: []string{".hal/prd.md"}}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   projectDir,
		SandboxName:  "factory-dev",
		RunRecord:    record,
		RemoteAuto:   remoteAuto,
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			calls = append(calls, "store")
			return store, nil
		},
		now: func() time.Time {
			calls = append(calls, "now")
			return now
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			calls = append(calls, "load")
			if name != "factory-dev" {
				t.Fatalf("load sandbox name = %q, want factory-dev", name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatalf("provision should not be called when resolve succeeds")
			return nil, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			if providerName != "daytona" {
				t.Fatalf("providerName = %q, want daytona", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			calls = append(calls, "driver")
			if target.Provider != "daytona" {
				t.Fatalf("runtime target provider = %q, want daytona", target.Provider)
			}
			if target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("runtime target driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverSSHMachine)
			}
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				calls = append(calls, "runtime_exec")
				gotExecTarget = req.Target
				gotExecArgs = append([]string(nil), req.Args...)
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, info *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			calls = append(calls, "exec")
			execCalls++
			if info == nil || info.Name != "factory-dev" || info.IP != "127.0.0.1" {
				t.Fatalf("copy exec info = %#v, want factory-dev at 127.0.0.1", info)
			}
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			calls = append(calls, "save")
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			calls = append(calls, "event")
			appendedEvent = *event
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}

	wantCalls := []string{"store", "now", "save", "load", "now", "save", "now", "event", "driver", "provider", "exec", "exec", "now", "event", "runtime_exec", "now", "event"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	if savedRecords[0].ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("saved executorMode = %q, want %q", savedRecords[0].ExecutorMode, factory.ExecutorModeSandbox)
	}
	if !savedRecords[0].UpdatedAt.Equal(now) {
		t.Fatalf("saved UpdatedAt = %s, want %s", savedRecords[0].UpdatedAt, now)
	}
	if savedRecords[1].SandboxName != "factory-dev" {
		t.Fatalf("saved sandboxName = %q, want factory-dev", savedRecords[1].SandboxName)
	}
	if savedRecords[1].Sandbox == nil {
		t.Fatalf("saved sandbox metadata = nil")
	}
	if savedRecords[1].Sandbox.Name != "factory-dev" || savedRecords[1].Sandbox.Provider != "daytona" || savedRecords[1].Sandbox.Status != sandbox.StatusRunning {
		t.Fatalf("saved sandbox metadata = %#v", savedRecords[1].Sandbox)
	}
	if savedRecords[1].Sandbox.Connection == nil || savedRecords[1].Sandbox.Connection.PublicIP != "127.0.0.1" {
		t.Fatalf("saved sandbox connection = %#v", savedRecords[1].Sandbox.Connection)
	}
	requireFactorySandboxSecurityMetadata(t, savedRecords[1].Sandbox.Security, []string{sandbox.SandboxSecretModeLegacyAuthSync})
	if gotExecTarget.Name != "factory-dev" || gotExecTarget.Connection.Address != "127.0.0.1" {
		t.Fatalf("runtime exec target = %#v, want factory-dev at 127.0.0.1", gotExecTarget)
	}
	if want := factorySandboxRemoteCommandArgs(record, remoteAuto); !reflect.DeepEqual(gotExecArgs, want) {
		t.Fatalf("exec args = %#v, want %#v", gotExecArgs, want)
	}
	if appendedEvent.RunID != "run-sandbox" || appendedEvent.EventType != factory.EventTypeStepEnded || appendedEvent.Metadata["executorMode"] != factory.ExecutorModeSandbox {
		t.Fatalf("appended event = %#v", appendedEvent)
	}
	if appendedEvent.Summary != "Remote sandbox execution completed" || appendedEvent.Metadata["source"] != "remote_sandbox" {
		t.Fatalf("appended completion event = %#v", appendedEvent)
	}
}

func TestRunFactorySandboxExecutorWithDepsPersistsSanitizedCredentialProxyMetadata(t *testing.T) {
	now := time.Date(2026, 7, 2, 13, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	target := &sandbox.SandboxState{
		Name:     "factory-credential-proxy",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	record := factory.RunRecord{
		RunID:      "run-factory-credential-proxy",
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@github.com:example/repo.git",
		BranchName: "hal/credential-proxy",
		BaseBranch: "main",
		Secrets: []factory.RunSecretMetadata{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}, {
			Name:     "bad-secret-name",
			Source:   factory.RunSecretSourceEnv,
			Required: false,
			Present:  true,
		}, {
			Name:     "OPTIONAL_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: false,
			Present:  false,
		}},
	}
	securityReq := fixture.SecurityRequest([]string{sandbox.SandboxSecretModeEnv}, []string{sandbox.SandboxSecretModeHTTPProxy})
	networkSession := fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory, "network-proxy-session-factory", "policy-snapshot-factory")

	var savedRecords []factory.RunRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:          t.TempDir(),
		SandboxName:         "factory-credential-proxy",
		RunRecord:           record,
		Security:            securityReq,
		NetworkProxySession: networkSession,
		RemoteAuto:          factoryRunAutoRequest{BaseBranch: "main"},
		RemoteOutput:        io.Discard,
		DeferSuccessCleanup: true,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-credential-proxy" {
				t.Fatalf("load sandbox name = %q, want factory-credential-proxy", name)
			}
			return target, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		saveRun: func(store factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return store.SaveRun(record)
		},
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(savedRecords) < 2 || savedRecords[1].Sandbox == nil {
		t.Fatalf("saved records = %#v, want sandbox metadata on second write", savedRecords)
	}
	sandboxMetadata := savedRecords[1].Sandbox
	if sandboxMetadata.CredentialProxyPlan == nil || sandboxMetadata.CredentialProxySession == nil {
		t.Fatalf("credential proxy plan/session = %#v/%#v, want metadata", sandboxMetadata.CredentialProxyPlan, sandboxMetadata.CredentialProxySession)
	}
	if sandboxMetadata.CredentialProxyPlan.Source != sandbox.SandboxCredentialProxySourceFactory {
		t.Fatalf("credential proxy source = %q, want factory", sandboxMetadata.CredentialProxyPlan.Source)
	}
	if sandboxMetadata.CredentialProxyPlan.SecretBrokerSessionID != "run-factory-credential-proxy-credential-proxy-secret-broker-session" {
		t.Fatalf("secret broker session id = %q", sandboxMetadata.CredentialProxyPlan.SecretBrokerSessionID)
	}
	if sandboxMetadata.CredentialProxyPlan.NetworkProxySessionID != "network-proxy-session-factory" {
		t.Fatalf("network proxy session id = %q", sandboxMetadata.CredentialProxyPlan.NetworkProxySessionID)
	}
	if sandboxMetadata.CredentialProxyPlan.PolicySnapshot == nil || sandboxMetadata.CredentialProxyPlan.PolicySnapshot.ID != "policy-snapshot-factory" {
		t.Fatalf("credential proxy policy snapshot = %#v", sandboxMetadata.CredentialProxyPlan.PolicySnapshot)
	}
	if sandboxMetadata.CredentialProxyPlan.PolicySnapshot.Version != "" || sandboxMetadata.CredentialProxyPlan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("unsafe policy snapshot fields survived sanitizer: %#v", sandboxMetadata.CredentialProxyPlan.PolicySnapshot)
	}
	if sandboxMetadata.CredentialProxySession.PolicySnapshot == nil || sandboxMetadata.CredentialProxySession.PolicySnapshot.ID != "policy-snapshot-factory" {
		t.Fatalf("credential proxy session policy snapshot = %#v", sandboxMetadata.CredentialProxySession.PolicySnapshot)
	}
	if sandboxMetadata.CredentialProxySession.PolicySnapshot.Version != "" || sandboxMetadata.CredentialProxySession.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("unsafe session policy snapshot fields survived sanitizer: %#v", sandboxMetadata.CredentialProxySession.PolicySnapshot)
	}
	if got, want := len(sandboxMetadata.CredentialProxyBindings), 3; got != want {
		t.Fatalf("credential proxy bindings = %#v, want %d safe bindings", sandboxMetadata.CredentialProxyBindings, want)
	}
	for _, binding := range sandboxMetadata.CredentialProxyBindings {
		if binding.SecretID != "env:GITHUB_TOKEN" {
			t.Fatalf("binding secret id = %q, want only sanitized broker secret reference", binding.SecretID)
		}
		if binding.Status == sandbox.SandboxCredentialProxyStatusActive || binding.Outcome == sandbox.SandboxCredentialProxyBindingOutcomeBound {
			t.Fatalf("binding overclaims live delivery: %#v", binding)
		}
		if result := sandbox.ValidateSandboxCredentialProxyBindingMetadata(binding); !result.Valid {
			t.Fatalf("binding validation = %#v, want valid", result)
		}
	}
	if result := sandbox.ValidateSandboxCredentialProxyPlanMetadata(*sandboxMetadata.CredentialProxyPlan); !result.Valid {
		t.Fatalf("plan validation = %#v, want valid", result)
	}
	if result := sandbox.ValidateSandboxCredentialProxySessionMetadata(*sandboxMetadata.CredentialProxySession); !result.Valid {
		t.Fatalf("session validation = %#v, want valid", result)
	}
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "factory sandbox credential proxy metadata", sandboxMetadata)

	storedRun, err := store.LoadRun("run-factory-credential-proxy")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	recordPayload, err := json.Marshal(storedRun)
	if err != nil {
		t.Fatalf("json.Marshal(run) error: %v", err)
	}
	assertFactorySandboxCredentialProxyPayloadExcludes(t, "stored run", string(recordPayload), fixture.ForbiddenValues()...)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "stored factory run", storedRun)
	assertPhase26CredentialProxyValuesPresent(t, "stored factory run", string(recordPayload),
		"run-factory-credential-proxy-credential-proxy-plan",
		"run-factory-credential-proxy-credential-proxy-session",
		"run-factory-credential-proxy-credential-proxy-secret-broker-session",
		"network-proxy-session-factory",
		"policy-snapshot-factory",
		"env:GITHUB_TOKEN",
		string(sandbox.SandboxCredentialProxySourceFactory),
		string(sandbox.SandboxCredentialProxyModeBrokeredNetworkReference),
		string(sandbox.SandboxCredentialProxyDeliveryModeEnv),
		string(sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy),
		string(sandbox.SandboxCredentialProxyDeliveryModeLegacyAuthSync),
		string(sandbox.SandboxCredentialProxyRequestNetworkAuth),
		string(sandbox.SandboxNetworkPolicyDestinationUnknown),
		string(sandbox.SandboxCredentialProxyBindingOutcomePlanned),
		string(sandbox.SandboxCredentialProxyBindingOutcomeAuditOnly),
		string(sandbox.SandboxCredentialProxyStatusPlanned),
		string(sandbox.SandboxCredentialProxyStatusReady),
		string(sandbox.SandboxCredentialProxyReasonRequested),
	)

	var statusJSON bytes.Buffer
	if err := renderFactoryStatusJSON(&statusJSON, *storedRun, nil, nil); err != nil {
		t.Fatalf("renderFactoryStatusJSON() error: %v", err)
	}
	assertFactorySandboxCredentialProxyPayloadExcludes(t, "factory status json", statusJSON.String(), fixture.ForbiddenValues()...)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "factory status json", statusJSON.String())
	assertPhase26CredentialProxyValuesPresent(t, "factory status json", statusJSON.String(),
		"run-factory-credential-proxy-credential-proxy-plan",
		"run-factory-credential-proxy-credential-proxy-session",
		"run-factory-credential-proxy-credential-proxy-secret-broker-session",
		"network-proxy-session-factory",
		"policy-snapshot-factory",
		"env:GITHUB_TOKEN",
		string(sandbox.SandboxCredentialProxySourceFactory),
		string(sandbox.SandboxCredentialProxyModeBrokeredNetworkReference),
		string(sandbox.SandboxCredentialProxyDeliveryModeEnv),
		string(sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy),
		string(sandbox.SandboxCredentialProxyDeliveryModeLegacyAuthSync),
		string(sandbox.SandboxCredentialProxyRequestNetworkAuth),
		string(sandbox.SandboxNetworkPolicyDestinationUnknown),
		string(sandbox.SandboxCredentialProxyReasonRequested),
	)
}

func TestRunFactorySandboxExecutorWithDepsUsesConfiguredSecurityRequest(t *testing.T) {
	now := time.Date(2026, 7, 2, 9, 15, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(prd.md) error: %v", err)
	}
	target := &sandbox.SandboxState{
		Name:     "factory-security",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	networkPolicy := sandbox.SandboxNetworkPolicyIntent{
		Preset: sandbox.SandboxNetworkPolicyPresetAllowListed,
		Rules: []sandbox.SandboxNetworkPolicyRule{{
			Kind:     sandbox.SandboxNetworkPolicyRuleKindDomain,
			Value:    "api.example.com",
			Decision: sandbox.SandboxNetworkPolicyDecisionAllow,
		}},
	}
	securityReq := sandbox.MapSandboxSecurityIntent(sandbox.SandboxSecurityIntent{
		RuntimeDriver: sandbox.SandboxRuntimeDriverSSHMachine,
		NetworkPolicy: &networkPolicy,
		Secrets: &sandbox.SandboxSecretDeliveryIntent{
			RequestedModes: []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeFileTmpfs},
			ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
		},
		CompatibilityAuthSync: true,
	})
	secretValue := "ghp_executor_security_secret_123"

	var savedRecords []factory.RunRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:      projectDir,
		SandboxName:     "factory-security",
		Security:        securityReq,
		ResolvedSecrets: []factory.ResolvedRunSecret{{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true, Value: secretValue}},
		RunRecord: factory.RunRecord{
			RunID:        "run-executor-security-config",
			Status:       factory.RunStatusRunning,
			ExecutorMode: factory.ExecutorModeLocal,
			RepoRemote:   "git@github.com:example/repo.git",
		},
		RemoteAuto:   factoryRunAutoRequest{Args: []string{".hal/prd.md"}},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-security" {
				t.Fatalf("load sandbox name = %q, want factory-security", name)
			}
			return target, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(store factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return store.SaveRun(record)
		},
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(savedRecords) < 2 || savedRecords[1].Sandbox == nil {
		t.Fatalf("saved records = %#v, want sandbox metadata", savedRecords)
	}
	requireFactorySandboxConfiguredSecurityMetadata(t, savedRecords[1].Sandbox.Security)

	events, err := store.LoadEvents("run-executor-security-config")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	requireFactorySandboxConfiguredSecurityPolicyEvent(t, events[0])

	payload, err := json.Marshal(struct {
		Records []factory.RunRecord   `json:"records"`
		Events  []factory.EventRecord `json:"events"`
	}{
		Records: savedRecords,
		Events:  events,
	})
	if err != nil {
		t.Fatalf("Marshal(factory sandbox security surfaces) error: %v", err)
	}
	if strings.Contains(string(payload), secretValue) {
		t.Fatalf("factory sandbox security surfaces leaked raw secret: %s", payload)
	}
}

func TestRunFactorySandboxExecutorRuntimeBoundaryRegressionMatchesSSHMachineBehavior(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:    sandbox.SandboxRuntimeDriverSSHMachine,
			RuntimeID: "runtime-ssh-machine",
		},
	}
	record := factory.RunRecord{
		RunID:      "run-runtime-regression",
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
		BranchName: "hal/runtime-regression",
	}
	remoteAuto := factoryRunAutoRequest{
		BaseBranch: "main",
		Engine:     "codex",
		SkipCI:     true,
	}
	secrets := []factory.ResolvedRunSecret{{
		Name:     "GITHUB_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Value:    "secret-token",
	}}
	wantEnv := factorySandboxResolvedSecretEnv(secrets)
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)

	var remoteOutput bytes.Buffer
	var resolvedDriverID string
	var gotExec sandboxruntime.ExecRequest
	var sawStdoutWriter bool
	var sawStderrWriter bool
	driver := fakeFactorySandboxRuntimeDriver{
		id: sandboxruntime.DriverSSHMachine,
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			sawStdoutWriter = req.Stdout != nil
			sawStderrWriter = req.Stderr != nil
			gotExec = sandboxruntime.ExecRequest{
				Target:  req.Target,
				Args:    append([]string(nil), req.Args...),
				Env:     map[string]string{},
				WorkDir: req.WorkDir,
			}
			for key, value := range req.Env {
				gotExec.Env[key] = value
			}
			if _, err := io.WriteString(req.Stdout, "runtime stdout\n"); err != nil {
				return nil, err
			}
			if _, err := io.WriteString(req.Stderr, "runtime stderr\n"); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:          t.TempDir(),
		SandboxName:         "factory-dev",
		RunRecord:           record,
		ResolvedSecrets:     secrets,
		RemoteAuto:          remoteAuto,
		RemoteOutput:        &remoteOutput,
		BeforeCleanup:       func(context.Context, factory.RunRecord) error { return nil },
		DeferSuccessCleanup: true,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-dev" {
				t.Fatalf("load sandbox name = %q, want factory-dev", name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for existing sandbox target")
			return nil, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			if providerName != "daytona" {
				t.Fatalf("providerName = %q, want daytona", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			if target.Provider != "daytona" {
				t.Fatalf("runtime target provider = %q, want daytona", target.Provider)
			}
			if target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("runtime target driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverSSHMachine)
			}
			resolvedDriverID = driver.ID()
			return driver, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(_ context.Context, req factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
			if req.WorkspaceDir != workspaceDir {
				t.Fatalf("bootstrap workspace dir = %q, want %q", req.WorkspaceDir, workspaceDir)
			}
			return factory.BootstrapResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}

	if resolvedDriverID != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime driver ID = %q, want %q", resolvedDriverID, sandboxruntime.DriverSSHMachine)
	}
	if gotExec.Target.Name != "factory-dev" || gotExec.Target.Provider != "daytona" || gotExec.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("exec target = %#v, want factory-dev/daytona with ssh_machine runtime", gotExec.Target)
	}
	if gotExec.Target.Connection.Address != "127.0.0.1" {
		t.Fatalf("exec target connection = %#v, want legacy SSH-machine address", gotExec.Target.Connection)
	}
	wantArgs := factorySandboxRemoteCommandArgs(record, remoteAuto)
	if !reflect.DeepEqual(gotExec.Args, wantArgs) {
		t.Fatalf("exec args = %#v, want %#v", gotExec.Args, wantArgs)
	}
	if gotExec.WorkDir != "" {
		t.Fatalf("exec workdir = %q, want empty because SSH-machine compatibility uses shell cd wrapper", gotExec.WorkDir)
	}
	if len(gotExec.Args) != 3 || !strings.Contains(gotExec.Args[2], "cd "+shellQuote(workspaceDir)) {
		t.Fatalf("exec args = %#v, want shell cd into %q", gotExec.Args, workspaceDir)
	}
	if !reflect.DeepEqual(gotExec.Env, wantEnv) {
		t.Fatalf("exec env = %#v, want %#v", gotExec.Env, wantEnv)
	}
	if !sawStdoutWriter || !sawStderrWriter {
		t.Fatalf("stdout/stderr writers seen = %v/%v, want both", sawStdoutWriter, sawStderrWriter)
	}
	if remoteOutput.String() != "runtime stdout\nruntime stderr\n" {
		t.Fatalf("remote output = %q, want runtime stdout/stderr", remoteOutput.String())
	}
}

func TestRunFactorySandboxExecutorUsesRootlessPodmanRuntimeMetadataForDriverResolution(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-rootless",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "container-123",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	record := factory.RunRecord{
		RunID:      "run-rootless-runtime",
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
		BranchName: "hal/rootless-runtime",
	}

	var resolvedTarget sandboxruntime.Target
	var gotExecTarget sandboxruntime.Target
	var savedRecords []factory.RunRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   t.TempDir(),
		SandboxName:  "factory-rootless",
		RunRecord:    record,
		RemoteAuto:   factoryRunAutoRequest{BaseBranch: "main"},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-rootless" {
				t.Fatalf("load sandbox name = %q, want factory-rootless", name)
			}
			return target, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			if providerName != "local" {
				t.Fatalf("providerName = %q, want local", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedTarget = target
			return fakeFactorySandboxRuntimeDriver{
				id: sandboxruntime.DriverRootlessPodman,
				execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					gotExecTarget = req.Target
					return &sandboxruntime.ExecResult{}, nil
				},
			}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(_ context.Context, req factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
			if req.WorkspaceDir != factorySandboxRemoteWorkspaceDir(record) {
				t.Fatalf("bootstrap workspace dir = %q, want %q", req.WorkspaceDir, factorySandboxRemoteWorkspaceDir(record))
			}
			return factory.BootstrapResult{}, nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}

	if resolvedTarget.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("resolved target runtime driver = %q, want %q", resolvedTarget.Runtime.Driver, sandboxruntime.DriverRootlessPodman)
	}
	if resolvedTarget.Runtime.RuntimeID != "container-123" || resolvedTarget.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("resolved target runtime metadata = %#v", resolvedTarget.Runtime)
	}
	if gotExecTarget.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("exec target runtime driver = %q, want %q", gotExecTarget.Runtime.Driver, sandboxruntime.DriverRootlessPodman)
	}
	if len(savedRecords) < 2 || savedRecords[1].Sandbox == nil {
		t.Fatalf("saved records missing sandbox metadata: %#v", savedRecords)
	}
	sandboxMetadata := savedRecords[1].Sandbox
	if sandboxMetadata.SSHCommand != "hal sandbox ssh factory-rootless" || sandboxMetadata.CleanupCommand != "hal sandbox delete factory-rootless" {
		t.Fatalf("handoff metadata = %#v", sandboxMetadata)
	}
	if sandboxMetadata.Runtime == nil {
		t.Fatal("saved sandbox runtime metadata = nil")
	}
	if sandboxMetadata.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("saved sandbox runtime driver = %q, want %q", sandboxMetadata.Runtime.Driver, sandbox.SandboxRuntimeDriverRootlessPodman)
	}
	if sandboxMetadata.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("saved sandbox runtime isolationLevel = %q, want %q", sandboxMetadata.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if sandboxMetadata.Runtime.IsolationLevel == sandbox.SandboxIsolationLevelVM {
		t.Fatalf("saved rootless Podman metadata must not report VM isolation: %#v", sandboxMetadata.Runtime)
	}
	requireFactorySandboxSecurityMetadata(t, sandboxMetadata.Security, []string{sandbox.SandboxSecretModeLegacyAuthSync})
}

func TestResolveFactorySandboxTargetRejectsExplicitRuntimeBeforeDefaultFallback(t *testing.T) {
	record := factory.RunRecord{
		RunID:      "run-microvm-target",
		RepoRemote: "git@example.com:org/repo.git",
		BranchName: "feature/microvm",
	}
	defaultCalled := false
	provisionCalled := false
	deps := factorySandboxExecutorDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:                "ssh-a",
				Name:              "ssh a",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			}}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for unsupported explicit runtime")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			defaultCalled = true
			return &sandbox.SandboxState{Name: "legacy", Status: sandbox.StatusRunning}, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
	}

	_, err := resolveFactorySandboxTarget(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     "/workspace/hal",
		SandboxRuntime: sandbox.SandboxRuntimeDriverMicroVM,
		RemoteOutput:   io.Discard,
	}, &record, "git@example.com:org/repo.git", deps)
	if err == nil {
		t.Fatal("resolveFactorySandboxTarget() error = nil, want explicit runtime failure")
	}
	if !strings.Contains(err.Error(), `no durable host supports requested runtime "microvm"`) {
		t.Fatalf("error = %q, want microvm unsupported failure", err.Error())
	}
	if defaultCalled || provisionCalled {
		t.Fatalf("defaultCalled=%v provisionCalled=%v, want no legacy fallback", defaultCalled, provisionCalled)
	}
}

func TestRunFactorySandboxExecutorWithDepsBootstrapsWorkspaceBeforeRemoteExecution(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var calls []string
	var bootstrapReq factory.BootstrapRequest
	var bootstrapDeps factory.BootstrapDeps
	var events []factory.EventRecord
	record := factory.RunRecord{
		RunID:      "run-bootstrap",
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
		BranchName: "hal/feature",
	}
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord:   record,
		RemoteAuto:  factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			calls = append(calls, "driver")
			return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				calls = append(calls, "runtime_exec")
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		bootstrap: func(_ context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			calls = append(calls, "bootstrap")
			bootstrapReq = req
			bootstrapDeps = deps
			return factory.BootstrapResult{
				Timeline: []factory.BootstrapTimelineEvent{{
					Timestamp:      now,
					Step:           factory.BootstrapStepCloneRepository,
					Status:         factory.RunStatusSucceeded,
					Message:        "bootstrap step succeeded",
					CommandSummary: "git clone <redacted> " + workspaceDir,
				}},
			}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			calls = append(calls, "exec")
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"driver", "provider", "bootstrap", "runtime_exec"}) {
		t.Fatalf("calls = %#v, want driver/provider/bootstrap/runtime_exec", calls)
	}
	if bootstrapReq.RepositoryURL != "git@github.com:example/repo.git" || bootstrapReq.BaseBranch != "main" || bootstrapReq.RunBranch != "hal/feature" || bootstrapReq.WorkspaceDir != workspaceDir {
		t.Fatalf("bootstrap request = %#v", bootstrapReq)
	}
	if !bootstrapReq.Options.RefreshHal {
		t.Fatalf("bootstrap refreshHal = false")
	}
	if bootstrapDeps.Executor == nil {
		t.Fatalf("bootstrap executor = nil")
	}
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeLegacyAuthSync})
	if events[1].Metadata["phase"] != "bootstrap" || events[1].Metadata["source"] != "remote_sandbox" {
		t.Fatalf("bootstrap event metadata = %#v", events[1].Metadata)
	}
	if events[2].Summary != "Remote sandbox execution started" || events[3].Summary != "Remote sandbox execution completed" {
		t.Fatalf("remote execution events = %#v", events)
	}
	if events[0].Sequence != 1 || events[1].Sequence != 2 || events[2].Sequence != 3 || events[3].Sequence != 4 {
		t.Fatalf("event sequences = %d/%d/%d/%d, want 1/2/3/4", events[0].Sequence, events[1].Sequence, events[2].Sequence, events[3].Sequence)
	}
}

func TestRunFactorySandboxExecutorWithDepsDoesNotPersistUnsanitizedBootstrapStreamingOutput(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	secret := "repo-secret"
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var userOut bytes.Buffer
	var events []factory.EventRecord
	execCalls := 0
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap-redaction",
			RepoRemote: "https://token:" + secret + "@github.com/example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
		},
		RemoteOutput: &userOut,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		bootstrap: func(ctx context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			step, commandResult, failure, err := factory.RunBootstrapStep(ctx, factory.BootstrapStepDeps{
				Executor: deps.Executor,
				Now:      deps.Now,
				Request:  req,
			}, factory.BootstrapStepCloneRepository, factory.BootstrapCommand{
				Name: "git",
				Args: []string{"clone", req.RepositoryURL, req.WorkspaceDir},
			})
			return factory.BootstrapResult{
				Steps:    []factory.BootstrapStepResult{step},
				Timeline: []factory.BootstrapTimelineEvent{factory.BootstrapTimelineEventFromStep(req, step, commandResult, failure)},
			}, err
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			execCalls++
			if execCalls == 1 {
				_, err := io.WriteString(out, "cloning with "+secret+"\n")
				return err
			}
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(userOut.String(), secret) {
		t.Fatalf("user output leaked bootstrap secret: %q", userOut.String())
	}
	if !strings.Contains(userOut.String(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("user output missing redaction marker: %q", userOut.String())
	}
	for _, event := range events {
		if strings.Contains(fmt.Sprintf("%#v", event), secret) {
			t.Fatalf("persisted event leaked bootstrap secret: %#v", event)
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsResolvedSecretsFromBootstrapTimeline(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 10, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	secret := "ghp_sandbox_bootstrap_secret_12345"

	var events []factory.EventRecord
	var bootstrapReq factory.BootstrapRequest
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap-secret",
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Value:    secret,
		}},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		bootstrap: func(_ context.Context, req factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
			bootstrapReq = req
			finishedAt := now.Add(time.Second)
			step := factory.BootstrapStepResult{
				Name:           factory.BootstrapStepCloneRepository,
				Status:         factory.RunStatusSucceeded,
				CommandSummary: "git clone https://" + secret + "@github.com/example/repo.git /workspace/repo",
				StartedAt:      now,
				FinishedAt:     &finishedAt,
			}
			commandResult := factory.BootstrapCommandResult{
				ExitCode:      0,
				OutputSummary: "bootstrap cloned with " + secret,
				Metadata: map[string]string{
					"remote": "https://" + secret + "@github.com/example/repo.git",
				},
			}
			return factory.BootstrapResult{
				Timeline: []factory.BootstrapTimelineEvent{
					factory.BootstrapTimelineEventFromStep(req, step, commandResult, nil),
				},
			}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if factory.NewBootstrapSanitizer(bootstrapReq).SanitizeString(secret) == secret {
		t.Fatalf("bootstrap request did not carry resolved secret values for sanitization")
	}
	if len(events) != 4 {
		t.Fatalf("events = %d, want policy/bootstrap/start/completion events: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync})
	bootstrapEvent := events[1]
	for _, value := range []string{bootstrapEvent.Message, bootstrapEvent.Summary} {
		if strings.Contains(value, secret) {
			t.Fatalf("bootstrap event leaked secret in %q: %#v", value, bootstrapEvent)
		}
	}
	for key, value := range bootstrapEvent.Metadata {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("bootstrap event metadata %q leaked secret in %q: %#v", key, text, bootstrapEvent)
		}
	}
	if command, ok := bootstrapEvent.Metadata["command"].(string); !ok || !strings.Contains(command, factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("bootstrap event command missing redaction marker: %#v", bootstrapEvent.Metadata["command"])
	}
}

func TestRunFactorySandboxExecutorWithDepsPassesResolvedSecretsToBootstrapEnvironment(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 20, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	requiredSecret := "ghp_bootstrap_env_secret_12345"
	optionalSecret := "npm_bootstrap_env_secret_67890"

	type execCall struct {
		args []string
		env  map[string]string
	}
	var execCalls []execCall
	var bootstrapReq factory.BootstrapRequest
	var bootstrapStep factory.BootstrapStepResult
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap-env",
			Status:     factory.RunStatusRunning,
			RepoRemote: "https://x:" + requiredSecret + "@github.com/example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
			Secrets: []factory.RunSecretMetadata{{
				Name:     "GITHUB_TOKEN",
				Source:   factory.RunSecretSourceEnv,
				Required: true,
				Present:  true,
			}, {
				Name:     "OPTIONAL_TOKEN",
				Source:   factory.RunSecretSourceEnv,
				Required: false,
				Present:  true,
			}},
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Value:    requiredSecret,
		}, {
			Name:     "OPTIONAL_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: false,
			Value:    optionalSecret,
		}},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				envCopy := map[string]string{}
				for key, value := range req.Env {
					envCopy[key] = value
				}
				execCalls = append(execCalls, execCall{
					args: append([]string(nil), req.Args...),
					env:  envCopy,
				})
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		bootstrap: func(ctx context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			bootstrapReq = req
			step, commandResult, failure, runErr := factory.RunBootstrapStep(ctx, factory.BootstrapStepDeps{
				Executor: deps.Executor,
				Now:      func() time.Time { return now },
				Request:  req,
			}, "secret_bootstrap", factory.BootstrapCommand{
				Name: "hal",
				Args: []string{"init"},
			})
			bootstrapStep = step
			return factory.BootstrapResult{
				Timeline: []factory.BootstrapTimelineEvent{
					factory.BootstrapTimelineEventFromStep(req, step, commandResult, failure),
				},
			}, runErr
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, env map[string]string, _ io.Writer) error {
			envCopy := map[string]string{}
			for key, value := range env {
				envCopy[key] = value
			}
			execCalls = append(execCalls, execCall{
				args: append([]string(nil), args...),
				env:  envCopy,
			})
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(bootstrapReq.RequiredEnvKeys, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("required env keys = %#v, want GITHUB_TOKEN", bootstrapReq.RequiredEnvKeys)
	}
	if bootstrapReq.RepositoryURL != "https://x:"+requiredSecret+"@github.com/example/repo.git" {
		t.Fatalf("bootstrap repository URL = %q, want raw in-memory remote", bootstrapReq.RepositoryURL)
	}
	if bootstrapReq.Env["GITHUB_TOKEN"] != requiredSecret || bootstrapReq.Env["OPTIONAL_TOKEN"] != optionalSecret {
		t.Fatalf("bootstrap env = %#v, want resolved secrets", bootstrapReq.Env)
	}
	if len(execCalls) != 2 {
		t.Fatalf("exec calls = %d, want bootstrap and remote execution: %#v", len(execCalls), execCalls)
	}
	if execCalls[0].env["GITHUB_TOKEN"] != requiredSecret || execCalls[0].env["OPTIONAL_TOKEN"] != optionalSecret {
		t.Fatalf("bootstrap exec env = %#v, want resolved secret env", execCalls[0].env)
	}
	argText := strings.Join(execCalls[0].args, " ")
	if strings.Contains(argText, requiredSecret) || strings.Contains(argText, optionalSecret) || strings.Contains(argText, "GITHUB_TOKEN=") || strings.Contains(argText, "OPTIONAL_TOKEN=") {
		t.Fatalf("bootstrap exec args leaked secret env data: %#v", execCalls[0].args)
	}
	wantBootstrapArgs := []string{"sh", "-c", factorySandboxRemoteHalScript([]string{"init"})}
	if !reflect.DeepEqual(execCalls[0].args, wantBootstrapArgs) {
		t.Fatalf("bootstrap exec args = %#v, want %#v", execCalls[0].args, wantBootstrapArgs)
	}
	if strings.Contains(bootstrapStep.CommandSummary, requiredSecret) || strings.Contains(bootstrapStep.CommandSummary, "GITHUB_TOKEN") {
		t.Fatalf("bootstrap command summary leaked secret data: %q", bootstrapStep.CommandSummary)
	}

	storedRun, loadErr := store.LoadRun("run-bootstrap-env")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	runData, err := json.Marshal(storedRun)
	if err != nil {
		t.Fatalf("json.Marshal(run) error: %v", err)
	}
	if strings.Contains(string(runData), requiredSecret) || strings.Contains(string(runData), optionalSecret) {
		t.Fatalf("stored run leaked secret values: %s", string(runData))
	}
	if storedRun.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/example/repo.git" {
		t.Fatalf("stored repo remote = %q, want redacted secret value", storedRun.RepoRemote)
	}
	events, loadErr := store.LoadEvents("run-bootstrap-env")
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	eventData, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("json.Marshal(events) error: %v", err)
	}
	if strings.Contains(string(eventData), requiredSecret) || strings.Contains(string(eventData), optionalSecret) {
		t.Fatalf("stored events leaked secret values: %s", string(eventData))
	}
}

func TestRunFactorySandboxExecutorWithDepsPassesResolvedSecretsToRemoteExecutionEnvironment(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	requiredSecret := "ghp_remote_env_secret_12345"
	optionalSecret := "npm_remote_env_secret_67890"

	var gotArgs []string
	var gotEnv map[string]string
	var events []factory.EventRecord
	record := factory.RunRecord{
		RunID:      "run-remote-env",
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@github.com:example/repo.git",
		BranchName: "hal/feature",
		Secrets: []factory.RunSecretMetadata{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}, {
			Name:     "OPTIONAL_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: false,
			Present:  true,
		}},
	}
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord:   record,
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Value:    requiredSecret,
		}, {
			Name:     "OPTIONAL_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: false,
			Value:    optionalSecret,
		}},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				gotArgs = append([]string(nil), req.Args...)
				gotEnv = map[string]string{}
				for key, value := range req.Env {
					gotEnv[key] = value
				}
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, env map[string]string, _ io.Writer) error {
			if len(env) != 0 {
				t.Fatalf("provider exec env = %#v, want final remote env handled by runtime driver", env)
			}
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if gotEnv["GITHUB_TOKEN"] != requiredSecret || gotEnv["OPTIONAL_TOKEN"] != optionalSecret {
		t.Fatalf("remote exec env = %#v, want resolved secrets", gotEnv)
	}
	argText := strings.Join(gotArgs, " ")
	if strings.Contains(argText, requiredSecret) || strings.Contains(argText, optionalSecret) {
		t.Fatalf("remote exec args leaked secret values: %#v", gotArgs)
	}
	if len(gotArgs) != 3 || gotArgs[0] != "sh" || gotArgs[1] != "-c" {
		t.Fatalf("remote exec args = %#v", gotArgs)
	}
	command := gotArgs[2]
	for _, want := range []string{"cd " + shellQuote(workspaceDir), "export HAL_FACTORY_MAX_RUN_ATTEMPTS=0", `exec "$HOME/.local/bin/hal" 'auto' '--base' 'main'`} {
		if !strings.Contains(command, want) {
			t.Fatalf("remote exec command = %q, want fragment %q", command, want)
		}
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want policy/start/completion: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync})
	eventCommand, _ := events[1].Metadata["command"].(string)
	if strings.Contains(eventCommand, requiredSecret) || strings.Contains(eventCommand, optionalSecret) {
		t.Fatalf("remote start command leaked secret values: %q", eventCommand)
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsResolvedSecretsFromRemoteOutput(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 45, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	secret := "ghp_remote_output_secret_12345"

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-output-secret",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:   "GITHUB_TOKEN",
			Source: factory.RunSecretSourceEnv,
			Value:  secret,
		}},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if req.Env["GITHUB_TOKEN"] != secret {
					t.Fatalf("GITHUB_TOKEN env = %q, want secret", req.Env["GITHUB_TOKEN"])
				}
				if _, err := io.WriteString(req.Stdout, "using "+secret[:12]); err != nil {
					return nil, err
				}
				if _, err := io.WriteString(req.Stdout, secret[12:]+"\n"); err != nil {
					return nil, err
				}
				_, err := io.WriteString(req.Stdout, "finished\n")
				return &sandboxruntime.ExecResult{}, err
			}}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, env map[string]string, _ io.Writer) error {
			if len(env) != 0 {
				t.Fatalf("provider exec env = %#v, want final remote env handled by runtime driver", env)
			}
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("remote output leaked secret: %q", out.String())
	}
	if !strings.Contains(out.String(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("remote output missing redaction marker: %q", out.String())
	}
	foundRedactedEvent := false
	for _, event := range events {
		text := fmt.Sprintf("%#v", event)
		if strings.Contains(text, secret) {
			t.Fatalf("remote event leaked secret: %#v", event)
		}
		if strings.Contains(text, factory.RunSecretRedactionPlaceholder) {
			foundRedactedEvent = true
		}
	}
	if !foundRedactedEvent {
		t.Fatalf("remote events missing redaction marker: %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsCredentialedRemoteURLsFromRemoteOutput(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 46, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	credential := "ghp_remote_url_credential_12345"

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-output-credentialed-url",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				_, err := io.WriteString(req.Stdout, "fatal: unable to access https://x:"+credential+"@github.com/example/repo.git\n")
				return &sandboxruntime.ExecResult{}, err
			}}, nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	for name, text := range map[string]string{
		"remote output": out.String(),
		"events":        fmt.Sprintf("%#v", events),
	} {
		if strings.Contains(text, credential) {
			t.Fatalf("%s leaked credentialed remote: %q", name, text)
		}
		if !strings.Contains(text, factory.RunSecretRedactionPlaceholder) {
			t.Fatalf("%s missing redaction marker: %q", name, text)
		}
	}
	chunks, err := store.LoadLogChunks("run-remote-output-credentialed-url")
	if err != nil {
		t.Fatalf("LoadLogChunks() error: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("LoadLogChunks() returned no remote output chunks")
	}
	chunkData, err := json.Marshal(chunks)
	if err != nil {
		t.Fatalf("json.Marshal(chunks) error: %v", err)
	}
	if strings.Contains(string(chunkData), credential) {
		t.Fatalf("remote log chunks leaked credentialed remote: %s", string(chunkData))
	}
	if !strings.Contains(string(chunkData), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("remote log chunks missing redaction marker: %s", string(chunkData))
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsSecretAssignmentsFromRemoteTimeline(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 46, 30, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-output-secret-assignment",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				_, err := io.WriteString(req.Stdout, "TOKEN=undeclared_remote_secret\n")
				return &sandboxruntime.ExecResult{}, err
			}}, nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "TOKEN=undeclared_remote_secret") {
		t.Fatalf("remote output = %q, want unsanitized user-visible output", out.String())
	}
	foundRedactedEvent := false
	for _, event := range events {
		if strings.Contains(event.Message, "TOKEN=undeclared_remote_secret") {
			t.Fatalf("remote event leaked secret assignment: %#v", event)
		}
		if event.Message == "[redacted]" {
			foundRedactedEvent = true
		}
	}
	if !foundRedactedEvent {
		t.Fatalf("remote events missing redacted command output: %#v", events)
	}
	chunks, err := store.LoadLogChunks("run-remote-output-secret-assignment")
	if err != nil {
		t.Fatalf("LoadLogChunks() error: %v", err)
	}
	if len(chunks) == 0 {
		t.Fatal("LoadLogChunks() returned no remote output chunks")
	}
	for _, chunk := range chunks {
		if strings.Contains(chunk.Text, "TOKEN=undeclared_remote_secret") {
			t.Fatalf("remote log chunk leaked secret assignment: %#v", chunk)
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsMultilineSecretsFromRemoteOutput(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 47, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	fragments := []string{
		"line_one_multiline_secret_fragment_12345",
		"line_two_multiline_secret_fragment_67890",
	}
	secret := strings.Join(fragments, "\n")

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-output-multiline-secret",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:   "PRIVATE_KEY",
			Source: factory.RunSecretSourceEnv,
			Value:  secret,
		}},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if req.Env["PRIVATE_KEY"] != secret {
					t.Fatalf("PRIVATE_KEY env = %q, want secret", req.Env["PRIVATE_KEY"])
				}
				if _, err := io.WriteString(req.Stdout, "first "+fragments[0]+"\n"); err != nil {
					return nil, err
				}
				_, err := io.WriteString(req.Stdout, "second "+fragments[1]+"\n")
				return &sandboxruntime.ExecResult{}, err
			}}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, env map[string]string, _ io.Writer) error {
			if len(env) != 0 {
				t.Fatalf("provider exec env = %#v, want final remote env handled by runtime driver", env)
			}
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	for _, fragment := range fragments {
		if strings.Contains(out.String(), fragment) {
			t.Fatalf("remote output leaked multiline secret fragment %q: %q", fragment, out.String())
		}
	}
	if !strings.Contains(out.String(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("remote output missing redaction marker: %q", out.String())
	}
	for _, event := range events {
		text := fmt.Sprintf("%#v", event)
		for _, fragment := range fragments {
			if strings.Contains(text, fragment) {
				t.Fatalf("remote event leaked multiline secret fragment %q: %#v", fragment, event)
			}
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsResolvedSecretsFromFailureRecords(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 50, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	secret := "ghp_remote_failure_secret_12345"

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-failure-secret",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:   "GITHUB_TOKEN",
			Source: factory.RunSecretSourceEnv,
			Value:  secret,
		}},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if req.Env["GITHUB_TOKEN"] != secret {
					t.Fatalf("GITHUB_TOKEN env = %q, want secret", req.Env["GITHUB_TOKEN"])
				}
				return &sandboxruntime.ExecResult{}, fmt.Errorf("remote failed with token %s", secret)
			}}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, env map[string]string, _ io.Writer) error {
			if len(env) != 0 {
				t.Fatalf("provider exec env = %#v, want final remote env handled by runtime driver", env)
			}
			return nil
		},
	})
	if err == nil {
		t.Fatal("runFactorySandboxExecutorWithDeps() error = nil, want remote failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("returned error leaked secret: %v", err)
	}
	if !strings.Contains(err.Error(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("returned error missing redaction marker: %v", err)
	}

	storedRun, loadErr := store.LoadRun("run-remote-failure-secret")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	runData, err := json.Marshal(storedRun)
	if err != nil {
		t.Fatalf("json.Marshal(run) error: %v", err)
	}
	if strings.Contains(string(runData), secret) {
		t.Fatalf("stored run leaked secret values: %s", string(runData))
	}
	if !strings.Contains(string(runData), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("stored run missing redaction marker: %s", string(runData))
	}

	events, loadErr := store.LoadEvents("run-remote-failure-secret")
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	eventData, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("json.Marshal(events) error: %v", err)
	}
	if strings.Contains(string(eventData), secret) {
		t.Fatalf("stored events leaked secret values: %s", string(eventData))
	}
	if !strings.Contains(string(eventData), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("stored events missing redaction marker: %s", string(eventData))
	}
}

func TestRecordFactorySandboxFailureRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 52, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	credential := "ghp_sandbox_failure_url_12345"
	record := factory.RunRecord{
		RunID:  "run-sandbox-credentialed-failure",
		Status: factory.RunStatusRunning,
	}

	err := recordFactorySandboxFailure(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		saveRun:     saveFactorySandboxRunRecord,
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &record, nil, "provision", fmt.Errorf("provider failed cloning https://x:%s@github.com/example/repo.git", credential), factory.RunSecretRedactor{})
	if err != nil {
		t.Fatalf("recordFactorySandboxFailure() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	for name, value := range map[string]any{"run": loaded, "events": events} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error: %v", name, err)
		}
		payload := string(data)
		if strings.Contains(payload, credential) {
			t.Fatalf("%s leaked credentialed remote: %s", name, payload)
		}
		if !strings.Contains(payload, factory.RunSecretRedactionPlaceholder) {
			t.Fatalf("%s missing redaction marker: %s", name, payload)
		}
	}
}

func TestRecordFactorySandboxFailurePreservesCredentialProxyMetadata(t *testing.T) {
	now := time.Date(2026, 7, 2, 16, 20, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	networkSession := &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     "network-proxy-session-failure",
		Source: sandbox.SandboxNetworkPolicyDecisionSourceFactory,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:      "policy-snapshot-failure",
			Version: "v1",
			Preset:  sandbox.SandboxNetworkPolicyPresetDenyByDefault,
		},
	}
	record := factory.RunRecord{
		RunID:       "run-sandbox-failure-preserves-credential-proxy",
		Status:      factory.RunStatusRunning,
		SandboxName: "factory-ready",
		Sandbox: &factory.SandboxMetadata{
			Name:                "factory-ready",
			Provider:            "daytona",
			Status:              sandbox.StatusRunning,
			NetworkProxySession: networkSession,
			CredentialProxyPlan: &sandbox.SandboxCredentialProxyPlanMetadata{
				ID:                    "credential-plan-failure",
				Source:                sandbox.SandboxCredentialProxySourceFactory,
				NetworkProxySessionID: networkSession.ID,
				Mode:                  sandbox.SandboxCredentialProxyModeNetworkProxyReference,
				Status:                sandbox.SandboxCredentialProxyStatusPlanned,
			},
			CredentialProxySession: &sandbox.SandboxCredentialProxySessionMetadata{
				ID:                    "credential-session-failure",
				PlanID:                "credential-plan-failure",
				Source:                sandbox.SandboxCredentialProxySourceFactory,
				NetworkProxySessionID: networkSession.ID,
				Status:                sandbox.SandboxCredentialProxyStatusReady,
			},
			CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{{
				ID:                  "credential-binding-failure",
				PlanID:              "credential-plan-failure",
				SessionID:           "credential-session-failure",
				SecretID:            "env:GITHUB_TOKEN",
				DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy,
				RequestCategory:     sandbox.SandboxCredentialProxyRequestNetworkAuth,
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
				Outcome:             sandbox.SandboxCredentialProxyBindingOutcomePlanned,
				Status:              sandbox.SandboxCredentialProxyStatusPlanned,
				ReasonCode:          sandbox.SandboxCredentialProxyReasonRequested,
			}},
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	target := &sandbox.SandboxState{
		Name:     "factory-ready",
		Provider: "daytona",
		Size:     "medium",
		Status:   sandbox.StatusRunning,
	}

	err := recordFactorySandboxFailure(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		saveRun:     saveFactorySandboxRunRecord,
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &record, target, "bootstrap", errors.New("bootstrap failed"), factory.RunSecretRedactor{})
	if err != nil {
		t.Fatalf("recordFactorySandboxFailure() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Sandbox == nil {
		t.Fatal("loaded sandbox metadata = nil")
	}
	if loaded.Sandbox.Provider != "daytona" || loaded.Sandbox.Size != "medium" || loaded.Sandbox.Status != sandbox.StatusRunning {
		t.Fatalf("loaded sandbox state fields = %#v, want refreshed target metadata", loaded.Sandbox)
	}
	if loaded.Sandbox.NetworkProxySession == nil || loaded.Sandbox.NetworkProxySession.ID != networkSession.ID {
		t.Fatalf("loaded network proxy session = %#v, want preserved target-ready metadata", loaded.Sandbox.NetworkProxySession)
	}
	if loaded.Sandbox.CredentialProxyPlan == nil || loaded.Sandbox.CredentialProxyPlan.ID != "credential-plan-failure" {
		t.Fatalf("loaded credential proxy plan = %#v, want preserved metadata", loaded.Sandbox.CredentialProxyPlan)
	}
	if loaded.Sandbox.CredentialProxySession == nil || loaded.Sandbox.CredentialProxySession.ID != "credential-session-failure" {
		t.Fatalf("loaded credential proxy session = %#v, want preserved metadata", loaded.Sandbox.CredentialProxySession)
	}
	if len(loaded.Sandbox.CredentialProxyBindings) != 1 || loaded.Sandbox.CredentialProxyBindings[0].ID != "credential-binding-failure" {
		t.Fatalf("loaded credential proxy bindings = %#v, want preserved metadata", loaded.Sandbox.CredentialProxyBindings)
	}
}

func TestRunFactorySandboxExecutorWithDepsCopiesLocalMarkdownBeforeRemoteExecution(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd-feature.md"), []byte("# Feature\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var execArgs [][]string
	var runtimeArgs []string
	record := factory.RunRecord{
		RunID:      "run-copy-markdown",
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
	}
	remoteAuto := factoryRunAutoRequest{
		Args:       []string{".hal/prd-feature.md"},
		BaseBranch: "main",
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   projectDir,
		SandboxName:  "factory-dev",
		RunRecord:    record,
		RemoteAuto:   remoteAuto,
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				runtimeArgs = append([]string(nil), req.Args...)
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(execArgs) != 2 {
		t.Fatalf("copy exec calls = %d, want 2: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], `base64 -d >> "$remote_tmp"`) {
		t.Fatalf("copy exec args = %#v", execArgs[0])
	}
	if !strings.Contains(execArgs[1][2], `mv -f "$remote_tmp" "$remote_file"`) {
		t.Fatalf("finalize exec args = %#v", execArgs[1])
	}
	wantRemote := factorySandboxRemoteCommandArgs(record, remoteAuto)
	if !reflect.DeepEqual(runtimeArgs, wantRemote) {
		t.Fatalf("runtime exec args = %#v, want %#v", runtimeArgs, wantRemote)
	}
}

func TestRunFactorySandboxExecutorWithDepsCopiesAbsoluteReportToRemoteInputPath(t *testing.T) {
	projectDir := t.TempDir()
	reportPath := filepath.Join(projectDir, "analysis.md")
	if err := os.WriteFile(reportPath, []byte("# Analysis\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var execArgs [][]string
	var runtimeArgs []string
	record := factory.RunRecord{
		RunID:      "run-copy-report",
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  projectDir,
		SandboxName: "factory-dev",
		RunRecord:   record,
		RemoteAuto: factoryRunAutoRequest{
			ReportPath: reportPath,
			BaseBranch: "main",
		},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				runtimeArgs = append([]string(nil), req.Args...)
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(execArgs) != 2 {
		t.Fatalf("copy exec calls = %d, want 2: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], `refusing symlink destination: $remote_file`) {
		t.Fatalf("copy exec args = %#v, want no-follow guard", execArgs[0])
	}
	if !strings.Contains(execArgs[0][2], `base64 -d >> "$remote_tmp"`) {
		t.Fatalf("copy exec args = %#v", execArgs[0])
	}
	if !strings.Contains(execArgs[1][2], `mv -f "$remote_tmp" "$remote_file"`) {
		t.Fatalf("finalize exec args = %#v", execArgs[1])
	}
	wantRemote := factorySandboxRemoteCommandArgs(record, factoryRunAutoRequest{
		ReportPath: ".hal/factory-inputs/analysis.md",
		BaseBranch: "main",
	})
	if !reflect.DeepEqual(runtimeArgs, wantRemote) {
		t.Fatalf("runtime exec args = %#v, want %#v", runtimeArgs, wantRemote)
	}
}

func TestFactorySandboxCopyInputToRemoteSplitsLargeInputCommands(t *testing.T) {
	projectDir := t.TempDir()
	inputPath := filepath.Join(projectDir, "large.md")
	if err := os.WriteFile(inputPath, bytes.Repeat([]byte("a"), factorySandboxCopyInputChunkEncodedBytes), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	var execArgs [][]string

	remotePath, changed, err := factorySandboxCopyInputToRemote(context.Background(), projectDir, "large.md", "/workspace/repo", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("factorySandboxCopyInputToRemote() unexpected error: %v", err)
	}
	if !changed || remotePath != "large.md" {
		t.Fatalf("remotePath = %q, changed = %v, want large.md and changed", remotePath, changed)
	}
	if len(execArgs) != 3 {
		t.Fatalf("exec calls = %d, want 3: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], `base64 -d >> "$remote_tmp"`) {
		t.Fatalf("first chunk command = %q, want temp append", execArgs[0][2])
	}
	if !strings.Contains(execArgs[1][2], `base64 -d >> "$remote_tmp"`) {
		t.Fatalf("second chunk command = %q, want temp append", execArgs[1][2])
	}
	if !strings.Contains(execArgs[2][2], `mv -f "$remote_tmp" "$remote_file"`) {
		t.Fatalf("finalize command = %q, want atomic rename", execArgs[2][2])
	}
	for _, args := range execArgs {
		if len(args[2]) > factorySandboxCopyInputChunkEncodedBytes+2048 {
			t.Fatalf("copy command length = %d, want bounded chunk command", len(args[2]))
		}
	}
}

func TestFactorySandboxCopyContentToRemoteRejectsSymlinks(t *testing.T) {
	runScript := func(home string) func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
		return func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, _ io.Writer) error {
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "HOME="+home)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}

	t.Run("workspace symlink parent", func(t *testing.T) {
		root := tempFactorySandboxRemoteRoot(t)
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatalf("Mkdir() error: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
			t.Fatalf("Symlink() error: %v", err)
		}

		err := factorySandboxCopyContentToRemote(context.Background(), []byte("secret"), filepath.Join(root, "linked", "input.md"), "", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
			runProviderScript: runScript(root),
		})
		if err == nil || !strings.Contains(err.Error(), "refusing symlink parent") {
			t.Fatalf("copy error = %v, want symlink parent refusal", err)
		}
	})

	t.Run("workspace symlink destination", func(t *testing.T) {
		root := tempFactorySandboxRemoteRoot(t)
		dir := filepath.Join(root, "inputs")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatalf("Mkdir() error: %v", err)
		}
		if err := os.Symlink(filepath.Join(root, "target"), filepath.Join(dir, "input.md")); err != nil {
			t.Fatalf("Symlink() error: %v", err)
		}

		err := factorySandboxCopyContentToRemote(context.Background(), []byte("secret"), filepath.Join(dir, "input.md"), "", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
			runProviderScript: runScript(root),
		})
		if err == nil || !strings.Contains(err.Error(), "refusing symlink destination") {
			t.Fatalf("copy error = %v, want symlink destination refusal", err)
		}
	})

	t.Run("home symlink parent", func(t *testing.T) {
		home := tempFactorySandboxRemoteRoot(t)
		target := filepath.Join(home, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatalf("Mkdir() error: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(home, ".codex")); err != nil {
			t.Fatalf("Symlink() error: %v", err)
		}

		err := factorySandboxCopyContentToRemoteHome(context.Background(), []byte("secret"), ".codex/auth.json", "0600", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
			runProviderScript: runScript(home),
		})
		if err == nil || !strings.Contains(err.Error(), "refusing symlink parent") {
			t.Fatalf("copy error = %v, want symlink parent refusal", err)
		}
	})

	t.Run("home symlink destination", func(t *testing.T) {
		home := tempFactorySandboxRemoteRoot(t)
		dir := filepath.Join(home, ".codex")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatalf("Mkdir() error: %v", err)
		}
		if err := os.Symlink(filepath.Join(home, "target"), filepath.Join(dir, "auth.json")); err != nil {
			t.Fatalf("Symlink() error: %v", err)
		}

		err := factorySandboxCopyContentToRemoteHome(context.Background(), []byte("secret"), ".codex/auth.json", "0600", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
			runProviderScript: runScript(home),
		})
		if err == nil || !strings.Contains(err.Error(), "refusing symlink destination") {
			t.Fatalf("copy error = %v, want symlink destination refusal", err)
		}
	})
}

func tempFactorySandboxRemoteRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "remote-copy-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs() error: %v", err)
	}
	return abs
}

func TestRunFactorySandboxExecutorWithDepsSyncsEngineAuthBeforeRemoteExecution(t *testing.T) {
	projectDir := t.TempDir()
	authPath := filepath.Join(projectDir, "codex-auth.json")
	if err := os.WriteFile(authPath, []byte(`{"tokens":true}`), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var calls []string

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  projectDir,
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-sync-auth",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
		},
		RemoteAuto:   factoryRunAutoRequest{BaseBranch: "main"},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				calls = append(calls, "remote-auto")
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return []factorySandboxAuthFile{{SourcePath: authPath, RemotePath: ".codex/auth.json"}}
		},
		runProviderScript: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, _ io.Writer) error {
			calls = append(calls, "script:"+script)
			return nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, _ io.Writer) error {
			t.Fatalf("runProviderExecWithEnv should not run final remote command")
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %#v, want auth write, chmod, remote auto", calls)
	}
	if !strings.Contains(calls[0], `remote_file="$remote_home"/'.codex/auth.json'`) {
		t.Fatalf("auth copy call = %q", calls[0])
	}
	if !strings.Contains(calls[0], `base64 -d >> "$remote_tmp"`) {
		t.Fatalf("auth copy call = %q", calls[0])
	}
	if !strings.Contains(calls[1], `chmod '0600' "$remote_tmp"`) || !strings.Contains(calls[1], `mv -f "$remote_tmp" "$remote_file"`) {
		t.Fatalf("auth finalize call = %q", calls[1])
	}
	if calls[2] != "remote-auto" {
		t.Fatalf("final call = %q, want remote auto", calls[2])
	}
}

func TestFactorySandboxEngineAuthFilesDiscoversCodexAndPiFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("PI_HOME", "")
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatalf("MkdirAll(.codex) error: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".pi", "agent"), 0700); err != nil {
		t.Fatalf("MkdirAll(.pi/agent) error: %v", err)
	}
	writeFile(t, filepath.Join(home, ".codex"), "auth.json", "{}")
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", "model = \"gpt-5\"\n")
	writeFile(t, filepath.Join(home, ".pi", "agent"), "auth.json", "{}")
	writeFile(t, filepath.Join(home, ".pi", "agent"), "settings.json", "{}")
	writeFile(t, filepath.Join(home, ".pi", "agent"), "trust.json", "{}")

	files := factorySandboxEngineAuthFiles()
	got := make(map[string]string, len(files))
	for _, file := range files {
		got[file.RemotePath] = file.SourcePath
	}
	want := map[string]string{
		".codex/auth.json":        filepath.Join(home, ".codex", "auth.json"),
		".codex/config.toml":      filepath.Join(home, ".codex", "config.toml"),
		".pi/agent/auth.json":     filepath.Join(home, ".pi", "agent", "auth.json"),
		".pi/agent/settings.json": filepath.Join(home, ".pi", "agent", "settings.json"),
		".pi/agent/trust.json":    filepath.Join(home, ".pi", "agent", "trust.json"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auth files = %#v, want %#v", got, want)
	}
}

func TestFactorySandboxBootstrapCommandArgsRunsHalFromRemoteHome(t *testing.T) {
	args := factorySandboxBootstrapCommandArgs(factory.BootstrapCommand{
		Name: "hal",
		Args: []string{"init", "--refresh-templates"},
		Dir:  "/workspace/hal",
	})
	if len(args) != 3 || args[0] != "sh" || args[1] != "-c" {
		t.Fatalf("bootstrap args = %#v, want shell wrapper", args)
	}
	script := args[2]
	for _, want := range []string{
		"cd '/workspace/hal'",
		`remote_home="${HOME:-}"`,
		`exec "$HOME/.local/bin/hal" 'init' '--refresh-templates'`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("bootstrap script = %q, want %q", script, want)
		}
	}
}

func TestFactorySandboxRemoteAutoArgsBuildsDeterministicHalAutoCommand(t *testing.T) {
	withAutoArgs := func(args ...string) []string {
		return append([]string{"auto"}, args...)
	}

	tests := []struct {
		name string
		req  factoryRunAutoRequest
		want []string
	}{
		{
			name: "auto discovery",
			req:  factoryRunAutoRequest{},
			want: withAutoArgs(),
		},
		{
			name: "markdown with base",
			req: factoryRunAutoRequest{
				Args:       []string{" .hal/prd-feature.md "},
				BaseBranch: " main ",
			},
			want: withAutoArgs(".hal/prd-feature.md", "--base", "main"),
		},
		{
			name: "report with base",
			req: factoryRunAutoRequest{
				ReportPath: " .hal/reports/analysis.md ",
				BaseBranch: " develop ",
			},
			want: withAutoArgs("--report", ".hal/reports/analysis.md", "--base", "develop"),
		},
		{
			name: "engine",
			req: factoryRunAutoRequest{
				Engine: " Claude ",
			},
			want: withAutoArgs("--engine", "claude"),
		},
		{
			name: "empty args are omitted",
			req: factoryRunAutoRequest{
				Args: []string{"", "  ", ".hal/prd-feature.md"},
			},
			want: withAutoArgs(".hal/prd-feature.md"),
		},
		{
			name: "attempt policy env",
			req: factoryRunAutoRequest{
				BaseBranch: "main",
				AttemptPolicy: autoFactoryAttemptPolicy{
					MaxRunAttempts:       1,
					MaxReviewFixAttempts: 2,
					MaxCIFixAttempts:     3,
				},
			},
			want: withAutoArgs("--base", "main"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := factorySandboxRemoteAutoArgs(tt.req); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("factorySandboxRemoteAutoArgs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestFactorySandboxRemoteCommandArgsSelectsWorkspaceDirectory(t *testing.T) {
	record := factory.RunRecord{
		RepoRemote: "git@github.com:jywlabs/hal.git",
	}
	got := factorySandboxRemoteCommandArgs(record, factoryRunAutoRequest{
		Args:       []string{" .hal/prd-feature.md "},
		BaseBranch: " hal/factory-remote-workspace-bootstrap ",
	})
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)

	wantScript := strings.Join([]string{
		"set -eu",
		"cd " + shellQuote(workspaceDir),
		"set -eu",
		`remote_home="${HOME:-}"`,
		`if [ -z "$remote_home" ] && command -v getent >/dev/null 2>&1; then`,
		`  remote_home="$(getent passwd "$(id -u)" | cut -d: -f6)"`,
		`fi`,
		`if [ -z "$remote_home" ]; then remote_home="$(pwd)"; fi`,
		`export HOME="$remote_home"`,
		"export HAL_FACTORY_MAX_RUN_ATTEMPTS=0",
		"export HAL_FACTORY_MAX_REVIEW_FIX_ATTEMPTS=0",
		"export HAL_FACTORY_MAX_CI_FIX_ATTEMPTS=0",
		`exec "$HOME/.local/bin/hal" 'auto' '.hal/prd-feature.md' '--base' 'hal/factory-remote-workspace-bootstrap'`,
	}, "\n")
	want := []string{"sh", "-c", wantScript}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("factorySandboxRemoteCommandArgs() = %#v, want %#v", got, want)
	}
}

func TestFactorySandboxRemoteCommandArgsResumeDoesNotReplaySourceInputs(t *testing.T) {
	record := factory.RunRecord{
		RepoRemote: "git@github.com:jywlabs/hal.git",
	}
	got := factorySandboxRemoteCommandArgs(record, factoryRunAutoRequest{
		Resume:     true,
		Args:       []string{".hal/prd-feature.md"},
		ReportPath: ".hal/reports/analysis.md",
		BaseBranch: "develop",
		Engine:     "codex",
		SkipCI:     true,
	})
	commandMetadata := strings.Join(got, " ")
	for _, forbidden := range []string{".hal/prd-feature.md", ".hal/reports/analysis.md", "--base"} {
		if strings.Contains(commandMetadata, forbidden) {
			t.Fatalf("resume command replayed %q: %q", forbidden, commandMetadata)
		}
	}
	for _, want := range []string{"'auto' '--resume'", "'--engine' 'codex'", "'--no-ci'"} {
		if !strings.Contains(commandMetadata, want) {
			t.Fatalf("resume command missing %q: %q", want, commandMetadata)
		}
	}
}

func TestFactorySandboxRemoteAutoEnvIncludesRuntimeStatePolicy(t *testing.T) {
	got := factorySandboxRemoteAutoEnv(factoryRunAutoRequest{
		RuntimeStatePolicy: "checkpoint_factory_state",
	})
	found := false
	for _, entry := range got {
		if entry == "HAL_FACTORY_RUNTIME_STATE_POLICY='checkpoint_factory_state'" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("factorySandboxRemoteAutoEnv() = %#v, want runtime state policy env", got)
	}
}

func TestRunFactorySandboxRuntimeExecWithRetriesUsesResumeWhenAutoStateExists(t *testing.T) {
	transientErr := errors.New("transient remote failure")
	var commands [][]string
	driver := fakeFactorySandboxRuntimeDriver{
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			commands = append(commands, append([]string(nil), req.Args...))
			joined := strings.Join(req.Args, " ")
			switch len(commands) {
			case 1:
				return &sandboxruntime.ExecResult{}, transientErr
			case 2:
				if !strings.Contains(joined, "test -f .hal/auto-state.json") {
					t.Fatalf("second command = %#v, want auto-state probe", req.Args)
				}
				return &sandboxruntime.ExecResult{}, nil
			case 3:
				if !strings.Contains(joined, "'auto' '--resume'") {
					t.Fatalf("third command = %#v, want resume auto command", req.Args)
				}
				return &sandboxruntime.ExecResult{}, nil
			default:
				t.Fatalf("unexpected exec command %d: %#v", len(commands), req.Args)
				return &sandboxruntime.ExecResult{}, nil
			}
		},
	}
	err := runFactorySandboxRuntimeExecWithRetries(context.Background(), sandboxexec.RunContext{
		Driver: driver,
		Target: sandboxruntime.Target{Name: "dev"},
	}, sandboxexec.CommandRequest{
		Command: []string{"sh", "-c", "hal auto .hal/prd-feature.md"},
		WorkDir: "/root/workspace/repo",
	}, factory.RunRecord{RepoPath: "/root/workspace/repo"}, factoryRunAutoRequest{
		Args:              []string{".hal/prd-feature.md"},
		MaxCommandRetries: 2,
	}, nil)
	if err != nil {
		t.Fatalf("runFactorySandboxRuntimeExecWithRetries() unexpected error: %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("exec commands = %d, want 3: %#v", len(commands), commands)
	}
}

func TestRepositoryNameFromRemoteStripsCredentialedURLParts(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "https query access token",
			remote: "https://github.com/example/repo.git?access_token=secret-value",
			want:   "repo",
		},
		{
			name:   "https query client secret with slash",
			remote: "https://user:pass@github.com/example/repo.git?client_secret=secret/value",
			want:   "repo",
		},
		{
			name:   "https fragment secret",
			remote: "https://github.com/example/repo.git#client_secret=secret-value",
			want:   "repo",
		},
		{
			name:   "scp ssh remote",
			remote: "git@github.com:example/repo.git",
			want:   "repo",
		},
		{
			name:   "scp query access token",
			remote: "git@github.com:example/repo.git?access_token=secret-value",
			want:   "repo",
		},
		{
			name:   "ssh url remote",
			remote: "ssh://git@github.com/example/repo.git",
			want:   "repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := repositoryNameFromRemote(tt.remote); got != tt.want {
				t.Fatalf("repositoryNameFromRemote(%q) = %q, want %q", tt.remote, got, tt.want)
			}
		})
	}
}

func TestFactorySandboxRemoteCommandArgsMetadataOmitsCredentialedRemoteQuery(t *testing.T) {
	record := factory.RunRecord{
		RepoRemote: "https://github.com/example/repo.git?access_token=secret-value&client_secret=other-secret",
	}
	got := factorySandboxRemoteCommandArgs(record, factoryRunAutoRequest{
		Args: []string{".hal/prd-feature.md"},
	})

	commandMetadata := strings.Join(got, " ")
	if strings.Contains(commandMetadata, "secret") || strings.Contains(commandMetadata, "access_token") || strings.Contains(commandMetadata, "client_secret") {
		t.Fatalf("remote command metadata contains credentialed remote data: %q", commandMetadata)
	}
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if !strings.HasPrefix(workspaceDir, factorySandboxRemoteWorkspaceRoot+"/repo-") {
		t.Fatalf("workspace dir = %q, want hashed repo workspace", workspaceDir)
	}
	if !strings.Contains(commandMetadata, "cd "+shellQuote(workspaceDir)) {
		t.Fatalf("remote command metadata = %q, want workspace %s", commandMetadata, workspaceDir)
	}
}

func TestFactorySandboxRemoteWorkspaceDirIncludesRemoteIdentity(t *testing.T) {
	first := factorySandboxRemoteWorkspaceDir(factory.RunRecord{RepoRemote: "git@github.com:example/repo.git"})
	second := factorySandboxRemoteWorkspaceDir(factory.RunRecord{RepoRemote: "git@github.com:other/repo.git"})
	if first == second {
		t.Fatalf("workspace dirs should differ for remotes with the same basename: %q", first)
	}
	if !strings.HasPrefix(first, factorySandboxRemoteWorkspaceRoot+"/repo-") || !strings.HasPrefix(second, factorySandboxRemoteWorkspaceRoot+"/repo-") {
		t.Fatalf("workspace dirs = %q and %q, want repo basename plus identity hash", first, second)
	}
}

func TestRunFactorySandboxExecutorWithDepsRequiresRemoteWorkspaceBeforeExecution(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 45, 0, 0, time.UTC)
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord
	loadCalled := false
	provisionCalled := false
	resolveProviderCalled := false
	execCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-local",
		RunRecord: factory.RunRecord{
			RunID:       "run-missing-workspace",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoPath:    "/Users/v/work/hal",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			loadCalled = true
			return nil, fs.ErrNotExist
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			resolveProviderCalled = true
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			execCalled = true
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	wantErr := "prepare factory sandbox inputs: sandbox workspace directory is required; configure remote.origin.url or run from a remote workspace checkout"
	if err == nil || err.Error() != wantErr {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want %q", err, wantErr)
	}
	if loadCalled || provisionCalled || resolveProviderCalled {
		t.Fatalf("sandbox lifecycle should not run without a workspace directory: load=%t provision=%t resolveProvider=%t", loadCalled, provisionCalled, resolveProviderCalled)
	}
	if execCalled {
		t.Fatalf("remote execution should not run without a workspace directory")
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "prepare_inputs" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.Failure == nil || failed.Failure.Message != strings.TrimPrefix(wantErr, "prepare factory sandbox inputs: ") {
		t.Fatalf("failure summary = %#v", failed.Failure)
	}
	if len(events) != 1 || events[0].Metadata["step"] != "prepare_inputs" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxProviderExecWithEnvUsesStdinScriptWithoutArgSecrets(t *testing.T) {
	secret := "ghp_provider_exec_secret_12345"
	provider := &capturingFactorySandboxProvider{
		cmd: exec.Command("sh", "-c", "cat"),
	}

	var out bytes.Buffer
	err := runFactorySandboxProviderExecWithEnv(context.Background(), provider, &sandbox.ConnectInfo{Name: "factory-dev"}, []string{"sh", "-c", "cd '/workspace/repo' && exec 'hal' 'auto'"}, map[string]string{
		"GITHUB_TOKEN": secret,
		"EMPTY_TOKEN":  "",
	}, &out)
	if err != nil {
		t.Fatalf("runFactorySandboxProviderExecWithEnv() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(provider.args, []string{"sh", "-s"}) {
		t.Fatalf("provider args = %#v, want shell stdin execution", provider.args)
	}
	if strings.Contains(strings.Join(provider.args, " "), secret) {
		t.Fatalf("provider args leaked secret value: %#v", provider.args)
	}
	script := out.String()
	if !strings.Contains(script, "export GITHUB_TOKEN='"+secret+"'") {
		t.Fatalf("stdin script did not export secret env assignment: %q", script)
	}
	if strings.Contains(script, "EMPTY_TOKEN") {
		t.Fatalf("stdin script included empty secret assignment: %q", script)
	}
	if strings.Contains(script, "exec 'env'") {
		t.Fatalf("stdin script used env argv assignment wrapper: %q", script)
	}
	if !strings.Contains(script, "exec 'sh' '-c'") {
		t.Fatalf("stdin script did not exec remote command: %q", script)
	}
}

func TestRunFactorySandboxProviderExecWithEnvUsesStdinForDaytona(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script to stand in for the daytona CLI")
	}
	secret := "daytona_provider_exec_secret_12345"
	binDir := t.TempDir()
	argFile := filepath.Join(t.TempDir(), "args.txt")
	daytonaPath := filepath.Join(binDir, "daytona")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DAYTONA_ARG_FILE\"\ncat\n"
	if err := os.WriteFile(daytonaPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake daytona: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DAYTONA_ARG_FILE", argFile)

	provider := &sandbox.DaytonaProvider{APIKey: "test-key"}
	var out bytes.Buffer
	err := runFactorySandboxProviderExecWithEnv(context.Background(), provider, &sandbox.ConnectInfo{Name: "factory-dev"}, []string{"sh", "-c", "cd '/workspace/repo' && exec 'hal' 'auto'"}, map[string]string{
		"GITHUB_TOKEN": secret,
	}, &out)
	if err != nil {
		t.Fatalf("runFactorySandboxProviderExecWithEnv() unexpected error: %v", err)
	}
	args, err := os.ReadFile(argFile)
	if err != nil {
		t.Fatalf("read fake daytona args: %v", err)
	}
	if strings.Contains(string(args), secret) {
		t.Fatalf("daytona command args leaked secret value: %q", string(args))
	}
	if !strings.Contains(string(args), "'sh' '-s'") {
		t.Fatalf("daytona command args = %q, want stdin shell execution", string(args))
	}
	if !strings.Contains(out.String(), "export GITHUB_TOKEN='"+secret+"'") {
		t.Fatalf("stdin script did not export secret env assignment: %q", out.String())
	}
}

func TestRunFactorySandboxProviderExecWithEnvUsesStdinScriptWithoutEnv(t *testing.T) {
	provider := &capturingFactorySandboxProvider{
		cmd: exec.Command("sh", "-c", "cat"),
	}

	var out bytes.Buffer
	err := runFactorySandboxProviderExecWithEnv(context.Background(), provider, &sandbox.ConnectInfo{Name: "factory-dev"}, []string{"git", "fetch", "--prune", "origin"}, nil, &out)
	if err != nil {
		t.Fatalf("runFactorySandboxProviderExecWithEnv() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(provider.args, []string{"sh", "-s"}) {
		t.Fatalf("provider args = %#v, want shell stdin execution", provider.args)
	}
	script := out.String()
	if !strings.Contains(script, "exec 'git' 'fetch' '--prune' 'origin'") {
		t.Fatalf("stdin script did not exec command args: %q", script)
	}
}

func TestRunFactorySandboxProviderScriptUsesStdin(t *testing.T) {
	provider := &capturingFactorySandboxProvider{
		cmd: exec.Command("sh", "-c", "cat"),
	}

	var out bytes.Buffer
	err := runFactorySandboxProviderScript(context.Background(), provider, &sandbox.ConnectInfo{Name: "factory-dev"}, "printf %s ok > /tmp/probe\n", &out)
	if err != nil {
		t.Fatalf("runFactorySandboxProviderScript() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(provider.args, []string{"sh", "-s"}) {
		t.Fatalf("provider args = %#v, want shell stdin execution", provider.args)
	}
	if got := out.String(); got != "printf %s ok > /tmp/probe\n" {
		t.Fatalf("stdin script = %q", got)
	}
}

func TestRunFactorySandboxProviderExecShellQuotesRemoteArgs(t *testing.T) {
	provider := &capturingFactorySandboxProvider{
		cmd: exec.Command("true"),
	}

	err := runFactorySandboxProviderExec(context.Background(), provider, &sandbox.ConnectInfo{Name: "factory-dev"}, []string{"sh", "-c", "cd '/workspace/hal' && exec hal auto"}, io.Discard)
	if err != nil {
		t.Fatalf("runFactorySandboxProviderExec() unexpected error: %v", err)
	}
	want := []string{"sh", "-c", "'sh' '-c' 'cd '\"'\"'/workspace/hal'\"'\"' && exec hal auto'"}
	if !reflect.DeepEqual(provider.args, want) {
		t.Fatalf("provider args = %#v, want %#v", provider.args, want)
	}
}

func TestFactorySandboxBootstrapExecutorReportsRemoteExitCode(t *testing.T) {
	provider := &capturingFactorySandboxProvider{
		cmd: exec.Command("sh", "-c", "exit 7"),
	}
	executor := &factorySandboxBootstrapExecutor{
		provider:               provider,
		connectInfo:            &sandbox.ConnectInfo{Name: "factory-dev"},
		runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	}

	result, err := executor.Run(context.Background(), factory.BootstrapCommand{
		Name: "git",
		Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/missing"},
	})
	if err == nil {
		t.Fatal("Run() error = nil, want remote exit error")
	}
	if result.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", result.ExitCode)
	}
}

func TestFactorySandboxBootstrapExecutorReportsUnknownFailureExitCode(t *testing.T) {
	executor := &factorySandboxBootstrapExecutor{
		provider:    fakeFactorySandboxProvider{},
		connectInfo: &sandbox.ConnectInfo{Name: "factory-dev"},
		runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
			return fmt.Errorf("transport unavailable")
		},
	}

	result, err := executor.Run(context.Background(), factory.BootstrapCommand{
		Name: "git",
		Args: []string{"fetch", "origin"},
	})
	if err == nil {
		t.Fatal("Run() error = nil, want transport error")
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1", result.ExitCode)
	}
}

func TestFactorySandboxRemoteRepoExistsUsesRemoteExitCodes(t *testing.T) {
	exitError := func(code int) error {
		return exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	}

	tests := []struct {
		name      string
		err       error
		want      bool
		wantError string
	}{
		{name: "git checkout exists", want: true},
		{name: "missing or empty path", err: exitError(10), want: false},
		{name: "non git non empty path", err: exitError(11), wantError: "repository path exists but is not a git checkout and is not empty"},
		{name: "transport style exit one stays fatal", err: exitError(1), wantError: "exit status 1"},
		{name: "unexpected remote error", err: exitError(127), wantError: "exit status 127"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotScript string
			got, err := factorySandboxRemoteRepoExists(context.Background(), fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, out io.Writer) error {
				gotScript = script
				if tt.err == nil {
					_, _ = io.WriteString(out, "git@github.com:jywlabs/hal.git\n")
				}
				return tt.err
			}, "/workspace/hal", "https://github.com/jywlabs/hal.git")
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("factorySandboxRemoteRepoExists() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("exists = %v, want %v", got, tt.want)
			}
			if !strings.Contains(gotScript, "[ -e '/workspace/hal/.git' ]") {
				t.Fatalf("remote repo check script = %q", gotScript)
			}
		})
	}
}

func TestFactorySandboxRemoteRepoExistsRejectsMismatchedOrigin(t *testing.T) {
	got, err := factorySandboxRemoteRepoExists(context.Background(), fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ string, out io.Writer) error {
		_, _ = io.WriteString(out, "git@github.com:other/hal.git\n")
		return nil
	}, "/workspace/hal", "git@github.com:jywlabs/hal.git")
	if err == nil || !strings.Contains(err.Error(), "existing checkout origin does not match requested repository") {
		t.Fatalf("error = %v, want origin mismatch", err)
	}
	if got {
		t.Fatal("exists = true, want false for mismatched origin")
	}
}

func TestFactorySandboxEnvExecScriptRejectsInvalidEnvNames(t *testing.T) {
	_, err := factorySandboxEnvExecScript([]string{"hal", "auto"}, map[string]string{
		"BAD-NAME": "secret",
	})
	if err == nil {
		t.Fatal("factorySandboxEnvExecScript() error = nil, want invalid name error")
	}
	if !strings.Contains(err.Error(), `invalid sandbox environment variable name "BAD-NAME"`) {
		t.Fatalf("factorySandboxEnvExecScript() error = %v", err)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsSanitizedRemoteOutputEvents(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-remote",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName:  "factory-remote",
		RunRecord:    factory.RunRecord{RunID: "run-remote-output", Status: factory.RunStatusRunning, RepoRemote: "git@github.com:example/repo.git"},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if _, err := io.WriteString(req.Stdout, "Step: run\nconnecting to 203.0."); err != nil {
					return nil, err
				}
				_, err := io.WriteString(req.Stdout, "113.42\n")
				return &sandboxruntime.ExecResult{}, err
			}}, nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(out.String(), "203.0.113.42") {
		t.Fatalf("remote output writer leaked address: %q", out.String())
	}
	if !strings.Contains(out.String(), "<address redacted>") {
		t.Fatalf("remote output writer missing redaction marker: %q", out.String())
	}
	if len(events) != 5 {
		t.Fatalf("events = %d, want 5: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeLegacyAuthSync})
	started, firstLine, secondLine, completed := events[1], events[2], events[3], events[4]
	if started.EventType != factory.EventTypeStepStarted || started.Summary != "Remote sandbox execution started" {
		t.Fatalf("start event = %#v", started)
	}
	if started.Metadata["source"] != "remote_sandbox" || started.Metadata["status"] != factory.RunStatusRunning || started.Metadata["step"] != factory.RunDurationStepEngineRun {
		t.Fatalf("start event metadata = %#v", started.Metadata)
	}
	if firstLine.EventType != factory.EventTypeCommandOutputSummary || secondLine.EventType != factory.EventTypeCommandOutputSummary {
		t.Fatalf("remote event types = %q/%q, want command output summaries", firstLine.EventType, secondLine.EventType)
	}
	if firstLine.Message != "Step: run" {
		t.Fatalf("first remote message = %q", firstLine.Message)
	}
	if strings.Contains(secondLine.Message, "203.0.113.42") {
		t.Fatalf("second remote message leaked address: %q", secondLine.Message)
	}
	if !strings.Contains(secondLine.Message, "<address redacted>") {
		t.Fatalf("second remote message missing redaction marker: %q", secondLine.Message)
	}
	if secondLine.Metadata["source"] != "remote_sandbox" || secondLine.Metadata["stream"] != "remote" {
		t.Fatalf("second remote metadata = %#v", secondLine.Metadata)
	}
	if secondLine.Metadata["sandboxName"] != "factory-remote" || secondLine.Metadata["provider"] != "daytona" {
		t.Fatalf("second remote target metadata = %#v", secondLine.Metadata)
	}
	if completed.EventType != factory.EventTypeStepEnded || completed.Summary != "Remote sandbox execution completed" {
		t.Fatalf("completion event = %#v", completed)
	}
	if completed.Metadata["source"] != "remote_sandbox" || completed.Metadata["status"] != factory.RunStatusSucceeded || completed.Metadata["step"] != factory.RunDurationStepEngineRun {
		t.Fatalf("completion event metadata = %#v", completed.Metadata)
	}
	durations := factory.DeriveRunStepDurations(events)
	if len(durations) != 1 || durations[0].Step != factory.RunDurationStepEngineRun {
		t.Fatalf("derived step durations = %#v, want one engine_run duration", durations)
	}
}

func TestRunFactorySandboxExecutorWithDepsPersistsOnlyRemoteCommandOutputSummaries(t *testing.T) {
	now := time.Date(2026, 7, 1, 20, 10, 0, 0, time.UTC)
	projectDir := t.TempDir()
	inputPath := filepath.Join(projectDir, "story.md")
	if err := os.WriteFile(inputPath, []byte("# Story\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	authPath := filepath.Join(projectDir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-remote-clean-output",
		Provider: "daytona",
		Status:   sandbox.StatusStopped,
	}

	var out bytes.Buffer
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   projectDir,
		SandboxName:  target.Name,
		RemoteOutput: &out,
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-command-only-output",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
			RepoPath:   projectDir,
		},
		RemoteAuto: factoryRunAutoRequest{Args: []string{inputPath}},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{
				startFn: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					_, _ = io.WriteString(req.Stdout, "local setup stdout\n")
					_, _ = io.WriteString(req.Stderr, "local setup stderr\n")
					started := req.Target
					started.Status = sandbox.StatusRunning
					return &started, nil
				},
				execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					_, _ = io.WriteString(req.Stdout, "remote stdout line\n")
					_, _ = io.WriteString(req.Stderr, "remote stderr line\n")
					return &sandboxruntime.ExecResult{}, nil
				},
			}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return []factorySandboxAuthFile{{SourcePath: authPath, RemotePath: ".codex/auth.json"}}
		},
		runProviderScript: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, out io.Writer) error {
			switch {
			case strings.Contains(script, ".codex/auth.json"):
				_, _ = io.WriteString(out, "auth prep output\n")
			case strings.Contains(script, "story.md"):
				_, _ = io.WriteString(out, "copy prep output\n")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
	}
	for _, want := range []string{"local setup stdout", "local setup stderr", "auth prep output", "copy prep output", "remote stdout line", "remote stderr line"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want visible %q", out.String(), want)
		}
	}

	events, err := store.LoadEvents("run-remote-command-only-output")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	var summaryMessages []string
	for _, event := range events {
		if event.EventType != factory.EventTypeCommandOutputSummary {
			continue
		}
		if event.Metadata["source"] != factory.LogSourceRemoteSandbox {
			t.Fatalf("summary event source = %#v, want %q", event.Metadata["source"], factory.LogSourceRemoteSandbox)
		}
		summaryMessages = append(summaryMessages, event.Message)
	}
	wantMessages := []string{"remote stdout line", "remote stderr line"}
	if !reflect.DeepEqual(summaryMessages, wantMessages) {
		t.Fatalf("summary messages = %#v, want %#v", summaryMessages, wantMessages)
	}
	for _, disallowed := range []string{"local setup", "auth prep", "copy prep"} {
		if strings.Contains(strings.Join(summaryMessages, "\n"), disallowed) {
			t.Fatalf("summary messages included preparation output %q: %#v", disallowed, summaryMessages)
		}
	}

	chunks, err := store.LoadLogChunks("run-remote-command-only-output")
	if err != nil {
		t.Fatalf("LoadLogChunks() error: %v", err)
	}
	if len(chunks) != len(wantMessages) {
		t.Fatalf("log chunks = %d, want %d: %#v", len(chunks), len(wantMessages), chunks)
	}
	for i, chunk := range chunks {
		if chunk.Source != factory.LogSourceRemoteSandbox {
			t.Fatalf("log chunk %d source = %q, want %q", i, chunk.Source, factory.LogSourceRemoteSandbox)
		}
		if chunk.Text != wantMessages[i] {
			t.Fatalf("log chunk %d text = %q, want %q", i, chunk.Text, wantMessages[i])
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsRedactsResolvedSecretsFromExecutorEvents(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 20, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{Name: "factory-remote", Provider: "daytona", Status: sandbox.StatusRunning}
	secret := "ghp_remote_command_secret_12345"

	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-remote",
		RunRecord: factory.RunRecord{
			RunID:      "run-remote-command-secret",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Value:    secret,
		}},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "release-" + secret},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want policy/start/end events: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync})
	eventData, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("json.Marshal(events) error: %v", err)
	}
	if strings.Contains(string(eventData), secret) {
		t.Fatalf("executor events leaked resolved secret: %s", string(eventData))
	}
	if !strings.Contains(string(eventData), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("executor events missing redaction marker: %s", string(eventData))
	}
}

func TestRunFactorySandboxExecutorWithDepsCanProvisionAndStartWithFakes(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	secret := "ghp_provision_repo_secret_12345"
	rawRemote := "https://x:" + secret + "@github.com/example/repo.git"
	redactedRemote := "https://" + factory.RunSecretRedactionPlaceholder + "@github.com/example/repo.git"
	provisioned := &sandbox.SandboxState{
		Name:     "factory-new",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
	}

	var provisionReq factorySandboxProvisionRequest
	startCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  "/repo",
		SandboxName: "factory-new",
		RunRecord: factory.RunRecord{
			RunID:      "run-provision",
			RepoRemote: rawRemote,
		},
		ResolvedSecrets: []factory.ResolvedRunSecret{{
			Name:  "GITHUB_TOKEN",
			Value: secret,
		}},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-new" {
				t.Fatalf("load sandbox name = %q, want factory-new", name)
			}
			return nil, errFactorySandboxNotExist
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionReq = req
			return provisioned, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{
				startFn: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					startCalled = true
					if req.Target.Name != "factory-new" || req.Target.Status != sandbox.StatusStopped {
						t.Fatalf("start target = %#v, want stopped factory-new runtime target", req.Target)
					}
					started := target
					started.Status = sandbox.StatusRunning
					return &started, nil
				},
			}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if provisionReq.ProjectDir != "/repo" || provisionReq.Name != "factory-new" || provisionReq.Repo != redactedRemote {
		t.Fatalf("provision request = %#v", provisionReq)
	}
	if strings.Contains(provisionReq.Repo, secret) {
		t.Fatalf("provision repo label leaked secret: %q", provisionReq.Repo)
	}
	if provisionReq.BranchName != "" {
		t.Fatalf("provision branchName = %q, want empty", provisionReq.BranchName)
	}
	if !startCalled {
		t.Fatalf("runtime driver Start was not called for stopped provisioned target")
	}
}

func TestRunFactorySandboxExecutorWithDepsReturnsExplicitLoadFailure(t *testing.T) {
	loadErr := factorySandboxTestError("read sandbox \"factory-broken\": parse failed")
	provisionCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-broken",
		RunRecord:   factory.RunRecord{RunID: "run-load-failure", RepoRemote: "git@github.com:example/repo.git"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return nil, loadErr
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil || err.Error() != "load factory sandbox \"factory-broken\": read sandbox \"factory-broken\": parse failed" {
		t.Fatalf("error = %v", err)
	}
	if provisionCalled {
		t.Fatalf("provision should not be called for non-not-exist load failures")
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesDefaultResolutionWithoutExplicitTarget(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "factory-only",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	resolved := false
	var savedRecords []factory.RunRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		RunRecord: factory.RunRecord{RunID: "run-default", RepoRemote: "git@github.com:example/repo.git"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatalf("loadSandbox should not be called without explicit sandbox target")
			return nil, nil
		},
		resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			resolved = true
			if !filter(target) {
				t.Fatalf("running sandbox filter rejected running target")
			}
			return target, "connecting to only active sandbox \"factory-only\"", nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !resolved {
		t.Fatalf("resolveDefault was not called")
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	if savedRecords[1].SandboxName != "factory-only" {
		t.Fatalf("saved sandboxName = %q, want factory-only", savedRecords[1].SandboxName)
	}
	if savedRecords[1].Sandbox == nil || savedRecords[1].Sandbox.Provider != "daytona" {
		t.Fatalf("saved sandbox metadata = %#v", savedRecords[1].Sandbox)
	}
}

func TestRunFactorySandboxExecutorWithDepsProvisionsWhenDefaultResolutionHasNoUsableTarget(t *testing.T) {
	resolveErr := errNoFactorySandbox
	provisioned := &sandbox.SandboxState{
		Name:     "hal-feature",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	var provisionReq factorySandboxProvisionRequest
	var savedRecords []factory.RunRecord
	loadCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: "/repo",
		RunRecord: factory.RunRecord{
			RunID:      "run-no-default",
			BranchName: "hal/feature",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			loadCalled = true
			if name != "hal-feature" {
				t.Fatalf("loadSandbox name = %q, want hal-feature", name)
			}
			return nil, errFactorySandboxNotExist
		},
		resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			if !filter(&sandbox.SandboxState{Status: sandbox.StatusRunning}) {
				t.Fatalf("running sandbox filter rejected running target")
			}
			if filter(&sandbox.SandboxState{Status: sandbox.StatusStopped}) {
				t.Fatalf("running sandbox filter accepted stopped target")
			}
			return nil, "", resolveErr
		},
		provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionReq = req
			return provisioned, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !loadCalled {
		t.Fatalf("loadSandbox was not called for derived sandbox name")
	}
	if provisionReq.Name != "hal-feature" || provisionReq.BranchName != "hal/feature" || provisionReq.ProjectDir != "/repo" || provisionReq.Repo != "git@github.com:example/repo.git" {
		t.Fatalf("provision request = %#v", provisionReq)
	}
	if len(savedRecords) < 2 || savedRecords[1].SandboxName != "hal-feature" {
		t.Fatalf("saved records = %#v", savedRecords)
	}
}

func TestRunFactorySandboxExecutorWithDepsStartsStoppedDerivedDefaultBeforeProvisioning(t *testing.T) {
	stopped := &sandbox.SandboxState{
		Name:     "hal-feature",
		Provider: "daytona",
		Status:   sandbox.StatusStopped,
	}
	provisionCalled := false
	startCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: "/repo",
		RunRecord: factory.RunRecord{
			RunID:      "run-stopped-default",
			BranchName: "hal/feature",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return nil, "", errNoFactorySandbox
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "hal-feature" {
				t.Fatalf("loadSandbox name = %q, want hal-feature", name)
			}
			return stopped, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{
				startFn: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					startCalled = true
					if req.Target.Name != "hal-feature" || req.Target.Status != sandbox.StatusStopped {
						t.Fatalf("start target = %#v, want stopped hal-feature runtime target", req.Target)
					}
					started := target
					started.Status = sandbox.StatusRunning
					return &started, nil
				},
			}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if provisionCalled {
		t.Fatalf("provision should not be called when derived stopped sandbox exists")
	}
	if !startCalled {
		t.Fatalf("runtime driver Start was not called for stopped default sandbox")
	}
}

func TestRunFactorySandboxExecutorWithDepsReturnsAmbiguousDefaultResolutionError(t *testing.T) {
	resolveErr := factorySandboxTestError("multiple sandboxes found: one, two")
	provisionCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		RunRecord: factory.RunRecord{
			RunID:      "run-ambiguous-default",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return nil, "", resolveErr
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want %q", resolveErr)
	}
	if err.Error() != resolveErr.Error() {
		t.Fatalf("error = %q, want %q", err.Error(), resolveErr.Error())
	}
	if provisionCalled {
		t.Fatalf("provision should not be called when default resolution is ambiguous")
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsProvisionFailure(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
	provisionErr := factorySandboxTestError("provider quota exceeded")
	store := factory.NewStore(t.TempDir())
	if err := store.AppendEvent(&factory.EventRecord{
		Sequence:  7,
		RunID:     "run-provision-failure",
		EventType: factory.EventTypeStepStarted,
		Timestamp: now.Add(-time.Minute),
		Summary:   "Existing event",
	}); err != nil {
		t.Fatalf("AppendEvent() error: %v", err)
	}
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  "/repo",
		SandboxName: "factory-new",
		RunRecord: factory.RunRecord{
			RunID:       "run-provision-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			BranchName:  "hal/factory-sandbox-executor",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return nil, errFactorySandboxNotExist
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			return nil, provisionErr
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil || err.Error() != "provision factory sandbox: provider quota exceeded" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "provision" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-new" || failed.Sandbox == nil || failed.Sandbox.Handoff != "Inspect sandbox with `hal sandbox ssh factory-new`." {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Failure == nil || failed.Failure.Category != factory.FailureCategorySandbox || failed.Failure.Message != provisionErr.Error() {
		t.Fatalf("failed failure summary = %#v", failed.Failure)
	}
	if len(events) != 1 || events[0].Sequence != 8 || events[0].EventType != factory.EventTypeFailureClassification || events[0].Metadata["step"] != "provision" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsStartFailureWithSandboxMetadataAndAlwaysCleanup(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 45, 0, 0, time.UTC)
	startErr := factorySandboxTestError("start failed")
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorAlways
	target := &sandbox.SandboxState{
		Name:     "factory-stopped",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
	}
	var savedRecords []factory.RunRecord
	var cleanupCalls int

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-stopped",
		RunRecord: factory.RunRecord{
			RunID:       "run-start-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
			Policy:      &policy,
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			if providerName != "hetzner" {
				t.Fatalf("providerName = %q, want hetzner", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{
				startFn: func(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					return nil, startErr
				},
			}, nil
		},
		cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
			cleanupCalls++
			if req.Target == nil || req.Target.Name != "factory-stopped" {
				t.Fatalf("cleanup target = %#v, want factory-stopped", req.Target)
			}
			if req.Provider == nil {
				t.Fatalf("cleanup provider = nil")
			}
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil || err.Error() != "start factory sandbox \"factory-stopped\": start failed" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 3 {
		t.Fatalf("saved records = %d, want 3", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "start" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-stopped" || failed.Sandbox == nil || failed.Sandbox.Provider != "hetzner" || failed.Sandbox.Status != sandbox.StatusStopped {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Sandbox.SSHCommand != "hal sandbox ssh factory-stopped" {
		t.Fatalf("ssh command = %q", failed.Sandbox.SSHCommand)
	}
	cleaned := savedRecords[2]
	if cleaned.SandboxName != "factory-stopped" || cleaned.Sandbox == nil || cleaned.Sandbox.Provider != "hetzner" || cleaned.Sandbox.Status != sandbox.StatusUnknown {
		t.Fatalf("cleaned sandbox metadata = %#v", cleaned.Sandbox)
	}
	if cleaned.Sandbox.SSHCommand != "" || cleaned.Sandbox.CleanupCommand != "" || cleaned.Sandbox.Handoff != "" {
		t.Fatalf("cleaned sandbox commands not cleared: %#v", cleaned.Sandbox)
	}
	if cleaned.Failure == nil || cleaned.Failure.SuggestedCommand != factoryRunInspectCommand("run-start-failure") {
		t.Fatalf("cleaned failure suggested command = %#v", cleaned.Failure)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsResolveDriverFailureHandoff(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	providerErr := factorySandboxTestError("unknown provider missing")
	target := &sandbox.SandboxState{
		Name:     "factory-provider",
		Provider: "missing",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-provider",
		RunRecord: factory.RunRecord{
			RunID:       "run-provider-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			if providerName != "missing" {
				t.Fatalf("providerName = %q, want missing", providerName)
			}
			return nil, providerErr
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			t.Fatalf("runProviderExec should not run when provider resolution fails")
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil || err.Error() != "resolve sandbox provider \"missing\": unknown provider missing" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 3 {
		t.Fatalf("saved records = %d, want 3", len(savedRecords))
	}
	failed := savedRecords[2]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "resolve_driver" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-provider" || failed.Sandbox == nil || failed.Sandbox.Provider != "missing" {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Failure == nil || failed.Failure.Message != providerErr.Error() || failed.Failure.SuggestedCommand != "hal sandbox ssh factory-provider" {
		t.Fatalf("failed failure summary = %#v", failed.Failure)
	}
	if len(events) != 2 {
		t.Fatalf("failure events = %#v", events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeLegacyAuthSync})
	if events[1].EventType != factory.EventTypeFailureClassification || events[1].Metadata["step"] != "resolve_driver" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsRemoteExecutionFailureHandoff(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 15, 0, 0, time.UTC)
	execErr := factorySandboxTestError("remote pipeline failed on 203.0.113.42")
	target := &sandbox.SandboxState{
		Name:     "factory-failed",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}
	var out bytes.Buffer
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName:  "factory-failed",
		RunRecord:    factory.RunRecord{RunID: "run-remote-failure", Status: factory.RunStatusRunning, CurrentStep: "run", RepoRemote: "git@github.com:example/repo.git"},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if _, err := io.WriteString(req.Stdout, "remote stderr mentions 203.0.113.42\n"); err != nil {
					return nil, err
				}
				return &sandboxruntime.ExecResult{}, execErr
			}}, nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want remote failure")
	}
	if strings.Contains(err.Error(), "203.0.113.42") {
		t.Fatalf("returned error leaked address: %v", err)
	}
	if !strings.Contains(err.Error(), "<address redacted>") {
		t.Fatalf("returned error missing redaction marker: %v", err)
	}
	if len(savedRecords) != 3 {
		t.Fatalf("saved records = %d, want 3", len(savedRecords))
	}
	failed := savedRecords[2]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "run" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-failed" || failed.Sandbox == nil || failed.Sandbox.Provider != "daytona" {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Sandbox.Connection == nil || failed.Sandbox.Connection.PublicIP != "203.0.113.42" {
		t.Fatalf("failed sandbox connection = %#v", failed.Sandbox.Connection)
	}
	if failed.Failure == nil {
		t.Fatalf("failed failure summary = nil")
	}
	if failed.Failure.SuggestedCommand != "hal sandbox ssh factory-failed" {
		t.Fatalf("suggested command = %q", failed.Failure.SuggestedCommand)
	}
	if strings.Contains(failed.Failure.Message, "203.0.113.42") {
		t.Fatalf("failure message leaked address: %q", failed.Failure.Message)
	}
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4: %#v", len(events), events)
	}
	requireFactorySandboxSecurityPolicyEvent(t, events[0], []string{sandbox.SandboxSecretModeLegacyAuthSync})
	if events[2].EventType != factory.EventTypeCommandOutputSummary || strings.Contains(events[2].Message, "203.0.113.42") {
		t.Fatalf("remote output event was not sanitized: %#v", events[2])
	}
	if events[3].EventType != factory.EventTypeFailureClassification || events[3].Metadata["source"] != "remote_sandbox" {
		t.Fatalf("failure event = %#v", events[3])
	}
	if strings.Contains(events[3].Message, "203.0.113.42") {
		t.Fatalf("failure event leaked address: %q", events[3].Message)
	}
}

func TestRunFactorySandboxExecutorWithDepsGeneratesRecoveryOnRunFailure(t *testing.T) {
	now := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	execErr := factorySandboxTestError("remote pipeline failed")
	target := &sandbox.SandboxState{
		Name:     "factory-recovery-failed",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var recoveryCalls int
	var recoveryReq factorySandboxRecoveryArtifactRequest
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-recovery-failed",
		RunRecord: factory.RunRecord{
			RunID:       "run-recovery-on-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
			BaseBranch:  "main",
		},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				return &sandboxruntime.ExecResult{}, execErr
			}}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		generateRecovery: func(_ context.Context, req factorySandboxRecoveryArtifactRequest) error {
			recoveryCalls++
			recoveryReq = req
			return nil
		},
	})
	if err == nil || err.Error() != "execute factory sandbox command: remote pipeline failed" {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want original run failure", err)
	}
	if recoveryCalls != 1 {
		t.Fatalf("generateRecovery calls = %d, want 1", recoveryCalls)
	}
	if recoveryReq.Record.RunID != "run-recovery-on-failure" || recoveryReq.Record.BaseBranch != "main" {
		t.Fatalf("recovery record = %#v", recoveryReq.Record)
	}
	if recoveryReq.Target == nil || recoveryReq.Target.Name != "factory-recovery-failed" {
		t.Fatalf("recovery target = %#v, want factory-recovery-failed", recoveryReq.Target)
	}
	if recoveryReq.Provider == nil {
		t.Fatalf("recovery provider = nil, want resolved provider")
	}
}

func TestRunFactorySandboxExecutorWithDepsKeepsRunFailureWhenRecoveryGenerationFails(t *testing.T) {
	now := time.Date(2026, 7, 8, 9, 15, 0, 0, time.UTC)
	execErr := factorySandboxTestError("remote command failed")
	recoveryErr := errors.New("recovery artifact generation failed")
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-recovery-warning",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-recovery-warning",
		RunRecord: factory.RunRecord{
			RunID:       "run-recovery-warning",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				return &sandboxruntime.ExecResult{}, execErr
			}}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		generateRecovery: func(context.Context, factorySandboxRecoveryArtifactRequest) error {
			return recoveryErr
		},
	})
	if err == nil || err.Error() != "execute factory sandbox command: remote command failed" {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want original run failure", err)
	}
	if strings.Contains(err.Error(), recoveryErr.Error()) {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error included recovery failure: %v", err)
	}
	events, err := store.LoadEvents("run-recovery-warning")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	var warning *factory.EventRecord
	for i := range events {
		if events[i].EventType == factory.EventTypeArtifactSync {
			warning = &events[i]
			break
		}
	}
	if warning == nil {
		t.Fatalf("artifact sync warning not recorded: %#v", events)
	}
	if warning.Summary != "Sandbox recovery artifact generation skipped" || warning.Metadata["status"] != "warning" || warning.Metadata["reason"] != "recovery_generation_failed" {
		t.Fatalf("artifact sync warning = %#v", warning)
	}
}

func TestFactorySandboxRecoveryArtifactScriptIncludesRichRecoveryFiles(t *testing.T) {
	script := factorySandboxRecoveryArtifactScript("/workspace/repo", "main")
	for _, want := range []string{
		"git rev-parse HEAD > .hal/recovery/head.txt",
		"git branch --show-current > .hal/recovery/branch.txt",
		"git format-patch --stdout",
		".hal/recovery/git-format-patch.patch",
		"git bundle create .hal/recovery/git-bundle.bundle",
		"git status --short --branch > .hal/recovery/status.txt",
		"git log --oneline --decorate -20 > .hal/recovery/log.txt",
		"git diff --binary --no-ext-diff > .hal/recovery/dirty.patch",
		"git diff --cached --binary --no-ext-diff > .hal/recovery/staged.patch",
		".hal/auto-state.json .hal/prd.json .hal/progress.txt",
		".hal/recovery/manifest.json",
		"\"baseBranch\"",
		"\"createdAt\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("recovery script missing %q:\n%s", want, script)
		}
	}
}

func requireFactorySandboxSecurityMetadata(t *testing.T, security *factory.SandboxSecurityMetadata, wantActiveModes []string) {
	t.Helper()
	if security == nil {
		t.Fatal("sandbox security metadata = nil")
	}
	if security.Network == nil {
		t.Fatal("sandbox network security metadata = nil")
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want %q", security.Network.PolicyRequested, sandbox.SandboxNetworkPolicyDenyByDefault)
	}
	if security.Network.PolicyEnforced == sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyEnforced = %q, compatibility path must not claim deny-by-default", security.Network.PolicyEnforced)
	}
	if security.Network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyEnforced = %q, want %q", security.Network.PolicyEnforced, sandbox.SandboxNetworkPolicyBestEffort)
	}
	if security.Network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want %q", security.Network.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if security.Secrets == nil {
		t.Fatal("sandbox secret security metadata = nil")
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("requested secret modes = %#v, want http_proxy", security.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, wantActiveModes) {
		t.Fatalf("active secret modes = %#v, want %#v", security.Secrets.ActiveModes, wantActiveModes)
	}
}

func requireFactorySandboxSecurityPolicyEvent(t *testing.T, event factory.EventRecord, wantActiveModes []string) {
	t.Helper()
	if event.EventType != factory.EventTypePolicyDecision {
		t.Fatalf("policy event type = %q, want %q: %#v", event.EventType, factory.EventTypePolicyDecision, event)
	}
	if event.Summary != "Sandbox security policy evaluated" {
		t.Fatalf("policy event summary = %q", event.Summary)
	}
	if event.Metadata["policyField"] != "sandbox.security" {
		t.Fatalf("policy event field = %#v", event.Metadata)
	}
	if event.Metadata["decision"] != factory.PolicyDecisionAllowedExecution || event.Metadata["outcome"] != factory.PolicyOutcomeAllowed {
		t.Fatalf("policy event decision/outcome = %#v", event.Metadata)
	}
	security, ok := event.Metadata["security"].(map[string]any)
	if !ok {
		t.Fatalf("policy event security metadata = %#v", event.Metadata["security"])
	}
	network, ok := security["network"].(map[string]any)
	if !ok {
		t.Fatalf("policy event network metadata = %#v", security["network"])
	}
	if network["policyRequested"] != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policy event requested network = %#v", network)
	}
	if network["policyEnforced"] == sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policy event overclaimed enforcement = %#v", network)
	}
	if network["policyEnforced"] != sandbox.SandboxNetworkPolicyBestEffort || network["enforcementMode"] != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("policy event network metadata = %#v", network)
	}
	secrets, ok := security["secrets"].(map[string]any)
	if !ok {
		t.Fatalf("policy event secret metadata = %#v", security["secrets"])
	}
	if !reflect.DeepEqual(secrets["requestedModes"], []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("policy event requested modes = %#v", secrets["requestedModes"])
	}
	if !reflect.DeepEqual(secrets["activeModes"], wantActiveModes) {
		t.Fatalf("policy event active modes = %#v, want %#v", secrets["activeModes"], wantActiveModes)
	}
}

func requireFactorySandboxConfiguredSecurityMetadata(t *testing.T, security *factory.SandboxSecurityMetadata) {
	t.Helper()
	if security == nil {
		t.Fatal("sandbox security metadata = nil")
	}
	if security.Network == nil || security.Network.PolicyResult == nil {
		t.Fatalf("sandbox network security metadata = %#v, want policy result", security.Network)
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want deny_by_default compatibility label", security.Network.PolicyRequested)
	}
	if security.Network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyEnforced = %q, want best_effort", security.Network.PolicyEnforced)
	}
	if security.Network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want none", security.Network.EnforcementMode)
	}
	if security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("policyResult.requested.preset = %q, want allow_listed", security.Network.PolicyResult.Requested.Preset)
	}
	if security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("policyResult.effective.preset = %q, want legacy_default", security.Network.PolicyResult.Effective.Preset)
	}
	if len(security.Network.PolicyResult.Warnings) == 0 {
		t.Fatal("policyResult.warnings = empty, want unsupported enforcement warning")
	}
	if security.Secrets == nil {
		t.Fatal("sandbox secret security metadata = nil")
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeFileTmpfs}) {
		t.Fatalf("requested secret modes = %#v, want configured modes", security.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("active secret modes = %#v, want env plus legacy auth sync", security.Secrets.ActiveModes)
	}
}

func requireFactorySandboxConfiguredSecurityPolicyEvent(t *testing.T, event factory.EventRecord) {
	t.Helper()
	if event.EventType != factory.EventTypePolicyDecision {
		t.Fatalf("policy event type = %q, want %q: %#v", event.EventType, factory.EventTypePolicyDecision, event)
	}
	security, ok := event.Metadata["security"].(map[string]any)
	if !ok {
		t.Fatalf("policy event security metadata = %#v", event.Metadata["security"])
	}
	network, ok := security["network"].(map[string]any)
	if !ok {
		t.Fatalf("policy event network metadata = %#v", security["network"])
	}
	requireFactorySandboxPolicyEventRequestedPreset(t, network["policyResult"], sandbox.SandboxNetworkPolicyPresetAllowListed)
	secrets, ok := security["secrets"].(map[string]any)
	if !ok {
		t.Fatalf("policy event secret metadata = %#v", security["secrets"])
	}
	if !reflect.DeepEqual(factorySandboxPolicyEventStringSlice(secrets["requestedModes"]), []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeFileTmpfs}) {
		t.Fatalf("policy event requested modes = %#v", secrets["requestedModes"])
	}
	if !reflect.DeepEqual(factorySandboxPolicyEventStringSlice(secrets["activeModes"]), []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("policy event active modes = %#v", secrets["activeModes"])
	}
}

func requireFactorySandboxPolicyEventRequestedPreset(t *testing.T, value any, want sandbox.SandboxNetworkPolicyPreset) {
	t.Helper()
	switch result := value.(type) {
	case *sandbox.SandboxNetworkPolicyResult:
		if result == nil || result.Requested.Preset != want {
			t.Fatalf("policy event requested preset = %#v, want %q", result, want)
		}
	case map[string]any:
		requested, ok := result["requested"].(map[string]any)
		if !ok {
			t.Fatalf("policy event requested result = %#v", result["requested"])
		}
		if requested["preset"] != string(want) {
			t.Fatalf("policy event requested preset = %#v, want %q", requested["preset"], want)
		}
	default:
		t.Fatalf("policy event result metadata = %#v", value)
	}
}

func factorySandboxPolicyEventStringSlice(value any) []string {
	switch modes := value.(type) {
	case []string:
		return append([]string(nil), modes...)
	case []any:
		out := make([]string, 0, len(modes))
		for _, mode := range modes {
			if text, ok := mode.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func assertFactorySandboxCredentialProxyPayloadExcludes(t *testing.T, label string, payload string, forbiddenValues ...string) {
	t.Helper()
	for _, forbidden := range forbiddenValues {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked forbidden value %q: %s", label, forbidden, payload)
		}
	}
}

type factorySandboxTestError string

func (e factorySandboxTestError) Error() string { return string(e) }

const errNoFactorySandbox = factorySandboxTestError("no running sandboxes")

var errFactorySandboxNotExist = factorySandboxNotExistError("sandbox does not exist")

type factorySandboxNotExistError string

func (e factorySandboxNotExistError) Error() string { return string(e) }
func (e factorySandboxNotExistError) Unwrap() error { return fs.ErrNotExist }

type fakeFactorySandboxProvider struct{}

func (fakeFactorySandboxProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (fakeFactorySandboxProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return exec.Command("true"), nil
}

type fakeFactorySandboxRuntimeDriver struct {
	id      string
	startFn func(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error)
	execFn  func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
}

func (d fakeFactorySandboxRuntimeDriver) ID() string {
	if d.id != "" {
		return d.id
	}
	return sandboxruntime.DriverSSHMachine
}

func (d fakeFactorySandboxRuntimeDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (d fakeFactorySandboxRuntimeDriver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	if d.startFn != nil {
		return d.startFn(ctx, req)
	}
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (d fakeFactorySandboxRuntimeDriver) Stop(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (d fakeFactorySandboxRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (d fakeFactorySandboxRuntimeDriver) Inspect(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (d fakeFactorySandboxRuntimeDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	if d.execFn != nil {
		return d.execFn(ctx, req)
	}
	return &sandboxruntime.ExecResult{}, nil
}

func (d fakeFactorySandboxRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (d fakeFactorySandboxRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (fakeFactorySandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

type capturingFactorySandboxProvider struct {
	args []string
	cmd  *exec.Cmd
}

func (p *capturingFactorySandboxProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (p *capturingFactorySandboxProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (p *capturingFactorySandboxProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (p *capturingFactorySandboxProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (p *capturingFactorySandboxProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (p *capturingFactorySandboxProvider) Exec(_ *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	p.args = append([]string(nil), args...)
	return p.cmd, nil
}

func (p *capturingFactorySandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}
