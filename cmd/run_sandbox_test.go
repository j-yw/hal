package cmd

import (
	"bytes"
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
	"github.com/spf13/cobra"
)

func TestParseRunSandboxRequestArgumentContract(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		opts            runSandboxOptions
		wantIterations  int
		wantSandboxName string
		wantHostID      string
		wantRuntime     string
		wantErr         string
	}{
		{
			name:           "no args uses default iterations",
			wantIterations: 10,
		},
		{
			name:           "numeric positional means iterations",
			args:           []string{"3"},
			wantIterations: 3,
		},
		{
			name:            "non-numeric positional means sandbox name",
			args:            []string{"dev-box"},
			wantIterations:  10,
			wantSandboxName: "dev-box",
		},
		{
			name: "sandbox-name flag sets sandbox name",
			opts: runSandboxOptions{
				SandboxName:        "named-box",
				SandboxNameChanged: true,
			},
			wantIterations:  10,
			wantSandboxName: "named-box",
		},
		{
			name: "positional name conflicts with sandbox-name flag",
			args: []string{"dev-box"},
			opts: runSandboxOptions{
				SandboxName:        "named-box",
				SandboxNameChanged: true,
			},
			wantErr: "sandbox name provided both positionally and via --sandbox-name",
		},
		{
			name: "target-selection flags set cached intent",
			opts: runSandboxOptions{
				SandboxHostID:         "worker-1",
				SandboxHostChanged:    true,
				SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
				SandboxRuntimeChanged: true,
			},
			wantIterations: 10,
			wantHostID:     "worker-1",
			wantRuntime:    sandboxruntime.DriverRootlessPodman,
		},
		{
			name: "empty sandbox-host is rejected",
			opts: runSandboxOptions{
				SandboxHostChanged: true,
			},
			wantErr: "--sandbox-host must not be empty",
		},
		{
			name: "empty sandbox-runtime is rejected",
			opts: runSandboxOptions{
				SandboxRuntimeChanged: true,
			},
			wantErr: "--sandbox-runtime must not be empty",
		},
		{
			name: "unknown sandbox-runtime is rejected",
			opts: runSandboxOptions{
				SandboxRuntime:        "worker_only",
				SandboxRuntimeChanged: true,
			},
			wantErr: "--sandbox-runtime must be one of ssh_machine, rootless_podman, or microvm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRunSandboxRequest(tt.args, tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("parseRunSandboxRequest() error = nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseRunSandboxRequest() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRunSandboxRequest() unexpected error: %v", err)
			}
			if got.Iterations != tt.wantIterations {
				t.Fatalf("Iterations = %d, want %d", got.Iterations, tt.wantIterations)
			}
			if got.SandboxName != tt.wantSandboxName {
				t.Fatalf("SandboxName = %q, want %q", got.SandboxName, tt.wantSandboxName)
			}
			if got.SandboxHostID != tt.wantHostID {
				t.Fatalf("SandboxHostID = %q, want %q", got.SandboxHostID, tt.wantHostID)
			}
			if got.SandboxRuntime != tt.wantRuntime {
				t.Fatalf("SandboxRuntime = %q, want %q", got.SandboxRuntime, tt.wantRuntime)
			}
		})
	}
}

func TestBuildRunSandboxRemoteCommandPreservesRunFlags(t *testing.T) {
	req, err := parseRunSandboxRequest([]string{"7"}, runSandboxOptions{
		Engine:                "codex",
		EngineChanged:         true,
		Base:                  "main",
		BaseChanged:           true,
		JSON:                  true,
		JSONChanged:           true,
		SandboxName:           "local-box",
		SandboxNameChanged:    true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	})
	if err != nil {
		t.Fatalf("parseRunSandboxRequest() unexpected error: %v", err)
	}

	want := []string{"hal", "run", "--json", "--engine", "codex", "--base", "main", "7"}
	if !reflect.DeepEqual(req.RemoteCommand, want) {
		t.Fatalf("RemoteCommand = %#v, want %#v", req.RemoteCommand, want)
	}

	joined := strings.Join(req.RemoteCommand, " ")
	for _, disallowed := range []string{"--sandbox", "--sandbox-name", "local-box", "--sandbox-host", "worker-1", "--sandbox-runtime", sandboxruntime.DriverRootlessPodman, "--" + sandboxSyncOutFlagName, "--" + sandboxApplyFlagName} {
		if strings.Contains(joined, disallowed) {
			t.Fatalf("RemoteCommand %q should not contain sandbox-only value %q", joined, disallowed)
		}
	}
}

func TestRunSandboxDepsUseRuntimeDriverForRemoteExecution(t *testing.T) {
	depsType := reflect.TypeOf(runSandboxDeps{})
	if _, ok := depsType.FieldByName("runProviderCommand"); ok {
		t.Fatal("runSandboxDeps exposes direct provider command execution; use runtime-driver execution")
	}
	field, ok := depsType.FieldByName("resolveRuntimeDriver")
	if !ok {
		t.Fatal("runSandboxDeps missing resolveRuntimeDriver")
	}
	want := reflect.TypeOf((func(sandboxruntime.Target) (sandboxruntime.Driver, error))(nil))
	if field.Type != want {
		t.Fatalf("resolveRuntimeDriver type = %v, want %v", field.Type, want)
	}
}

func TestRunSandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata(t *testing.T) {
	deps := normalizeRunSandboxDeps(runSandboxDeps{
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

func TestRunSandboxDefaultRuntimeDriverResolverKeepsSSHMachineForAbsentOrExplicitSSHMetadata(t *testing.T) {
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
			deps := normalizeRunSandboxDeps(runSandboxDeps{
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

func TestRunSandboxSecurityRequestKeepsLegacyDefaultsWithoutConfig(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 4, 10, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-security-defaults"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/security-defaults", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, _ runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			captured = req
			running, err := store.LoadManifest("run-security-defaults")
			if err != nil {
				t.Fatalf("LoadManifest() before execute: %v", err)
			}
			requireRunSandboxLegacySecurityManifest(t, running.Security)
			return runSandboxExecutionResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	if captured.Security.RuntimeDriver != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("RuntimeDriver = %q, want %q", captured.Security.RuntimeDriver, sandbox.SandboxRuntimeDriverSSHMachine)
	}
	if captured.Security.RequestedNetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("RequestedNetworkPolicy = %q, want %q", captured.Security.RequestedNetworkPolicy, sandbox.SandboxNetworkPolicyDenyByDefault)
	}
	if captured.Security.RequestedNetworkPolicyIntent != nil {
		t.Fatalf("RequestedNetworkPolicyIntent = %#v, want nil without config", captured.Security.RequestedNetworkPolicyIntent)
	}
	if !reflect.DeepEqual(captured.Security.RequestedSecretModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("RequestedSecretModes = %#v, want legacy http_proxy", captured.Security.RequestedSecretModes)
	}
	if len(captured.Security.ActiveSecretModes) != 0 {
		t.Fatalf("ActiveSecretModes = %#v, want no configured active modes", captured.Security.ActiveSecretModes)
	}
	if !captured.Security.CompatibilityAuthSync {
		t.Fatal("CompatibilityAuthSync = false, want legacy auth sync preserved")
	}

	manifest, err := store.LoadManifest("run-security-defaults")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	requireRunSandboxLegacySecurityManifest(t, manifest.Security)
}

func TestRunSandboxSecurityRequestLoadsLocalSandboxConfig(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 4, 12, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  env:
    RAW_SECRET: "ghp_config_secret_should_not_persist"
    SOCKET_PATH: "unix:///tmp/private/worker.sock"
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: api.example.com
        decision: allow
      - kind: metadata_endpoint
        value: "169.254.169.254"
        decision: deny
  secrets:
    requestedModes:
      - env
      - file_tmpfs
    activeModes:
      - env
`)
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-security-config"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/security-config", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, _ runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			captured = req
			running, err := store.LoadManifest("run-security-config")
			if err != nil {
				t.Fatalf("LoadManifest() before execute: %v", err)
			}
			requireRunSandboxConfiguredSecurityManifest(t, running.Security)
			return runSandboxExecutionResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	if captured.Security.RequestedNetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("RequestedNetworkPolicy = %q, want restrictive compatibility label", captured.Security.RequestedNetworkPolicy)
	}
	if captured.Security.RequestedNetworkPolicyIntent == nil {
		t.Fatal("RequestedNetworkPolicyIntent = nil, want config policy")
	}
	if captured.Security.RequestedNetworkPolicyIntent.Preset != sandbox.SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("RequestedNetworkPolicyIntent.Preset = %q, want allow_listed", captured.Security.RequestedNetworkPolicyIntent.Preset)
	}
	wantRules := []sandbox.SandboxNetworkPolicyRule{
		{Kind: sandbox.SandboxNetworkPolicyRuleKindDomain, Value: "api.example.com", Decision: sandbox.SandboxNetworkPolicyDecisionAllow},
		{Kind: sandbox.SandboxNetworkPolicyRuleKindMetadataEndpoint, Value: "169.254.169.254", Decision: sandbox.SandboxNetworkPolicyDecisionDeny},
	}
	if !reflect.DeepEqual(captured.Security.RequestedNetworkPolicyIntent.Rules, wantRules) {
		t.Fatalf("RequestedNetworkPolicyIntent.Rules = %#v, want %#v", captured.Security.RequestedNetworkPolicyIntent.Rules, wantRules)
	}
	if !reflect.DeepEqual(captured.Security.RequestedSecretModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeFileTmpfs}) {
		t.Fatalf("RequestedSecretModes = %#v, want configured modes", captured.Security.RequestedSecretModes)
	}
	if !reflect.DeepEqual(captured.Security.ActiveSecretModes, []string{sandbox.SandboxSecretModeEnv}) {
		t.Fatalf("ActiveSecretModes = %#v, want configured active modes", captured.Security.ActiveSecretModes)
	}
	if !captured.Security.CompatibilityAuthSync {
		t.Fatal("CompatibilityAuthSync = false, want compatibility auth sync preserved")
	}

	manifest, err := store.LoadManifest("run-security-config")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	requireRunSandboxConfiguredSecurityManifest(t, manifest.Security)
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	for _, forbidden := range []string{"ghp_config_secret_should_not_persist", "unix://", "/tmp/private/worker.sock", "https://token@", "/Users/private"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest security metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRunSandboxManifestUsesConfiguredSecurityIntentAndRedactsUnsafeValues(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  env:
    TOKEN: "ghp_manifest_secret_should_not_persist"
    LOCAL_PATH: "/Users/private/.ssh/id_ed25519"
  networkPolicy:
    preset: disabled
  secrets:
    requestedModes:
      - ssh_agent
    activeModes:
      - ssh_agent
`)
	store := sandboxexecution.NewStore(t.TempDir())
	startedAt := time.Date(2026, 7, 2, 4, 13, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-security-manifest"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/security-manifest", nil },
		execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			return runSandboxExecutionResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	manifest, err := store.LoadManifest("run-security-manifest")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Security == nil || manifest.Security.Network == nil || manifest.Security.Network.PolicyResult == nil {
		t.Fatalf("Security = %#v, want policy result", manifest.Security)
	}
	if manifest.Security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("PolicyRequested = %q, want best_effort compatibility label for disabled policy", manifest.Security.Network.PolicyRequested)
	}
	if manifest.Security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.requested.preset = %q, want disabled", manifest.Security.Network.PolicyResult.Requested.Preset)
	}
	if manifest.Security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.effective.preset = %q, want disabled", manifest.Security.Network.PolicyResult.Effective.Preset)
	}
	if manifest.Security.Secrets == nil || !reflect.DeepEqual(manifest.Security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeSSHAgent}) {
		t.Fatalf("secret metadata = %#v, want configured ssh_agent request", manifest.Security.Secrets)
	}
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	for _, forbidden := range []string{"ghp_manifest_secret_should_not_persist", "/Users/private", "credential", "token=", "provider"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest security metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestParseRunSandboxRequestRejectsEmptyExplicitEngine(t *testing.T) {
	_, err := parseRunSandboxRequest(nil, runSandboxOptions{
		EngineChanged: true,
		Engine:        " ",
	})
	if err == nil {
		t.Fatal("parseRunSandboxRequest() error = nil")
	}
	if !strings.Contains(err.Error(), "--engine must not be empty") {
		t.Fatalf("error = %q, want empty engine validation", err.Error())
	}
}

func TestRunWithWriterRejectsSandboxTargetFlagsWithoutSandbox(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := newRunSandboxTestCommand(&out, &errOut)
	if err := cmd.Flags().Set(sandboxRuntimeFlagName, sandboxruntime.DriverRootlessPodman); err != nil {
		t.Fatalf("set sandbox-runtime: %v", err)
	}

	err := runRunWithWriter(cmd, nil, &errOut)
	if err == nil {
		t.Fatal("runRunWithWriter() error = nil, want sandbox target flag validation")
	}
	if !strings.Contains(err.Error(), "--sandbox-runtime requires --sandbox") {
		t.Fatalf("error = %q, want sandbox-runtime require sandbox", err.Error())
	}
}

func TestRunSandboxResolveTargetRejectsExplicitRuntimeBeforeDefaultFallback(t *testing.T) {
	defaultCalled := false
	provisionCalled := false
	deps := runSandboxDeps{
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

	_, err := deps.resolveRunSandboxTarget(context.Background(), runSandboxRequest{
		SandboxRuntime: sandbox.SandboxRuntimeDriverMicroVM,
		ProjectDir:     "/workspace/hal",
		RepoRemote:     "git@example.com:org/repo.git",
		RunBranch:      "feature/microvm",
	}, io.Discard)
	if err == nil {
		t.Fatal("resolveRunSandboxTarget() error = nil, want explicit runtime failure")
	}
	if !strings.Contains(err.Error(), `no durable host supports requested runtime "microvm"`) {
		t.Fatalf("error = %q, want microvm unsupported failure", err.Error())
	}
	if defaultCalled || provisionCalled {
		t.Fatalf("defaultCalled=%v provisionCalled=%v, want no legacy fallback", defaultCalled, provisionCalled)
	}
}

func TestRunSandboxResolveTargetUsesSelectedRuntimeMetadata(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "worker-a",
			Name: "worker a",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "ctr-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	deps := runSandboxDeps{
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "podman-dev" {
				t.Fatalf("loadSandbox name = %q, want podman-dev", name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:                "worker-a",
				Name:              "worker a",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			}}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit sandbox")
			return nil, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for an existing selected sandbox")
			return nil, nil
		},
	}

	got, err := deps.resolveRunSandboxTarget(context.Background(), runSandboxRequest{
		SandboxName:    "podman-dev",
		SandboxRuntime: sandbox.SandboxRuntimeDriverRootlessPodman,
		ProjectDir:     "/workspace/hal",
		RepoRemote:     "git@example.com:org/repo.git",
		RunBranch:      "feature/rootless",
	}, io.Discard)
	if err != nil {
		t.Fatalf("resolveRunSandboxTarget() unexpected error: %v", err)
	}
	if got != target || got.Runtime == nil || got.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("target = %#v, want selected rootless runtime metadata", got)
	}
}

func TestRunRunSandboxWithWriterJSONPreRemotePreflightFailures(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)

	tests := []struct {
		name          string
		repoRemote    func(string) (string, error)
		currentBranch func(string) (string, error)
		wantError     string
	}{
		{
			name: "missing repository remote",
			repoRemote: func(string) (string, error) {
				return "", nil
			},
			currentBranch: func(string) (string, error) {
				t.Fatal("currentBranch should not run when repository remote is missing")
				return "", nil
			},
			wantError: "remote.origin.url is required for sandbox execution",
		},
		{
			name: "missing base branch",
			repoRemote: func(string) (string, error) {
				return "git@example.com:org/repo.git", nil
			},
			currentBranch: func(string) (string, error) {
				return "", nil
			},
			wantError: "current branch is required for sandbox execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			now := runSandboxTestClock(startedAt, finishedAt)
			var out bytes.Buffer
			var errOut bytes.Buffer
			executeCalled := false

			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				JSON:        true,
				JSONChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "run-json-preflight"
				},
				now:           now,
				workingDir:    func() (string, error) { return t.TempDir(), nil },
				repoRemote:    tt.repoRemote,
				currentBranch: tt.currentBranch,
				execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					executeCalled = true
					return runSandboxExecutionResult{}, errors.New("execute should not run")
				},
			})
			requireRenderedJSONExitCode(t, err, ExitCodeValidation)
			if executeCalled {
				t.Fatal("execute should not be called for pre-remote preflight failure")
			}

			var result RunResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
			}
			if result.ContractVersion != 1 || result.OK {
				t.Fatalf("RunResult = %#v, want contractVersion 1 and ok false", result)
			}
			if !strings.Contains(result.Error, tt.wantError) {
				t.Fatalf("RunResult.Error = %q, want %q", result.Error, tt.wantError)
			}
			if strings.TrimSpace(errOut.String()) != "" {
				t.Fatalf("stderr = %q, want empty for JSON preflight failure", errOut.String())
			}

			manifest, err := store.LoadManifest("run-json-preflight")
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if manifest.Purpose != sandboxexecution.PurposeRun {
				t.Fatalf("Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeRun)
			}
			if manifest.Status != sandboxexecution.StatusFailed {
				t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusFailed)
			}
			if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
				t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
			}
		})
	}
}

func TestRunRunSandboxWithWriterWorkspacePlannerPreflightFailures(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 15, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)

	tests := []struct {
		name          string
		status        sandboxworkspace.GitStatus
		wantError     string
		wantWorkspace *sandbox.SandboxWorkspace
	}{
		{
			name: "dirty clone workspace",
			status: sandboxworkspace.GitStatus{
				IsGitWorktree: true,
				Repository:    "git@example.com:org/repo.git",
				Branch:        "feature/dirty",
				Dirty:         sandboxworkspace.DirtyState{Unstaged: true},
			},
			wantError: "dirty worktree",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectDir := t.TempDir()
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			var out bytes.Buffer
			var errOut bytes.Buffer
			executeCalled := false

			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				JSON:        true,
				JSONChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "run-workspace-preflight"
				},
				now:        runSandboxTestClock(startedAt, finishedAt),
				workingDir: func() (string, error) { return projectDir, nil },
				planWorkspace: func(ctx context.Context, req sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					if req.WorkspaceMode != sandbox.SandboxWorkspaceModeClone || req.DirectOptIn {
						t.Fatalf("workspace planning request = %#v, want clone mode without direct opt-in", req)
					}
					return sandboxworkspace.Planner{Git: fakeRunSandboxGitInspector{status: tt.status}}.Plan(ctx, req)
				},
				execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					executeCalled = true
					return runSandboxExecutionResult{}, errors.New("execute should not run")
				},
			})
			requireRenderedJSONExitCode(t, err, ExitCodeValidation)
			if executeCalled {
				t.Fatal("execute should not run after workspace preflight failure")
			}
			var result RunResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
			}
			if result.ContractVersion != 1 || result.OK {
				t.Fatalf("RunResult = %#v, want contractVersion 1 and ok false", result)
			}
			if !strings.Contains(result.Error, tt.wantError) {
				t.Fatalf("RunResult.Error = %q, want %q", result.Error, tt.wantError)
			}
			if strings.TrimSpace(errOut.String()) != "" {
				t.Fatalf("stderr = %q, want empty for JSON workspace preflight failure", errOut.String())
			}
			manifest, err := store.LoadManifest("run-workspace-preflight")
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if manifest.Status != sandboxexecution.StatusFailed {
				t.Fatalf("Status = %q, want failed", manifest.Status)
			}
			if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
				t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
			}
			if tt.wantWorkspace == nil {
				if manifest.Workspace != nil {
					t.Fatalf("Workspace = %#v, want nil", manifest.Workspace)
				}
				return
			}
			if manifest.Workspace == nil {
				t.Fatal("Workspace = nil, want planned workspace metadata")
			}
			if *manifest.Workspace != *tt.wantWorkspace {
				t.Fatalf("Workspace = %#v, want %#v", manifest.Workspace, tt.wantWorkspace)
			}
			encodedWorkspace, err := json.Marshal(manifest.Workspace)
			if err != nil {
				t.Fatalf("Marshal(workspace) error: %v", err)
			}
			if strings.Contains(string(encodedWorkspace), projectDir) {
				t.Fatalf("workspace metadata leaks local project path %q: %s", projectDir, encodedWorkspace)
			}
		})
	}
}

func TestRunRunSandboxWithWriterGitBundlePlanMaterializesAndExecutes(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "bundle-run", Provider: "test-provider", Status: sandbox.StatusRunning}
	plan := sandboxworkspace.Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     projectDir,
		Repository:     "git@example.com:org/repo.git",
		Branch:         "feature/unpushed",
		Upstream:       "origin/main",
		SyncRef:        "abc123",
		RequiresBundle: true,
	}
	var order []string
	var materialized bool
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-git-bundle-exec"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return plan, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					script := ""
					if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
						script = got.Args[2]
					}
					switch {
					case strings.TrimSpace(got.WorkDir) != "" && strings.Contains(script, "workspace.patch"):
						order = append(order, "recovery_generation")
					case strings.TrimSpace(got.WorkDir) != "" && strings.Contains(script, "reports.tar"):
						order = append(order, "reports_generation")
					default:
						order = append(order, "runtime_exec")
						_, _ = io.WriteString(got.Stdout, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
					}
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			t.Fatal("legacy bootstrap should not run for git-bundle workspace")
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(_ context.Context, _ sandboxexec.PrepareContext, got sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			order = append(order, "materialize_workspace")
			materialized = true
			if got.Plan == nil {
				t.Fatal("materialization plan = nil, want original workspace plan")
			}
			if got.Plan.Upstream != "origin/main" {
				t.Fatalf("plan upstream = %q, want origin/main", got.Plan.Upstream)
			}
			if got.Plan.ProjectDir != projectDir || got.ProjectDir != projectDir {
				t.Fatalf("materialization dirs plan=%q request=%q, want %q", got.Plan.ProjectDir, got.ProjectDir, projectDir)
			}
			if got.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || got.Workspace.SyncRef != "abc123" {
				t.Fatalf("workspace metadata = %#v, want git-bundle metadata", got.Workspace)
			}
			return sandboxworkspace.MaterializationResult{InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle}, nil
		},
		prepareCommandContext: func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
			order = append(order, "command_config")
			return sandboxworkspace.MaterializationOperation{Phase: sandboxworkspace.MaterializationPhaseCommandConfig}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			order = append(order, "auth")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !materialized {
		t.Fatal("materializeWorkspace was not called")
	}
	wantOrder := []string{"materialize_workspace", "command_config", "auth", "runtime_exec", "recovery_generation", "reports_generation"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %#v, want %#v", order, wantOrder)
	}
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable remote RunResult JSON: %v\n%s", err, out.String())
	}
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("RunResult = %#v, want successful remote result", result)
	}
	if strings.Contains(out.String(), "git bundle workspace input is not implemented") {
		t.Fatalf("stdout contains old implementation guard: %s", out.String())
	}
	manifest, err := store.LoadManifest("run-git-bundle-exec")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	wantWorkspace := sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
		Repo:        "git@example.com:org/repo.git",
		Branch:      "feature/unpushed",
		SyncRef:     "abc123",
	}
	if manifest.Workspace == nil || *manifest.Workspace != wantWorkspace {
		t.Fatalf("Workspace = %#v, want %#v", manifest.Workspace, wantWorkspace)
	}
	encodedWorkspace, err := json.Marshal(manifest.Workspace)
	if err != nil {
		t.Fatalf("Marshal(workspace) error: %v", err)
	}
	if strings.Contains(string(encodedWorkspace), projectDir) || strings.Contains(string(encodedWorkspace), "origin/main") {
		t.Fatalf("workspace metadata leaks transient plan details: %s", encodedWorkspace)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
	}
}

func TestRunRunSandboxWithWriterJSONPreRemoteExecutionFailureIncludesTargetMetadata(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "stopped-box",
		Provider: "test-provider",
		Status:   sandbox.StatusStopped,
		Host:     &sandbox.SandboxHost{ID: "host-start", Name: "worker-start"},
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine, RuntimeID: "runtime-start"},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-start-failure"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/start-failure", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("resolveProvider should not run after start failure")
			return nil, nil
		},
		resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
			if runtimeTarget.Name != "stopped-box" || runtimeTarget.Status != sandbox.StatusStopped {
				t.Fatalf("runtime target = %#v, want stopped-box stopped", runtimeTarget)
			}
			return fakeRunSandboxRuntimeDriver{
				start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					if req.Target.Name != "stopped-box" || req.Target.Status != sandbox.StatusStopped {
						t.Fatalf("start target = %#v, want stopped-box stopped", req.Target)
					}
					if _, err := io.WriteString(req.Stdout, "starting sandbox\n"); err != nil {
						return nil, err
					}
					return nil, errors.New("start failed")
				},
			}, nil
		},
	})
	requireRenderedJSONExitCode(t, err, ExitCodeValidation)
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(result.Error, "start failed") {
		t.Fatalf("RunResult.Error = %q, want start failure", result.Error)
	}
	if !strings.Contains(errOut.String(), "starting sandbox") {
		t.Fatalf("stderr = %q, want start output routed to stderr", errOut.String())
	}

	manifest, err := store.LoadManifest("run-start-failure")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("Status = %q, want failed", manifest.Status)
	}
	if manifest.SandboxName != "stopped-box" {
		t.Fatalf("SandboxName = %q, want stopped-box", manifest.SandboxName)
	}
	if manifest.Host == nil || manifest.Host.ID != "host-start" {
		t.Fatalf("Host = %#v, want phase-error target host metadata", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.RuntimeID != "runtime-start" {
		t.Fatalf("Runtime = %#v, want phase-error target runtime metadata", manifest.Runtime)
	}
}

func TestRunRunSandboxWithWriterJSONRuntimeDriverSetupFailureSynthesizesRunResult(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 45, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "ready-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-provider-setup-failure"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/provider-setup-failure", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return nil, errors.New("runtime driver setup failed")
		},
	})
	requireRenderedJSONExitCode(t, err, ExitCodeValidation)
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(result.Error, "runtime driver setup failed") {
		t.Fatalf("RunResult.Error = %q, want runtime driver setup failure", result.Error)
	}
}

func TestRunRunSandboxWithWriterJSONRemoteOutputPassesThroughAfterStdout(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 50, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "ready-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-remote-json-pass-through"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/remote-json", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					_, _ = io.WriteString(req.Stdout, `{"contractVersion":1,"ok":false,"summary":"remote"}`+"\n")
					return nil, errors.New("remote failed after writing json")
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected remote command error after stdout pass-through, got nil")
	}
	if !strings.Contains(err.Error(), "remote failed after writing json") {
		t.Fatalf("error = %q, want remote failure", err.Error())
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if result.Summary != "remote" {
		t.Fatalf("Summary = %q, want remote", result.Summary)
	}
	if strings.Contains(out.String(), "remote failed after writing json") {
		t.Fatalf("stdout contains synthesized local error: %s", out.String())
	}
}

func TestExecuteRunSandboxUsesRuntimeDriverAfterAuthPreparation(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:        "ready-box",
		Provider:    "test-provider",
		Status:      sandbox.StatusRunning,
		TailscaleIP: "100.64.0.10",
	}
	req := runSandboxRequest{
		ProjectDir:    t.TempDir(),
		SandboxName:   "ready-box",
		RepoRemote:    "git@example.com:org/repo.git",
		BaseBranch:    "main",
		RunBranch:     "feature/runtime-run",
		WorkDir:       "/root/workspace/repo",
		RemoteCommand: []string{"hal", "run", "--json"},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "git@example.com:org/repo.git",
			Branch:      "feature/runtime-run",
			SyncRef:     "refs/remotes/origin/feature/runtime-run",
		},
		Security: runSandboxSecurityRequest(),
	}
	var order []string
	var execReq sandboxruntime.ExecRequest
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			order = append(order, "runtime_exec")
			execReq = got
			_, _ = io.WriteString(got.Stdout, "runtime stdout\n")
			_, _ = io.WriteString(got.Stderr, "runtime stderr\n")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := (runSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			order = append(order, "resolve_runtime_driver")
			if target.Provider != "test-provider" || target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("target = %#v, want test-provider SSH-machine runtime target", target)
			}
			return driver, nil
		},
		bootstrap: func(_ context.Context, got factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
			order = append(order, "bootstrap")
			if got.RepositoryURL != req.RepoRemote || got.BaseBranch != req.BaseBranch || got.RunBranch != req.RunBranch || got.WorkspaceDir != req.WorkDir {
				t.Fatalf("bootstrap request = %#v, want remote-ref workspace request", got)
			}
			if !got.Options.ExactUpstream {
				t.Fatalf("bootstrap options = %#v, want exact-upstream reconciliation", got.Options)
			}
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			t.Fatal("materializeWorkspace should not run for remote-ref workspace")
			return sandboxworkspace.MaterializationResult{}, nil
		},
		prepareCommandContext: func(_ context.Context, _ sandboxexec.PrepareContext, projectDir, workspaceDir string, _ io.Writer) (sandboxworkspace.MaterializationOperation, error) {
			order = append(order, "command_config")
			if projectDir != req.ProjectDir || workspaceDir != req.WorkDir {
				t.Fatalf("command context dirs = %q, %q, want %q, %q", projectDir, workspaceDir, req.ProjectDir, req.WorkDir)
			}
			return sandboxworkspace.MaterializationOperation{Phase: sandboxworkspace.MaterializationPhaseCommandConfig}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			order = append(order, "auth")
			return nil
		},
	}).executeRunSandbox(context.Background(), req, &out, &errOut, runSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeRunSandbox() unexpected error: %v", err)
	}
	if result.Result == nil {
		t.Fatal("Result = nil")
	}
	if !result.RemoteStarted {
		t.Fatal("RemoteStarted = false, want true after runtime stdout")
	}
	wantOrder := []string{"resolve_runtime_driver", "bootstrap", "command_config", "auth", "runtime_exec"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %#v, want %#v", order, wantOrder)
	}
	wantArgs := runSandboxRemoteExecArgs(sandboxexec.CommandRequest{Command: req.RemoteCommand, WorkDir: req.WorkDir})
	if !reflect.DeepEqual(execReq.Args, wantArgs) {
		t.Fatalf("Exec args = %#v, want %#v", execReq.Args, wantArgs)
	}
	if execReq.Target.Name != "ready-box" || execReq.Target.Provider != "test-provider" || execReq.Target.Connection.TailscaleIP != "100.64.0.10" {
		t.Fatalf("Exec target = %#v, want runtime target metadata", execReq.Target)
	}
	if out.String() != "runtime stdout\n" {
		t.Fatalf("stdout = %q, want runtime stdout", out.String())
	}
	if errOut.String() != "runtime stderr\n" {
		t.Fatalf("stderr = %q, want runtime stderr", errOut.String())
	}
}

func TestExecuteRunSandboxGitBundleWorkspaceUsesSharedMaterializer(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:        "ready-box",
		Provider:    "local",
		Status:      sandbox.StatusRunning,
		TailscaleIP: "100.64.0.10",
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	req := runSandboxRequest{
		ProjectDir:    t.TempDir(),
		SandboxName:   "ready-box",
		RepoRemote:    "git@example.com:org/repo.git",
		BaseBranch:    "main",
		RunBranch:     "feature/bundle-run",
		WorkDir:       "/root/workspace/repo",
		RemoteCommand: []string{"hal", "run", "--json"},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repo:        "git@example.com:org/repo.git",
			Branch:      "feature/bundle-run",
			SyncRef:     "refs/hal/workspace-sync/bundle-run",
		},
		Security: runSandboxSecurityRequest(),
	}
	var order []string
	var materialized bool
	driver := &fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			order = append(order, "runtime_exec")
			if got.Target.Name != "ready-box" || got.Target.Provider != "local" || got.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || got.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
				t.Fatalf("runtime exec target = %#v, want prepared rootless runtime target", got.Target)
			}
			_, _ = io.WriteString(got.Stdout, "runtime stdout\n")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := (runSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			order = append(order, "resolve_runtime_driver")
			if target.Provider != "local" || target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("target = %#v, want local rootless runtime target", target)
			}
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			t.Fatal("legacy bootstrap should not run for git-bundle workspace")
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(_ context.Context, prep sandboxexec.PrepareContext, got sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			order = append(order, "materialize_workspace")
			materialized = true
			if prep.Driver != driver {
				t.Fatalf("prep driver = %#v, want resolved runtime driver", prep.Driver)
			}
			if prep.Target.Name != "ready-box" || prep.Target.Provider != "local" || prep.Target.Connection.TailscaleIP != "100.64.0.10" || prep.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || prep.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
				t.Fatalf("prep target = %#v, want rootless runtime target metadata", prep.Target)
			}
			if got.ProjectDir != req.ProjectDir || got.WorkspaceDir != req.WorkDir {
				t.Fatalf("materialize request = %#v, want project/work dirs from request", got)
			}
			if got.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || got.Workspace.SyncRef != req.Workspace.SyncRef {
				t.Fatalf("workspace metadata = %#v, want git-bundle metadata", got.Workspace)
			}
			return sandboxworkspace.MaterializationResult{InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle}, nil
		},
		prepareCommandContext: func(_ context.Context, _ sandboxexec.PrepareContext, projectDir, workspaceDir string, _ io.Writer) (sandboxworkspace.MaterializationOperation, error) {
			order = append(order, "command_config")
			if projectDir != req.ProjectDir || workspaceDir != req.WorkDir {
				t.Fatalf("command context dirs = %q, %q, want %q, %q", projectDir, workspaceDir, req.ProjectDir, req.WorkDir)
			}
			return sandboxworkspace.MaterializationOperation{Phase: sandboxworkspace.MaterializationPhaseCommandConfig}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			order = append(order, "auth")
			return nil
		},
	}).executeRunSandbox(context.Background(), req, &out, &errOut, runSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeRunSandbox() unexpected error: %v", err)
	}
	if result.Result == nil {
		t.Fatal("Result = nil")
	}
	if !result.RemoteStarted {
		t.Fatal("RemoteStarted = false, want true after runtime stdout")
	}
	if !materialized {
		t.Fatal("materializeWorkspace was not called")
	}
	wantOrder := []string{"resolve_runtime_driver", "materialize_workspace", "command_config", "auth", "runtime_exec"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %#v, want %#v", order, wantOrder)
	}
	if out.String() != "runtime stdout\n" {
		t.Fatalf("stdout = %q, want runtime stdout", out.String())
	}
	if errOut.String() != "" {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}
}

func TestRunRunSandboxWithWriterSuccessfulExecutorUpdatesManifest(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		ID:       "sandbox-123",
		Name:     "ready-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "host-1",
			Name: "worker-1",
			Kind: sandbox.SandboxHostKindSSH,
			Labels: map[string]string{
				"role": "test",
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-1",
			Image:          "hal:test",
			WorkerID:       "worker-1",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
				ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
			},
		},
	}

	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, []string{"2"}, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-success-manifest"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/sandbox-run", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			running, err := store.LoadManifest("run-success-manifest")
			if err != nil {
				t.Fatalf("LoadManifest() before executor target ready: %v", err)
			}
			if running.Status != sandboxexecution.StatusRunning {
				t.Fatalf("pre-execute Status = %q, want running", running.Status)
			}
			if running.Workspace == nil || running.Workspace.Mode != sandbox.SandboxWorkspaceModeClone {
				t.Fatalf("pre-execute Workspace = %#v, want clone metadata", running.Workspace)
			}
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			return runSandboxExecutionResult{
				Result: &sandboxexec.Result{Target: sandboxruntime.Target{Name: target.Name, Provider: target.Provider, Status: target.Status}},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	manifest, err := store.LoadManifest("run-success-manifest")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Purpose != sandboxexecution.PurposeRun {
		t.Fatalf("Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeRun)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusSucceeded)
	}
	if manifest.SandboxName != "ready-box" {
		t.Fatalf("SandboxName = %q, want ready-box", manifest.SandboxName)
	}
	if manifest.ProjectDir != projectDir {
		t.Fatalf("ProjectDir = %q, want %q", manifest.ProjectDir, projectDir)
	}
	wantCommand := []string{"hal", "run", "--json", "--base", "main", "2"}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	if manifest.WorkDir == "" || manifest.WorkDir != captured.WorkDir {
		t.Fatalf("WorkDir = %q, captured %q", manifest.WorkDir, captured.WorkDir)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
	}
	if manifest.Workspace == nil {
		t.Fatal("Workspace = nil")
	}
	if manifest.Workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		manifest.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef ||
		manifest.Workspace.Repo != "git@example.com:org/repo.git" ||
		manifest.Workspace.Branch != "feature/sandbox-run" ||
		manifest.Workspace.SyncRef != "main" {
		t.Fatalf("Workspace = %#v, want remote clone of feature/sandbox-run from main", manifest.Workspace)
	}
	if manifest.Host == nil || manifest.Host.ID != "host-1" || manifest.Host.Labels["role"] != "test" {
		t.Fatalf("Host = %#v, want copied target host metadata", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.RuntimeID != "runtime-1" {
		t.Fatalf("Runtime = %#v, want copied target runtime metadata", manifest.Runtime)
	}
	if manifest.Security == nil || manifest.Security.Network == nil || manifest.Security.Secrets == nil {
		t.Fatalf("Security = %#v, want copied target security metadata", manifest.Security)
	}
	if !reflect.DeepEqual(manifest.Security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("ActiveModes = %#v, want http_proxy", manifest.Security.Secrets.ActiveModes)
	}
}

func TestRunRunSandboxWithWriterCollectsCoreStateArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "core-state-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "run-core-state",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/core-state",
		BaseBranch: "main",
	})
	expectedSources := []string{
		expectedWorkspace + "/.hal/prd.json",
		expectedWorkspace + "/.hal/progress.txt",
		expectedWorkspace + "/.hal/recovery/workspace.patch",
		expectedWorkspace + "/.hal/reports.tar",
	}
	var copyOutSources []string
	var order []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				order = append(order, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				order = append(order, "reports_generation")
			default:
				order = append(order, "runtime_exec")
				if got.Target.Name != "core-state-box" {
					t.Fatalf("Exec target = %#v, want core-state-box", got.Target)
				}
				_, _ = io.WriteString(got.Stdout, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			order = append(order, "copy_out")
			copyOutSources = append(copyOutSources, got.SourcePath)
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-core-state"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return repoRemote, nil },
		currentBranch: func(string) (string, error) { return "feature/core-state", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !reflect.DeepEqual(order, []string{"runtime_exec", "copy_out", "copy_out", "recovery_generation", "copy_out", "reports_generation", "copy_out"}) {
		t.Fatalf("order = %#v, want runtime exec before core state copy out", order)
	}
	if !reflect.DeepEqual(copyOutSources, expectedSources) {
		t.Fatalf("CopyOut sources = %#v, want %#v", copyOutSources, expectedSources)
	}
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable remote RunResult JSON: %v\n%s", err, out.String())
	}
	if !result.OK {
		t.Fatalf("RunResult = %#v, want ok", result)
	}

	manifest, err := store.LoadManifest("run-core-state")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want collected core state metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != 5 {
		t.Fatalf("collected = %#v, want core state, generated artifacts, and stdout summary", manifest.ArtifactMetadata.Collected)
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected[".hal/prd.json"], ".hal/prd.json", "run-core-state/artifacts/core/hal-prd.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/progress.txt"], ".hal/progress.txt", "run-core-state/artifacts/core/hal-progress.txt")
	assertRunSandboxCollectedArtifact(t, collected[".hal/recovery/workspace.patch"], ".hal/recovery/workspace.patch", "run-core-state/recovery/workspace.patch")
	assertRunSandboxCollectedArtifact(t, collected[".hal/reports.tar"], ".hal/reports.tar", "run-core-state/artifacts/reports/reports.tar")
	assertRunSandboxCollectedArtifact(t, collected["output/stdout-summary.txt"], "output/stdout-summary.txt", "run-core-state/artifacts/output/stdout-summary.txt")
	if len(manifest.ArtifactMetadata.Partial) != 0 || len(manifest.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("partial/warnings = %#v/%#v, want none", manifest.ArtifactMetadata.Partial, manifest.ArtifactMetadata.Warnings)
	}
}

func TestRunRunSandboxWithWriterCollectsGeneratedArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 45, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "generated-artifacts-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "run-generated-artifacts",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/generated-artifacts",
		BaseBranch: "main",
	})
	expectedSources := []string{
		expectedWorkspace + "/.hal/prd.json",
		expectedWorkspace + "/.hal/progress.txt",
		expectedWorkspace + "/.hal/recovery/workspace.patch",
		expectedWorkspace + "/.hal/reports.tar",
	}
	var execCalls []string
	var copyOutSources []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				execCalls = append(execCalls, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				execCalls = append(execCalls, "reports_generation")
			default:
				execCalls = append(execCalls, "remote_run")
				if got.Target.Name != "generated-artifacts-box" {
					t.Fatalf("Exec target = %#v, want generated-artifacts-box", got.Target)
				}
				_, _ = io.WriteString(got.Stdout, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			copyOutSources = append(copyOutSources, got.SourcePath)
			if got.SourcePath == expectedWorkspace+"/.hal/reports.tar" {
				return os.ErrNotExist
			}
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-generated-artifacts"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return repoRemote, nil },
		currentBranch: func(string) (string, error) { return "feature/generated-artifacts", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !reflect.DeepEqual(execCalls, []string{"remote_run", "recovery_generation", "reports_generation"}) {
		t.Fatalf("exec calls = %#v, want remote command followed by generated artifact commands", execCalls)
	}
	if !reflect.DeepEqual(copyOutSources, expectedSources) {
		t.Fatalf("CopyOut sources = %#v, want %#v", copyOutSources, expectedSources)
	}

	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("RunResult = %#v, want ok remote result", result)
	}
	for _, disallowed := range []string{".hal/reports.tar", "artifact warning"} {
		if strings.Contains(out.String(), disallowed) {
			t.Fatalf("stdout contains collection warning text %q outside remote JSON document: %s", disallowed, out.String())
		}
	}

	manifest, err := store.LoadManifest("run-generated-artifacts")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want generated artifact metadata")
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected[".hal/prd.json"], ".hal/prd.json", "run-generated-artifacts/artifacts/core/hal-prd.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/progress.txt"], ".hal/progress.txt", "run-generated-artifacts/artifacts/core/hal-progress.txt")
	assertRunSandboxCollectedArtifact(t, collected[".hal/recovery/workspace.patch"], ".hal/recovery/workspace.patch", "run-generated-artifacts/recovery/workspace.patch")
	if len(manifest.ArtifactMetadata.Partial) != 1 {
		t.Fatalf("partial = %#v, want missing reports archive partial", manifest.ArtifactMetadata.Partial)
	}
	if manifest.ArtifactMetadata.Partial[0].Path != ".hal/reports.tar" || manifest.ArtifactMetadata.Partial[0].StoredPath != "" {
		t.Fatalf("reports partial = %#v, want safe display path without stored path", manifest.ArtifactMetadata.Partial[0])
	}
	if len(manifest.ArtifactMetadata.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want missing reports archive warning", manifest.ArtifactMetadata.Warnings)
	}
	warning := manifest.ArtifactMetadata.Warnings[0]
	if warning.Artifact.Path != ".hal/reports.tar" || !strings.Contains(warning.Message, "missing") {
		t.Fatalf("reports warning = %#v, want missing reports archive warning", warning)
	}
}

func TestCollectRunSandboxGeneratedArtifactsKeepsRecoveryGenerationBestEffort(t *testing.T) {
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	if err := store.SaveManifest(&sandboxexecution.Manifest{
		ID:        "run-recovery-best-effort",
		Purpose:   sandboxexecution.PurposeRun,
		Status:    sandboxexecution.StatusRunning,
		StartedAt: time.Date(2026, 7, 7, 12, 30, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	const workspace = "/root/workspace/repo"
	var recoveryCopyOut bool
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			if got.WorkDir == workspace && strings.Contains(script, "workspace.patch") {
				return nil, errors.New("chdir /root/workspace/repo: no such file or directory")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			if strings.Contains(got.SourcePath, "workspace.patch") {
				recoveryCopyOut = true
			}
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}

	err := collectRunSandboxGeneratedArtifacts(context.Background(), store, runSandboxRequest{
		ExecutionID: "run-recovery-best-effort",
		WorkDir:     workspace,
	}, runSandboxExecutionResult{
		RuntimeDriver: driver,
		Result: &sandboxexec.Result{Target: sandboxruntime.Target{
			Name: "run-recovery-best-effort-box",
			Runtime: sandboxruntime.RuntimeState{
				Driver: sandboxruntime.DriverSSHMachine,
			},
		}},
	})
	if err != nil {
		t.Fatalf("collectRunSandboxGeneratedArtifacts() error = %v, want best-effort recovery warning", err)
	}
	if recoveryCopyOut {
		t.Fatal("recovery patch copy-out should not run after recovery generation failure")
	}
	manifest, err := store.LoadManifest("run-recovery-best-effort")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.ArtifactMetadata == nil || len(manifest.ArtifactMetadata.Warnings) == 0 {
		t.Fatalf("artifact metadata = %#v, want recovery warning", manifest.ArtifactMetadata)
	}
	if got := manifest.ArtifactMetadata.Warnings[0].Phase; got != "recovery-generation" {
		t.Fatalf("warning phase = %q, want recovery-generation", got)
	}
}

func TestRunRunSandboxWithWriterRecordsArtifactCopyWarningsAtCommandBoundary(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 9, 10, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "artifact-warning-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "run-artifact-copy-warning",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/artifact-warning",
		BaseBranch: "main",
	})
	copyErr := errors.New("copy_out failed from unix:///tmp/private/worker-1.sock at /workspace/.hal/tmp/session token=secret")
	var execCalls []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				execCalls = append(execCalls, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				execCalls = append(execCalls, "reports_generation")
			default:
				execCalls = append(execCalls, "remote_run")
				_, _ = io.WriteString(got.Stdout, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			if got.SourcePath == expectedWorkspace+"/.hal/recovery/workspace.patch" {
				return copyErr
			}
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-artifact-copy-warning"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return repoRemote, nil },
		currentBranch: func(string) (string, error) { return "feature/artifact-warning", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !reflect.DeepEqual(execCalls, []string{"remote_run", "recovery_generation", "reports_generation"}) {
		t.Fatalf("exec calls = %#v, want remote command and both artifact generation commands", execCalls)
	}

	manifest, err := store.LoadManifest("run-artifact-copy-warning")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want warning metadata")
	}
	if len(manifest.ArtifactMetadata.Partial) != 1 {
		t.Fatalf("partial = %#v, want one recovery partial entry", manifest.ArtifactMetadata.Partial)
	}
	if manifest.ArtifactMetadata.Partial[0].Path != ".hal/recovery/workspace.patch" ||
		manifest.ArtifactMetadata.Partial[0].StoredPath != "" {
		t.Fatalf("partial = %#v, want safe recovery display path without stored path", manifest.ArtifactMetadata.Partial[0])
	}
	if len(manifest.ArtifactMetadata.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one recovery copy-out warning", manifest.ArtifactMetadata.Warnings)
	}
	warning := manifest.ArtifactMetadata.Warnings[0]
	if warning.Phase != "recovery-copyout" ||
		warning.Message != "sandbox execution recovery artifact copy failed" ||
		warning.Artifact.Path != ".hal/recovery/workspace.patch" ||
		warning.Artifact.StoredPath != "" {
		t.Fatalf("warning = %#v, want sanitized recovery copy-out warning", warning)
	}
	encoded, err := json.Marshal(manifest.ArtifactMetadata)
	if err != nil {
		t.Fatalf("Marshal(ArtifactMetadata) error: %v", err)
	}
	for _, forbidden := range []string{"unix://", "/tmp/private/worker-1.sock", "/workspace/.hal/tmp/session", "token=secret"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("artifact warning leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRunRunSandboxWithWriterCollectsRecoveryAfterRemoteFailure(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 48, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:        "failed-run-box",
		Provider:    "test-provider",
		Status:      sandbox.StatusRunning,
		WorkspaceID: "workspace-failed-run",
		Runtime:     &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "run-failed-recovery",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/failed-recovery",
		BaseBranch: "main",
	})
	remoteErr := errors.New("remote command failed")
	var execCalls []string
	var copyOutSources []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			if got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch") {
				execCalls = append(execCalls, "recovery_generation")
				return &sandboxruntime.ExecResult{ExitCode: 0}, nil
			}
			execCalls = append(execCalls, "remote_run")
			return nil, remoteErr
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			copyOutSources = append(copyOutSources, got.SourcePath)
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("recovery payload"), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-failed-recovery"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return repoRemote, nil },
		currentBranch: func(string) (string, error) { return "feature/failed-recovery", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if !errors.Is(err, remoteErr) {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want original remote error", err)
	}
	if !reflect.DeepEqual(execCalls, []string{"remote_run", "recovery_generation"}) {
		t.Fatalf("exec calls = %#v, want remote failure followed by recovery generation", execCalls)
	}
	expectedRecoverySource := expectedWorkspace + "/.hal/recovery/workspace.patch"
	if !reflect.DeepEqual(copyOutSources, []string{expectedRecoverySource}) {
		t.Fatalf("CopyOut sources = %#v, want only recovery artifact", copyOutSources)
	}

	manifest, err := store.LoadManifest("run-failed-recovery")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("Status = %q, want failed", manifest.Status)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want failed-run recovery metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != 1 {
		t.Fatalf("collected = %#v, want recovery artifact", manifest.ArtifactMetadata.Collected)
	}
	recovery := manifest.ArtifactMetadata.Collected[0]
	assertRunSandboxCollectedArtifact(t, recovery, ".hal/recovery/workspace.patch", "run-failed-recovery/recovery/workspace.patch")
	if len(manifest.ArtifactMetadata.Partial) != 0 || len(manifest.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("partial/warnings = %#v/%#v, want none after successful recovery", manifest.ArtifactMetadata.Partial, manifest.ArtifactMetadata.Warnings)
	}
	if payload := readRunSandboxStoreFile(t, store, recovery.StoredPath); payload != "recovery payload" {
		t.Fatalf("recovery payload = %q, want copied recovery payload", payload)
	}
}

func TestRunRunSandboxWithWriterSavesOutputSummaryArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 50, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:        "summary-box",
		Provider:    "test-provider",
		Status:      sandbox.StatusRunning,
		IP:          "203.0.113.42",
		TailscaleIP: "100.64.0.42",
		Runtime:     &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "run-output-summary",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/output-summary",
		BaseBranch: "main",
	})
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
			default:
				_, _ = io.WriteString(got.Stdout, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
				_, _ = io.WriteString(got.Stderr, "warning from 203.0.113.42\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-output-summary"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return repoRemote, nil },
		currentBranch: func(string) (string, error) { return "feature/output-summary", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("RunResult = %#v, want ok remote summary", result)
	}

	manifest, err := store.LoadManifest("run-output-summary")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want output summary metadata")
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected["output/stdout-summary.txt"], "output/stdout-summary.txt", "run-output-summary/artifacts/output/stdout-summary.txt")
	assertRunSandboxCollectedArtifact(t, collected["output/stderr-summary.txt"], "output/stderr-summary.txt", "run-output-summary/artifacts/output/stderr-summary.txt")
	stdoutPayload := readRunSandboxStoreFile(t, store, collected["output/stdout-summary.txt"].StoredPath)
	if stdoutPayload != `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n" {
		t.Fatalf("stdout summary payload = %q, want remote JSON summary", stdoutPayload)
	}
	stderrPayload := readRunSandboxStoreFile(t, store, collected["output/stderr-summary.txt"].StoredPath)
	if strings.Contains(stderrPayload, "203.0.113.42") {
		t.Fatalf("stderr summary payload leaked sandbox address: %q", stderrPayload)
	}
	if !strings.Contains(stderrPayload, "<address redacted>") {
		t.Fatalf("stderr summary payload = %q, want redacted address marker", stderrPayload)
	}
}

func TestRunRunWithWriterSandboxFlagDispatchesToSandboxExecutor(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 11, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "flag-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer

	originalDeps := defaultRunSandboxDeps
	defaultRunSandboxDeps = runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-flag-dispatch"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return t.TempDir(), nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/flag-dispatch", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			return runSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxruntime.Target{Name: target.Name, Provider: target.Provider, Status: target.Status}}}, nil
		},
	}
	t.Cleanup(func() {
		defaultRunSandboxDeps = originalDeps
	})

	cmd := newRunSandboxTestCommand(&out, &errOut)
	for flag, value := range map[string]string{
		"sandbox":         "true",
		"sandbox-name":    "flag-box",
		"sandbox-host":    "worker-1",
		"sandbox-runtime": sandboxruntime.DriverRootlessPodman,
		"json":            "true",
		"engine":          "codex-test",
		"base":            "main",
		"dry-run":         "true",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := runRunWithWriter(cmd, []string{"4"}, &errOut); err != nil {
		t.Fatalf("runRunWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	if captured.SandboxName != "flag-box" {
		t.Fatalf("SandboxName = %q, want flag-box", captured.SandboxName)
	}
	if captured.SandboxHostID != "worker-1" {
		t.Fatalf("SandboxHostID = %q, want worker-1", captured.SandboxHostID)
	}
	if captured.SandboxRuntime != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("SandboxRuntime = %q, want %q", captured.SandboxRuntime, sandboxruntime.DriverRootlessPodman)
	}
	wantCommand := []string{"hal", "run", "--json", "--engine", "codex-test", "--dry-run", "--base", "main", "4"}
	if !reflect.DeepEqual(captured.RemoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", captured.RemoteCommand, wantCommand)
	}
	manifest, err := store.LoadManifest("run-flag-dispatch")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusSucceeded)
	}
}

func TestRunRunWithWriterAppliesProjectConfigDefaultsToSandbox(t *testing.T) {
	captured := captureRunSandboxRequestWithConfig(t, `
sandbox:
  defaults:
    name: config-box
    host: local-worker
    runtime: rootless_podman
    workspaceMode: clone
    syncOut: true
    apply: false
run:
  base: develop
  timeout: 20m
`, nil, map[string]string{
		"sandbox": "true",
	})

	if captured.SandboxName != "config-box" {
		t.Fatalf("SandboxName = %q, want config-box", captured.SandboxName)
	}
	if captured.SandboxHostID != "local-worker" {
		t.Fatalf("SandboxHostID = %q, want local-worker", captured.SandboxHostID)
	}
	if captured.SandboxRuntime != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("SandboxRuntime = %q, want %q", captured.SandboxRuntime, sandboxruntime.DriverRootlessPodman)
	}
	if !captured.SyncOut.Enabled || captured.SyncOut.Apply {
		t.Fatalf("SyncOut = %#v, want enabled without apply", captured.SyncOut)
	}
	if captured.Flags.Base != "develop" || !captured.Flags.BaseChanged {
		t.Fatalf("Base flags = %q changed=%v, want develop changed", captured.Flags.Base, captured.Flags.BaseChanged)
	}
	if captured.Flags.Timeout != 20*time.Minute || !captured.Flags.TimeoutChanged {
		t.Fatalf("Timeout flags = %v changed=%v, want 20m changed", captured.Flags.Timeout, captured.Flags.TimeoutChanged)
	}
	wantCommand := []string{"hal", "run", "--timeout", "20m0s", "--base", "develop"}
	if !reflect.DeepEqual(captured.RemoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", captured.RemoteCommand, wantCommand)
	}
}

func TestRunRunWithWriterCLIOverridesProjectConfigDefaults(t *testing.T) {
	captured := captureRunSandboxRequestWithConfig(t, `
sandbox:
  defaults:
    name: config-box
    host: config-worker
    runtime: ssh_machine
    workspaceMode: clone
    syncOut: true
    apply: true
run:
  base: develop
  timeout: 20m
`, nil, map[string]string{
		"sandbox":              "true",
		"sandbox-name":         "flag-box",
		sandboxHostFlagName:    "flag-worker",
		sandboxRuntimeFlagName: sandboxruntime.DriverMicroVM,
		sandboxSyncOutFlagName: "false",
		sandboxApplyFlagName:   "false",
		"base":                 "release",
		"timeout":              "5m",
	})

	if captured.SandboxName != "flag-box" {
		t.Fatalf("SandboxName = %q, want flag-box", captured.SandboxName)
	}
	if captured.SandboxHostID != "flag-worker" {
		t.Fatalf("SandboxHostID = %q, want flag-worker", captured.SandboxHostID)
	}
	if captured.SandboxRuntime != sandboxruntime.DriverMicroVM {
		t.Fatalf("SandboxRuntime = %q, want %q", captured.SandboxRuntime, sandboxruntime.DriverMicroVM)
	}
	if captured.SyncOut.Enabled || captured.SyncOut.Apply {
		t.Fatalf("SyncOut = %#v, want disabled by explicit false flags", captured.SyncOut)
	}
	if captured.Flags.Base != "release" || captured.Flags.Timeout != 5*time.Minute {
		t.Fatalf("run flags base/timeout = %q/%v, want release/5m", captured.Flags.Base, captured.Flags.Timeout)
	}
	wantCommand := []string{"hal", "run", "--timeout", "5m0s", "--base", "release"}
	if !reflect.DeepEqual(captured.RemoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", captured.RemoteCommand, wantCommand)
	}
}

func TestRunRunWithWriterProjectConfigSandboxDefaultsDoNotEnableSandbox(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `
sandbox:
  defaults:
    name: config-box
    host: local-worker
    runtime: rootless_podman
    syncOut: true
    apply: true
`)
	t.Chdir(projectDir)

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := newRunSandboxTestCommand(&out, &errOut)
	err := runRunWithWriter(cmd, nil, &errOut)
	if err == nil || !strings.Contains(err.Error(), "prd.json not found") {
		t.Fatalf("runRunWithWriter() error = %v, want local run prd.json validation", err)
	}
}

func TestRunSandboxCmdContextSplitsStdoutAndStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runSandboxCmdContext(context.Background(), exec.Command("sh", "-c", "printf stdout; printf stderr >&2"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runSandboxCmdContext() unexpected error: %v", err)
	}
	if stdout.String() != "stdout" {
		t.Fatalf("stdout = %q, want stdout", stdout.String())
	}
	if stderr.String() != "stderr" {
		t.Fatalf("stderr = %q, want stderr", stderr.String())
	}
}

func newRunSandboxTestCommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "run"}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().Int("iterations", 10, "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Int("retries", 3, "")
	cmd.Flags().Duration("retry-delay", 5*time.Second, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().String("story", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("sandbox", false, "")
	cmd.Flags().String("sandbox-name", "", "")
	cmd.Flags().String("sandbox-host", "", "")
	cmd.Flags().String("sandbox-runtime", "", "")
	cmd.Flags().Bool(sandboxSyncOutFlagName, false, "")
	cmd.Flags().Bool(sandboxApplyFlagName, false, "")
	return cmd
}

func captureRunSandboxRequestWithConfig(t *testing.T, config string, args []string, flags map[string]string) runSandboxRequest {
	t.Helper()
	startedAt := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, config)
	t.Chdir(projectDir)

	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "selected-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer

	originalDeps := defaultRunSandboxDeps
	defaultRunSandboxDeps = runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-config-defaults"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/config-defaults", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			return runSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxruntime.Target{Name: target.Name, Provider: target.Provider, Status: target.Status}}}, nil
		},
	}
	t.Cleanup(func() {
		defaultRunSandboxDeps = originalDeps
	})

	cmd := newRunSandboxTestCommand(&out, &errOut)
	for flag, value := range flags {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}
	if err := runRunWithWriter(cmd, args, &errOut); err != nil {
		t.Fatalf("runRunWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	return captured
}

func runSandboxTestClock(times ...time.Time) func() time.Time {
	return func() time.Time {
		if len(times) == 0 {
			return time.Time{}
		}
		next := times[0]
		if len(times) > 1 {
			times = times[1:]
		}
		return next
	}
}

func writeRunSandboxConfig(t *testing.T, projectDir, content string) {
	t.Helper()
	halDir := filepath.Join(projectDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(config.yaml) error: %v", err)
	}
}

func requireRunSandboxLegacySecurityManifest(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.Network == nil || security.Network.PolicyResult == nil {
		t.Fatalf("Security = %#v, want network policy result", security)
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("PolicyRequested = %q, want deny_by_default", security.Network.PolicyRequested)
	}
	if security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("policyResult.requested.preset = %q, want deny_by_default", security.Network.PolicyResult.Requested.Preset)
	}
	if security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("policyResult.effective.preset = %q, want legacy_default", security.Network.PolicyResult.Effective.Preset)
	}
	if security.Secrets == nil || !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("secret metadata = %#v, want legacy http_proxy request", security.Secrets)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("active modes = %#v, want legacy auth sync", security.Secrets.ActiveModes)
	}
}

func requireRunSandboxConfiguredSecurityManifest(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.Network == nil || security.Network.PolicyResult == nil {
		t.Fatalf("Security = %#v, want network policy result", security)
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("PolicyRequested = %q, want deny_by_default compatibility label", security.Network.PolicyRequested)
	}
	if security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("policyResult.requested.preset = %q, want allow_listed", security.Network.PolicyResult.Requested.Preset)
	}
	if security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("policyResult.effective.preset = %q, want legacy_default downgrade", security.Network.PolicyResult.Effective.Preset)
	}
	if len(security.Network.PolicyResult.Warnings) == 0 {
		t.Fatal("policyResult.warnings = empty, want unsupported enforcement warning")
	}
	if security.Secrets == nil {
		t.Fatal("Secrets = nil, want configured secret metadata")
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeFileTmpfs}) {
		t.Fatalf("RequestedModes = %#v, want configured requested modes", security.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("ActiveModes = %#v, want configured active mode plus compatibility auth sync", security.Secrets.ActiveModes)
	}
}

type fakeRunSandboxGitInspector struct {
	status sandboxworkspace.GitStatus
	err    error
}

func (f fakeRunSandboxGitInspector) InspectGit(context.Context, string) (sandboxworkspace.GitStatus, error) {
	return f.status, f.err
}

type fakeRunSandboxRuntimeDriver struct {
	id      string
	create  func(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error)
	start   func(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error)
	exec    func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
	copyIn  func(context.Context, sandboxruntime.CopyRequest) error
	copyOut func(context.Context, sandboxruntime.CopyRequest) error
}

func (f fakeRunSandboxRuntimeDriver) ID() string {
	if f.id != "" {
		return f.id
	}
	return sandboxruntime.DriverSSHMachine
}

func (f fakeRunSandboxRuntimeDriver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	if f.create != nil {
		return f.create(ctx, req)
	}
	return &sandboxruntime.Target{
		ID:     req.Name + "-runtime",
		Name:   req.Name,
		Status: sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    f.ID(),
			RuntimeID: req.Name + "-runtime",
		},
	}, nil
}

func (f fakeRunSandboxRuntimeDriver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	if f.start != nil {
		return f.start(ctx, req)
	}
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (fakeRunSandboxRuntimeDriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRunSandboxRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (fakeRunSandboxRuntimeDriver) Inspect(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (f fakeRunSandboxRuntimeDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	if f.exec != nil {
		return f.exec(ctx, req)
	}
	return &sandboxruntime.ExecResult{}, nil
}

func (f fakeRunSandboxRuntimeDriver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	if f.copyIn != nil {
		return f.copyIn(ctx, req)
	}
	return nil
}

func (f fakeRunSandboxRuntimeDriver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	if f.copyOut != nil {
		return f.copyOut(ctx, req)
	}
	if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte("fake sandbox artifact"), 0o600)
}

func decodeExactlyOneJSONDocument(t *testing.T, data []byte, dst any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(dst); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, string(data))
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout is not exactly one JSON document: extra=%#v err=%v\n%s", extra, err, string(data))
	}
}

func assertRunSandboxCollectedArtifact(t *testing.T, got sandboxexecution.ArtifactMetadataEntry, wantPath, wantStoredPath string) {
	t.Helper()
	if got.Path != wantPath {
		t.Fatalf("artifact path = %q, want %q", got.Path, wantPath)
	}
	if got.StoredPath != wantStoredPath {
		t.Fatalf("artifact storedPath = %q, want %q", got.StoredPath, wantStoredPath)
	}
	if got.SizeBytes == nil || *got.SizeBytes == 0 {
		t.Fatalf("artifact size = %v, want non-zero", got.SizeBytes)
	}
	if got.CreatedAt == nil {
		t.Fatal("artifact CreatedAt = nil")
	}
}

func readRunSandboxStoreFile(t *testing.T, store sandboxexecution.Store, storedPath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(storedPath)))
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", storedPath, err)
	}
	return string(data)
}
