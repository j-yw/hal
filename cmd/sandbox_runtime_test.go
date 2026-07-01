package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

func TestSandboxRuntimeCommandScaffoldRegistered(t *testing.T) {
	runtime, err := commandAtPath(Root(), "sandbox", "runtime")
	if err != nil {
		t.Fatalf("sandbox runtime command missing: %v", err)
	}
	if missing := missingCommandMetadataFields(runtime); len(missing) > 0 {
		t.Fatalf("sandbox runtime missing metadata fields: %v", missing)
	}

	for _, path := range [][]string{
		{"sandbox", "runtime", "list"},
		{"sandbox", "runtime", "status"},
	} {
		cmd, err := commandAtPath(Root(), path...)
		if err != nil {
			t.Fatalf("command path %q missing: %v", strings.Join(path, " "), err)
		}
		if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
			t.Fatalf("command %q missing metadata fields: %v", strings.Join(path, " "), missing)
		}
		if !strings.Contains(cmd.Example, commandPathLabel(cmd)) {
			t.Fatalf("command %q example must include full command path, got %q", commandPathLabel(cmd), cmd.Example)
		}
		for _, flagName := range []string{"json", "live"} {
			if cmd.Flags().Lookup(flagName) == nil {
				t.Fatalf("command %q missing --%s flag", commandPathLabel(cmd), flagName)
			}
		}
	}
}

func TestSandboxRuntimeHelpListsScaffoldSubcommands(t *testing.T) {
	cmd := newSandboxRuntimeCommand(sandboxRuntimeDeps{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandbox runtime --help error: %v", err)
	}

	help := stdout.String()
	for _, want := range []string{"list", "status"} {
		if !strings.Contains(help, want) {
			t.Fatalf("sandbox runtime help = %q, want subcommand %q", help, want)
		}
	}
}

func TestSandboxRuntimeCommandsUseInjectedDependencies(t *testing.T) {
	var gotList sandboxRuntimeListRequest
	var gotStatus sandboxRuntimeStatusRequest
	deps := sandboxRuntimeDeps{
		list: func(_ context.Context, req sandboxRuntimeListRequest, out io.Writer) error {
			gotList = req
			_, err := out.Write([]byte("list ok\n"))
			return err
		},
		status: func(_ context.Context, req sandboxRuntimeStatusRequest, out io.Writer) error {
			gotStatus = req
			_, err := out.Write([]byte("status ok\n"))
			return err
		},
	}

	listCmd, listOut, listErr := newTestSandboxRuntimeCommand(deps)
	listCmd.SetArgs([]string{"list", "local-worker", "--live", "--json"})
	if err := listCmd.Execute(); err != nil {
		t.Fatalf("runtime list Execute() error = %v; stderr=%q", err, listErr.String())
	}
	if gotList.HostID != "local-worker" || !gotList.Live || !gotList.JSON {
		t.Fatalf("runtime list request = %#v, want host id with live/json flags", gotList)
	}
	if got := listOut.String(); got != "list ok\n" {
		t.Fatalf("runtime list stdout = %q", got)
	}

	statusCmd, statusOut, statusErr := newTestSandboxRuntimeCommand(deps)
	statusCmd.SetArgs([]string{"status", "local-worker", "rootless_podman", "--live", "--json"})
	if err := statusCmd.Execute(); err != nil {
		t.Fatalf("runtime status Execute() error = %v; stderr=%q", err, statusErr.String())
	}
	if gotStatus.HostID != "local-worker" || gotStatus.RuntimeID != "rootless_podman" || !gotStatus.Live || !gotStatus.JSON {
		t.Fatalf("runtime status request = %#v, want host/runtime ids with live/json flags", gotStatus)
	}
	if got := statusOut.String(); got != "status ok\n" {
		t.Fatalf("runtime status stdout = %q", got)
	}
}

func TestSandboxRuntimeGeneratedCLIReferenceLinks(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		wantFragments []string
	}{
		{
			name: "sandbox cli reference links runtime command",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox.md"),
			wantFragments: []string{
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
		{
			name: "runtime cli reference links subcommands",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime.md"),
			wantFragments: []string{
				"hal sandbox runtime list local-worker",
				"[hal sandbox runtime list](hal_sandbox_runtime_list.md)",
				"[hal sandbox runtime status](hal_sandbox_runtime_status.md)",
			},
		},
		{
			name: "runtime list cli reference links parent",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_list.md"),
			wantFragments: []string{
				SandboxRuntimeListContractVersion,
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
		{
			name: "runtime status cli reference links parent",
			path: filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_status.md"),
			wantFragments: []string{
				SandboxRuntimeStatusContractVersion,
				"[hal sandbox runtime](hal_sandbox_runtime.md)",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", tt.path, err)
			}
			text := string(data)
			for _, fragment := range tt.wantFragments {
				if !strings.Contains(text, fragment) {
					t.Fatalf("%s missing %q", tt.path, fragment)
				}
			}
		})
	}
}

func TestSandboxRuntimeListCachedWorkerHostStableAndSafe(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "worker-a",
		Name:     "builder",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
			sandbox.SandboxRuntimeDriverRootlessPodman,
			sandbox.SandboxRuntimeDriverSSHMachine,
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeSSHAgent},
				ActiveModes:    []string{sandbox.SandboxSecretModeLegacyAuthSync, sandbox.SandboxSecretModeEnv},
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime list should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "worker-a"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"Sandbox runtimes for builder (cached)",
		"cached durable runtime metadata",
		"worker-a",
		sandbox.SandboxHostKindWorker,
		"local Unix socket",
		"max 2 sandboxes",
		"requested network deny_by_default",
		"enforced network best_effort via none",
		"requested credentials ssh_agent",
		"active credentials env,legacy_auth_sync",
		"rootless_podman",
		"ssh_machine",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}
	rootlessIndex := strings.Index(output, sandbox.SandboxRuntimeDriverRootlessPodman)
	sshIndex := strings.Index(output, sandbox.SandboxRuntimeDriverSSHMachine)
	if rootlessIndex == -1 || sshIndex == -1 || rootlessIndex > sshIndex {
		t.Fatalf("runtime order in stdout = %q, want rootless_podman before ssh_machine", output)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("stdout leaked endpoint detail %q: %q", leaked, output)
		}
	}
}

func TestSandboxRuntimeListJSONCachedWorkerHostContractStableAndSafe(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "worker-a",
		Name:     "builder",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
			sandbox.SandboxRuntimeDriverRootlessPodman,
			sandbox.SandboxRuntimeDriverSSHMachine,
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeSSHAgent},
				ActiveModes:    []string{sandbox.SandboxSecretModeLegacyAuthSync, sandbox.SandboxSecretModeEnv},
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime list --json should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "worker-a", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}
	firstOutput := stdout.String()

	cmd2, stdout2, stderr2 := newTestSandboxRuntimeCommand(deps)
	cmd2.SetArgs([]string{"list", "worker-a", "--json"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second Execute() error = %v; stderr=%q", err, stderr2.String())
	}
	if stdout2.String() != firstOutput {
		t.Fatalf("repeated JSON output differed:\nfirst=%s\nsecond=%s", firstOutput, stdout2.String())
	}

	resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
	if resp.ContractType != SandboxRuntimeListContractType || resp.ContractVersion != SandboxRuntimeListContractVersion {
		t.Fatalf("contract identity = %q/%q, want %q/%q", resp.ContractType, resp.ContractVersion, SandboxRuntimeListContractType, SandboxRuntimeListContractVersion)
	}
	if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want cached durable source", resp.Source)
	}
	if resp.Host.ID != "worker-a" || resp.Host.Name != "builder" || resp.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("host identity = %#v, want worker-a builder worker", resp.Host)
	}
	if resp.Host.Endpoint.Type != "unix_socket" || resp.Host.Endpoint.Summary != "local Unix socket" || resp.Host.Endpoint.Scheme == nil || *resp.Host.Endpoint.Scheme != "unix" {
		t.Fatalf("endpoint = %#v, want safe Unix socket summary", resp.Host.Endpoint)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 2 || resp.Capacity.Summary != "max 2 sandboxes" {
		t.Fatalf("capacity = %#v, want cached max sandbox summary", resp.Capacity)
	}
	if resp.Security.Requested.NetworkPolicy == nil || *resp.Security.Requested.NetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("requested security = %#v, want durable requested network policy", resp.Security.Requested)
	}
	if resp.Security.Enforced.NetworkPolicy == nil || *resp.Security.Enforced.NetworkPolicy != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("enforced security = %#v, want durable enforced network policy", resp.Security.Enforced)
	}
	if resp.Security.Enforced.NetworkEnforcement == nil || *resp.Security.Enforced.NetworkEnforcement != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforced security = %#v, want durable network enforcement", resp.Security.Enforced)
	}
	if got := strings.Join(resp.Security.Requested.CredentialModes, ","); got != sandbox.SandboxSecretModeSSHAgent {
		t.Fatalf("requested credential modes = %q, want ssh_agent", got)
	}
	if got := strings.Join(resp.Security.Enforced.CredentialModes, ","); got != "env,legacy_auth_sync" {
		t.Fatalf("enforced credential modes = %q, want sorted active modes", got)
	}
	if len(resp.Runtimes) != 2 {
		t.Fatalf("runtime len = %d, want 2", len(resp.Runtimes))
	}
	if resp.Runtimes[0].ID != sandbox.SandboxRuntimeDriverRootlessPodman || resp.Runtimes[1].ID != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("runtime order = %#v, want sorted unique ids", resp.Runtimes)
	}
	for _, runtimeEntry := range resp.Runtimes {
		if runtimeEntry.HostKind != nil || runtimeEntry.IsolationLevel != nil {
			t.Fatalf("cached runtime entry = %#v, want sparse host/isolation metadata", runtimeEntry)
		}
		if len(runtimeEntry.SupportedOperations) != 0 || len(runtimeEntry.Diagnostics) != 0 {
			t.Fatalf("cached runtime entry = %#v, want empty operation/diagnostic arrays", runtimeEntry)
		}
	}
	if len(resp.Diagnostics) != 0 || len(resp.Errors) != 0 {
		t.Fatalf("diagnostics/errors = %#v/%#v, want empty arrays", resp.Diagnostics, resp.Errors)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(firstOutput, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, firstOutput)
		}
	}
	if strings.Contains(firstOutput, "Sandbox runtimes for builder") {
		t.Fatalf("JSON stdout included human list text: %q", firstOutput)
	}
}

func TestSandboxRuntimeListLiveWorkerHostRefreshesCapabilitiesWithoutPersisting(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 1, 14, 0, 0, 0, time.UTC)
	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID:   "worker-a",
			HostKind:   sandboxworker.HostKindLocal,
			SocketPath: "/tmp/worker-reported.sock",
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 4,
				ActiveSandboxes:        1,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID: "worker-a",
			Security: sandboxworker.SecurityPolicy{
				Requested: sandboxworker.SecurityControls{
					NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
					NetworkEnforcement: sandboxworker.NetworkEnforcementRuntime,
					CredentialModes:    []string{sandboxworker.CredentialModeSSHAgent},
					IsolationLevel:     sandboxworker.IsolationLevelContainer,
				},
				Enforced: sandboxworker.SecurityControls{
					NetworkPolicy:      sandboxworker.NetworkPolicyBestEffort,
					NetworkEnforcement: sandboxworker.NetworkEnforcementNone,
					CredentialModes: []string{
						sandboxworker.CredentialModeLegacyAuthSync,
						sandboxworker.CredentialModeEnv,
					},
					IsolationLevel: sandboxworker.IsolationLevelHost,
				},
			},
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverSSHMachine,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelHost,
					Operations: []string{
						sandboxworker.OperationStop,
						sandboxworker.OperationExec,
						sandboxworker.OperationCopyOut,
					},
					Security: sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelHost),
				},
				{
					ID:             sandboxworker.RuntimeDriverRootlessPodman,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelContainer,
					Operations: []string{
						sandboxworker.OperationStart,
						sandboxworker.OperationCopyIn,
						sandboxworker.OperationExec,
					},
					Security: sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelContainer),
				},
			},
		},
	}
	var clientSocketPath string
	deps := defaultSandboxRuntimeDeps()
	deps.now = func() time.Time { return refreshedAt }
	deps.newWorkerClient = func(socketPath string) (sandboxHostWorkerClient, error) {
		clientSocketPath = socketPath
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "worker-a", "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}
	if clientSocketPath != "/tmp/private/worker-a.sock" {
		t.Fatalf("client socket path = %q, want stripped local socket path", clientSocketPath)
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed || !resp.Source.RequestedLive || resp.Source.CacheUpdated {
		t.Fatalf("source = %#v, want live-refreshed without cache update", resp.Source)
	}
	if resp.Source.RefreshedAt == nil || !resp.Source.RefreshedAt.Equal(refreshedAt) {
		t.Fatalf("refreshedAt = %v, want %v", resp.Source.RefreshedAt, refreshedAt)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 4 ||
		resp.Capacity.ActiveSandboxes == nil || *resp.Capacity.ActiveSandboxes != 1 ||
		resp.Capacity.Summary != "1 of 4 sandboxes active" {
		t.Fatalf("capacity = %#v, want live worker capacity", resp.Capacity)
	}
	if len(resp.Runtimes) != 2 {
		t.Fatalf("runtime len = %d, want 2", len(resp.Runtimes))
	}
	rootless := resp.Runtimes[0]
	if rootless.ID != sandboxworker.RuntimeDriverRootlessPodman {
		t.Fatalf("first runtime = %#v, want rootless_podman sorted before ssh_machine", rootless)
	}
	if rootless.HostKind == nil || *rootless.HostKind != sandboxworker.HostKindLocal ||
		rootless.IsolationLevel == nil || *rootless.IsolationLevel != sandboxworker.IsolationLevelContainer {
		t.Fatalf("rootless runtime metadata = %#v, want live host kind/isolation", rootless)
	}
	if got := strings.Join(rootless.SupportedOperations, ","); got != "copy_in,exec,start" {
		t.Fatalf("rootless operations = %q, want sorted live operations", got)
	}
	if rootless.Security.Requested.IsolationLevel == nil || *rootless.Security.Requested.IsolationLevel != sandboxworker.IsolationLevelContainer {
		t.Fatalf("rootless security = %#v, want runtime isolation metadata", rootless.Security)
	}
	requireWorkerBestEffortPolicyResult(t, rootless.Security.NetworkPolicyResult)
	if resp.Security.Enforced.IsolationLevel == nil || *resp.Security.Enforced.IsolationLevel != sandboxworker.IsolationLevelHost {
		t.Fatalf("host security = %#v, want worker capability security", resp.Security)
	}
	requireWorkerBestEffortPolicyResult(t, resp.Security.NetworkPolicyResult)
	for _, leaked := range []string{"/tmp/private", "worker-a.sock", "worker-reported.sock"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, output)
		}
	}

	loaded, err := sandbox.LoadHost("worker-a")
	if err != nil {
		t.Fatalf("LoadHost(worker-a) error = %v", err)
	}
	if strings.Join(loaded.SupportedRuntimes, ",") != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("durable supported runtimes = %#v, want original cached metadata", loaded.SupportedRuntimes)
	}
	if loaded.Capacity == nil || loaded.Capacity.MaxConcurrentSandboxes != 2 {
		t.Fatalf("durable capacity = %#v, want original cached capacity", loaded.Capacity)
	}

	humanCmd, humanStdout, humanStderr := newTestSandboxRuntimeCommand(deps)
	humanCmd.SetArgs([]string{"list", "worker-a", "--live"})
	if err := humanCmd.Execute(); err != nil {
		t.Fatalf("human Execute() error = %v; stderr=%q", err, humanStderr.String())
	}
	humanOutput := humanStdout.String()
	for _, want := range []string{
		"Sandbox runtimes for builder (live-refreshed)",
		"live worker runtime capabilities",
		"1 of 4 sandboxes active",
		"rootless_podman",
		"local",
		"container",
		"copy_in,exec,start",
	} {
		if !strings.Contains(humanOutput, want) {
			t.Fatalf("human stdout = %q, want %q", humanOutput, want)
		}
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock", "worker-reported.sock"} {
		if strings.Contains(humanOutput, leaked) {
			t.Fatalf("human output leaked endpoint detail %q: %q", leaked, humanOutput)
		}
	}
}

func TestSandboxRuntimeListLiveWorkerClientFailureSanitizedAndDoesNotPersist(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID: "worker-a",
			HostKind: sandboxworker.HostKindLocal,
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilitiesErr: errors.New("dial /tmp/private/worker-a.sock failed token=supersecret"),
	}
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "worker-a", "--live", "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want live capabilities failure")
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want no partial JSON on live failure", got)
	}
	detail := err.Error() + "\n" + stderr.String()
	for _, leaked := range []string{"/tmp/private/worker-a.sock", "supersecret"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("live failure detail leaked %q: %q", leaked, detail)
		}
	}
	for _, want := range []string{"Sandbox Runtime List failed", "[redacted-path]", "token=[redacted]"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("live failure detail = %q, want %q", detail, want)
		}
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}
	loaded, loadErr := sandbox.LoadHost("worker-a")
	if loadErr != nil {
		t.Fatalf("LoadHost(worker-a) error = %v", loadErr)
	}
	if strings.Join(loaded.SupportedRuntimes, ",") != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("durable supported runtimes = %#v, want unchanged after failed live list", loaded.SupportedRuntimes)
	}
}

func TestSandboxRuntimeListJSONMissingHostEmitsEndpointSafeErrorDocument(t *testing.T) {
	setSandboxHostRegistryHome(t)
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime list missing-host path should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "missing-host", "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want missing host error")
	}

	resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
	if resp.ContractType != SandboxRuntimeListContractType || resp.ContractVersion != SandboxRuntimeListContractVersion {
		t.Fatalf("contract identity = %q/%q, want runtime list contract", resp.ContractType, resp.ContractVersion)
	}
	if resp.Host.ID != "missing-host" || resp.Host.Name != "missing-host" || resp.Host.Kind != "unknown" {
		t.Fatalf("host = %#v, want requested missing host identity", resp.Host)
	}
	if resp.Host.Endpoint.Type != "none" || resp.Host.Endpoint.Summary != "none" || resp.Host.Endpoint.Scheme != nil {
		t.Fatalf("endpoint = %#v, want empty safe endpoint", resp.Host.Endpoint)
	}
	if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want cached durable source", resp.Source)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorHostNotFound {
		t.Fatalf("errors = %#v, want host_not_found", resp.Errors)
	}
	if len(resp.Diagnostics) != 0 || len(resp.Runtimes) != 0 {
		t.Fatalf("diagnostics/runtimes = %#v/%#v, want empty arrays", resp.Diagnostics, resp.Runtimes)
	}
	detail := stdout.String() + "\n" + stderr.String()
	for _, leaked := range []string{os.Getenv("HAL_CONFIG_HOME"), "sandbox-hosts", ".json"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("missing host output leaked storage detail %q:\n%s", leaked, detail)
		}
	}
	if !strings.Contains(stderr.String(), `host "missing-host" was not found`) {
		t.Fatalf("stderr = %q, want requested host id", stderr.String())
	}
}

func TestSandboxRuntimeListLiveWorkerHostRequiresLocalSocketBeforeClient(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "worker-a",
		Name:     "builder",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "ssh://user:secret@example.internal/worker.sock?token=top-secret",
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("live runtime list should reject non-local worker endpoints before constructing a client")
		return nil, nil
	}

	cmd, _, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "worker-a", "--live"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want unsupported endpoint error")
	}
	detail := err.Error() + "\n" + stderr.String()
	if !strings.Contains(detail, "absolute local Unix socket path") {
		t.Fatalf("error detail = %q, want local Unix socket validation", detail)
	}
	for _, leaked := range []string{"user", "secret", "example.internal", "top-secret"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("error detail leaked endpoint value %q: %q", leaked, detail)
		}
	}
}

func TestSandboxRuntimeListCachedNonWorkerHostWithoutMetadataDurableOnly(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "ssh-a",
		Name:     "ssh-box",
		Kind:     sandbox.SandboxHostKindSSH,
		Endpoint: "ssh://deploy:secret@example.internal:22?token=top-secret",
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime list for non-worker hosts should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "ssh-a"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"Sandbox runtimes for ssh-box (cached)",
		"cached durable runtime metadata",
		"ssh-a",
		sandbox.SandboxHostKindSSH,
		"ssh endpoint",
		"No cached runtime metadata is available.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}
	for _, leaked := range []string{"deploy", "secret", "example.internal", "top-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("stdout leaked endpoint detail %q: %q", leaked, output)
		}
	}
}

func TestSandboxRuntimeListJSONCachedNonWorkerHostWithoutMetadataDurableOnly(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "local-a",
		Name:     "laptop",
		Kind:     sandbox.SandboxHostKindLocal,
		Endpoint: "https://user:secret@runtime.example.internal/api?token=top-secret",
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime list --json for non-worker hosts should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "local-a", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want cached durable source", resp.Source)
	}
	if resp.Host.ID != "local-a" || resp.Host.Name != "laptop" || resp.Host.Kind != sandbox.SandboxHostKindLocal {
		t.Fatalf("host identity = %#v, want local-a laptop local", resp.Host)
	}
	if resp.Host.Endpoint.Type != "endpoint" || resp.Host.Endpoint.Summary != "https endpoint" || resp.Host.Endpoint.Scheme == nil || *resp.Host.Endpoint.Scheme != "https" {
		t.Fatalf("endpoint = %#v, want safe HTTPS endpoint summary", resp.Host.Endpoint)
	}
	if len(resp.Runtimes) != 0 {
		t.Fatalf("runtime len = %d, want empty cached runtime list", len(resp.Runtimes))
	}
	if resp.Capacity.Summary != "unknown" || resp.Capacity.CPUCores != nil || resp.Capacity.MaxConcurrentSandboxes != nil {
		t.Fatalf("capacity = %#v, want sparse unknown capacity", resp.Capacity)
	}
	if len(resp.Security.Requested.CredentialModes) != 0 || len(resp.Security.Enforced.CredentialModes) != 0 {
		t.Fatalf("security = %#v, want sparse empty credential metadata", resp.Security)
	}
	if len(resp.Diagnostics) != 0 || len(resp.Errors) != 0 {
		t.Fatalf("diagnostics/errors = %#v/%#v, want empty arrays", resp.Diagnostics, resp.Errors)
	}
	for _, leaked := range []string{"user", "secret", "runtime.example.internal", "top-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, output)
		}
	}
	if strings.Contains(output, "No cached runtime metadata is available.") {
		t.Fatalf("JSON stdout included human no-metadata text: %q", output)
	}
}

func TestSandboxRuntimeListLiveNonWorkerHostUsesUnsupportedLiveCachedMetadata(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "ssh-1",
		Name:     "zeta",
		Kind:     sandbox.SandboxHostKindSSH,
		Endpoint: "ssh://deploy:secret@example.com:22/workspace?token=supersecret",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
			sandbox.SandboxRuntimeDriverRootlessPodman,
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 3},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyBestEffort,
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("runtime list --live should not contact worker daemons for non-worker hosts")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "ssh-1", "--live"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"Sandbox runtimes for zeta (unsupported-live)",
		"live runtime inspection is unsupported for host kind ssh; using cached durable metadata",
		"ssh endpoint",
		"max 3 sandboxes",
		"requested network best_effort",
		sandbox.SandboxRuntimeDriverRootlessPodman,
		sandbox.SandboxRuntimeDriverSSHMachine,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}
	for _, leaked := range []string{"deploy", "secret", "example.com", "token=supersecret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("stdout leaked endpoint detail %q: %q", leaked, output)
		}
	}
}

func TestSandboxRuntimeListJSONLiveNonWorkerHostUsesUnsupportedLiveCachedMetadata(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "local-a",
		Name:     "laptop",
		Kind:     sandbox.SandboxHostKindLocal,
		Endpoint: "https://user:secret@runtime.example.internal/api?token=top-secret",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("runtime list --live --json should not contact worker daemons for non-worker hosts")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"list", "local-a", "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceUnsupportedLive || !resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want unsupported-live without cache update", resp.Source)
	}
	if !strings.Contains(resp.Source.Summary, "host kind local") {
		t.Fatalf("source summary = %q, want host kind", resp.Source.Summary)
	}
	if resp.Host.ID != "local-a" || resp.Host.Name != "laptop" || resp.Host.Kind != sandbox.SandboxHostKindLocal {
		t.Fatalf("host identity = %#v, want local-a laptop local", resp.Host)
	}
	if resp.Host.Endpoint.Type != "endpoint" || resp.Host.Endpoint.Summary != "https endpoint" || resp.Host.Endpoint.Scheme == nil || *resp.Host.Endpoint.Scheme != "https" {
		t.Fatalf("endpoint = %#v, want safe HTTPS endpoint summary", resp.Host.Endpoint)
	}
	if len(resp.Runtimes) != 1 || resp.Runtimes[0].ID != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("runtimes = %#v, want cached ssh_machine metadata", resp.Runtimes)
	}
	if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Code != SandboxRuntimeStatusErrorLiveUnsupported || resp.Diagnostics[0].Severity != "warning" {
		t.Fatalf("diagnostics = %#v, want live_unsupported warning", resp.Diagnostics)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("errors = %#v, want empty errors", resp.Errors)
	}
	for _, leaked := range []string{"user", "secret", "runtime.example.internal", "top-secret"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, output)
		}
	}
	if strings.Contains(output, "Sandbox runtimes for laptop") {
		t.Fatalf("JSON stdout included human list text: %q", output)
	}
}

func TestSandboxRuntimeStatusCachedWorkerRuntimeStableAndSafe(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "worker-a",
		Name:     "builder",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
			sandbox.SandboxRuntimeDriverRootlessPodman,
			sandbox.SandboxRuntimeDriverSSHMachine,
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeSSHAgent},
				ActiveModes:    []string{sandbox.SandboxSecretModeLegacyAuthSync, sandbox.SandboxSecretModeEnv},
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime status should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"Sandbox runtime rootless_podman on builder (cached)",
		"cached durable runtime metadata",
		"worker-a",
		sandbox.SandboxHostKindWorker,
		"local Unix socket",
		"Runtime ID",
		sandbox.SandboxRuntimeDriverRootlessPodman,
		"unknown (cached metadata confirms runtime registration; live readiness unknown)",
		"max 2 sandboxes",
		"requested network deny_by_default",
		"enforced network best_effort via none",
		"requested credentials ssh_agent",
		"active credentials env,legacy_auth_sync",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("stdout leaked endpoint detail %q: %q", leaked, output)
		}
	}
}

func TestSandboxRuntimeStatusJSONCachedWorkerRuntimeContractStableAndSafe(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "worker-a",
		Name:     "builder",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverSSHMachine,
			sandbox.SandboxRuntimeDriverRootlessPodman,
			sandbox.SandboxRuntimeDriverSSHMachine,
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeSSHAgent},
				ActiveModes:    []string{sandbox.SandboxSecretModeLegacyAuthSync, sandbox.SandboxSecretModeEnv},
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime status --json should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}
	firstOutput := stdout.String()

	cmd2, stdout2, stderr2 := newTestSandboxRuntimeCommand(deps)
	cmd2.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second Execute() error = %v; stderr=%q", err, stderr2.String())
	}
	if stdout2.String() != firstOutput {
		t.Fatalf("repeated JSON output differed:\nfirst=%s\nsecond=%s", firstOutput, stdout2.String())
	}

	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.ContractType != SandboxRuntimeStatusContractType || resp.ContractVersion != SandboxRuntimeStatusContractVersion {
		t.Fatalf("contract identity = %q/%q, want %q/%q", resp.ContractType, resp.ContractVersion, SandboxRuntimeStatusContractType, SandboxRuntimeStatusContractVersion)
	}
	if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want cached durable source", resp.Source)
	}
	if resp.Host.ID != "worker-a" || resp.Host.Name != "builder" || resp.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("host identity = %#v, want worker-a builder worker", resp.Host)
	}
	if resp.Host.Endpoint.Type != "unix_socket" || resp.Host.Endpoint.Summary != "local Unix socket" || resp.Host.Endpoint.Scheme == nil || *resp.Host.Endpoint.Scheme != "unix" {
		t.Fatalf("endpoint = %#v, want safe Unix socket summary", resp.Host.Endpoint)
	}
	if resp.Runtime.ID != sandbox.SandboxRuntimeDriverRootlessPodman || resp.Runtime.HostKind != nil || resp.Runtime.IsolationLevel != nil {
		t.Fatalf("runtime identity = %#v, want cached sparse runtime metadata", resp.Runtime)
	}
	if len(resp.SupportedOperations) != 0 {
		t.Fatalf("supported operations = %#v, want empty cached operation metadata", resp.SupportedOperations)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessUnknown || resp.Readiness.CheckedAt != nil ||
		resp.Readiness.Summary != "cached metadata confirms runtime registration; live readiness unknown" {
		t.Fatalf("readiness = %#v, want cached unknown readiness", resp.Readiness)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 2 || resp.Capacity.Summary != "max 2 sandboxes" {
		t.Fatalf("capacity = %#v, want cached max sandbox summary", resp.Capacity)
	}
	if resp.Security.Requested.NetworkPolicy == nil || *resp.Security.Requested.NetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("requested security = %#v, want durable requested network policy", resp.Security.Requested)
	}
	if resp.Security.Enforced.NetworkPolicy == nil || *resp.Security.Enforced.NetworkPolicy != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("enforced security = %#v, want durable enforced network policy", resp.Security.Enforced)
	}
	if resp.Security.Enforced.NetworkEnforcement == nil || *resp.Security.Enforced.NetworkEnforcement != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforced security = %#v, want durable network enforcement", resp.Security.Enforced)
	}
	if got := strings.Join(resp.Security.Enforced.CredentialModes, ","); got != "env,legacy_auth_sync" {
		t.Fatalf("enforced credential modes = %q, want sorted active modes", got)
	}
	if len(resp.Diagnostics) != 0 || len(resp.Errors) != 0 {
		t.Fatalf("diagnostics/errors = %#v/%#v, want empty arrays", resp.Diagnostics, resp.Errors)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(firstOutput, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, firstOutput)
		}
	}
	if strings.Contains(firstOutput, "Sandbox runtime rootless_podman") {
		t.Fatalf("JSON stdout included human status text: %q", firstOutput)
	}
}

func TestSandboxRuntimeStatusLiveWorkerRuntimeRefreshesCapabilitiesWithoutPersisting(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 1, 15, 0, 0, 0, time.UTC)
	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID: "worker-a",
			HostKind: sandboxworker.HostKindLocal,
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 4,
				ActiveSandboxes:        1,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID: "worker-a",
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverRootlessPodman,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelContainer,
					Operations: []string{
						sandboxworker.OperationStart,
						sandboxworker.OperationExec,
						sandboxworker.OperationCopyIn,
					},
					Security: sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelContainer),
				},
				{
					ID:             sandboxworker.RuntimeDriverSSHMachine,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelHost,
					Operations:     []string{sandboxworker.OperationExec},
					Security:       sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelHost),
				},
			},
		},
	}
	var clientSocketPath string
	deps := defaultSandboxRuntimeDeps()
	deps.now = func() time.Time { return refreshedAt }
	deps.newWorkerClient = func(socketPath string) (sandboxHostWorkerClient, error) {
		clientSocketPath = socketPath
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman, "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}
	if clientSocketPath != "/tmp/private/worker-a.sock" {
		t.Fatalf("client socket path = %q, want stripped local socket path", clientSocketPath)
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed || !resp.Source.RequestedLive || resp.Source.CacheUpdated {
		t.Fatalf("source = %#v, want live-refreshed without cache update", resp.Source)
	}
	if resp.Source.RefreshedAt == nil || !resp.Source.RefreshedAt.Equal(refreshedAt) {
		t.Fatalf("refreshedAt = %v, want %v", resp.Source.RefreshedAt, refreshedAt)
	}
	if resp.Runtime.ID != sandboxworker.RuntimeDriverRootlessPodman ||
		resp.Runtime.HostKind == nil || *resp.Runtime.HostKind != sandboxworker.HostKindLocal ||
		resp.Runtime.IsolationLevel == nil || *resp.Runtime.IsolationLevel != sandboxworker.IsolationLevelContainer {
		t.Fatalf("runtime = %#v, want live runtime metadata", resp.Runtime)
	}
	if got := strings.Join(resp.SupportedOperations, ","); got != "copy_in,exec,start" {
		t.Fatalf("supported operations = %q, want sorted live operations", got)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessReady || resp.Readiness.CheckedAt == nil ||
		!resp.Readiness.CheckedAt.Equal(refreshedAt) || resp.Readiness.Summary != "worker health is healthy" {
		t.Fatalf("readiness = %#v, want live healthy readiness", resp.Readiness)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 4 ||
		resp.Capacity.ActiveSandboxes == nil || *resp.Capacity.ActiveSandboxes != 1 ||
		resp.Capacity.Summary != "1 of 4 sandboxes active" {
		t.Fatalf("capacity = %#v, want live worker capacity", resp.Capacity)
	}
	if resp.Security.Requested.IsolationLevel == nil || *resp.Security.Requested.IsolationLevel != sandboxworker.IsolationLevelContainer ||
		resp.Security.Enforced.IsolationLevel == nil || *resp.Security.Enforced.IsolationLevel != sandboxworker.IsolationLevelContainer {
		t.Fatalf("security = %#v, want runtime driver security", resp.Security)
	}
	if len(resp.Diagnostics) != 0 || len(resp.Errors) != 0 {
		t.Fatalf("diagnostics/errors = %#v/%#v, want empty arrays", resp.Diagnostics, resp.Errors)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("JSON output leaked endpoint detail %q: %q", leaked, output)
		}
	}

	loaded, err := sandbox.LoadHost("worker-a")
	if err != nil {
		t.Fatalf("LoadHost(worker-a) error = %v", err)
	}
	if strings.Join(loaded.SupportedRuntimes, ",") != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("durable supported runtimes = %#v, want original cached metadata", loaded.SupportedRuntimes)
	}
	if loaded.Capacity == nil || loaded.Capacity.MaxConcurrentSandboxes != 2 {
		t.Fatalf("durable capacity = %#v, want original cached capacity", loaded.Capacity)
	}

	humanCmd, humanStdout, humanStderr := newTestSandboxRuntimeCommand(deps)
	humanCmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman, "--live"})
	if err := humanCmd.Execute(); err != nil {
		t.Fatalf("human Execute() error = %v; stderr=%q", err, humanStderr.String())
	}
	humanOutput := humanStdout.String()
	for _, want := range []string{
		"Sandbox runtime rootless_podman on builder (live-refreshed)",
		"live worker runtime capabilities",
		"ready (worker health is healthy)",
		"copy_in,exec,start",
		"1 of 4 sandboxes active",
		"container",
	} {
		if !strings.Contains(humanOutput, want) {
			t.Fatalf("human stdout = %q, want %q", humanOutput, want)
		}
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(humanOutput, leaked) {
			t.Fatalf("human output leaked endpoint detail %q: %q", leaked, humanOutput)
		}
	}
}

func TestSandboxRuntimeStatusLiveWorkerMissingRuntimeEmitsEndpointSafeErrorDocument(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 1, 15, 30, 0, 0, time.UTC)
	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID: "worker-a",
			HostKind: sandboxworker.HostKindLocal,
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 3,
				ActiveSandboxes:        0,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID: "worker-a",
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverSSHMachine,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelHost,
					Operations:     []string{sandboxworker.OperationExec},
					Security:       sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelHost),
				},
			},
		},
	}
	deps := defaultSandboxRuntimeDeps()
	deps.now = func() time.Time { return refreshedAt }
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverMicroVM, "--live", "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want missing live runtime error")
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed || !resp.Source.RequestedLive || resp.Source.CacheUpdated ||
		resp.Source.RefreshedAt == nil || !resp.Source.RefreshedAt.Equal(refreshedAt) {
		t.Fatalf("source = %#v, want live-refreshed missing-runtime source", resp.Source)
	}
	if resp.Runtime.ID != sandbox.SandboxRuntimeDriverMicroVM || resp.Runtime.HostKind != nil || resp.Runtime.IsolationLevel != nil {
		t.Fatalf("runtime = %#v, want requested sparse runtime identity", resp.Runtime)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessUnavailable || resp.Readiness.CheckedAt == nil ||
		!resp.Readiness.CheckedAt.Equal(refreshedAt) || resp.Readiness.Summary != "runtime is not advertised by this worker" {
		t.Fatalf("readiness = %#v, want unavailable live missing runtime", resp.Readiness)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 3 ||
		resp.Capacity.ActiveSandboxes == nil || *resp.Capacity.ActiveSandboxes != 0 {
		t.Fatalf("capacity = %#v, want live worker capacity", resp.Capacity)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorRuntimeNotFound {
		t.Fatalf("errors = %#v, want runtime_not_found", resp.Errors)
	}
	if len(resp.Diagnostics) != 0 || len(resp.SupportedOperations) != 0 {
		t.Fatalf("diagnostics/operations = %#v/%#v, want empty arrays", resp.Diagnostics, resp.SupportedOperations)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(output, leaked) || strings.Contains(stderr.String(), leaked) {
			t.Fatalf("missing-runtime output leaked endpoint detail %q:\nstdout=%s\nstderr=%s", leaked, output, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), `runtime "microvm" is not advertised by this worker`) {
		t.Fatalf("stderr = %q, want requested runtime id", stderr.String())
	}
	if strings.Contains(stderr.String(), "worker-a") {
		t.Fatalf("missing runtime human error named host id: %q", stderr.String())
	}
}

func TestSandboxRuntimeStatusJSONLiveNonWorkerMissingRuntimeUsesUnsupportedLiveCachedMetadata(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "ssh-a",
		Name:              "ssh-box",
		Kind:              sandbox.SandboxHostKindSSH,
		Endpoint:          "ssh://deploy:secret@example.internal:22/workspace?token=top-secret",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyBestEffort,
			},
		},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("runtime status --live --json should not contact worker daemons for non-worker hosts")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "ssh-a", sandbox.SandboxRuntimeDriverMicroVM, "--live", "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want missing runtime error")
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceUnsupportedLive || !resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want unsupported-live without cache update", resp.Source)
	}
	if !strings.Contains(resp.Source.Summary, "host kind ssh") {
		t.Fatalf("source summary = %q, want host kind", resp.Source.Summary)
	}
	if resp.Host.ID != "ssh-a" || resp.Host.Name != "ssh-box" || resp.Host.Kind != sandbox.SandboxHostKindSSH {
		t.Fatalf("host identity = %#v, want ssh-a ssh-box ssh", resp.Host)
	}
	if resp.Host.Endpoint.Type != "endpoint" || resp.Host.Endpoint.Summary != "ssh endpoint" || resp.Host.Endpoint.Scheme == nil || *resp.Host.Endpoint.Scheme != "ssh" {
		t.Fatalf("endpoint = %#v, want safe SSH endpoint summary", resp.Host.Endpoint)
	}
	if resp.Runtime.ID != sandbox.SandboxRuntimeDriverMicroVM || resp.Runtime.HostKind != nil || resp.Runtime.IsolationLevel != nil {
		t.Fatalf("runtime = %#v, want requested sparse runtime identity", resp.Runtime)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessUnavailable || resp.Readiness.Summary != "runtime is not registered for this host" {
		t.Fatalf("readiness = %#v, want missing runtime unavailable", resp.Readiness)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 2 {
		t.Fatalf("capacity = %#v, want cached host capacity", resp.Capacity)
	}
	if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Code != SandboxRuntimeStatusErrorLiveUnsupported || resp.Diagnostics[0].Severity != "warning" {
		t.Fatalf("diagnostics = %#v, want live_unsupported warning", resp.Diagnostics)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorRuntimeNotFound {
		t.Fatalf("errors = %#v, want runtime_not_found", resp.Errors)
	}
	for _, leaked := range []string{"deploy", "secret", "example.internal", "top-secret"} {
		if strings.Contains(output, leaked) || strings.Contains(stderr.String(), leaked) {
			t.Fatalf("missing-runtime output leaked endpoint detail %q:\nstdout=%s\nstderr=%s", leaked, output, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), `runtime "microvm" is not registered for this host`) {
		t.Fatalf("stderr = %q, want requested runtime id", stderr.String())
	}
}

func TestSandboxRuntimeStatusLiveWorkerClientFailureSanitizedAndDoesNotPersist(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	fakeClient := &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID: "worker-a",
			HostKind: sandboxworker.HostKindLocal,
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilitiesErr: errors.New("dial /tmp/private/worker-a.sock failed token=supersecret"),
	}
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverRootlessPodman, "--live", "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want live capabilities failure")
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want no partial JSON on live failure", got)
	}
	detail := err.Error() + "\n" + stderr.String()
	for _, leaked := range []string{"/tmp/private/worker-a.sock", "supersecret"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("live failure detail leaked %q: %q", leaked, detail)
		}
	}
	for _, want := range []string{"Sandbox Runtime Status failed", "[redacted-path]", "token=[redacted]"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("live failure detail = %q, want %q", detail, want)
		}
	}
	if fakeClient.statusCalls != 1 || fakeClient.capabilitiesCalls != 1 {
		t.Fatalf("worker calls status=%d capabilities=%d, want one each", fakeClient.statusCalls, fakeClient.capabilitiesCalls)
	}
	loaded, loadErr := sandbox.LoadHost("worker-a")
	if loadErr != nil {
		t.Fatalf("LoadHost(worker-a) error = %v", loadErr)
	}
	if strings.Join(loaded.SupportedRuntimes, ",") != sandbox.SandboxRuntimeDriverSSHMachine {
		t.Fatalf("durable supported runtimes = %#v, want unchanged after failed live status", loaded.SupportedRuntimes)
	}
}

func TestSandboxRuntimeStatusJSONMissingHostEmitsEndpointSafeErrorDocument(t *testing.T) {
	setSandboxHostRegistryHome(t)
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime status missing-host path should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "missing-host", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want missing host error")
	}

	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.ContractType != SandboxRuntimeStatusContractType || resp.ContractVersion != SandboxRuntimeStatusContractVersion {
		t.Fatalf("contract identity = %q/%q, want runtime status contract", resp.ContractType, resp.ContractVersion)
	}
	if resp.Host.ID != "missing-host" || resp.Host.Name != "missing-host" || resp.Host.Kind != "unknown" {
		t.Fatalf("host = %#v, want requested missing host identity", resp.Host)
	}
	if resp.Host.Endpoint.Type != "none" || resp.Host.Endpoint.Summary != "none" || resp.Host.Endpoint.Scheme != nil {
		t.Fatalf("endpoint = %#v, want empty safe endpoint", resp.Host.Endpoint)
	}
	if resp.Runtime.ID != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("runtime = %#v, want requested runtime id", resp.Runtime)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessUnavailable {
		t.Fatalf("readiness = %#v, want unavailable", resp.Readiness)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorHostNotFound {
		t.Fatalf("errors = %#v, want host_not_found", resp.Errors)
	}
	if len(resp.Diagnostics) != 0 || len(resp.SupportedOperations) != 0 {
		t.Fatalf("diagnostics/operations = %#v/%#v, want empty arrays", resp.Diagnostics, resp.SupportedOperations)
	}
	detail := stderr.String()
	if !strings.Contains(detail, `host "missing-host" was not found`) {
		t.Fatalf("stderr = %q, want requested host id", detail)
	}
	if strings.Contains(detail, sandbox.SandboxRuntimeDriverRootlessPodman) {
		t.Fatalf("missing host human error named runtime id: %q", detail)
	}
}

func TestSandboxRuntimeStatusJSONMissingRuntimeEmitsEndpointSafeErrorDocument(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime status missing-runtime path should not contact worker daemons")
		return nil, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverMicroVM, "--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want missing runtime error")
	}

	output := stdout.String()
	resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
	if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
		t.Fatalf("source = %#v, want cached durable source", resp.Source)
	}
	if resp.Host.ID != "worker-a" || resp.Host.Name != "builder" || resp.Host.Endpoint.Summary != "local Unix socket" {
		t.Fatalf("host = %#v, want safe cached host identity", resp.Host)
	}
	if resp.Runtime.ID != sandbox.SandboxRuntimeDriverMicroVM || resp.Runtime.HostKind != nil || resp.Runtime.IsolationLevel != nil {
		t.Fatalf("runtime = %#v, want requested sparse runtime identity", resp.Runtime)
	}
	if resp.Readiness.Status != SandboxRuntimeReadinessUnavailable || resp.Readiness.Summary != "runtime is not registered for this host" {
		t.Fatalf("readiness = %#v, want missing runtime unavailable", resp.Readiness)
	}
	if resp.Capacity.MaxConcurrentSandboxes == nil || *resp.Capacity.MaxConcurrentSandboxes != 2 {
		t.Fatalf("capacity = %#v, want cached host capacity", resp.Capacity)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorRuntimeNotFound {
		t.Fatalf("errors = %#v, want runtime_not_found", resp.Errors)
	}
	if len(resp.Diagnostics) != 0 || len(resp.SupportedOperations) != 0 {
		t.Fatalf("diagnostics/operations = %#v/%#v, want empty arrays", resp.Diagnostics, resp.SupportedOperations)
	}
	for _, leaked := range []string{"/tmp/private", "worker-a.sock"} {
		if strings.Contains(output, leaked) || strings.Contains(stderr.String(), leaked) {
			t.Fatalf("missing-runtime output leaked endpoint detail %q:\nstdout=%s\nstderr=%s", leaked, output, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), `runtime "microvm" is not registered for this host`) {
		t.Fatalf("stderr = %q, want requested runtime id", stderr.String())
	}
	if strings.Contains(stderr.String(), "worker-a") {
		t.Fatalf("missing runtime human error named host id: %q", stderr.String())
	}
}

func TestSandboxRuntimeStatusHumanMissingErrorsNameOnlyRequestedIdentity(t *testing.T) {
	setSandboxHostRegistryHome(t)
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("cached sandbox runtime status error paths should not contact worker daemons")
		return nil, nil
	}

	missingHostCmd, missingHostStdout, missingHostStderr := newTestSandboxRuntimeCommand(deps)
	missingHostCmd.SetArgs([]string{"status", "missing-host", sandbox.SandboxRuntimeDriverRootlessPodman})
	err := missingHostCmd.Execute()
	if err == nil {
		t.Fatal("missing host Execute() error = nil")
	}
	if got := missingHostStdout.String(); got != "" {
		t.Fatalf("missing host stdout = %q, want empty", got)
	}
	missingHostDetail := missingHostStderr.String()
	if !strings.Contains(missingHostDetail, `host "missing-host" was not found`) {
		t.Fatalf("missing host stderr = %q, want requested host id", missingHostDetail)
	}
	if strings.Contains(missingHostDetail, sandbox.SandboxRuntimeDriverRootlessPodman) {
		t.Fatalf("missing host stderr named runtime id: %q", missingHostDetail)
	}

	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-a.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	missingRuntimeCmd, missingRuntimeStdout, missingRuntimeStderr := newTestSandboxRuntimeCommand(deps)
	missingRuntimeCmd.SetArgs([]string{"status", "worker-a", sandbox.SandboxRuntimeDriverMicroVM})
	err = missingRuntimeCmd.Execute()
	if err == nil {
		t.Fatal("missing runtime Execute() error = nil")
	}
	if got := missingRuntimeStdout.String(); got != "" {
		t.Fatalf("missing runtime stdout = %q, want empty", got)
	}
	missingRuntimeDetail := missingRuntimeStderr.String()
	if !strings.Contains(missingRuntimeDetail, `runtime "microvm" is not registered for this host`) {
		t.Fatalf("missing runtime stderr = %q, want requested runtime id", missingRuntimeDetail)
	}
	for _, leaked := range []string{"worker-a", "builder", "/tmp/private", "worker-a.sock"} {
		if strings.Contains(missingRuntimeDetail, leaked) {
			t.Fatalf("missing runtime stderr leaked host detail %q: %q", leaked, missingRuntimeDetail)
		}
	}
}

func TestSandboxRuntimeOutputSafetyMatrix(t *testing.T) {
	refreshedAt := time.Date(2026, 7, 1, 16, 0, 0, 0, time.UTC)
	credentialedEndpoint := "ssh://user:s3cr3t-value@runtime.internal:22/workspace?token=top-secret"
	forbidden := []string{
		"/tmp/private",
		".sock",
		"s3cr3t-value",
		"runtime.internal",
		"token=top-secret",
		"top-secret",
		"supersecret",
	}

	tests := []struct {
		name       string
		host       *sandbox.SandboxHost
		args       []string
		client     *fakeSandboxHostWorkerClient
		wantErr    bool
		wantErrOut []string
		check      func(*testing.T, []byte)
	}{
		{
			name: "cached human list raw socket endpoint",
			host: &sandbox.SandboxHost{
				ID:                "worker-raw",
				Name:              "raw-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "/tmp/private/worker-raw.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args: []string{"list", "worker-raw"},
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				output := string(stdout)
				if !strings.Contains(output, "local Unix socket") {
					t.Fatalf("stdout = %q, want safe Unix socket summary", output)
				}
			},
		},
		{
			name: "cached json list credentialed endpoint",
			host: &sandbox.SandboxHost{
				ID:       "ssh-json",
				Name:     "ssh-json",
				Kind:     sandbox.SandboxHostKindSSH,
				Endpoint: credentialedEndpoint,
				Security: &sandbox.SandboxSecurity{
					Network: &sandbox.SandboxNetworkSecurity{
						PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
						PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
						EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
					},
				},
			},
			args: []string{"list", "ssh-json", "--json"},
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				resp := decodeOneSandboxRuntimeListJSON(t, stdout)
				if resp.Host.Endpoint.Type != "endpoint" || resp.Host.Endpoint.Summary != "ssh endpoint" {
					t.Fatalf("endpoint = %#v, want safe scheme-only endpoint", resp.Host.Endpoint)
				}
				if resp.Source.Mode != SandboxRuntimeSourceCached {
					t.Fatalf("source = %#v, want cached", resp.Source)
				}
				assertSandboxRuntimeListResponseDoesNotOverclaimSecurity(t, resp)
			},
		},
		{
			name: "live human status worker endpoint",
			host: &sandbox.SandboxHost{
				ID:                "worker-live",
				Name:              "live-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "unix:///tmp/private/worker-live.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args:   []string{"status", "worker-live", sandbox.SandboxRuntimeDriverRootlessPodman, "--live"},
			client: newSandboxRuntimeSafetyWorkerClient("worker-live"),
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				output := string(stdout)
				for _, want := range []string{
					"live-refreshed",
					"local Unix socket",
					"requested network deny_by_default",
					"enforced network best_effort via none",
					"requested isolation container",
					"enforced isolation container",
				} {
					if !strings.Contains(output, want) {
						t.Fatalf("stdout = %q, want %q", output, want)
					}
				}
				for _, unsupported := range []string{"enforced network deny_by_default", "via firewall", "via proxy", "enforced isolation microvm", "enforced credential proxy true"} {
					if strings.Contains(output, unsupported) {
						t.Fatalf("stdout made unsupported security claim %q: %q", unsupported, output)
					}
				}
			},
		},
		{
			name: "live json list raw socket endpoint",
			host: &sandbox.SandboxHost{
				ID:                "worker-json-live",
				Name:              "json-live-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "/tmp/private/worker-json-live.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			},
			args:   []string{"list", "worker-json-live", "--live", "--json"},
			client: newSandboxRuntimeSafetyWorkerClient("worker-json-live"),
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				resp := decodeOneSandboxRuntimeListJSON(t, stdout)
				if resp.Host.Endpoint.Type != "unix_socket" || resp.Host.Endpoint.Summary != "local Unix socket" {
					t.Fatalf("endpoint = %#v, want safe Unix socket summary", resp.Host.Endpoint)
				}
				if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed {
					t.Fatalf("source = %#v, want live-refreshed", resp.Source)
				}
				assertSandboxRuntimeListResponseDoesNotOverclaimSecurity(t, resp)
			},
		},
		{
			name: "unsupported-live human list credentialed endpoint",
			host: &sandbox.SandboxHost{
				ID:                "ssh-live",
				Name:              "ssh-live",
				Kind:              sandbox.SandboxHostKindSSH,
				Endpoint:          credentialedEndpoint,
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			},
			args: []string{"list", "ssh-live", "--live"},
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				output := string(stdout)
				for _, want := range []string{"unsupported-live", "ssh endpoint"} {
					if !strings.Contains(output, want) {
						t.Fatalf("stdout = %q, want %q", output, want)
					}
				}
			},
		},
		{
			name: "unsupported-live json status credentialed endpoint",
			host: &sandbox.SandboxHost{
				ID:                "ssh-status",
				Name:              "ssh-status",
				Kind:              sandbox.SandboxHostKindSSH,
				Endpoint:          credentialedEndpoint,
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			},
			args: []string{"status", "ssh-status", sandbox.SandboxRuntimeDriverSSHMachine, "--live", "--json"},
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				resp := decodeOneSandboxRuntimeStatusJSON(t, stdout)
				if resp.Host.Endpoint.Type != "endpoint" || resp.Host.Endpoint.Summary != "ssh endpoint" {
					t.Fatalf("endpoint = %#v, want safe scheme-only endpoint", resp.Host.Endpoint)
				}
				if resp.Source.Mode != SandboxRuntimeSourceUnsupportedLive {
					t.Fatalf("source = %#v, want unsupported-live", resp.Source)
				}
				assertSandboxRuntimeStatusResponseDoesNotOverclaimSecurity(t, resp)
			},
		},
		{
			name: "cached human missing-runtime error",
			host: &sandbox.SandboxHost{
				ID:                "worker-missing",
				Name:              "missing-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "/tmp/private/worker-missing.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args:    []string{"status", "worker-missing", "unknown_runtime"},
			wantErr: true,
		},
		{
			name: "cached json missing-runtime error document",
			host: &sandbox.SandboxHost{
				ID:                "worker-missing-json",
				Name:              "missing-json-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "/tmp/private/worker-missing-json.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args:    []string{"status", "worker-missing-json", "unknown_runtime", "--json"},
			wantErr: true,
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				resp := decodeOneSandboxRuntimeStatusJSON(t, stdout)
				if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorRuntimeNotFound {
					t.Fatalf("errors = %#v, want runtime_not_found", resp.Errors)
				}
				assertSandboxRuntimeStatusResponseDoesNotOverclaimSecurity(t, resp)
			},
		},
		{
			name: "live json worker client failure",
			host: &sandbox.SandboxHost{
				ID:                "worker-failure",
				Name:              "failure-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "unix:///tmp/private/worker-failure.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args: []string{"status", "worker-failure", sandbox.SandboxRuntimeDriverRootlessPodman, "--live", "--json"},
			client: &fakeSandboxHostWorkerClient{
				status: &sandboxworker.Status{
					WorkerID: "worker-failure",
					HostKind: sandboxworker.HostKindLocal,
					Health: sandboxworker.WorkerHealth{
						Status: sandboxworker.HealthStatusHealthy,
					},
					Security: sandboxworker.DefaultWorkerSecurityPolicy(),
				},
				capabilitiesErr: errors.New("dial /tmp/private/worker-failure.sock failed token=supersecret"),
			},
			wantErr:    true,
			wantErrOut: []string{"[redacted-path]", "token=[redacted]"},
			check: func(t *testing.T, stdout []byte) {
				t.Helper()
				if len(stdout) != 0 {
					t.Fatalf("stdout = %q, want no partial JSON on live client failure", string(stdout))
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHostRegistryHome(t)
			if tt.host != nil {
				if err := sandbox.SaveHost(tt.host); err != nil {
					t.Fatalf("SaveHost() error = %v", err)
				}
			}

			deps := defaultSandboxRuntimeDeps()
			deps.now = func() time.Time { return refreshedAt }
			deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
				if tt.client == nil {
					t.Fatal("sandbox runtime safety test unexpectedly constructed a worker client")
				}
				return tt.client, nil
			}

			cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Execute() error = nil, want error")
				}
			} else if err != nil {
				t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
			}

			combined := stdout.String() + "\n" + stderr.String()
			if err != nil {
				combined += "\n" + err.Error()
			}
			assertSandboxRuntimeOutputOmits(t, combined, forbidden)
			for _, want := range tt.wantErrOut {
				if !strings.Contains(combined, want) {
					t.Fatalf("combined output = %q, want sanitized marker %q", combined, want)
				}
			}
			if tt.check != nil {
				tt.check(t, stdout.Bytes())
			}
		})
	}
}

func newSandboxRuntimeSafetyWorkerClient(workerID string) *fakeSandboxHostWorkerClient {
	return &fakeSandboxHostWorkerClient{
		status: &sandboxworker.Status{
			WorkerID:   workerID,
			HostKind:   sandboxworker.HostKindLocal,
			SocketPath: "/tmp/private/reported-live.sock",
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Capacity: sandboxworker.WorkerCapacity{
				MaxConcurrentSandboxes: 2,
				ActiveSandboxes:        1,
			},
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
		},
		capabilities: &sandboxworker.Capabilities{
			WorkerID: workerID,
			Security: sandboxworker.DefaultWorkerSecurityPolicy(),
			RuntimeDrivers: []sandboxworker.RuntimeDriver{
				{
					ID:             sandboxworker.RuntimeDriverRootlessPodman,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelContainer,
					Operations:     []string{sandboxworker.OperationExec},
					Security:       sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelContainer),
				},
				{
					ID:             sandboxworker.RuntimeDriverSSHMachine,
					HostKind:       sandboxworker.HostKindLocal,
					IsolationLevel: sandboxworker.IsolationLevelHost,
					Operations:     []string{sandboxworker.OperationExec},
					Security:       sandboxRuntimeTestWorkerSecurity(sandboxworker.IsolationLevelHost),
				},
			},
		},
	}
}

func assertSandboxRuntimeOutputOmits(t *testing.T, output string, forbidden []string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("runtime output leaked sensitive detail %q: %q", value, output)
		}
	}
}

func assertSandboxRuntimeListResponseDoesNotOverclaimSecurity(t *testing.T, resp SandboxRuntimeListResponse) {
	t.Helper()
	assertSandboxRuntimeSecurityDoesNotOverclaim(t, "host", resp.Security)
	for _, runtimeEntry := range resp.Runtimes {
		assertSandboxRuntimeSecurityDoesNotOverclaim(t, "runtime "+runtimeEntry.ID, runtimeEntry.Security)
	}
}

func assertSandboxRuntimeStatusResponseDoesNotOverclaimSecurity(t *testing.T, resp SandboxRuntimeStatusResponse) {
	t.Helper()
	assertSandboxRuntimeSecurityDoesNotOverclaim(t, "runtime status", resp.Security)
}

func assertSandboxRuntimeSecurityDoesNotOverclaim(t *testing.T, label string, security SandboxRuntimeSecuritySummary) {
	t.Helper()
	if sandboxRuntimeStringPtrEquals(security.Enforced.NetworkPolicy, sandbox.SandboxNetworkPolicyDenyByDefault) {
		t.Fatalf("%s security enforced deny-by-default networking: %#v", label, security)
	}
	for _, unsupported := range []string{
		sandbox.SandboxNetworkEnforcementModeFirewall,
		sandbox.SandboxNetworkEnforcementModeProxy,
		sandbox.SandboxNetworkEnforcementModeProxyFirewall,
	} {
		if sandboxRuntimeStringPtrEquals(security.Enforced.NetworkEnforcement, unsupported) {
			t.Fatalf("%s security overclaimed network enforcement %q: %#v", label, unsupported, security)
		}
	}
	for _, unsupported := range []string{sandbox.SandboxSecretModeHTTPProxy, "credential_proxy"} {
		if sandboxRuntimeContainsString(security.Enforced.CredentialModes, unsupported) {
			t.Fatalf("%s security overclaimed credential proxy mode %q: %#v", label, unsupported, security)
		}
	}
	if security.Enforced.CredentialProxyMode != nil && *security.Enforced.CredentialProxyMode {
		t.Fatalf("%s security overclaimed credential proxy support: %#v", label, security)
	}
	if sandboxRuntimeStringPtrEquals(security.Enforced.IsolationLevel, sandbox.SandboxRuntimeDriverMicroVM) {
		t.Fatalf("%s security overclaimed microVM isolation: %#v", label, security)
	}
}

func sandboxRuntimeStringPtrEquals(value *string, want string) bool {
	return value != nil && *value == want
}

func sandboxRuntimeContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sandboxRuntimeTestWorkerSecurity(isolationLevel string) sandboxworker.SecurityPolicy {
	return sandboxworker.SecurityPolicy{
		Requested: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementRuntime,
			CredentialModes:    []string{sandboxworker.CredentialModeSSHAgent},
			IsolationLevel:     isolationLevel,
		},
		Enforced: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyBestEffort,
			NetworkEnforcement: sandboxworker.NetworkEnforcementNone,
			CredentialModes: []string{
				sandboxworker.CredentialModeEnv,
				sandboxworker.CredentialModeLegacyAuthSync,
			},
			IsolationLevel: isolationLevel,
		},
	}
}

func decodeOneSandboxRuntimeListJSON(t *testing.T, data []byte) SandboxRuntimeListResponse {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var resp SandboxRuntimeListResponse
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode runtime list JSON error: %v\n%s", err, string(data))
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("runtime list JSON stdout should contain exactly one document; second decode error = %v extra=%#v output=%q", err, extra, string(data))
	}
	return resp
}

func decodeOneSandboxRuntimeStatusJSON(t *testing.T, data []byte) SandboxRuntimeStatusResponse {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var resp SandboxRuntimeStatusResponse
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode runtime status JSON error: %v\n%s", err, string(data))
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("runtime status JSON stdout should contain exactly one document; second decode error = %v extra=%#v output=%q", err, extra, string(data))
	}
	return resp
}

func newTestSandboxRuntimeCommand(deps sandboxRuntimeDeps) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := newSandboxRuntimeCommand(deps)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	return cmd, &stdout, &stderr
}
