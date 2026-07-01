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

	"github.com/jywlabs/hal/internal/sandbox"
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
