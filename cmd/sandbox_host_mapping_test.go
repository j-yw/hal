package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxHostFromWorkerMetadataMapsOfflineWorkerConservatively(t *testing.T) {
	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:   "worker-001",
		SocketPath: "/tmp/hal-sandboxworker.sock",
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}

	if host.ID != "worker-001" || host.Name != "worker-001" || host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("host identity = %#v, want worker durable identity", host)
	}
	if host.Endpoint != "unix:///tmp/hal-sandboxworker.sock" {
		t.Fatalf("host endpoint = %q, want unix socket endpoint", host.Endpoint)
	}
	if host.Health == nil || host.Health.Status != sandboxworker.HealthStatusUnknown {
		t.Fatalf("host health = %#v, want unknown offline health", host.Health)
	}
	if len(host.SupportedRuntimes) != 0 {
		t.Fatalf("supported runtimes = %#v, want none for offline mapping", host.SupportedRuntimes)
	}
	if host.Capacity != nil {
		t.Fatalf("capacity = %#v, want nil for offline mapping", host.Capacity)
	}
	if host.Security != nil {
		t.Fatalf("security = %#v, want nil for offline mapping", host.Security)
	}
}

func TestSandboxHostFromWorkerMetadataMapsLiveStatusAndCapabilities(t *testing.T) {
	checkedAt := time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC)
	status := sandboxworker.Status{
		WorkerID:   "worker-001",
		HostKind:   sandboxworker.HostKindLocal,
		SocketPath: "/tmp/reported-sandboxworker.sock",
		SupportedRuntimeDrivers: []string{
			sandboxworker.RuntimeDriverSSHMachine,
			sandboxworker.RuntimeDriverRootlessPodman,
		},
		Health: sandboxworker.WorkerHealth{
			Status:  sandboxworker.HealthStatusHealthy,
			Message: "ready",
		},
		Capacity: sandboxworker.WorkerCapacity{
			MaxConcurrentSandboxes: 4,
			ActiveSandboxes:        1,
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}
	capabilities := sandboxworker.Capabilities{
		WorkerID: "worker-001",
		RuntimeDrivers: []sandboxworker.RuntimeDriver{
			{
				ID:             sandboxworker.RuntimeDriverRootlessPodman,
				HostKind:       sandboxworker.HostKindLocal,
				IsolationLevel: sandboxworker.IsolationLevelContainer,
				Security:       sandboxworker.DefaultWorkerSecurityPolicy(),
			},
			{
				ID:             sandboxworker.RuntimeDriverSSHMachine,
				HostKind:       sandboxworker.HostKindLocal,
				IsolationLevel: sandboxworker.IsolationLevelHost,
				Security:       sandboxworker.DefaultWorkerSecurityPolicy(),
			},
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}

	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:     "worker-001",
		SocketPath:   "/tmp/requested-sandboxworker.sock",
		Status:       &status,
		Capabilities: &capabilities,
		CheckedAt:    checkedAt,
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}

	if host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("host kind = %q, want worker", host.Kind)
	}
	if host.Endpoint != "unix:///tmp/requested-sandboxworker.sock" {
		t.Fatalf("host endpoint = %q, want requested socket endpoint", host.Endpoint)
	}
	wantRuntimes := []string{sandboxworker.RuntimeDriverRootlessPodman, sandboxworker.RuntimeDriverSSHMachine}
	if strings.Join(host.SupportedRuntimes, ",") != strings.Join(wantRuntimes, ",") {
		t.Fatalf("supported runtimes = %#v, want %#v", host.SupportedRuntimes, wantRuntimes)
	}
	if host.Capacity == nil || host.Capacity.MaxConcurrentSandboxes != 4 {
		t.Fatalf("capacity = %#v, want max concurrent from worker status", host.Capacity)
	}
	if host.Capacity.CPUCores != 0 || host.Capacity.MemoryMB != 0 || host.Capacity.DiskGB != 0 {
		t.Fatalf("capacity = %#v, want only worker-reported capacity fields", host.Capacity)
	}
	if host.Health == nil || host.Health.Status != sandboxworker.HealthStatusHealthy || !host.Health.CheckedAt.Equal(checkedAt) || host.Health.Message != "ready" {
		t.Fatalf("health = %#v, want checked healthy worker status", host.Health)
	}
	if host.Security == nil || host.Security.Network == nil || host.Security.Secrets == nil {
		t.Fatalf("security = %#v, want mapped requested/enforced worker security", host.Security)
	}
	if host.Security.Network.PolicyRequested != sandboxworker.NetworkPolicyDenyByDefault {
		t.Fatalf("requested network policy = %q, want worker requested policy", host.Security.Network.PolicyRequested)
	}
	if host.Security.Network.PolicyEnforced != sandboxworker.NetworkPolicyBestEffort {
		t.Fatalf("enforced network policy = %q, want worker enforced policy", host.Security.Network.PolicyEnforced)
	}
	if host.Security.Network.EnforcementMode != sandboxworker.NetworkEnforcementNone {
		t.Fatalf("network enforcement mode = %q, want worker enforced mode only", host.Security.Network.EnforcementMode)
	}
	requireWorkerBestEffortPolicyResult(t, host.Security.Network.PolicyResult)
	if strings.Join(host.Security.Secrets.RequestedModes, ",") != sandboxworker.CredentialModeSSHAgent {
		t.Fatalf("requested secret modes = %#v, want worker requested modes", host.Security.Secrets.RequestedModes)
	}
	wantActiveModes := []string{sandboxworker.CredentialModeEnv, sandboxworker.CredentialModeLegacyAuthSync}
	if strings.Join(host.Security.Secrets.ActiveModes, ",") != strings.Join(wantActiveModes, ",") {
		t.Fatalf("active secret modes = %#v, want worker enforced modes", host.Security.Secrets.ActiveModes)
	}

	encoded, err := json.Marshal(host.Security)
	if err != nil {
		t.Fatalf("json.Marshal(security) error: %v", err)
	}
	for _, leaked := range []string{"/tmp/requested-sandboxworker.sock", "worker-reported.sock", "supersecret", "token=", "://"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("security metadata leaked %q: %s", leaked, encoded)
		}
	}
}

func TestSandboxHostFromWorkerMetadataMapsRuntimeCapabilityWithoutDefaultDenyOverclaim(t *testing.T) {
	policy := sandboxworker.SecurityPolicy{
		Requested: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementRuntime,
		},
		Enforced: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyBestEffort,
			NetworkEnforcement: sandboxworker.NetworkEnforcementRuntime,
		},
	}
	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:   "worker-001",
		SocketPath: "/tmp/hal-sandboxworker.sock",
		Status: &sandboxworker.Status{
			WorkerID: "worker-001",
			HostKind: sandboxworker.HostKindLocal,
			Health: sandboxworker.WorkerHealth{
				Status: sandboxworker.HealthStatusHealthy,
			},
			Security: policy,
		},
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}
	if host.Security == nil || host.Security.Network == nil {
		t.Fatalf("security = %#v, want network security", host.Security)
	}
	result := host.Security.Network.PolicyResult
	if result == nil {
		t.Fatal("policyResult = nil, want worker network policy result")
	}
	if result.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("requested preset = %q, want %q", result.Requested.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if result.Capability.Supported != true || strings.Join(result.Capability.Modes, ",") != sandbox.SandboxNetworkEnforcementModeRuntime {
		t.Fatalf("capability = %#v, want runtime mode support", result.Capability)
	}
	if result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("capability overclaimed default-deny support: %#v", result.Capability)
	}
	if result.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("effective preset = %q, want %q", result.Effective.Preset, sandbox.SandboxNetworkPolicyPresetLegacyDefault)
	}
	if result.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcement mode = %q, want %q", result.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
}

func TestSandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability(t *testing.T) {
	policy := sandboxworker.SecurityPolicy{
		Requested: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementFirewall,
		},
		Enforced: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementFirewall,
			NetworkEnforcementCapability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{sandboxworker.NetworkEnforcementFirewall},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsDefaultDenyPosture: true,
			},
		},
	}
	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:   "worker-001",
		SocketPath: "/tmp/hal-sandboxworker.sock",
		Status: &sandboxworker.Status{
			WorkerID: "worker-001",
			HostKind: sandboxworker.HostKindLocal,
			Health:   sandboxworker.WorkerHealth{Status: sandboxworker.HealthStatusHealthy},
			Security: policy,
		},
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}
	result := host.Security.Network.PolicyResult
	if result == nil {
		t.Fatal("policyResult = nil, want explicit worker network policy result")
	}
	if !result.Capability.Supported ||
		strings.Join(result.Capability.Modes, ",") != sandbox.SandboxNetworkEnforcementModeFirewall ||
		!result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("capability = %#v, want explicit firewall default-deny support", result.Capability)
	}
	if result.Effective.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("effective preset = %q, want deny_by_default", result.Effective.Preset)
	}
	if result.EnforcementMode != sandbox.SandboxNetworkEnforcementModeFirewall {
		t.Fatalf("enforcement mode = %q, want firewall", result.EnforcementMode)
	}
}

func TestSandboxHostFromWorkerMetadataUsesOnlyReportedRuntimeDrivers(t *testing.T) {
	status := sandboxworker.Status{
		WorkerID: "worker-001",
		HostKind: sandboxworker.HostKindLocal,
		Health: sandboxworker.WorkerHealth{
			Status: sandboxworker.HealthStatusHealthy,
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}
	capabilities := sandboxworker.Capabilities{
		WorkerID: "worker-001",
		RuntimeDrivers: []sandboxworker.RuntimeDriver{
			{
				ID:             sandboxworker.RuntimeDriverRootlessPodman,
				HostKind:       sandboxworker.HostKindLocal,
				IsolationLevel: sandboxworker.IsolationLevelContainer,
				Security:       sandboxworker.DefaultWorkerSecurityPolicy(),
			},
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}

	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		SocketPath:   "/tmp/hal-sandboxworker.sock",
		Status:       &status,
		Capabilities: &capabilities,
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}
	if len(host.SupportedRuntimes) != 1 || host.SupportedRuntimes[0] != sandboxworker.RuntimeDriverRootlessPodman {
		t.Fatalf("supported runtimes = %#v, want only worker capability runtime driver", host.SupportedRuntimes)
	}
}

func TestSandboxHostFromWorkerMetadataPreservesMicroVMRuntimeDriverID(t *testing.T) {
	status := sandboxworker.Status{
		WorkerID: "worker-001",
		HostKind: sandboxworker.HostKindLocal,
		SupportedRuntimeDrivers: []string{
			sandbox.SandboxRuntimeDriverMicroVM,
		},
		Health:   sandboxworker.WorkerHealth{Status: sandboxworker.HealthStatusHealthy},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}
	capabilities := sandboxworker.Capabilities{
		WorkerID: "worker-001",
		RuntimeDrivers: []sandboxworker.RuntimeDriver{
			{
				ID:             sandbox.SandboxRuntimeDriverMicroVM,
				HostKind:       sandboxworker.HostKindLocal,
				IsolationLevel: sandboxworker.IsolationLevelHost,
				Operations:     []string{sandboxworker.OperationStatus, sandboxworker.OperationCapabilities},
				Security: sandboxworker.SecurityPolicy{
					Requested: sandboxworker.SecurityControls{
						NetworkPolicy:      sandboxworker.NetworkPolicyBestEffort,
						NetworkEnforcement: sandboxworker.NetworkEnforcementNone,
						IsolationLevel:     sandboxworker.IsolationLevelHost,
					},
					Enforced: sandboxworker.SecurityControls{
						NetworkPolicy:      sandboxworker.NetworkPolicyBestEffort,
						NetworkEnforcement: sandboxworker.NetworkEnforcementNone,
						IsolationLevel:     sandboxworker.IsolationLevelHost,
					},
				},
			},
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}

	host, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:     "worker-001",
		SocketPath:   "/tmp/hal-sandboxworker.sock",
		Status:       &status,
		Capabilities: &capabilities,
	})
	if err != nil {
		t.Fatalf("sandboxHostFromWorkerMetadata() error = %v", err)
	}
	if len(host.SupportedRuntimes) != 1 || host.SupportedRuntimes[0] != sandbox.SandboxRuntimeDriverMicroVM {
		t.Fatalf("supported runtimes = %#v, want metadata-preserved microVM runtime ID", host.SupportedRuntimes)
	}
	if host.Security == nil || host.Security.Network == nil {
		t.Fatalf("security = %#v, want metadata-only worker security", host.Security)
	}
}

func TestSandboxHostFromWorkerMetadataRejectsInvalidLiveMetadata(t *testing.T) {
	status := sandboxworker.Status{
		WorkerID: "worker-001",
		HostKind: sandboxworker.HostKindLocal,
		Health: sandboxworker.WorkerHealth{
			Status: sandboxworker.HealthStatusHealthy,
		},
		Capacity: sandboxworker.WorkerCapacity{
			MaxConcurrentSandboxes: 1,
			ActiveSandboxes:        2,
		},
		Security: sandboxworker.DefaultWorkerSecurityPolicy(),
	}

	_, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
		WorkerID:   "worker-001",
		SocketPath: "/tmp/hal-sandboxworker.sock",
		Status:     &status,
	})
	if err == nil {
		t.Fatal("sandboxHostFromWorkerMetadata() error = nil, want invalid status error")
	}
	if !strings.Contains(err.Error(), "activeSandboxes") {
		t.Fatalf("error = %q, want worker validation detail", err.Error())
	}
}

func TestSandboxHostFromWorkerMetadataRejectsNonLocalWorkerSocketWithoutLeakingEndpoint(t *testing.T) {
	for _, socketPath := range []string{
		"relative.sock",
		"ssh://user:supersecret@example.test/workspace?token=abc",
		"unix:ssh://user:supersecret@example.test/workspace?token=abc",
		"unix://ssh://user:supersecret@example.test/workspace?token=abc",
	} {
		t.Run(socketPath, func(t *testing.T) {
			_, err := sandboxHostFromWorkerMetadata(sandboxHostWorkerMetadataRequest{
				WorkerID:   "worker-001",
				SocketPath: socketPath,
			})
			if err == nil {
				t.Fatal("sandboxHostFromWorkerMetadata() error = nil, want non-local socket validation error")
			}
			if !strings.Contains(err.Error(), "absolute local Unix socket path") {
				t.Fatalf("error = %q, want absolute local socket validation detail", err.Error())
			}
			for _, leaked := range []string{"supersecret", "example.test", "token=abc", socketPath} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error leaked endpoint detail %q: %q", leaked, err.Error())
				}
			}
		})
	}
}

func requireWorkerBestEffortPolicyResult(t *testing.T, result *sandbox.SandboxNetworkPolicyResult) {
	t.Helper()
	if result == nil {
		t.Fatal("policyResult = nil, want worker network policy result")
	}
	if result.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("requested preset = %q, want %q", result.Requested.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if result.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("effective preset = %q, want %q", result.Effective.Preset, sandbox.SandboxNetworkPolicyPresetLegacyDefault)
	}
	if result.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcement mode = %q, want %q", result.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("capability overclaimed default-deny support: %#v", result.Capability)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("warnings = empty, want downgrade warning")
	}
	for _, warning := range result.Warnings {
		for _, leaked := range []string{"/tmp/", ".sock", "://", "supersecret", "token="} {
			if strings.Contains(warning.Policy, leaked) || strings.Contains(warning.Message, leaked) {
				t.Fatalf("warning leaked %q: %#v", leaked, warning)
			}
		}
	}
}
