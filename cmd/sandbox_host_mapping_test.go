package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
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
	if strings.Join(host.Security.Secrets.RequestedModes, ",") != sandboxworker.CredentialModeSSHAgent {
		t.Fatalf("requested secret modes = %#v, want worker requested modes", host.Security.Secrets.RequestedModes)
	}
	wantActiveModes := []string{sandboxworker.CredentialModeEnv, sandboxworker.CredentialModeLegacyAuthSync}
	if strings.Join(host.Security.Secrets.ActiveModes, ",") != strings.Join(wantActiveModes, ",") {
		t.Fatalf("active secret modes = %#v, want worker enforced modes", host.Security.Secrets.ActiveModes)
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
