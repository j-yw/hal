package sandbox

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSandboxStateJSONTags(t *testing.T) {
	createdAt := time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC)
	stoppedAt := createdAt.Add(2 * time.Hour)

	tests := []struct {
		name        string
		state       SandboxState
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name: "minimal state omits optional fields",
			state: SandboxState{
				ID:           "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
				Name:         "api-backend",
				Provider:     "daytona",
				IP:           "",
				Status:       StatusRunning,
				CreatedAt:    createdAt,
				AutoShutdown: false,
			},
			wantPresent: []string{"id", "name", "provider", "ip", "status", "createdAt", "autoShutdown"},
			wantAbsent: []string{
				"workspaceId", "tailscaleIp", "tailscaleHostname", "tailscaleLockdown", "stoppedAt", "idleHours", "size",
				"repo", "snapshotId", "host", "runtime", "workspace", "security", "lease",
			},
		},
		{
			name: "full state includes optional fields with camelCase keys",
			state: SandboxState{
				ID:                "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
				Name:              "api-backend",
				Provider:          "digitalocean",
				WorkspaceID:       "123456789",
				IP:                "104.131.5.22",
				TailscaleIP:       "100.64.1.10",
				TailscaleHostname: "hal-api-backend",
				TailscaleLockdown: true,
				Status:            StatusStopped,
				CreatedAt:         createdAt,
				StoppedAt:         &stoppedAt,
				AutoShutdown:      true,
				IdleHours:         48,
				Size:              "s-2vcpu-4gb",
				Repo:              "api",
				SnapshotID:        "snap-123",
			},
			wantPresent: []string{
				"id", "name", "provider", "workspaceId", "ip", "tailscaleIp", "tailscaleHostname", "tailscaleLockdown",
				"status", "createdAt", "stoppedAt", "autoShutdown", "idleHours", "size", "repo", "snapshotId",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.state)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			for _, key := range tt.wantPresent {
				if _, ok := got[key]; !ok {
					t.Errorf("missing expected key %q in %s", key, string(data))
				}
			}
			for _, key := range tt.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("unexpected key %q in %s", key, string(data))
				}
			}
		})
	}
}

func TestSandboxStateUnmarshalsLegacyJSONWithoutRuntimeV2Metadata(t *testing.T) {
	data := []byte(`{
		"id": "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
		"name": "api-backend",
		"provider": "daytona",
		"workspaceId": "123456789",
		"ip": "104.131.5.22",
		"status": "running",
		"createdAt": "2026-03-21T10:00:00Z",
		"autoShutdown": true,
		"idleHours": 48,
		"size": "s-2vcpu-4gb",
		"repo": "api",
		"snapshotId": "snap-123"
	}`)

	var got SandboxState
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal legacy sandbox state failed: %v", err)
	}

	if got.ID != "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f" || got.Name != "api-backend" {
		t.Fatalf("legacy identity = %q/%q, want api-backend state", got.ID, got.Name)
	}
	if got.Host != nil || got.Runtime != nil || got.Workspace != nil || got.Security != nil || got.Lease != nil {
		t.Fatalf("runtime v2 metadata = host:%#v runtime:%#v workspace:%#v security:%#v lease:%#v, want nil", got.Host, got.Runtime, got.Workspace, got.Security, got.Lease)
	}
}

func TestSandboxStateOmitsNilRuntimeV2Metadata(t *testing.T) {
	got := mustMarshalObject(t, SandboxState{
		ID:           "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
		Name:         "api-backend",
		Provider:     "daytona",
		Status:       StatusRunning,
		CreatedAt:    time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
		AutoShutdown: true,
	})

	assertObjectKeys(t, got, nil, []string{"host", "runtime", "workspace", "security", "lease"})
}

func TestSandboxStateRuntimeV2MetadataJSONTags(t *testing.T) {
	expiresAt := time.Date(2026, 6, 29, 18, 0, 0, 0, time.UTC)

	got := mustMarshalObject(t, SandboxState{
		ID:           "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
		Name:         "api-backend",
		Provider:     "daytona",
		Status:       StatusRunning,
		CreatedAt:    time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
		AutoShutdown: true,
		Host: &SandboxHost{
			ID:   "host-01",
			Name: "builder-01",
			Kind: SandboxHostKindWorker,
			Capacity: &HostCapacity{
				CPUCores:               8,
				MemoryMB:               32768,
				DiskGB:                 250,
				MaxConcurrentSandboxes: 4,
			},
		},
		Runtime: &SandboxRuntimeState{
			Driver:         SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-01",
			Image:          "ghcr.io/jywlabs/hal-worker:latest",
			WorkerID:       "worker-01",
		},
		Workspace: &SandboxWorkspace{
			Mode:        SandboxWorkspaceModeClone,
			InputSource: SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "git@github.com:jywlabs/hal.git",
			Branch:      "phase/sandbox-runtime-v2-1-types",
			SyncRef:     "refs/heads/phase/sandbox-runtime-v2-1-types",
		},
		Security: &SandboxSecurity{
			Network: &SandboxNetworkSecurity{
				PolicyRequested: "deny_by_default",
				PolicyEnforced:  "best_effort",
				EnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
			},
			Secrets: &SandboxSecretSecurity{
				RequestedModes: []string{SandboxSecretModeEnv, SandboxSecretModeSSHAgent},
				ActiveModes:    []string{SandboxSecretModeFileTmpfs},
			},
		},
		Lease: &SandboxLeaseRef{
			ID:          "lease-01",
			ResourceKey: "runtime:runtime-01",
			Holder:      "worker-01",
			Purpose:     SandboxLeasePurposeFactory,
			RunID:       "run-01",
			ExpiresAt:   expiresAt,
		},
	})

	assertObjectKeys(t, got, []string{"host", "runtime", "workspace", "security", "lease"}, nil)
	assertObjectKeys(t, got["host"], []string{"id", "name", "kind", "capacity"}, []string{"endpoint", "labels", "supportedRuntimes", "health", "cost"})
	assertObjectKeys(t, got["runtime"], []string{"driver", "isolationLevel", "runtimeId", "image", "workerId"}, nil)
	assertObjectKeys(t, got["workspace"], []string{"mode", "inputSource", "repo", "branch", "syncRef"}, nil)
	assertObjectKeys(t, got["security"], []string{"network", "secrets"}, nil)
	assertObjectKeys(t, got["lease"], []string{"id", "resourceKey", "holder", "purpose", "runId", "expiresAt"}, nil)

	security := got["security"].(map[string]any)
	assertObjectKeys(t, security["network"], []string{"policyRequested", "policyEnforced", "enforcementMode"}, nil)
	assertObjectKeys(t, security["secrets"], []string{"requestedModes", "activeModes"}, nil)

	network := security["network"].(map[string]any)
	if network["policyRequested"] != "deny_by_default" || network["policyEnforced"] != "best_effort" {
		t.Fatalf("network policy summaries = %#v, want requested/enforced string summaries", network)
	}
}

func TestSandboxHostMetadataJSONTags(t *testing.T) {
	checkedAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	lastHeartbeatAt := checkedAt.Add(-1 * time.Minute)

	tests := []struct {
		name        string
		host        SandboxHost
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name: "minimal host omits optional metadata",
			host: SandboxHost{
				ID:   "host-01",
				Name: "builder-01",
				Kind: SandboxHostKindLocal,
			},
			wantPresent: []string{"id", "name", "kind"},
			wantAbsent:  []string{"endpoint", "labels", "supportedRuntimes", "capacity", "health", "cost"},
		},
		{
			name: "full host includes metadata with camelCase keys",
			host: SandboxHost{
				ID:       "host-01",
				Name:     "builder-01",
				Kind:     SandboxHostKindWorker,
				Endpoint: "ssh://builder-01.example.test",
				Labels: map[string]string{
					"region": "iad",
					"tier":   "trusted",
				},
				SupportedRuntimes: []string{
					SandboxRuntimeDriverSSHMachine,
					SandboxRuntimeDriverRootlessPodman,
				},
				Capacity: &HostCapacity{
					CPUCores:               8,
					MemoryMB:               32768,
					DiskGB:                 250,
					MaxConcurrentSandboxes: 4,
				},
				Health: &HostHealth{
					Status:          StatusRunning,
					CheckedAt:       checkedAt,
					LastHeartbeatAt: &lastHeartbeatAt,
					Message:         "ready",
				},
				Cost: &HostCost{
					Currency:       "USD",
					HourlyEstimate: 0.42,
					BillingScope:   "host",
				},
			},
			wantPresent: []string{"id", "name", "kind", "endpoint", "labels", "supportedRuntimes", "capacity", "health", "cost"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustMarshalObject(t, tt.host)

			for _, key := range tt.wantPresent {
				if _, ok := got[key]; !ok {
					t.Errorf("missing expected key %q in %#v", key, got)
				}
			}
			for _, key := range tt.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("unexpected key %q in %#v", key, got)
				}
			}
		})
	}
}

func TestSandboxHostNestedMetadataJSONTags(t *testing.T) {
	checkedAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)

	host := SandboxHost{
		ID:   "host-01",
		Name: "builder-01",
		Kind: SandboxHostKindWorker,
		Capacity: &HostCapacity{
			CPUCores:               8,
			MemoryMB:               32768,
			DiskGB:                 250,
			MaxConcurrentSandboxes: 4,
		},
		Health: &HostHealth{
			Status:    StatusRunning,
			CheckedAt: checkedAt,
		},
		Cost: &HostCost{
			Currency:       "USD",
			HourlyEstimate: 0.42,
		},
	}

	got := mustMarshalObject(t, host)

	assertObjectKeys(t, got["capacity"], []string{"cpuCores", "memoryMb", "diskGb", "maxConcurrentSandboxes"}, nil)
	assertObjectKeys(t, got["health"], []string{"status", "checkedAt"}, []string{"lastHeartbeatAt", "message"})
	assertObjectKeys(t, got["cost"], []string{"currency", "hourlyEstimate"}, []string{"billingScope"})
}

func TestSandboxHostRefJSONTags(t *testing.T) {
	got := mustMarshalObject(t, SandboxHostRef{
		ID:   "host-01",
		Name: "builder-01",
		Kind: SandboxHostKindSSH,
	})

	assertObjectKeys(t, got, []string{"id", "name", "kind"}, nil)
	if len(got) != 3 {
		t.Fatalf("SandboxHostRef keys = %#v, want only id, name, and kind", got)
	}
}

func TestSandboxLeaseJSONTags(t *testing.T) {
	acquiredAt := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	expiresAt := acquiredAt.Add(30 * time.Minute)
	heartbeatAt := acquiredAt.Add(5 * time.Minute)

	got := mustMarshalObject(t, SandboxLease{
		ID:          "lease-01",
		SandboxID:   "sandbox-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
		RunID:       "run-01",
		AcquiredAt:  acquiredAt,
		ExpiresAt:   expiresAt,
		HeartbeatAt: heartbeatAt,
		Status:      SandboxLeaseStatusActive,
	})

	assertObjectKeys(t, got, []string{
		"id", "sandboxId", "sandboxName", "resourceKey", "holder", "purpose", "runId",
		"acquiredAt", "expiresAt", "heartbeatAt", "status",
	}, nil)
}

func TestSandboxRuntimeWorkspaceSecurityLeaseMetadataJSONTags(t *testing.T) {
	expiresAt := time.Date(2026, 6, 29, 18, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		value       any
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name: "runtime state uses camelCase keys",
			value: SandboxRuntimeState{
				Driver:         SandboxRuntimeDriverRootlessPodman,
				IsolationLevel: SandboxIsolationLevelContainer,
				RuntimeID:      "runtime-01",
				Image:          "ghcr.io/jywlabs/hal-worker:latest",
				WorkerID:       "worker-01",
			},
			wantPresent: []string{"driver", "isolationLevel", "runtimeId", "image", "workerId"},
		},
		{
			name: "workspace uses camelCase keys",
			value: SandboxWorkspace{
				Mode:        SandboxWorkspaceModeClone,
				InputSource: SandboxWorkspaceInputSourceRemoteRef,
				Repo:        "git@github.com:jywlabs/hal.git",
				Branch:      "phase/sandbox-runtime-v2-1-types",
				SyncRef:     "refs/heads/phase/sandbox-runtime-v2-1-types",
			},
			wantPresent: []string{"mode", "inputSource", "repo", "branch", "syncRef"},
		},
		{
			name:  "security omits optional nested metadata",
			value: SandboxSecurity{},
			wantAbsent: []string{
				"network",
				"secrets",
			},
		},
		{
			name: "security includes optional nested metadata",
			value: SandboxSecurity{
				Network: &SandboxNetworkSecurity{
					PolicyRequested: "deny_by_default",
					PolicyEnforced:  "best_effort",
					EnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
				},
				Secrets: &SandboxSecretSecurity{
					RequestedModes: []string{SandboxSecretModeEnv, SandboxSecretModeSSHAgent},
					ActiveModes:    []string{SandboxSecretModeFileTmpfs},
				},
			},
			wantPresent: []string{"network", "secrets"},
		},
		{
			name: "lease ref uses camelCase keys",
			value: SandboxLeaseRef{
				ID:          "lease-01",
				ResourceKey: "runtime:runtime-01",
				Holder:      "worker-01",
				Purpose:     SandboxLeasePurposeFactory,
				RunID:       "run-01",
				ExpiresAt:   expiresAt,
			},
			wantPresent: []string{"id", "resourceKey", "holder", "purpose", "runId", "expiresAt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustMarshalObject(t, tt.value)

			for _, key := range tt.wantPresent {
				if _, ok := got[key]; !ok {
					t.Errorf("missing expected key %q in %#v", key, got)
				}
			}
			for _, key := range tt.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("unexpected key %q in %#v", key, got)
				}
			}
		})
	}
}

func TestSandboxRuntimeV2NestedSecurityMetadataJSONTags(t *testing.T) {
	security := SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyRequested: "deny_by_default",
			PolicyEnforced:  "best_effort",
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		},
		Secrets: &SandboxSecretSecurity{
			RequestedModes: []string{SandboxSecretModeEnv, SandboxSecretModeHTTPProxy},
			ActiveModes:    []string{SandboxSecretModeEnv},
		},
	}

	got := mustMarshalObject(t, security)

	assertObjectKeys(t, got["network"], []string{"policyRequested", "policyEnforced", "enforcementMode"}, nil)
	assertObjectKeys(t, got["secrets"], []string{"requestedModes", "activeModes"}, nil)
}

func TestSandboxNetworkSecurityOmitsEmptyPolicySummaries(t *testing.T) {
	got := mustMarshalObject(t, SandboxNetworkSecurity{})

	assertObjectKeys(t, got, nil, []string{"policyRequested", "policyEnforced", "enforcementMode"})
	if len(got) != 0 {
		t.Fatalf("zero network policy metadata = %#v, want empty object", got)
	}
}

func TestSandboxSecretSecurityOmitsEmptyModeLists(t *testing.T) {
	got := mustMarshalObject(t, SandboxSecretSecurity{})

	assertObjectKeys(t, got, nil, []string{"requestedModes", "activeModes"})
}

func TestSandboxStatusConstants(t *testing.T) {
	if StatusRunning != "running" {
		t.Fatalf("StatusRunning = %q, want %q", StatusRunning, "running")
	}
	if StatusStopped != "stopped" {
		t.Fatalf("StatusStopped = %q, want %q", StatusStopped, "stopped")
	}
	if StatusUnknown != "unknown" {
		t.Fatalf("StatusUnknown = %q, want %q", StatusUnknown, "unknown")
	}
}

func mustMarshalObject(t *testing.T, v any) map[string]any {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	return got
}

func assertObjectKeys(t *testing.T, v any, wantPresent, wantAbsent []string) {
	t.Helper()

	got, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want JSON object", v)
	}

	for _, key := range wantPresent {
		if _, ok := got[key]; !ok {
			t.Errorf("missing expected key %q in %#v", key, got)
		}
	}
	for _, key := range wantAbsent {
		if _, ok := got[key]; ok {
			t.Errorf("unexpected key %q in %#v", key, got)
		}
	}
}

func TestSandboxRuntimeV2MetadataConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "host kind local", got: SandboxHostKindLocal, want: "local"},
		{name: "host kind ssh", got: SandboxHostKindSSH, want: "ssh"},
		{name: "host kind worker", got: SandboxHostKindWorker, want: "worker"},
		{name: "host kind k8s", got: SandboxHostKindK8s, want: "k8s"},
		{name: "runtime driver ssh machine", got: SandboxRuntimeDriverSSHMachine, want: "ssh_machine"},
		{name: "runtime driver rootless podman", got: SandboxRuntimeDriverRootlessPodman, want: "rootless_podman"},
		{name: "runtime driver microvm", got: SandboxRuntimeDriverMicroVM, want: "microvm"},
		{name: "isolation level host", got: SandboxIsolationLevelHost, want: "host"},
		{name: "isolation level container", got: SandboxIsolationLevelContainer, want: "container"},
		{name: "isolation level vm", got: SandboxIsolationLevelVM, want: "vm"},
		{name: "workspace mode clone", got: SandboxWorkspaceModeClone, want: "clone"},
		{name: "workspace mode copy", got: SandboxWorkspaceModeCopy, want: "copy"},
		{name: "workspace mode direct", got: SandboxWorkspaceModeDirect, want: "direct"},
		{name: "workspace input source remote ref", got: SandboxWorkspaceInputSourceRemoteRef, want: "remote_ref"},
		{name: "workspace input source git bundle", got: SandboxWorkspaceInputSourceGitBundle, want: "git_bundle"},
		{name: "workspace input source copy", got: SandboxWorkspaceInputSourceCopy, want: "copy"},
		{name: "network enforcement mode none", got: SandboxNetworkEnforcementModeNone, want: "none"},
		{name: "network enforcement mode best effort", got: SandboxNetworkEnforcementModeBestEffort, want: "best_effort"},
		{name: "network enforcement mode proxy", got: SandboxNetworkEnforcementModeProxy, want: "proxy"},
		{name: "network enforcement mode firewall", got: SandboxNetworkEnforcementModeFirewall, want: "firewall"},
		{name: "network enforcement mode runtime", got: SandboxNetworkEnforcementModeRuntime, want: "runtime"},
		{name: "network enforcement mode proxy firewall", got: SandboxNetworkEnforcementModeProxyFirewall, want: "proxy_firewall"},
		{name: "secret mode env", got: SandboxSecretModeEnv, want: "env"},
		{name: "secret mode file tmpfs", got: SandboxSecretModeFileTmpfs, want: "file_tmpfs"},
		{name: "secret mode ssh agent", got: SandboxSecretModeSSHAgent, want: "ssh_agent"},
		{name: "secret mode http proxy", got: SandboxSecretModeHTTPProxy, want: "http_proxy"},
		{name: "secret mode legacy auth sync", got: SandboxSecretModeLegacyAuthSync, want: "legacy_auth_sync"},
		{name: "lease status active", got: SandboxLeaseStatusActive, want: "active"},
		{name: "lease status released", got: SandboxLeaseStatusReleased, want: "released"},
		{name: "lease status expired", got: SandboxLeaseStatusExpired, want: "expired"},
		{name: "lease purpose run", got: SandboxLeasePurposeRun, want: "run"},
		{name: "lease purpose auto", got: SandboxLeasePurposeAuto, want: "auto"},
		{name: "lease purpose factory", got: SandboxLeasePurposeFactory, want: "factory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
