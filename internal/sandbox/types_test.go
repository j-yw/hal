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
			wantAbsent:  []string{"workspaceId", "tailscaleIp", "tailscaleHostname", "tailscaleLockdown", "stoppedAt", "idleHours", "size", "repo", "snapshotId"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
