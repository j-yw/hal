package firecracker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProcessLaunchMetadataDistinguishesSafeLaunchStates(t *testing.T) {
	tests := []struct {
		name      string
		metadata  ProcessLaunchMetadata
		wantState ProcessLaunchState
		wantID    string
	}{
		{
			name:      "process boundary available",
			metadata:  NewProcessLaunchMetadata(ProcessLaunchStateBoundaryAvailable, ProcessHandleMetadata{ID: "pid-1234", Source: "adapter"}),
			wantState: ProcessLaunchStateBoundaryAvailable,
		},
		{
			name:      "process launch attempted",
			metadata:  NewProcessLaunchMetadata(ProcessLaunchStateAttempted, ProcessHandleMetadata{ID: "pid-1234", Source: "adapter"}),
			wantState: ProcessLaunchStateAttempted,
		},
		{
			name:      "process launch accepted",
			metadata:  NewProcessLaunchMetadata(ProcessLaunchStateAccepted, ProcessHandleMetadata{ID: "pid-1234", Source: "adapter"}),
			wantState: ProcessLaunchStateAccepted,
			wantID:    "pid-1234",
		},
	}

	seenStates := map[ProcessLaunchState]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.metadata.State != tt.wantState {
				t.Fatalf("State = %q, want %q", tt.metadata.State, tt.wantState)
			}
			if !reflect.DeepEqual(tt.metadata.Labels, []string{string(tt.wantState)}) {
				t.Fatalf("Labels = %#v, want canonical state label", tt.metadata.Labels)
			}
			if tt.metadata.ProcessID != tt.wantID {
				t.Fatalf("ProcessID = %q, want %q", tt.metadata.ProcessID, tt.wantID)
			}
			if tt.metadata.ProcessID != "" && !safeLaunchTokenForTest(tt.metadata.ProcessID) {
				t.Fatalf("ProcessID = %q, want strict safe token", tt.metadata.ProcessID)
			}
			runtimeMetadata := tt.metadata.RuntimeMetadata()
			if runtimeMetadata == nil {
				t.Fatal("RuntimeMetadata() = nil, want shared runtime launch metadata")
			}
			if runtimeMetadata.State != string(tt.wantState) {
				t.Fatalf("runtime State = %q, want %q", runtimeMetadata.State, tt.wantState)
			}
			seenStates[tt.metadata.State] = true
		})
	}

	for _, state := range []ProcessLaunchState{
		ProcessLaunchStateBoundaryAvailable,
		ProcessLaunchStateAttempted,
		ProcessLaunchStateAccepted,
	} {
		if !seenStates[state] {
			t.Fatalf("launch metadata did not distinguish state %q", state)
		}
	}
}

func TestProcessLaunchMetadataSanitizesRawLaunchInputs(t *testing.T) {
	raw := ProcessLaunchMetadata{
		State: ProcessLaunchStateAccepted,
		Labels: []string{
			string(ProcessLaunchStateAccepted),
			"/usr/bin/firecracker",
			"--api-sock",
			"guest_ready",
			"network_enforced",
			"credential_delivery",
			"exec_support",
			"copy_support",
		},
		ProcessID:       "pid:/Users/alice/private/firecracker.sock",
		ProcessIDSource: "env:OPENAI_API_KEY token=ghp_secret",
	}

	metadata := SanitizeProcessLaunchMetadata(raw)
	encoded, err := json.Marshal(struct {
		Launch  ProcessLaunchMetadata `json:"launch"`
		Runtime any                   `json:"runtime"`
	}{
		Launch:  metadata,
		Runtime: metadata.RuntimeMetadata(),
	})
	if err != nil {
		t.Fatalf("Marshal(launch metadata) error = %v", err)
	}

	publicText := string(encoded)
	for _, unsafe := range []string{
		"/usr/bin/firecracker",
		"--api-sock",
		"/Users/alice",
		"private",
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"vmlinux",
		"rootfs.ext4",
		"OPENAI_API_KEY",
		"ghp_secret",
		"token=",
		"secret",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("launch metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	if metadata.ProcessID != "" {
		t.Fatalf("unsafe ProcessID was exposed as %q", metadata.ProcessID)
	}
	if metadata.ProcessIDSource != "" {
		t.Fatalf("unsafe ProcessIDSource was exposed as %q", metadata.ProcessIDSource)
	}
}

func TestProcessLaunchMetadataDoesNotClaimGuestReadinessOrUnsupportedCapabilities(t *testing.T) {
	metadata := []ProcessLaunchMetadata{
		NewProcessLaunchMetadata(ProcessLaunchStateBoundaryAvailable, ProcessHandleMetadata{}),
		NewProcessLaunchMetadata(ProcessLaunchStateAttempted, ProcessHandleMetadata{}),
		NewProcessLaunchMetadata(ProcessLaunchStateAccepted, ProcessHandleMetadata{ID: "pid-1234", Source: "adapter"}),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(launch metadata) error = %v", err)
	}
	publicText := string(encoded)

	for _, unsupported := range []string{
		"guest_ready",
		"vm_boot_ready",
		"boot_ready",
		"network_enforced",
		"deny_by_default",
		"credential_delivery",
		"credential_proxy",
		"exec_support",
		"copy_support",
		"guest_agent",
		"vsock_exec",
		"file_copy",
	} {
		if strings.Contains(publicText, unsupported) {
			t.Fatalf("launch metadata claims unsupported capability %q in %s", unsupported, publicText)
		}
	}
}

func safeLaunchTokenForTest(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"token", "secret", "password", "credential", "authorization", "bearer", "api_key", "apikey"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}
