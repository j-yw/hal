package firecrackerhost

import (
	"strings"
	"testing"
)

func TestGuestAgentUnixSocketPathFromEndpointValidatesLocalSocketEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantPath string
	}{
		{
			name:     "unix scheme",
			endpoint: "unix:///tmp/hal-guest-agent.sock",
			wantPath: "/tmp/hal-guest-agent.sock",
		},
		{
			name:     "unix prefix",
			endpoint: "unix:/tmp/hal-guest-agent.sock",
			wantPath: "/tmp/hal-guest-agent.sock",
		},
		{
			name:     "absolute path",
			endpoint: "/tmp/hal-guest-agent.sock",
			wantPath: "/tmp/hal-guest-agent.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := guestAgentUnixSocketPathFromEndpoint(tt.endpoint)
			if err != nil {
				t.Fatalf("guestAgentUnixSocketPathFromEndpoint() error = %v, want nil", err)
			}
			if got != tt.wantPath {
				t.Fatalf("guestAgentUnixSocketPathFromEndpoint() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestGuestAgentUnixSocketPathFromEndpointRejectsUnsafeEndpointWithoutLeakingRawValues(t *testing.T) {
	tests := []string{
		"",
		"relative/agent.sock",
		"tcp://guest.internal:8080/path?token=ghp_secret",
		"unix:///tmp/hal-agent.sock?token=ghp_secret",
		"/",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			_, err := guestAgentUnixSocketPathFromEndpoint(endpoint)
			if err == nil {
				t.Fatal("guestAgentUnixSocketPathFromEndpoint() error = nil, want validation error")
			}
			for _, leaked := range []string{"tcp://", "guest.internal", "8080", "token=ghp_secret", "ghp_secret", "/tmp/hal-agent.sock"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error leaked %q: %q", leaked, err.Error())
				}
			}
		})
	}
}
