package firecrackerhost

import (
	"strings"
	"testing"
)

func TestNewGuestTransportFromEndpointIsOptional(t *testing.T) {
	transport, err := NewGuestTransportFromEndpoint(GuestAgentEndpointOptions{})
	if err != nil {
		t.Fatalf("NewGuestTransportFromEndpoint() error = %v, want nil", err)
	}
	if transport != nil {
		t.Fatalf("NewGuestTransportFromEndpoint() = %T, want nil without endpoint", transport)
	}
}

func TestNewGuestTransportFromEndpointBuildsGuestAgentTransport(t *testing.T) {
	transport, err := NewGuestTransportFromEndpoint(GuestAgentEndpointOptions{
		Endpoint: "unix:///tmp/hal-guest-agent.sock",
	})
	if err != nil {
		t.Fatalf("NewGuestTransportFromEndpoint() error = %v, want nil", err)
	}
	if _, ok := transport.(*GuestAgentTransport); !ok {
		t.Fatalf("transport = %T, want *GuestAgentTransport", transport)
	}
}

func TestValidateGuestAgentEndpointRejectsUnsafeEndpointWithoutRawDetails(t *testing.T) {
	err := ValidateGuestAgentEndpoint("vsock://3:1024/path?token=ghp_secret")
	if err == nil {
		t.Fatal("ValidateGuestAgentEndpoint() error = nil, want validation error")
	}
	for _, leaked := range []string{"vsock://", "1024", "token=ghp_secret", "ghp_secret"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error leaked %q: %q", leaked, err.Error())
		}
	}
}
