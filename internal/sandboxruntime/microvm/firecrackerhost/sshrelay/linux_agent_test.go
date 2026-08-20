//go:build linux

package sshrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestLinuxAgentAdaptersValidatePrivateConfigurationWithoutOpening(t *testing.T) {
	for _, path := range []string{"", "relative.sock", "/tmp/../agent.sock", "/tmp/agent\x00.sock"} {
		if dialer, err := NewLinuxAgentDialer(LinuxAgentDialerOptions{EndpointPath: path, ExpectedUID: 1000, ExpectedGID: 1000}); dialer != nil || !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("NewLinuxAgentDialer(%q) = (%v, %v)", path, dialer, err)
		}
	}
	dialer, err := NewLinuxAgentDialer(LinuxAgentDialerOptions{EndpointPath: "/run/user/1000/agent.sock", ExpectedUID: 1000, ExpectedGID: 1000})
	if err != nil || dialer == nil {
		t.Fatalf("NewLinuxAgentDialer(valid) = (%v, %v)", dialer, err)
	}
	verifier, err := NewLinuxPeerVerifier(LinuxPeerVerifierOptions{ExpectedUID: 1000, ExpectedGID: 1000})
	if err != nil || verifier == nil {
		t.Fatalf("NewLinuxPeerVerifier() = (%v, %v)", verifier, err)
	}
	if _, err := verifier.Verify(context.Background(), &redAgentConnection{}, mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)); !errors.Is(err, ErrAgentPeer) {
		t.Fatalf("Verify(foreign connection) error = %v, want %v", err, ErrAgentPeer)
	}
}

func TestLinuxUnixPathUsesSockaddrUnPathnameBound(t *testing.T) {
	exact := "/" + strings.Repeat("a", 106)
	plusOne := "/" + strings.Repeat("a", 107)
	if !validUnixEndpointPath(exact) {
		t.Fatalf("exact sockaddr_un pathname length %d rejected", len(exact))
	}
	if validUnixEndpointPath(plusOne) {
		t.Fatalf("sockaddr_un pathname plus one length %d accepted", len(plusOne))
	}
}

func TestLinuxPeerVerifierUsesRawExactLengthCredentialSeam(t *testing.T) {
	source, err := os.ReadFile("linux_agent_linux.go")
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	text := string(source)
	if strings.Contains(text, "syscall.GetsockoptUcred") || !strings.Contains(text, "SYS_GETSOCKOPT") || !strings.Contains(text, "peerCredentialReader") {
		t.Fatal("Linux peer verifier does not use an injectable raw exact-length SO_PEERCRED seam")
	}
}

func TestLinuxAgentSourceHasNoEnvironmentFallbackOrGenericNetworkDial(t *testing.T) {
	source, err := os.ReadFile("linux_agent_linux.go")
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	for _, forbidden := range []string{"os.Getenv(", "os.LookupEnv(", "SSH_AUTH_SOCK", "net.Dial("} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("linux adapter contains forbidden fallback/dial marker %q", forbidden)
		}
	}
}

func TestLinuxAgentConfigurationFormattingAndSerializationAreRedacted(t *testing.T) {
	const endpoint = "/run/user/1000/agent-sensitive.sock"
	values := []any{
		LinuxAgentDialerOptions{EndpointPath: endpoint, ExpectedUID: 1000, ExpectedGID: 1000},
		LinuxPeerVerifierOptions{ExpectedUID: 1000, ExpectedGID: 1000},
		&linuxAgentDialer{path: endpoint, expectedUID: 1000, expectedGID: 1000},
		&linuxPeerVerifier{expectedUID: 1000, expectedGID: 1000},
		&linuxAgentConnection{},
	}
	for _, value := range values {
		rendered := fmt.Sprintf("%v %#v %+v", value, value, value)
		if strings.Contains(rendered, endpoint) {
			t.Fatalf("format exposed endpoint: %q", rendered)
		}
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), endpoint) {
			t.Fatalf("JSON exposed endpoint: %q", encoded)
		}
	}
}
