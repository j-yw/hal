package session

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestGuestHelloStrictOuterAndHeaderValidation(t *testing.T) {
	valid := mustHex(t, vectorGuestHelloHex)
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "missing outer", mutate: func([]byte) []byte { return []byte{0, 0, 0} }},
		{name: "zero inner", mutate: func(w []byte) []byte { binary.BigEndian.PutUint32(w[:4], 0); return w[:4] }},
		{name: "oversize declaration", mutate: func(w []byte) []byte { binary.BigEndian.PutUint32(w[:4], MaxHandshakeInnerBytes+1); return w }},
		{name: "truncated", mutate: func(w []byte) []byte { return w[:len(w)-1] }},
		{name: "trailing", mutate: func(w []byte) []byte { return append(w, 0) }},
		{name: "magic", mutate: func(w []byte) []byte { w[4] ^= 1; return w }},
		{name: "version", mutate: func(w []byte) []byte { w[8]++; return w }},
		{name: "type", mutate: func(w []byte) []byte { w[9] = handshakeTypeControllerAuth; return w }},
		{name: "reserved high", mutate: func(w []byte) []byte { w[10] = 1; return w }},
		{name: "reserved low", mutate: func(w []byte) []byte { w[11] = 1; return w }},
		{name: "suite", mutate: func(w []byte) []byte { w[13] = 2; return w }},
		{name: "channel", mutate: func(w []byte) []byte { w[14] = 3; return w }},
		{name: "channel reserved", mutate: func(w []byte) []byte { w[15] = 1; return w }},
		{name: "CID", mutate: func(w []byte) []byte { w[83] = 4; return w }},
		{name: "port", mutate: func(w []byte) []byte { w[87] = 2; return w }},
		{name: "empty token", mutate: func(w []byte) []byte { w[88], w[89] = 0, 0; return w }},
		{name: "token invalid first", mutate: func(w []byte) []byte { w[90] = '-'; return w }},
		{name: "token unicode", mutate: func(w []byte) []byte { w[90] = 0xff; return w }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			wire = tt.mutate(wire)
			if _, err := ParseGuestHello(wire); !errors.Is(err, ErrMalformedHandshake) {
				t.Fatalf("ParseGuestHello() error = %v, want ErrMalformedHandshake", err)
			}
		})
	}
}

func TestHandshakeLengthPrefixExactBounds(t *testing.T) {
	for _, tt := range []struct {
		value uint32
		ok    bool
	}{
		{value: 0, ok: false},
		{value: 1, ok: true},
		{value: MaxHandshakeInnerBytes, ok: true},
		{value: MaxHandshakeInnerBytes + 1, ok: false},
		{value: ^uint32(0), ok: false},
	} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], tt.value)
		got, err := ParseHandshakeLength(prefix[:])
		if tt.ok && (err != nil || got != tt.value) {
			t.Fatalf("ParseHandshakeLength(%d) = %d, %v", tt.value, got, err)
		}
		if !tt.ok && !errors.Is(err, ErrMalformedHandshake) {
			t.Fatalf("ParseHandshakeLength(%d) error = %v", tt.value, err)
		}
	}
	if _, err := ParseHandshakeLength([]byte{0, 0, 1}); !errors.Is(err, ErrMalformedHandshake) {
		t.Fatalf("ParseHandshakeLength(short) = %v", err)
	}
}

func TestGuestHelloTokenAndRelayExactBounds(t *testing.T) {
	identity := vectorIdentity()
	identity.RuntimeID = "A" + strings.Repeat("x", 127)
	hello := GuestHello{Suite: HandshakeSuite1, Identity: identity}
	wire, err := MarshalGuestHello(hello)
	if err != nil {
		t.Fatalf("MarshalGuestHello(128-byte token) error: %v", err)
	}
	if _, err := ParseGuestHello(wire); err != nil {
		t.Fatalf("ParseGuestHello(128-byte token) error: %v", err)
	}
	identity.RuntimeID += "x"
	if _, err := MarshalGuestHello(GuestHello{Suite: HandshakeSuite1, Identity: identity}); !errors.Is(err, ErrMalformedHandshake) {
		t.Fatalf("MarshalGuestHello(129-byte token) error = %v", err)
	}

	relay := vectorIdentity()
	relay.Channel = ChannelSSHRelay
	relay.GuestPort = SSHRelayPort
	relay.JobGeneration = "job-gen-1"
	relay.ActivationGeneration = "activation-gen-1"
	relay.RelayGeneration = "relay-gen-1"
	relayWire, err := MarshalGuestHello(GuestHello{Suite: HandshakeSuite1, Identity: relay})
	if err != nil {
		t.Fatalf("MarshalGuestHello(relay) error: %v", err)
	}
	parsed, err := ParseGuestHello(relayWire)
	if err != nil {
		t.Fatalf("ParseGuestHello(relay) error: %v", err)
	}
	if parsed.Identity != relay {
		t.Fatalf("relay identity = %#v, want %#v", parsed.Identity, relay)
	}

	for _, mutate := range []func(*Identity){
		func(value *Identity) { value.GuestPort = ControlPort },
		func(value *Identity) { value.JobGeneration = "" },
		func(value *Identity) { value.JobGeneration = "job:gen" },
		func(value *Identity) { value.ActivationGeneration = "" },
		func(value *Identity) { value.RelayGeneration = "" },
	} {
		invalid := relay
		mutate(&invalid)
		if _, err := MarshalGuestHello(GuestHello{Suite: HandshakeSuite1, Identity: invalid}); !errors.Is(err, ErrMalformedHandshake) {
			t.Fatalf("MarshalGuestHello(invalid relay %#v) error = %v", invalid, err)
		}
	}
}

func TestControllerAuthStrictValidation(t *testing.T) {
	valid := mustHex(t, vectorControllerAuthHex)
	for _, tt := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated", mutate: func(w []byte) []byte { return w[:len(w)-1] }},
		{name: "trailing", mutate: func(w []byte) []byte { return append(w, 0) }},
		{name: "outer length", mutate: func(w []byte) []byte { w[3]--; return w }},
		{name: "magic", mutate: func(w []byte) []byte { w[4] ^= 1; return w }},
		{name: "version", mutate: func(w []byte) []byte { w[8]++; return w }},
		{name: "type", mutate: func(w []byte) []byte { w[9] = handshakeTypeGuestHello; return w }},
		{name: "reserved", mutate: func(w []byte) []byte { w[10] = 1; return w }},
		{name: "suite", mutate: func(w []byte) []byte { w[13] = 2; return w }},
		{name: "channel", mutate: func(w []byte) []byte { w[14] = 9; return w }},
		{name: "channel reserved", mutate: func(w []byte) []byte { w[15] = 1; return w }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.mutate(append([]byte(nil), valid...))
			if _, err := ParseControllerAuth(wire); !errors.Is(err, ErrMalformedHandshake) {
				t.Fatalf("ParseControllerAuth() error = %v, want ErrMalformedHandshake", err)
			}
		})
	}
}

func TestHandshakeRejectsEveryAuthenticatedIdentityMutation(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*Identity)
	}{
		{name: "boot nonce", mutate: func(i *Identity) { i.GuestBootNonce[0] ^= 1 }},
		{name: "controller generation", mutate: func(i *Identity) { i.ControllerKeyGeneration += "x" }},
		{name: "runtime ID", mutate: func(i *Identity) { i.RuntimeID += "x" }},
		{name: "runtime generation", mutate: func(i *Identity) { i.RuntimeGeneration += "x" }},
		{name: "process generation", mutate: func(i *Identity) { i.FirecrackerProcessGeneration += "x" }},
		{name: "vsock generation", mutate: func(i *Identity) { i.VsockGeneration += "x" }},
		{name: "boot generation", mutate: func(i *Identity) { i.BootGeneration += "x" }},
		{name: "image generation", mutate: func(i *Identity) { i.ImageGeneration += "x" }},
		{name: "image digest", mutate: func(i *Identity) { i.ImageSHA256[0] ^= 1 }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			identity := vectorIdentity()
			tt.mutate(&identity)
			_, hello, err := NewGuestHandshake(GuestHandshakeConfig{
				Identity: identity, PinnedControllerPublicKey: vectorControllerPublicKey(t),
				Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)), Now: func() time.Time { return vectorNow }},
			})
			if err != nil {
				t.Fatalf("NewGuestHandshake() error: %v", err)
			}
			controller, err := newVectorControllerHandshake(t)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := controller.AcceptGuestHello(hello); !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("AcceptGuestHello() error = %v, want ErrIdentityMismatch", err)
			}
		})
	}
}

func TestHandshakeRejectsSignatureAndLowOrderShares(t *testing.T) {
	t.Run("signature", func(t *testing.T) {
		guest, _, controller, auth := vectorHandshakesThroughAuth(t)
		_ = controller
		auth[len(auth)-1] ^= 1
		if _, err := guest.AcceptControllerAuth(auth); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("AcceptControllerAuth() error = %v, want ErrAuthentication", err)
		}
	})

	t.Run("guest low order", func(t *testing.T) {
		wire := mustHex(t, vectorGuestHelloHex)
		for i := 16; i < 48; i++ {
			wire[i] = 0
		}
		controller, err := newVectorControllerHandshake(t)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := controller.AcceptGuestHello(wire); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("AcceptGuestHello() error = %v, want ErrAuthentication", err)
		}
	})

	t.Run("controller low order", func(t *testing.T) {
		guest, helloWire, err := newVectorGuestHandshake(t)
		if err != nil {
			t.Fatal(err)
		}
		hello, err := ParseGuestHello(helloWire)
		if err != nil {
			t.Fatal(err)
		}
		guestInner, _ := marshalGuestHelloInner(hello)
		auth := ControllerAuth{Suite: HandshakeSuite1, Channel: ChannelControl}
		unsigned, _ := marshalControllerUnsignedInner(auth)
		th := hashTranscript(guestInner, unsigned)
		input := opaqueHashInput(controllerSignatureLabel, th)
		copy(auth.Signature[:], ed25519.Sign(vectorControllerPrivateKey(t), input))
		zero(input)
		wire, _ := MarshalControllerAuth(auth)
		if _, err := guest.AcceptControllerAuth(wire); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("AcceptControllerAuth() error = %v, want ErrAuthentication", err)
		}
	})
}

func TestErrorsNeverIncludeUntrustedMaterial(t *testing.T) {
	secret := "token-super-secret.example.internal/tmp/key"
	identity := vectorIdentity()
	identity.RuntimeID = secret
	_, _, err := NewGuestHandshake(GuestHandshakeConfig{Identity: identity, PinnedControllerPublicKey: vectorControllerPublicKey(t)})
	if err == nil {
		t.Fatal("NewGuestHandshake() error = nil")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "example.internal") || strings.Contains(err.Error(), "/tmp/") {
		t.Fatalf("error leaked untrusted material: %q", err)
	}
}

func TestInjectedEntropyFailuresAreFixedAndTerminal(t *testing.T) {
	sensitive := errors.New("failed reading /tmp/controller-key token-super-secret")
	if _, _, err := NewGuestHandshake(GuestHandshakeConfig{
		Identity: vectorIdentity(), PinnedControllerPublicKey: vectorControllerPublicKey(t),
		Dependencies: Dependencies{Random: failingReader{err: sensitive}},
	}); !errors.Is(err, ErrAuthentication) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/tmp/") {
		t.Fatalf("NewGuestHandshake(entropy failure) = %q", err)
	}
	controller, err := NewControllerHandshake(ControllerHandshakeConfig{
		ExpectedIdentity: vectorIdentity(), SigningKey: vectorControllerPrivateKey(t),
		Dependencies: Dependencies{Random: failingReader{err: sensitive}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.AcceptGuestHello(mustHex(t, vectorGuestHelloHex)); !errors.Is(err, ErrAuthentication) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("AcceptGuestHello(entropy failure) = %q", err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

var _ io.Reader = failingReader{}

func newVectorGuestHandshake(t *testing.T) (*GuestHandshake, []byte, error) {
	t.Helper()
	return NewGuestHandshake(GuestHandshakeConfig{
		Identity: vectorIdentity(), PinnedControllerPublicKey: vectorControllerPublicKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorGuestPrivateHex)), Now: func() time.Time { return vectorNow }},
	})
}

func newVectorControllerHandshake(t *testing.T) (*ControllerHandshake, error) {
	t.Helper()
	return NewControllerHandshake(ControllerHandshakeConfig{
		ExpectedIdentity: vectorIdentity(), SigningKey: vectorControllerPrivateKey(t),
		Dependencies: Dependencies{Random: bytes.NewReader(mustHex(t, vectorControllerPrivateHex)), Now: func() time.Time { return vectorNow }},
	})
}

func vectorHandshakesThroughAuth(t *testing.T) (*GuestHandshake, []byte, *ControllerHandshake, []byte) {
	t.Helper()
	guest, hello, err := newVectorGuestHandshake(t)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := newVectorControllerHandshake(t)
	if err != nil {
		t.Fatal(err)
	}
	_, auth, err := controller.AcceptGuestHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	return guest, hello, controller, auth
}
