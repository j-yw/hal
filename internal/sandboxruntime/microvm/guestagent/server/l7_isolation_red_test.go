package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

type l7FakeIsolationVerifier struct {
	mu     sync.Mutex
	calls  int
	result IsolationProofResult
	err    error
	order  *[]string
}

func (verifier *l7FakeIsolationVerifier) VerifyIsolation(_ context.Context, _ guestagent.IsolationProofRequest) (IsolationProofResult, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.calls++
	if verifier.order != nil {
		*verifier.order = append(*verifier.order, "isolation")
	}
	return verifier.result, verifier.err
}

func TestL7ServerRequiresExactIsolationProofBeforeUserWork(t *testing.T) {
	order := []string{}
	backend := &l4FakeBackend{}
	verifier := &l7FakeIsolationVerifier{order: &order, result: IsolationProofResult{
		RestrictedIdentity:         true,
		CapabilitiesCleared:        true,
		NoNewPrivileges:            true,
		SupplementaryGroupsCleared: true,
		RawPacketSocketDenied:      true,
		Network: NetworkIsolationProofResult{
			Status:          guestagent.IsolationProofStatusVerified,
			SingleInterface: true,
			StaticRoutes:    true,
			ProxyReachable:  true,
		},
	}}
	run := startL4Server(t, Options{
		Transport:                       newL4BlockingTransport(),
		Backend:                         backend,
		IsolationVerifier:               verifier,
		RequireIsolationProofBeforeWork: true,
	})

	execRequest := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
	}
	l4RequireResponseCode(t, run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, execRequest)}), guestagent.ErrorCodeServerNotReady)
	if backend.execCalls.Load() != 0 {
		t.Fatal("user work reached backend before isolation proof")
	}

	readinessRequest := guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		IsolationProof: &guestagent.IsolationProofRequest{
			Generation:          "proof-generation-3",
			RuntimeGeneration:   "runtime-generation-3",
			RequireNetworkProof: true,
		},
	}
	response := l4DecodeResponse[guestagent.ReadinessResponse](t, run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, readinessRequest)}))
	if err := guestagent.ValidateReadinessResponseForRequest(response, readinessRequest); err != nil {
		t.Fatalf("proof response rejected: %v", err)
	}
	if !response.Ready || response.IsolationProof == nil {
		t.Fatalf("readiness = %#v, want proof-bearing ready response", response)
	}

	run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, execRequest)})
	if backend.execCalls.Load() != 1 {
		t.Fatalf("backend exec calls = %d, want one after proof", backend.execCalls.Load())
	}
	if verifier.calls != 1 {
		t.Fatalf("isolation verifier calls = %d, want one", verifier.calls)
	}
}

func TestL7ServerProofFailureIsFailClosedAndRedacted(t *testing.T) {
	secret := errors.New("read /proc/self/status at /home/alice: endpoint=http://10.0.0.2:8080 token=ghp_secret")
	verifier := &l7FakeIsolationVerifier{err: errors.Join(errors.New("outer"), errors.Join(secret, secret))}
	run := startL4Server(t, Options{
		Transport:                       newL4BlockingTransport(),
		Backend:                         &l4FakeBackend{},
		IsolationVerifier:               verifier,
		RequireIsolationProofBeforeWork: true,
	})
	request := guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		IsolationProof:  &guestagent.IsolationProofRequest{Generation: "proof-generation-4"},
	}
	response := run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, request)})
	var decoded guestagent.ReadinessResponse
	if err := json.Unmarshal(response.Encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Ready || decoded.IsolationProof == nil || decoded.IsolationProof.Status != guestagent.IsolationProofStatusFailed {
		t.Fatalf("readiness = %#v, want sanitized failed proof", decoded)
	}
	for _, leaked := range []string{"/proc/", "/home/alice", "10.0.0.2", "8080", "ghp_secret"} {
		if strings.Contains(string(response.Encoded), leaked) {
			t.Fatalf("response leaked %q: %s", leaked, response.Encoded)
		}
	}
}

func TestL7ServerStrictIsolationProofRequestNeverReachesVerifier(t *testing.T) {
	tests := []string{
		`{"protocolVersion":"guest-agent-v1","operation":"readiness","isolationProof":{"generation":"g","unknown":true}}`,
		`{"protocolVersion":"guest-agent-v1","operation":"readiness","isolationProof":{"generation":"g","generation":"g"}}`,
		`{"protocolVersion":"guest-agent-v1","operation":"readiness","isolationProof":{"generation":"` + strings.Repeat("a", guestagent.MaxIsolationProofGenerationBytes+1) + `"}}`,
		`{"protocolVersion":"guest-agent-v1","operation":"readiness","isolationProof":{"generation":"g","requireNetworkProof":null}}`,
	}
	for _, body := range tests {
		verifier := &l7FakeIsolationVerifier{}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: &l4FakeBackend{}, IsolationVerifier: verifier})
		response := run.server.Handle(context.Background(), Request{Encoded: []byte(body)})
		var decoded guestagent.ErrorResponse
		if err := json.Unmarshal(response.Encoded, &decoded); err != nil || decoded.Error == nil {
			t.Fatalf("strict response = %s, %v", response.Encoded, err)
		}
		if verifier.calls != 0 {
			t.Fatal("malformed isolation proof request reached verifier")
		}
	}
}

func l7JSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
