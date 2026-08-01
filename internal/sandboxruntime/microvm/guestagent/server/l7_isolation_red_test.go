package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestL7ServerOwnedNetworkProofRequirementCannotBeDowngraded(t *testing.T) {
	backend := &l4FakeBackend{}
	verifier := &l7FakeIsolationVerifier{result: IsolationProofResult{
		RestrictedIdentity:         true,
		CapabilitiesCleared:        true,
		NoNewPrivileges:            true,
		SupplementaryGroupsCleared: true,
		RawPacketSocketDenied:      true,
		Network: NetworkIsolationProofResult{
			Status: guestagent.IsolationProofStatusUnavailable,
		},
	}}
	options := Options{
		Transport:                     newL4BlockingTransport(),
		Backend:                       backend,
		IsolationVerifier:             verifier,
		RequireNetworkProofBeforeWork: true,
	}
	run := startL4Server(t, options)

	for _, request := range []guestagent.ReadinessRequest{
		{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			IsolationProof: &guestagent.IsolationProofRequest{
				Generation:        "network-policy-generation-1",
				RuntimeGeneration: "runtime-generation-1",
			},
		},
		{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			IsolationProof: &guestagent.IsolationProofRequest{
				Generation:          "network-policy-generation-2",
				RuntimeGeneration:   "runtime-generation-1",
				RequireNetworkProof: false,
			},
		},
	} {
		response := l4DecodeResponse[guestagent.ReadinessResponse](t, run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, request)}))
		if response.Ready || response.IsolationProof == nil || response.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
			t.Fatalf("readiness = %#v, want network-proof failure", response)
		}
	}
	verifier.mu.Lock()
	verifier.result.Network.Status = guestagent.IsolationProofStatusFailed
	verifier.mu.Unlock()
	failedRequest := guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		IsolationProof: &guestagent.IsolationProofRequest{
			Generation:        "network-policy-generation-failed",
			RuntimeGeneration: "runtime-generation-1",
		},
	}
	failedResponse := l4DecodeResponse[guestagent.ReadinessResponse](t, run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, failedRequest)}))
	if failedResponse.Ready || failedResponse.IsolationProof == nil || failedResponse.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
		t.Fatalf("failed readiness = %#v, want network-proof failure", failedResponse)
	}

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
		t.Fatal("user work reached backend without verified network proof")
	}
}

func TestL7ServerOwnedNetworkProofRequirementUpgradesConcurrentWeakRequests(t *testing.T) {
	verifier := &l7RequestRecordingIsolationVerifier{}
	options := Options{
		Transport:                     newL4BlockingTransport(),
		Backend:                       &l4FakeBackend{},
		IsolationVerifier:             verifier,
		RequireNetworkProofBeforeWork: true,
	}
	run := startL4Server(t, options)

	requests := []guestagent.ReadinessRequest{
		{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			IsolationProof: &guestagent.IsolationProofRequest{
				Generation:        "network-policy-generation-3",
				RuntimeGeneration: "runtime-generation-2",
			},
		},
		{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
			IsolationProof: &guestagent.IsolationProofRequest{
				Generation:          "network-policy-generation-4",
				RuntimeGeneration:   "runtime-generation-2",
				RequireNetworkProof: true,
			},
		},
	}
	responses := make(chan Response, len(requests))
	var wait sync.WaitGroup
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, request)})
		}()
	}
	wait.Wait()
	close(responses)
	for encodedResponse := range responses {
		response := l4DecodeResponse[guestagent.ReadinessResponse](t, encodedResponse)
		if !response.Ready || response.IsolationProof == nil || response.IsolationProof.Network == nil || response.IsolationProof.Network.Status != guestagent.IsolationProofStatusVerified {
			t.Fatalf("readiness = %#v, want verified server-required network proof", response)
		}
	}
	for index, request := range verifier.requestsSnapshot() {
		if !request.RequireNetworkProof {
			t.Fatalf("verifier request %d = %#v, want server-required network proof", index, request)
		}
	}
}

func TestL7ServerConcurrentProofCompletionOrdersControlAdmission(t *testing.T) {
	tests := []struct {
		name              string
		startOrder        []string
		completionOrder   []string
		wantWorkAdmission bool
	}{
		{
			name:              "failed proof completes after success",
			startOrder:        []string{"failure", "success"},
			completionOrder:   []string{"success", "failure"},
			wantWorkAdmission: false,
		},
		{
			name:              "current success completes after failure",
			startOrder:        []string{"failure", "success"},
			completionOrder:   []string{"failure", "success"},
			wantWorkAdmission: true,
		},
		{
			name:              "stale success completes after current failure",
			startOrder:        []string{"success", "failure"},
			completionOrder:   []string{"failure", "success"},
			wantWorkAdmission: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &l4FakeBackend{}
			verifier := newL7ProofOrderVerifier()
			run := startL4Server(t, Options{
				Transport:                     newL4BlockingTransport(),
				Backend:                       backend,
				IsolationVerifier:             verifier,
				RequireNetworkProofBeforeWork: true,
			})

			requests := map[string]guestagent.ReadinessRequest{
				"failure": {
					ProtocolVersion: guestagent.ProtocolVersionV1,
					Operation:       guestagent.OperationReadiness,
					IsolationProof: &guestagent.IsolationProofRequest{
						Generation:        "proof-failure",
						RuntimeGeneration: "runtime-generation-concurrent",
					},
				},
				"success": {
					ProtocolVersion: guestagent.ProtocolVersionV1,
					Operation:       guestagent.OperationReadiness,
					IsolationProof: &guestagent.IsolationProofRequest{
						Generation:          "proof-success",
						RuntimeGeneration:   "runtime-generation-concurrent",
						RequireNetworkProof: false,
					},
				},
			}
			responses := map[string]chan guestagent.ReadinessResponse{
				"failure": make(chan guestagent.ReadinessResponse, 1),
				"success": make(chan guestagent.ReadinessResponse, 1),
			}
			for _, name := range test.startOrder {
				name := name
				go func() {
					response := run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, requests[name])})
					responses[name] <- l4DecodeResponse[guestagent.ReadinessResponse](t, response)
				}()
				verifier.waitEntered(t, name)
			}

			for _, name := range test.completionOrder {
				verifier.release(name)
				response := l7WaitReadinessResponse(t, responses[name])
				if name == "success" {
					if !response.Ready || response.IsolationProof == nil || response.IsolationProof.Network == nil ||
						response.IsolationProof.Network.Status != guestagent.IsolationProofStatusVerified {
						t.Fatalf("success response = %#v, want verified readiness", response)
					}
				} else if response.Ready || response.IsolationProof == nil || response.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
					t.Fatalf("failure response = %#v, want failed readiness", response)
				}
			}
			for index, request := range verifier.requestsSnapshot() {
				if !request.RequireNetworkProof {
					t.Fatalf("verifier request %d = %#v, want server-owned network requirement", index, request)
				}
			}

			execRequest := guestagent.ExecRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationExec,
				Args:            []string{"tool"},
				WorkDir:         "/workspace",
				Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
				Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
			}
			copyRequest := guestagent.CopyOutRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationCopyOut,
				SourcePath:      "/workspace/artifact",
				Payload: guestagent.PayloadMetadata{
					MaxBytes: 16,
					Encoding: guestagent.PayloadEncodingBase64,
				},
			}
			execResponse := run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, execRequest)})
			copyResponse := run.server.Handle(context.Background(), Request{Encoded: l7JSON(t, copyRequest)})
			if test.wantWorkAdmission {
				if backend.execCalls.Load() != 1 || backend.copyOutCalls.Load() != 1 {
					t.Fatalf("backend work calls = exec:%d copy:%d, want one each", backend.execCalls.Load(), backend.copyOutCalls.Load())
				}
				return
			}
			l4RequireResponseCode(t, execResponse, guestagent.ErrorCodeServerNotReady)
			l4RequireResponseCode(t, copyResponse, guestagent.ErrorCodeServerNotReady)
			if backend.execCalls.Load() != 0 || backend.copyOutCalls.Load() != 0 {
				t.Fatalf("backend work calls = exec:%d copy:%d, want none after failed proof", backend.execCalls.Load(), backend.copyOutCalls.Load())
			}
		})
	}
}

func TestL7ServerOwnedNetworkProofRequirementImpliesIsolationVerifier(t *testing.T) {
	_, err := New(Options{
		Transport:                     newL4BlockingTransport(),
		Backend:                       &l4FakeBackend{},
		RequireNetworkProofBeforeWork: true,
	})
	if err == nil || err.Error() != "guest-agent isolation verifier is required" {
		t.Fatalf("New() error = %v, want isolation verifier requirement", err)
	}
}

type l7RequestRecordingIsolationVerifier struct {
	mu       sync.Mutex
	requests []guestagent.IsolationProofRequest
}

type l7ProofOrderVerifier struct {
	mu       sync.Mutex
	requests []guestagent.IsolationProofRequest
	entered  map[string]chan struct{}
	releases map[string]chan struct{}
}

func newL7ProofOrderVerifier() *l7ProofOrderVerifier {
	return &l7ProofOrderVerifier{
		entered: map[string]chan struct{}{
			"failure": make(chan struct{}),
			"success": make(chan struct{}),
		},
		releases: map[string]chan struct{}{
			"failure": make(chan struct{}),
			"success": make(chan struct{}),
		},
	}
}

func (verifier *l7ProofOrderVerifier) VerifyIsolation(ctx context.Context, request guestagent.IsolationProofRequest) (IsolationProofResult, error) {
	name := strings.TrimPrefix(request.Generation, "proof-")
	verifier.mu.Lock()
	verifier.requests = append(verifier.requests, request)
	entered := verifier.entered[name]
	release := verifier.releases[name]
	verifier.mu.Unlock()
	if entered == nil || release == nil {
		return IsolationProofResult{}, errors.New("unexpected proof generation")
	}
	close(entered)
	select {
	case <-ctx.Done():
		return IsolationProofResult{}, ctx.Err()
	case <-release:
	}
	if name == "failure" {
		return IsolationProofResult{}, errors.New("fixed proof failure")
	}
	return l7VerifiedIsolationResult(), nil
}

func (verifier *l7ProofOrderVerifier) waitEntered(t *testing.T, name string) {
	t.Helper()
	select {
	case <-verifier.entered[name]:
	case <-time.After(time.Second):
		t.Fatalf("%s proof verifier did not start", name)
	}
}

func (verifier *l7ProofOrderVerifier) release(name string) {
	close(verifier.releases[name])
}

func (verifier *l7ProofOrderVerifier) requestsSnapshot() []guestagent.IsolationProofRequest {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return append([]guestagent.IsolationProofRequest(nil), verifier.requests...)
}

func l7VerifiedIsolationResult() IsolationProofResult {
	return IsolationProofResult{
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
	}
}

func l7WaitReadinessResponse(t *testing.T, responses <-chan guestagent.ReadinessResponse) guestagent.ReadinessResponse {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("readiness response did not complete")
		return guestagent.ReadinessResponse{}
	}
}

func (verifier *l7RequestRecordingIsolationVerifier) VerifyIsolation(_ context.Context, request guestagent.IsolationProofRequest) (IsolationProofResult, error) {
	verifier.mu.Lock()
	verifier.requests = append(verifier.requests, request)
	verifier.mu.Unlock()
	result := IsolationProofResult{
		RestrictedIdentity:         true,
		CapabilitiesCleared:        true,
		NoNewPrivileges:            true,
		SupplementaryGroupsCleared: true,
		RawPacketSocketDenied:      true,
		Network: NetworkIsolationProofResult{
			Status: guestagent.IsolationProofStatusUnavailable,
		},
	}
	if request.RequireNetworkProof {
		result.Network = NetworkIsolationProofResult{
			Status:          guestagent.IsolationProofStatusVerified,
			SingleInterface: true,
			StaticRoutes:    true,
			ProxyReachable:  true,
		}
	}
	return result, nil
}

func (verifier *l7RequestRecordingIsolationVerifier) requestsSnapshot() []guestagent.IsolationProofRequest {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return append([]guestagent.IsolationProofRequest(nil), verifier.requests...)
}

func l7JSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
