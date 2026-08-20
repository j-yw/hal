//go:build linux

package sandboxworker

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8ServerBindsAuthenticatedPrincipalFromUnixPeerCredentials(t *testing.T) {
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", "daemon-generation-1")
	if err != nil {
		t.Fatalf("NewAuthenticatedWorkerPrincipalAuthority() error: %v", err)
	}

	principalSeen := make(chan sandboxruntime.AuthenticatedWorkerPrincipal, 1)
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath:         socketPath,
		PrincipalAuthority: authority,
		Handler: RequestHandlerFunc(func(_ context.Context, req Request) Response {
			return Response{RequestID: req.RequestID, Operation: req.Operation, OK: true}
		}),
		AuthenticatedHandler: &l8PrincipalCaptureHandler{seen: principalSeen},
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)
	response := roundTripWorkerRequest(t, socketPath, Request{
		RequestID:   "req-peer",
		Operation:   OperationJobStatusV2,
		JobStatusV2: &JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-peer"},
	})
	if response.Error == nil || response.Error.Code != ErrorCodeJobNotFound {
		t.Fatalf("response = %#v, want authenticated V2 dispatch", response)
	}

	principal := <-principalSeen
	if err := authority.ValidateAuthenticatedWorkerPrincipal(principal); err != nil {
		t.Fatalf("handler principal is not owned by configured authority: %v", err)
	}
	if principal.ID() != "local-unix-peer" {
		t.Fatalf("principal ID = %q, want private stable local peer identity", principal.ID())
	}
}

type l8PrincipalCaptureHandler struct {
	seen chan<- sandboxruntime.AuthenticatedWorkerPrincipal
}

func (*l8PrincipalCaptureHandler) HandlesAuthenticatedRequest(request Request) bool {
	return isWorkerV2Operation(request.Operation)
}

func (handler *l8PrincipalCaptureHandler) HandleAuthenticatedRequest(_ context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request Request) Response {
	handler.seen <- principal
	return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeJobNotFound, "worker v2 job was not found")
}

func TestL8ServerWithoutPrincipalAuthorityDoesNotMintPrincipal(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(ctx context.Context, req Request) Response {
			return Response{RequestID: req.RequestID, Operation: req.Operation, OK: true}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)
	response := roundTripWorkerRequest(t, socketPath, Request{RequestID: "req-default", Operation: OperationStatus})
	if !response.OK {
		t.Fatalf("response = %#v, want success", response)
	}
}
