//go:build linux

package sandboxworker

import (
	"context"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8D6WorkerServerPassesSameOwnerPrincipalOutOfBand(t *testing.T) {
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", l8WorkerV2DaemonGeneration)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan sandboxruntime.AuthenticatedWorkerPrincipal, 1)
	handler := &l8D6PrincipalCaptureHandler{authority: authority, seen: seen}
	server, err := NewServer(ServerOptions{
		SocketPath:               testWorkerSocketPath(t),
		Handler:                  RequestHandlerFunc(func(_ context.Context, request Request) Response { return unsupportedOperationResponse(request) }),
		AuthenticatedHandler:     handler,
		PrincipalAuthority:       authority,
		AuthenticatedPrincipalID: "local-unix-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)
	response := roundTripWorkerRequest(t, server.socketPath, Request{
		RequestID: "request-peer", Operation: OperationJobStatusV2,
		JobStatusV2: &JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-peer"},
	})
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeJobNotFound {
		t.Fatalf("authenticated response = %#v", response)
	}
	principal := <-seen
	if err := authority.ValidateAuthenticatedWorkerPrincipal(principal); err != nil {
		t.Fatalf("transport principal is not owned by configured authority: %v", err)
	}
	if principal.ID() != "local-unix-owner" || principal.UID() != uint32(os.Geteuid()) || principal.GID() != uint32(os.Getegid()) {
		t.Fatalf("transport principal identity = %q/%d/%d", principal.ID(), principal.UID(), principal.GID())
	}
}

func TestL8D6WorkerServerPrincipalInjectionIsExplicitAndPaired(t *testing.T) {
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", l8WorkerV2DaemonGeneration)
	if err != nil {
		t.Fatal(err)
	}
	handler := &l8D6PrincipalCaptureHandler{authority: authority, seen: make(chan sandboxruntime.AuthenticatedWorkerPrincipal, 1)}
	base := ServerOptions{SocketPath: testWorkerSocketPath(t), Handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
		return unsupportedOperationResponse(request)
	})}
	tests := []struct {
		name   string
		mutate func(*ServerOptions)
	}{
		{name: "handler without authority", mutate: func(options *ServerOptions) { options.AuthenticatedHandler = handler }},
		{name: "authority without handler", mutate: func(options *ServerOptions) {
			options.PrincipalAuthority = authority
			options.AuthenticatedPrincipalID = "local-unix-owner"
		}},
		{name: "authority without principal id", mutate: func(options *ServerOptions) {
			options.PrincipalAuthority = authority
			options.AuthenticatedHandler = handler
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := base
			tt.mutate(&options)
			if server, err := NewServer(options); err == nil || server != nil {
				t.Fatalf("NewServer() = %#v, %v, want paired explicit injection failure", server, err)
			}
		})
	}
}

type l8D6PrincipalCaptureHandler struct {
	authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	seen      chan<- sandboxruntime.AuthenticatedWorkerPrincipal
}

func (*l8D6PrincipalCaptureHandler) HandlesAuthenticatedRequest(request Request) bool {
	return isWorkerV2Operation(request.Operation)
}

func (handler *l8D6PrincipalCaptureHandler) HandleAuthenticatedRequest(_ context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request Request) Response {
	if err := handler.authority.ValidateAuthenticatedWorkerPrincipal(principal); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "authenticated worker principal was rejected")
	}
	handler.seen <- principal
	return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeJobNotFound, "worker v2 job was not found")
}

var _ AuthenticatedRequestHandler = (*l8D6PrincipalCaptureHandler)(nil)
