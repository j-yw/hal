package server

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// PrepareWorkload checks the backend and local process/network observations
// within the serving lifetime. The transport must call it before first readiness.
func (server *Server) PrepareWorkload(ctx context.Context) error {
	if server == nil || server.workloadIsolationVerifier == nil {
		return errServerNotReady
	}
	callCtx, cancel := server.contextWithTiming(ctx, nil)
	defer cancel()
	backendCtx, release, err := server.beginBackendCall(callCtx, false)
	if err != nil {
		return err
	}
	defer release()
	return server.inspectWorkload(backendCtx, true)
}

// HandleWorkload uses the common strict classifier and timed exec/copy paths.
// Selected Handle also excludes readiness, so it cannot provide a bypass.
func (server *Server) HandleWorkload(ctx context.Context, request Request) Response {
	if server == nil || server.workloadIsolationVerifier == nil {
		return encodeStandaloneError(guestagent.ErrorCodeServerNotReady, "", "server")
	}
	return server.Handle(ctx, request)
}

func (server *Server) inspectWorkload(ctx context.Context, prepare bool) (err error) {
	if err := workloadContextError(ctx); err != nil {
		return err
	}
	attempt := server.beginIsolationProofAttempt()
	defer func() {
		if recover() != nil {
			err = errServerNotReady
		}
		server.mu.Lock()
		defer server.mu.Unlock()
		if ctxErr := workloadContextError(ctx); ctxErr != nil {
			err = ctxErr
		}
		if server.state != StateServing || server.operationCtx.Err() != nil || attempt != server.currentProofAttempt {
			err = errServerNotReady
		}
		if attempt == server.currentProofAttempt {
			server.isolationProven = err == nil
		}
	}()
	if prepare {
		if err := server.backend.Ready(ctx); err != nil {
			return errServerNotReady
		}
		if err := workloadContextError(ctx); err != nil {
			return err
		}
	}
	result, err := server.workloadIsolationVerifier.VerifyWorkloadIsolation(ctx)
	if err != nil || !processIsolationVerified(result) || !networkIsolationVerified(result) {
		return errServerNotReady
	}
	return nil
}

func workloadContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
