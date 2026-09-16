package server

import "context"

// InspectWorkloadIsolation returns one fresh local observation under the same
// work permit and operation lifetime. It performs no backend or environment work.
// A verifier panic releases that lifetime and propagates only a fixed failure
// to the selected transport, which retires without waiting to send a reply.
func (server *Server) InspectWorkloadIsolation(ctx context.Context) (IsolationProofResult, error) {
	defer func() {
		if recover() != nil {
			panic(errServerNotReady)
		}
	}()
	if server == nil || server.workloadIsolationVerifier == nil {
		return IsolationProofResult{}, errServerNotReady
	}
	callCtx, cancel := server.contextWithTiming(ctx, nil)
	defer cancel()
	operationCtx, release, err := server.beginOperation(callCtx, true)
	if err != nil {
		return IsolationProofResult{}, err
	}
	defer release()
	return server.inspectWorkloadResult(operationCtx, false)
}
