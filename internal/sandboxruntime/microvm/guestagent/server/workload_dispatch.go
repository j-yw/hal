package server

import "context"

// PrepareWorkload is an unselected compiling RED scaffold; no local proof
// attempt, backend call or cached-state mutation is implemented here.
func (server *Server) PrepareWorkload(context.Context) error {
	return errServerNotReady
}

// HandleWorkload still delegates the unchanged legacy classifier for RED.
// It does not yet provide the selected work-only admission contract.
func (server *Server) HandleWorkload(ctx context.Context, request Request) Response {
	return server.Handle(ctx, request)
}
