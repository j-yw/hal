package minimalcontrol

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

// NewWorkloadTransport is an unselected compiling RED scaffold. It delegates
// only the unchanged readiness-only bootstrap; it does not dispatch work,
// establish local proof, or change the enclosing server's lifecycle state.
func NewWorkloadTransport(options BootstrapOptions) (server.Transport, error) {
	bootstrap, err := NewBootstrap(options)
	if err != nil {
		return nil, err
	}
	return &workloadTransport{bootstrap: bootstrap}, nil
}

type workloadTransport struct{ bootstrap *Server }

func (transport *workloadTransport) Serve(ctx context.Context, _ server.Limits, _ server.Handler) error {
	return transport.bootstrap.Serve(ctx)
}
