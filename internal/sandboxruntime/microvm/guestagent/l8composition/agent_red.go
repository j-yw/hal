package l8composition

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

var ErrAgentCompositionDependencyUnaccepted = errors.New("L8 guest agent composition dependency is unaccepted")

// Agent is the sole process-local lifecycle wrapper around the existing v1
// server and its optional explicit credential client. It owns no listener,
// credential operation, proof, or default wiring.
type Agent struct {
	compositionLiveValue
	server *server.Server
}

// NewAgent takes direct ownership of one explicit server.Options value.
func NewAgent(options server.Options) (*Agent, error) {
	owned, err := server.New(options)
	if err != nil {
		return nil, err
	}
	return &Agent{server: owned}, nil
}

func (agent *Agent) Serve(ctx context.Context) error {
	if agent == nil || agent.server == nil {
		return ErrAgentCompositionDependencyUnaccepted
	}
	return agent.server.Serve(ctx)
}

func (agent *Agent) Shutdown(ctx context.Context) error {
	if agent == nil || agent.server == nil {
		return ErrAgentCompositionDependencyUnaccepted
	}
	return agent.server.Shutdown(ctx)
}

func (agent *Agent) State() server.State {
	if agent == nil || agent.server == nil {
		return server.StateFailed
	}
	return agent.server.State()
}
