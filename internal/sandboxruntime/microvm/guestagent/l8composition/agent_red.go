package l8composition

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

var ErrAgentCompositionDependencyUnaccepted = errors.New("L8 guest agent composition dependency is unaccepted")

// Agent is the sole future process-local lifecycle wrapper around the existing
// v1 server and its optional explicit credential client. This RED candidate
// owns no listener, credential operation, proof, or default wiring.
type Agent struct {
	compositionLiveValue
	server *server.Server
}

// NewAgent freezes direct ownership of one explicit server.Options value.
// Construction remains dependency_unaccepted pending lifecycle review.
func NewAgent(server.Options) (*Agent, error) {
	return nil, ErrAgentCompositionDependencyUnaccepted
}

func (agent *Agent) Serve(context.Context) error {
	return ErrAgentCompositionDependencyUnaccepted
}

func (agent *Agent) Shutdown(context.Context) error {
	return ErrAgentCompositionDependencyUnaccepted
}

func (agent *Agent) State() server.State {
	return server.StateFailed
}
