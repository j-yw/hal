//go:build linux

package firecrackerhost

import (
	"context"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// Compiling RED resource holder only. The selected eight-role producer must
// retain these original resources before launch; there is no constructor from
// a received event, raw work FD, reconnect client or caller-supplied readiness.
type minimalControlProducerLaunch struct {
	original   *os.File
	directory  *os.File
	config     minimalControlSupervisorConfig
	supervisor l8RuntimeOwnerProcessObservation
}

type minimalControlWorkCandidate struct{}

func (*minimalControlProducerLaunch) awaitWork(context.Context) (*minimalControlWorkCandidate, error) {
	return nil, errL8RuntimeOwnerInvalid
}

func (*minimalControlWorkCandidate) RoundTrip(context.Context, guestagent.TransportRequest) (guestagent.TransportResponse, error) {
	return guestagent.TransportResponse{}, errL8RuntimeOwnerInvalid
}
