//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
)

var errMinimalControlController = errors.New("minimal control controller unavailable")

// Compiling RED boundary only: no transcript, readiness or runtime consumer.
type minimalControlController struct{}

type minimalControlReadiness struct {
	binding             minimalcontrol.Binding
	sessionID           [32]byte
	handle              firecracker.ProcessHandleMetadata
	transportGeneration uint64
}

func withMinimalControlController(_ context.Context, _ *minimalControlTransport, admission *minimalControlSupervisorAdmission, _ time.Time, _ func(*minimalControlController) error) error {
	if admission != nil {
		clear(admission.controllerKey)
	}
	return errMinimalControlController
}

func (*minimalControlController) WaitReady(context.Context) (*minimalControlReadiness, error) {
	return nil, errMinimalControlController
}

func (*minimalControlController) Close() error { return nil }

func (*minimalControlReadiness) Current() bool { return false }
