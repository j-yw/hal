package l7network

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

// NewProductionRawPacketVerifierFactory binds every verifier to the exact
// full-ID target supplied only after Podman create/start.
func NewProductionRawPacketVerifierFactory(runner rootlesspodman.LifecycleCommandRunner, podmanPath string) RawPacketVerifierFactory {
	return func(request rootlesspodman.NetworkTopologyTargetRequest) (linuxrules.RawPacketIsolationVerifier, error) {
		if runner == nil || request.Identity.RuntimeDriver != rootlesspodman.DriverID || request.Target.ID == "" ||
			request.Target.ID != request.Target.Runtime.RuntimeID || request.Target.Runtime.Driver != rootlesspodman.DriverID {
			return nil, ErrInvalidConfiguration
		}
		return rootlesspodman.NewPodmanRawPacketIsolationVerifier(rootlesspodman.PodmanRawPacketIsolationVerifierOptions{
			LifecycleRunner: runner, PodmanPath: podmanPath, Identity: request.Identity, Target: request.Target,
		}), nil
	}
}
