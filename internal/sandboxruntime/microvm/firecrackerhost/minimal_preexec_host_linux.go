//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
)

// These are borrowed deployment inputs, not request fields or readiness proof.
// The RED constructor does not retain or consume any of them yet.
type minimalPreexecHostInputs struct {
	policy                           jailerRecoveryHostPolicy
	vcpus                            int
	memoryMiB                        int64
	baseBootArguments, jailPathBase  string
	stateRoot, stableKey, executable *os.File
	executableSHA256                 [sha256.Size]byte
	networkPolicyID                  string
	proxy                            policyproxy.Config
	topology                         linuxtopology.Config
	tap                              l7network.TAPOptions
	rules                            linuxrules.ProductionExecutorOptions
	networkStateDirectory            string
	cleanupTimeout                   time.Duration
}

type minimalPreexecHost struct {
	stateRoot, stableKey, executable *os.File
}

func newMinimalPreexecHost(ctx context.Context, provider *minimalLaunchProvider, input minimalPreexecHostInputs) (*minimalPreexecHost, error) {
	if os.Geteuid() != 0 {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return newMinimalPreexecHostForUID(ctx, provider, input, 0)
}

// The ordinary-UID test seam does not replace the production root observation.
// No successful host or owned duplicate is manufactured by this RED scaffold.
func newMinimalPreexecHostForUID(context.Context, *minimalLaunchProvider, minimalPreexecHostInputs, uint32) (*minimalPreexecHost, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

func (*minimalPreexecHost) close() error { return sandboxruntime.ErrMinimalLaunchUnavailable }
