//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"sync"
	"sync/atomic"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

// Only the private per-call test sibling substitutes these boundaries. It
// cannot supply a Session, descriptor, claim, context or prepared result.
type minimalPreexecOps struct {
	network   func(minimalPreexecHostInputs, l7network.Identity, networkenforcement.Plan) (*l7network.Coordinator, error)
	seed      func(context.Context) (*minimalControllerSeedOwner, error)
	entropy   func([]byte) (int, error)
	duplicate func(*os.File) (*os.File, error)
	seal      func(context.Context, []byte) (*os.File, error)
}

type minimalPreexecAttempt struct {
	owner                                  *minimalTemplateAssetOwner
	host                                   *minimalPreexecHost
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	setupDone, stop, contextDone, lossDone chan struct{}
	stopOnce                               sync.Once
	lost                                   atomic.Bool
	prepared                               bool
	ops                                    minimalPreexecOps
	hostFiles                              [3]*os.File
	directory                              *os.File
	directoryPin                           l8RuntimeOwnerKeyIdentity
	directoryCreated                       bool
	coordinator                            *l7network.Coordinator
	session                                *l7network.Session
	networkIdentity                        l7network.Identity
	networkPlan                            networkenforcement.Plan
	namespace                              [2]*os.File
	namespacePins                          minimalControlNamespaces
	seed                                   *minimalControllerSeedOwner
	fcFile, configFile                     *os.File
	config                                 minimalControlSupervisorConfig
	configDigest                           [32]byte
	expectation                            minimalControlConfigExpectation
	filesClosed, rollbackComplete          bool
	closeErr                               error
}

// Preparation belongs to the exact claimed asset owner. There is no caller,
// replacement preparation context/deadline, successful assembly or exec yet.
func (*minimalTemplateAssetOwner) prepareMinimalInputs(*minimalPreexecHost) error {
	return sandboxruntime.ErrMinimalLaunchUnavailable
}

func (*minimalTemplateAssetOwner) prepareMinimalInputsWithOps(*minimalPreexecHost, minimalPreexecOps) error {
	return sandboxruntime.ErrMinimalLaunchUnavailable
}
