//go:build linux

package firecrackerhost

import (
	"sync"
	"time"
)

// Selected below-root composition. The executable/default routes do not select
// this entry. Its enclosing admission owns the borrowed key through every join.
type minimalControlSupervisorServing struct {
	owned           *l8RuntimeOwnerLinuxRuntime
	owner           *l8RuntimeOwnerSupervisor
	admission       *minimalControlSupervisorAdmission
	controllerDone  chan struct{}
	controllerErr   error
	mu              sync.Mutex
	controller      *minimalControlController
	server          *minimalControlWorkServer
	closing         bool
	closeDone       chan struct{}
	closeErr        error
	lifecycleDone   chan struct{}
	publicationDone chan struct{}
}

// The supplied FSM is the one originally constructed for this exact runtime.
// This below-root serving entry neither constructs nor replaces runtime/process
// authority. Its caller retains the admission and owner through every join.
func (owned *l8RuntimeOwnerLinuxRuntime) serveMinimalControlSupervisor(owner *l8RuntimeOwnerSupervisor, admission *minimalControlSupervisorAdmission) error {
	if owned == nil || owner == nil || admission == nil || owned.selected == nil || owned.minimalPreparation == nil ||
		owner.opts.Store != owned.store || owner.opts.GenesisRecord != owned.genesis || owner.opts.ExpectedUID != owned.config.DaemonUID {
		return errL8RuntimeOwnerInvalid
	}
	prep := owned.minimalPreparation
	if prep.owner != owned || !prep.matchesAdmission(admission, owned.selected.config) {
		return errL8RuntimeOwnerInvalid
	}
	serving := &minimalControlSupervisorServing{owned: owned, owner: owner, admission: admission,
		controllerDone: make(chan struct{}), closeDone: make(chan struct{}), lifecycleDone: make(chan struct{})}
	owned.mu.Lock()
	if owned.minimalServing != nil {
		owned.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	owned.minimalServing = serving
	owned.mu.Unlock()
	// Ending this entire serving scope joins its borrowed-key consumer. A
	// controller task returning alone does not end the cleanup accept service.
	defer func() { _ = serving.closeIO(); <-serving.lifecycleDone }()
	go func() {
		defer close(serving.lifecycleDone)
		<-prep.ctx.Done()
		// This task may enter lifecycle locks. The I/O barrier never joins it.
		if serving.closeIO() == nil {
			_, _ = owned.containChild()
		}
	}()
	if err := owned.serveMinimalControlPreparation(owner, admission.borrowed[0], admission); err != nil {
		close(serving.controllerDone)
		if !owned.selected.attempted {
			return errL8RuntimeOwnerInvalid
		}
		_ = owned.quarantineJailerBootstrap()
	} else {
		go func() {
			defer close(serving.controllerDone)
			defer prep.revoke()
			defer func() {
				if recover() != nil {
					serving.controllerErr = errL8RuntimeOwnerInvalid
				}
			}()
			serving.controllerErr = serving.runController()
		}()
	}
	// Control loss ends work, not the cleanup accept service. Only the existing
	// terminal cleanup protocol (or an accept error) ends this serving entry.
	return owned.serveControllers(owner)
}

func (serving *minimalControlSupervisorServing) runController() error {
	owned, prep := serving.owned, serving.owned.minimalPreparation
	selected := owned.selected
	// Thin capture of the existing post-bootstrap source. No manager/kernel
	// observation or controller I/O runs under these bookkeeping locks.
	selected.mu.Lock()
	if selected.minimalPreparation != prep || selected.coordinator == nil || selected.lifecycle == nil ||
		selected.store != owned.store || !selected.attempted || selected.terminal {
		selected.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	coordinator, lifecycle, starter := selected.coordinator, selected.lifecycle, selected.starter
	coordinator.mu.Lock()
	generation := coordinator.generation
	if generation == nil || generation.state != strictJailerCoordinatorActive || !generation.hasProcess ||
		selected.session.coordinator != coordinator || selected.session.generation != generation.id || coordinator.deps.lifecycle != lifecycle {
		coordinator.mu.Unlock()
		selected.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	process, manager := generation.process, lifecycle.manager
	coordinator.mu.Unlock()
	selected.mu.Unlock()
	if starter == nil || manager == nil || !lifecycle.validProcess(process) || !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	starter.mu.Lock()
	gate := starter.minimalGate
	var window minimalControlReleaseWindow
	complete := gate != nil && gate.matches(starter, prep) && starter.released && !starter.closed
	if complete {
		window = gate.window
	}
	starter.mu.Unlock()
	if !complete || window.startedAt.IsZero() || !time.Now().Before(window.deadline) || !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	transport, err := newMinimalControlTransport(manager, process.handle, serving.admission.config.Job.RuntimeID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return withMinimalWorkloadController(prep.ctx, transport, serving.admission, window.deadline, func(controller *minimalControlController) error {
		serving.mu.Lock()
		serving.controller = controller
		serving.mu.Unlock()
		ready, err := controller.WaitReady(prep.preparationCtx)
		if err != nil {
			return errL8RuntimeOwnerInvalid
		}
		return serving.publishWork(ready)
	})
}

func (serving *minimalControlSupervisorServing) closeIO() error {
	prep := serving.owned.minimalPreparation
	prep.revoke() // Publish before acquiring any bookkeeping/lifecycle lock.
	serving.mu.Lock()
	if serving.closing {
		done := serving.closeDone
		serving.mu.Unlock()
		<-done
		return serving.closeErr
	}
	serving.closing = true
	serving.mu.Unlock()
	// Controller consume owns every partial pair and publication operation.
	// Never join lifecycleDone: its entrant may need the caller's FSM locks.
	<-serving.controllerDone
	serving.closeErr = prep.close()
	close(serving.closeDone)
	return serving.closeErr
}
