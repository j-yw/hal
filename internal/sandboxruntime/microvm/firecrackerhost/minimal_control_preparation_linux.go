//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/hex"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// One selected owner's admission/I/O lifetime, not runtime or root authority.
// The original deadline and monitor outlive the immediate bootstrap reply.
type minimalControlPreparation struct {
	mu              sync.Mutex
	correlation     [32]byte
	configDigest    string
	deadline        time.Time
	borrowedFD      int
	original        *os.File
	ctx             context.Context
	cancel          context.CancelFunc
	preparationCtx  context.Context
	stopPreparation context.CancelFunc
	canceled        minimalControlPreparationLatch
	observerDone    chan struct{}
	ioDone          chan struct{}
	ioErr           error
	monitorDone     chan struct{}
	owner           *l8RuntimeOwnerLinuxRuntime
	used            bool
	operation       chan struct{}
	closing         bool
	closeDone       chan struct{}
	closeErr        error
}

func beginMinimalControlPreparation(admission *minimalControlSupervisorAdmission) (minimalControlSupervisorConfig, *minimalControlPreparation, error) {
	config, err := validateMinimalControlRuntimeAdmission(admission)
	if err != nil {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	deadline := time.Unix(0, config.Control.PreparationDeadlineUnixNano)
	if !time.Now().Before(deadline) {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.FcntlInt(uintptr(admission.borrowed[0]), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	prepCtx, stop := context.WithDeadline(ctx, deadline)
	prep := &minimalControlPreparation{correlation: admission.configDigest, configDigest: jailerRecoveryConfigDigest(config.jailerRecoverySupervisorConfig), deadline: deadline, borrowedFD: admission.borrowed[0],
		original: os.NewFile(uintptr(fd), "minimal-preparation-original"), ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
	prep.preparationCtx, prep.stopPreparation, prep.observerDone = prepCtx, stop, make(chan struct{})
	go func() {
		defer close(prep.observerDone)
		<-prepCtx.Done()
		prep.revoke()
	}()
	if !prep.current() {
		_ = prep.close()
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	return config, prep, nil
}

func (prep *minimalControlPreparation) current() bool {
	return prep != nil && prep.ctx != nil && !prep.canceled.Load() && prep.ctx.Err() == nil && time.Now().Before(prep.deadline)
}

// Never wait for an owner/FSM/starter lock to publish observed cancellation.
func (prep *minimalControlPreparation) revoke() {
	prep.canceled.cancel()
	prep.cancel()
}

func (prep *minimalControlPreparation) matchesAdmission(admission *minimalControlSupervisorAdmission, config jailerRecoverySupervisorConfig) bool {
	if !prep.current() || admission == nil || config.Version != minimalControlSupervisorConfigVersion ||
		prep.configDigest != jailerRecoveryConfigDigest(config) || prep.correlation != admission.configDigest ||
		prep.borrowedFD != admission.borrowed[0] || prep.deadline.UnixNano() != admission.config.Control.PreparationDeadlineUnixNano {
		return false
	}
	var retained, borrowed unix.Stat_t
	return unix.Fstat(int(prep.original.Fd()), &retained) == nil && unix.Fstat(prep.borrowedFD, &borrowed) == nil &&
		retained.Dev == borrowed.Dev && retained.Ino == borrowed.Ino && prep.current()
}

func bindMinimalControlPreparation(owned *l8RuntimeOwnerLinuxRuntime, prep *minimalControlPreparation) error {
	if owned == nil || prep == nil || owned.selected == nil || owned.store == nil || owned.store.selected == nil {
		return errL8RuntimeOwnerInvalid
	}
	prep.mu.Lock()
	defer prep.mu.Unlock()
	binding, err := owned.store.selected.recordBinding()
	if err != nil || !prep.current() || prep.owner != nil || prep.closing || owned.minimalPreparation != nil || owned.selected.minimalPreparation != nil ||
		owned.selected.config.Version != minimalControlSupervisorConfigVersion || owned.store.selected.minimal == nil ||
		prep.configDigest != jailerRecoveryConfigDigest(owned.selected.config) ||
		binding.configCorrelation != hex.EncodeToString(prep.correlation[:]) || owned.genesis.SeedCorrelationDigest != binding.configCorrelation {
		return errL8RuntimeOwnerInvalid
	}
	if bindMinimalControlGateIO(owned.selected.starter, prep) != nil {
		return errL8RuntimeOwnerInvalid
	}
	prep.owner = owned
	owned.minimalPreparation = prep
	owned.selected.minimalPreparation = prep
	return nil
}

// Only this operation reads BootstrapStart. The receive role transfers to the
// sole monitor before HandleBootstrap starts any owned allocation.
func (owned *l8RuntimeOwnerLinuxRuntime) serveMinimalControlPreparation(owner *l8RuntimeOwnerSupervisor, fd int, admission *minimalControlSupervisorAdmission) (resultErr error) {
	if owned == nil || owned.selected == nil || admission == nil || owned.minimalPreparation == nil {
		return errL8RuntimeOwnerInvalid
	}
	prep := owned.minimalPreparation
	prep.mu.Lock()
	if prep.owner != owned || owned.selected.minimalPreparation != prep || prep.used || prep.closing || !prep.matchesAdmission(admission, owned.selected.config) || fd != prep.borrowedFD ||
		admission.borrowed[0] != fd || admission.configDigest != prep.correlation || admission.config.Control.PreparationDeadlineUnixNano != prep.deadline.UnixNano() {
		prep.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	prep.used = true
	done := make(chan struct{})
	prep.operation = done
	originalFD := int(prep.original.Fd())
	prep.ioDone = make(chan struct{})
	go func() {
		defer close(prep.ioDone)
		<-prep.ctx.Done()
		prep.ioErr = unix.Shutdown(originalFD, unix.SHUT_RDWR)
	}()
	prep.mu.Unlock()
	defer close(done) // End this operation, not the continuing owner lifetime.
	defer func() {
		if resultErr != nil {
			prep.revoke()
		}
	}()
	if prep.setSocketBudget(originalFD, true) != nil {
		return errL8RuntimeOwnerInvalid
	}
	uid, received, err := owned.receiveBootstrap(owner, originalFD)
	if err != nil || !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	// Clearing receive timeout does not clear the independently bounded send.
	if unix.SetsockoptTimeval(originalFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{}) != nil {
		return errL8RuntimeOwnerInvalid
	}
	prep.mu.Lock()
	prep.monitorDone = make(chan struct{})
	monitorDone := prep.monitorDone
	prep.mu.Unlock()
	go func() {
		defer close(monitorDone)
		unexpected, _ := receiveL8RuntimeOwnerSeqpacket(originalFD)
		closeL8RuntimeOwnerFiles(unexpected.Files)
		prep.revoke() // EOF, error or any unsolicited packet has the same effect.
	}()
	if !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	result, err := owner.HandleBootstrap(prep.preparationCtx, uid, received)
	if err != nil || prep.setSocketBudget(originalFD, false) != nil || sendL8RuntimeOwnerControlResult(originalFD, result) != nil || !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (prep *minimalControlPreparation) setSocketBudget(fd int, receive bool) error {
	if !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	remaining := min(time.Until(prep.deadline), l8RuntimeOwnerHandshakeTimeout)
	if remaining < time.Microsecond {
		return errL8RuntimeOwnerInvalid // Zero would disable the timeout.
	}
	value := unix.NsecToTimeval(remaining.Nanoseconds())
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &value) != nil ||
		receive && unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &value) != nil || !prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (selected *jailerRecoveryRuntime) startMinimalControlChild() (l8RuntimeOwnerStartedChild, error) {
	if selected == nil || selected.minimalPreparation == nil || selected.minimalPreparation.owner == nil ||
		selected.minimalPreparation.owner.selected != selected {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	return selected.startChildForPreparation(selected.minimalPreparation)
}

// The outer owner/fixture calls this outside its locks and outside the bootstrap
// operation it joins. No observer/monitor calls this self-joining operation.
func (owned *l8RuntimeOwnerLinuxRuntime) shutdownMinimalControlPreparation() error {
	if owned == nil || owned.minimalPreparation == nil {
		return errL8RuntimeOwnerInvalid
	}
	return owned.minimalPreparation.close()
}

func (prep *minimalControlPreparation) close() error {
	prep.mu.Lock()
	if prep.closing {
		done := prep.closeDone
		prep.mu.Unlock()
		<-done
		return prep.closeErr
	}
	prep.closing = true
	operation := prep.operation
	ioDone := prep.ioDone
	file := prep.original
	prep.mu.Unlock()
	prep.revoke()
	prep.stopPreparation()
	var shutdownErr error
	if ioDone == nil {
		shutdownErr = unix.Shutdown(int(file.Fd()), unix.SHUT_RDWR)
	} else {
		<-ioDone
		shutdownErr = prep.ioErr
	}
	if operation != nil {
		<-operation
	}
	prep.mu.Lock()
	monitorDone := prep.monitorDone
	prep.mu.Unlock()
	if monitorDone != nil {
		<-monitorDone
	}
	<-prep.observerDone
	closeErr := file.Close()
	if shutdownErr != nil || closeErr != nil {
		prep.closeErr = errL8RuntimeOwnerInvalid
	}
	close(prep.closeDone)
	return prep.closeErr
}
