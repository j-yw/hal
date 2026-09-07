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

// Setup-only lifetime for the compiling RED. This is not runtime/root authority.
// No P observer, original-channel monitor or selected context propagation is
// implemented yet. The actual root constructor remains unchanged/unselected.
type minimalControlPreparation struct {
	mu          sync.Mutex
	correlation [32]byte
	deadline    time.Time
	borrowedFD  int
	original    *os.File
	ctx         context.Context
	cancel      context.CancelFunc
	owner       *l8RuntimeOwnerLinuxRuntime
	used        bool
	operation   chan struct{}
	closing     bool
	closeDone   chan struct{}
	closeErr    error
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
	prep := &minimalControlPreparation{correlation: admission.configDigest, deadline: deadline, borrowedFD: admission.borrowed[0],
		original: os.NewFile(uintptr(fd), "minimal-preparation-original"), ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
	return config, prep, nil
}

func bindMinimalControlPreparation(owned *l8RuntimeOwnerLinuxRuntime, prep *minimalControlPreparation) error {
	if owned == nil || prep == nil || owned.selected == nil || owned.store == nil || owned.store.selected == nil {
		return errL8RuntimeOwnerInvalid
	}
	prep.mu.Lock()
	defer prep.mu.Unlock()
	binding, err := owned.store.selected.recordBinding()
	if err != nil || prep.owner != nil || prep.closing || owned.minimalPreparation != nil || owned.selected.minimalPreparation != nil ||
		owned.selected.config.Version != minimalControlSupervisorConfigVersion || owned.store.selected.minimal == nil ||
		binding.configCorrelation != hex.EncodeToString(prep.correlation[:]) || owned.genesis.SeedCorrelationDigest != binding.configCorrelation {
		return errL8RuntimeOwnerInvalid
	}
	prep.owner = owned
	owned.minimalPreparation = prep
	owned.selected.minimalPreparation = prep
	return nil
}

// Compiling RED delegate: binding/lifetime is explicit, but bootstrap still
// loses the context and original-reader transfer. No executable calls this.
func (owned *l8RuntimeOwnerLinuxRuntime) serveMinimalControlPreparation(owner *l8RuntimeOwnerSupervisor, fd int, admission *minimalControlSupervisorAdmission) error {
	if owned == nil || owned.selected == nil || admission == nil || owned.minimalPreparation == nil {
		return errL8RuntimeOwnerInvalid
	}
	prep := owned.minimalPreparation
	prep.mu.Lock()
	if prep.owner != owned || owned.selected.minimalPreparation != prep || prep.used || prep.closing || fd != prep.borrowedFD ||
		admission.borrowed[0] != fd || admission.configDigest != prep.correlation || admission.config.Control.PreparationDeadlineUnixNano != prep.deadline.UnixNano() {
		prep.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	prep.used = true
	done := make(chan struct{})
	prep.operation = done
	originalFD := int(prep.original.Fd())
	prep.mu.Unlock()
	defer close(done) // End this operation, not the continuing owner lifetime.
	return owned.serveBootstrap(owner, originalFD)
}

func (selected *jailerRecoveryRuntime) startMinimalControlChild() (l8RuntimeOwnerStartedChild, error) {
	if selected == nil || selected.minimalPreparation == nil || selected.minimalPreparation.owner == nil ||
		selected.minimalPreparation.owner.selected != selected {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	return selected.startChild()
}

// The outer owner/fixture calls this outside its locks and outside the bootstrap
// operation it joins. Future P-observer/monitor joins belong here; none exists
// in this RED. The actual runtime close hook is intentionally not wired yet.
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
	file := prep.original
	prep.mu.Unlock()
	prep.cancel()
	shutdownErr := unix.Shutdown(int(file.Fd()), unix.SHUT_RDWR)
	if operation != nil {
		<-operation
	}
	closeErr := file.Close()
	if shutdownErr != nil || closeErr != nil {
		prep.closeErr = errL8RuntimeOwnerInvalid
	}
	close(prep.closeDone)
	return prep.closeErr
}
