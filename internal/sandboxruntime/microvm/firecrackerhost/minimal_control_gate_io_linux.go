//go:build linux

package firecrackerhost

import (
	"os"

	"golang.org/x/sys/unix"
)

// Bound before start, then immutable to this starter and preparation. Mutable
// operation/close bookkeeping and immutable release window use starter.mu;
// cancellation/release admission authority belongs to the preparation latch.
type minimalControlGateIO struct {
	starter    *jailerRecoveryStarter
	prep       *minimalControlPreparation
	window     minimalControlReleaseWindow
	attempted  bool
	operation  *minimalControlGateOperation
	closing    bool
	closeDone  chan struct{}
	cleanupErr error
}

type minimalControlGateOperation struct {
	file        *os.File
	done        chan struct{}
	stopWatcher chan struct{}
	watcherDone chan struct{}
	shutdownErr error // Written by watcher, read only after watcherDone.
}

// Called only by the existing exact preparation binder before publication.
// This grants I/O lifetime only, never process/launch or cleanup authority.
func bindMinimalControlGateIO(starter *jailerRecoveryStarter, prep *minimalControlPreparation) error {
	if starter == nil || prep == nil {
		return errL8RuntimeOwnerInvalid
	}
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if !prep.current() || starter.minimalGate != nil || starter.started || starter.released || starter.closed {
		return errL8RuntimeOwnerInvalid
	}
	starter.minimalGate = &minimalControlGateIO{starter: starter, prep: prep, closeDone: make(chan struct{})}
	return nil
}

func (gate *minimalControlGateIO) matches(starter *jailerRecoveryStarter, prep *minimalControlPreparation) bool {
	return gate != nil && prep != nil && gate.starter == starter && gate.prep == prep
}

func (starter *jailerRecoveryStarter) beginMinimalGateRelease(gate *minimalControlGateIO) (*minimalControlGateOperation, error) {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if gate == nil || !gate.matches(starter, gate.prep) || starter.minimalGate != gate || !gate.prep.current() ||
		!gate.prep.canceled.releaseAdmitted() || gate.window.startedAt.IsZero() ||
		gate.attempted || gate.closing || !starter.started || starter.closed || starter.released || starter.gate == nil || !starter.observation.pidfdOwned {
		return nil, errL8RuntimeOwnerInvalid
	}
	// Local I/O exclusion is additional to the original selected admission;
	// failed/ambiguous I/O never clears that admission or its original window.
	gate.attempted = true
	originalFD := int(starter.gate.Fd())
	var original unix.Stat_t
	flags, flagErr := unix.FcntlInt(uintptr(originalFD), unix.F_GETFD, 0)
	kind, kindErr := unix.GetsockoptInt(originalFD, unix.SOL_SOCKET, unix.SO_TYPE)
	if flagErr != nil || flags&unix.FD_CLOEXEC == 0 || kindErr != nil || kind != unix.SOCK_SEQPACKET ||
		unix.Fstat(originalFD, &original) != nil || original.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.FcntlInt(uintptr(originalFD), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "minimal-gate-release")
	var duplicate unix.Stat_t
	if unix.Fstat(fd, &duplicate) != nil || duplicate.Dev != original.Dev || duplicate.Ino != original.Ino || !gate.prep.current() {
		if file.Close() != nil {
			gate.cleanupErr = errL8RuntimeOwnerInvalid
		}
		return nil, errL8RuntimeOwnerInvalid
	}
	op := &minimalControlGateOperation{file: file, done: make(chan struct{}), stopWatcher: make(chan struct{}), watcherDone: make(chan struct{})}
	gate.operation = op
	return op, nil
}

func (starter *jailerRecoveryStarter) releaseMinimalGate(gate *minimalControlGateIO) (resultErr error) {
	op, err := starter.beginMinimalGateRelease(gate)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	fd := int(op.file.Fd())
	go func() {
		defer close(op.watcherDone)
		select {
		case <-gate.prep.preparationCtx.Done():
			// The writer keeps this owned duplicate open until this task joins.
			// Never close a borrowed raw descriptor under another task's I/O.
			op.shutdownErr = unix.Shutdown(fd, unix.SHUT_RDWR)
		case <-op.stopWatcher:
		}
	}()
	defer func() {
		close(op.stopWatcher) // Normal completion signal, not cancellation authority.
		<-op.watcherDone
		closeErr := op.file.Close()
		starter.mu.Lock()
		defer starter.mu.Unlock()
		if op.shutdownErr != nil || closeErr != nil {
			gate.cleanupErr = errL8RuntimeOwnerInvalid
		}
		if resultErr != nil || gate.cleanupErr != nil || starter.minimalGate != gate || gate.operation != op ||
			gate.closing || starter.closed || !gate.prep.current() {
			resultErr = errL8RuntimeOwnerInvalid
		} else {
			starter.released = true
		}
		// Close joins this operation only, never its enclosing bootstrap/FSM.
		close(op.done)
	}()
	// Reuse the original P and existing <=5s budget; no deadline rebase/retry.
	if gate.prep.setSocketBudget(fd, false) != nil || !gate.prep.current() ||
		sendL8RuntimeOwnerSeqpacket(fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease}, nil) != nil || !gate.prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (starter *jailerRecoveryStarter) closeMinimalGate(gate *minimalControlGateIO) error {
	if gate == nil || !gate.matches(starter, gate.prep) {
		return errL8RuntimeOwnerInvalid
	}
	// Publish through the SAME preparation latch without waiting for starter.mu.
	// Do not call prep.close: Abort may be inside the bootstrap it would join.
	gate.prep.revoke()
	starter.mu.Lock()
	if starter.minimalGate != gate {
		starter.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	if gate.closing {
		done := gate.closeDone
		starter.mu.Unlock()
		<-done
		return starter.closeErr
	}
	gate.closing, starter.closed = true, true
	op := gate.operation
	starter.mu.Unlock()
	if op != nil {
		<-op.done
	}
	starter.mu.Lock()
	defer starter.mu.Unlock()
	failed := starter.observation.Close() != nil
	if starter.gate != nil {
		failed = starter.gate.Close() != nil || failed
		starter.gate = nil
	}
	if failed || gate.cleanupErr != nil {
		starter.closeErr = errL8RuntimeOwnerInvalid
	}
	close(gate.closeDone)
	return starter.closeErr
}
