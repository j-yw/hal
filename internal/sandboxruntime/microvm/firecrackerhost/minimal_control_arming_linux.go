//go:build linux

package firecrackerhost

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

// Caller holds starter.mu on entry and return, but not during I/O or watcher
// joining. Outer launch locks remain with that caller and are never acquired
// by the operation watcher or completion path.
func (starter *jailerRecoveryStarter) awaitMinimalGateArmedLocked(ctx context.Context) (resultErr error) {
	entry := time.Now()
	gate := starter.minimalGate
	if ctx == nil || ctx.Err() != nil || gate == nil || !gate.matches(starter, gate.prep) ||
		!gate.prep.current() || gate.closing || gate.operation != nil || gate.attempted ||
		!starter.started || starter.closed || starter.released || starter.gate == nil || !starter.observation.pidfdOwned {
		return errStrictJailerNamespaceStartFailed
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errStrictJailerNamespaceStartFailed
	}
	if gate.prep.deadline.Before(deadline) {
		deadline = gate.prep.deadline
	}
	if limit := entry.Add(l8RuntimeOwnerHandshakeTimeout); limit.Before(deadline) {
		deadline = limit
	}
	current := func() bool { return ctx.Err() == nil && gate.prep.current() && time.Now().Before(deadline) }
	if !current() || time.Until(deadline) < time.Microsecond {
		return errStrictJailerNamespaceStartFailed
	}
	op, err := starter.newMinimalGateOperationLocked(gate)
	if err != nil {
		return errStrictJailerNamespaceStartFailed
	}
	operationCtx, cancel := context.WithDeadline(ctx, deadline)
	fd := int(op.file.Fd())
	starter.mu.Unlock()
	defer func() {
		close(op.stopWatcher)
		<-op.watcherDone
		cancel()
		closeErr := op.file.Close()
		starter.mu.Lock() // Restore the caller's lock before publishing completion.
		if op.shutdownErr != nil || closeErr != nil {
			gate.cleanupErr = errL8RuntimeOwnerInvalid
		}
		if resultErr != nil || gate.cleanupErr != nil || starter.minimalGate != gate || gate.operation != op ||
			gate.closing || starter.closed || !current() {
			resultErr = errStrictJailerNamespaceStartFailed
		}
		close(op.done)
	}()
	go func() {
		defer close(op.watcherDone)
		select {
		case <-operationCtx.Done():
			op.shutdownErr = unix.Shutdown(fd, unix.SHUT_RDWR)
		case <-gate.prep.preparationCtx.Done():
			op.shutdownErr = unix.Shutdown(fd, unix.SHUT_RDWR)
		case <-op.stopWatcher:
		}
	}()
	remaining := time.Until(deadline)
	if !current() || remaining < time.Microsecond || setL8RuntimeOwnerSocketTimeout(fd, remaining) != nil || !current() {
		return errStrictJailerNamespaceStartFailed
	}
	armed, err := receiveL8RuntimeOwnerSeqpacket(fd)
	defer closeL8RuntimeOwnerFiles(armed.Files)
	if err != nil || !current() || validateL8RuntimeOwnerPacketRole(armed.Packet, false, len(armed.Files)) != nil || armed.Packet.Opcode != l8RuntimeOwnerOpcodeChildArmed {
		return errStrictJailerNamespaceStartFailed
	}
	return nil
}
