package firecrackerhost

import (
	"bytes"
	"context"
	"time"
)

// No production serving path selects this method yet. The future selected
// caller owns a concrete, idempotent I/O shutdown/join barrier; the callback is
// not cleanup proof. Nil preserves the existing six/seven-role handler exactly.
func (owner *l8RuntimeOwnerSupervisor) handleControllerWithCleanup(ctx context.Context, received l8RuntimeOwnerReceivedPacketV1, closeSelectedControl func() error) (l8RuntimeOwnerControlResult, error) {
	if closeSelectedControl == nil {
		return owner.HandleController(ctx, received)
	}
	if owner == nil || len(received.Packet.Body) > l8RuntimeOwnerPacketLimit-l8RuntimeOwnerPacketHeaderSize ||
		validateL8RuntimeOwnerPacketRole(received.Packet, false, len(received.Files)) != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	// Retain exact owned request bytes across the unlocked callback. Rights stay
	// with the caller; selected cleanup permits none and never closes them here.
	received.Packet.Body = append([]byte(nil), received.Packet.Body...)
	ctx = nonNilContext(ctx)
	owner.mu.Lock()
	defer owner.mu.Unlock()
	replay, session, err := owner.classifyController(received.Packet)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, err
	}
	if replay {
		return owner.replayController(received.Packet)
	}
	switch received.Packet.Opcode {
	case l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit:
	default:
		return owner.handleFreshController(ctx, received, session)
	}
	if owner.admittedSession == "" || owner.admittedSession != session || owner.sessionGeneration != session {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if !minimalCleanupContextCurrent(ctx) {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	record, err := owner.opts.Store.Load(ctx)
	if err != nil || record.ControllerState != "controlled" {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	var finalizePlan *firecrackerRuntimeOwnerRecordV1
	switch received.Packet.Opcode {
	case l8RuntimeOwnerOpcodeStopReap:
		err = owner.validateStop(record)
	case l8RuntimeOwnerOpcodeFinalize:
		request, decodeErr := decodeL8RuntimeOwnerFinalizeRequest(received.Packet.Body)
		if decodeErr != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		var plan firecrackerRuntimeOwnerRecordV1
		plan, err = owner.planFinalize(record, request)
		finalizePlan = &plan
	case l8RuntimeOwnerOpcodeCommit:
		request, decodeErr := decodeL8RuntimeOwnerCommitRequest(received.Packet.Body)
		if decodeErr != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		err = owner.validateCommit(record, request)
	}
	if err != nil {
		return l8RuntimeOwnerControlResult{}, err
	}
	snapshot := owner.cleanupSnapshot()
	owner.mu.Unlock()
	barrierErr := callMinimalCleanupBarrier(ctx, closeSelectedControl)
	owner.mu.Lock()
	if barrierErr != nil || !minimalCleanupContextCurrent(ctx) || !snapshot.matches(owner) {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	// opts.Store is the constructor-retained store, never a request argument.
	// Full equality rejects even changed same-revision fields after owner loss.
	current, err := owner.opts.Store.Load(ctx)
	if err != nil || current != record || !snapshot.matches(owner) || !minimalCleanupContextCurrent(ctx) {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	result, err := owner.dispatchControllerRecord(ctx, received, current, finalizePlan)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, err
	}
	owner.cacheController(received.Packet, result)
	return result, nil
}

// This stack-local snapshot never escapes the compound operation. No mutex,
// callback, resource or authority is duplicated. Body copies detect in-place
// mutations as well as a changed sequence/session while the owner is unlocked.
type minimalCleanupControllerSnapshot struct {
	session, admitted string
	sequence          uint64
	opcode            uint16
	hasLast           bool
	packet            l8RuntimeOwnerPacketV1
	requestBody       []byte
}

func (owner *l8RuntimeOwnerSupervisor) cleanupSnapshot() minimalCleanupControllerSnapshot {
	packet := owner.lastPacket
	packet.Body = append([]byte(nil), packet.Body...)
	return minimalCleanupControllerSnapshot{session: owner.sessionGeneration, admitted: owner.admittedSession,
		sequence: owner.lastSequence, opcode: owner.lastOpcode, hasLast: owner.hasLast, packet: packet,
		requestBody: append([]byte(nil), owner.lastRequestBody...)}
}

func (snapshot minimalCleanupControllerSnapshot) matches(owner *l8RuntimeOwnerSupervisor) bool {
	return snapshot.session == owner.sessionGeneration && snapshot.admitted == owner.admittedSession &&
		snapshot.sequence == owner.lastSequence && snapshot.opcode == owner.lastOpcode && snapshot.hasLast == owner.hasLast &&
		snapshot.packet.Opcode == owner.lastPacket.Opcode && snapshot.packet.Status == owner.lastPacket.Status &&
		snapshot.packet.Sequence == owner.lastPacket.Sequence && bytes.Equal(snapshot.packet.Body, owner.lastPacket.Body) &&
		bytes.Equal(snapshot.requestBody, owner.lastRequestBody)
}

func minimalCleanupContextCurrent(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, bounded := ctx.Deadline()
	return !bounded || time.Now().Before(deadline)
}

func callMinimalCleanupBarrier(ctx context.Context, barrier func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if !minimalCleanupContextCurrent(ctx) || barrier() != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
