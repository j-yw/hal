//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"os"
	"sync"
)

// This self-bound handle only splits the existing cleanup protocol. It cannot
// attest L7 cleanup or worker persistence, and no production provider selects it.
type minimalJailerFinalization struct {
	self   *minimalJailerFinalization
	client *jailerRecoveryClient
	state  *minimalJailerFinalizationState
}

type minimalJailerFinalizationState struct {
	mu                      sync.Mutex
	expected                jailerRecoveryJob
	directory               *os.File
	correlation, generation string
	pid                     uint32
	startTime               uint64
	active                  *minimalJailerFinalizationAttempt
	frozen                  firecrackerRuntimeOwnerRecordV1
	ready, acknowledged     bool
	quarantined, closing    bool
	closeDone               chan struct{}
	closeErr                error
}

type minimalJailerFinalizationAttempt struct {
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	commit       bool
	stream       *minimalJailerIO
	frozen       firecrackerRuntimeOwnerRecordV1
	ready        bool
	contradicted bool
	err          error
}

type minimalJailerFinalizationResult struct {
	record       firecrackerRuntimeOwnerRecordV1
	finalized    bool
	acknowledged bool
}

func (client *jailerRecoveryClient) finalizeMinimalCleanup(ctx context.Context) (*minimalJailerFinalization, error) {
	if client == nil || !minimalJailerCallerCurrent(ctx) {
		return nil, errL8RuntimeOwnerInvalid
	}
	// An already-admitted legacy operation may hold this lock during its I/O.
	// This selected entry does not claim to interrupt that legacy operation.
	client.mu.Lock()
	if client.origin != client || client.closed || client.directory == nil || client.legacyAdmitted {
		client.mu.Unlock()
		return nil, errL8RuntimeOwnerInvalid
	}
	client.mu.Unlock()
	if !minimalJailerCallerCurrent(ctx) {
		return nil, errL8RuntimeOwnerInvalid
	}
	client.mu.Lock()
	if client.origin != client || client.closed || client.directory == nil || client.legacyAdmitted {
		client.mu.Unlock()
		return nil, errL8RuntimeOwnerInvalid
	}
	completion := client.minimal
	if client.minimal == nil {
		state := &minimalJailerFinalizationState{expected: client.expected, directory: client.directory, correlation: client.correlation, generation: client.generation,
			pid: client.supervisor.PID, startTime: client.supervisor.StartTime, closeDone: make(chan struct{})}
		completion = &minimalJailerFinalization{client: client, state: state}
		completion.self = completion
		client.minimal = completion
	} else {
		completion = client.minimal
	}
	client.mu.Unlock()
	return completion, completion.run(ctx, false)
}

func (completion *minimalJailerFinalization) commit(ctx context.Context) error {
	return completion.run(ctx, true)
}

func (completion *minimalJailerFinalization) valid() bool {
	return completion != nil && completion.self == completion && completion.client != nil && completion.state != nil &&
		completion.client.origin == completion.client && completion.client.minimal == completion
}

func (completion *minimalJailerFinalization) run(ctx context.Context, commit bool) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
	}()
	if !completion.valid() || !minimalJailerCallerCurrent(ctx) {
		return errL8RuntimeOwnerInvalid
	}
	state := completion.state
	for {
		if !minimalJailerCallerCurrent(ctx) {
			return errL8RuntimeOwnerInvalid
		}
		// Build the standard owned context outside bookkeeping locks, including
		// any caller Context methods invoked by context.WithCancel.
		var ownedCtx context.Context
		var cancel context.CancelFunc
		if deadline, bounded := ctx.Deadline(); bounded {
			ownedCtx, cancel = context.WithDeadline(ctx, deadline)
		} else {
			ownedCtx, cancel = context.WithCancel(ctx)
		}
		attempt := &minimalJailerFinalizationAttempt{ctx: ownedCtx, cancel: cancel, done: make(chan struct{}), commit: commit}
		state.mu.Lock()
		if state.closing || state.quarantined || state.acknowledged && !commit {
			state.mu.Unlock()
			cancel()
			return errL8RuntimeOwnerInvalid
		}
		if active := state.active; active != nil {
			state.mu.Unlock()
			select {
			case <-ownedCtx.Done():
				cancel()
				return errL8RuntimeOwnerInvalid
			case <-active.done:
			}
			cancel()
			if active.commit != commit {
				continue
			}
			current := minimalJailerCallerCurrent(ctx)
			state.mu.Lock()
			available := !state.closing && !state.quarantined
			state.mu.Unlock()
			if !current || !available {
				return errL8RuntimeOwnerInvalid
			}
			return active.err
		}
		if !completion.sameClient() {
			state.quarantined = true
			state.mu.Unlock()
			cancel()
			return errL8RuntimeOwnerInvalid
		}
		if commit && state.acknowledged {
			state.mu.Unlock()
			cancel()
			if !minimalJailerCallerCurrent(ctx) {
				return errL8RuntimeOwnerInvalid
			}
			return nil // Only this original handle retained the actual Commit ACK.
		}
		if commit && !state.ready {
			state.mu.Unlock()
			cancel()
			return errL8RuntimeOwnerInvalid
		}
		frozen, ready := state.frozen, state.ready
		attempt.frozen, attempt.ready = frozen, ready
		state.active = attempt
		state.mu.Unlock()
		result, err := completion.execute(attempt, frozen, ready)
		cancel()
		current := minimalJailerCallerCurrent(ctx)
		state.mu.Lock()
		if result.finalized {
			if !state.ready {
				state.frozen = result.record
			}
			state.ready = true
		}
		state.acknowledged = state.acknowledged || result.acknowledged
		state.quarantined = state.quarantined || attempt.contradicted
		if err != nil || !current || state.closing || state.quarantined {
			attempt.err = errL8RuntimeOwnerInvalid
		}
		state.active = nil
		close(attempt.done)
		state.mu.Unlock()
		return attempt.err
	}
}

func (attempt *minimalJailerFinalizationAttempt) attach(socket *os.File, ops *minimalJailerSocketOps) error {
	if attempt.stream != nil {
		return errL8RuntimeOwnerInvalid
	}
	stream, err := newMinimalJailerIO(attempt.ctx, socket, ops)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	attempt.stream = stream
	return nil
}

func (attempt *minimalJailerFinalizationAttempt) closeStream() error {
	if attempt.stream == nil {
		return nil
	}
	stream := attempt.stream
	attempt.stream = nil
	err := stream.close()
	attempt.contradicted = attempt.contradicted || err != nil
	return err
}

func (attempt *minimalJailerFinalizationAttempt) readRecord(client *jailerRecoveryClient) (firecrackerRuntimeOwnerRecordV1, error) {
	record, contradicted, err := client.readRecordObservation()
	if err == nil && attempt.ready && !sameMinimalJailerFinalizedRecord(attempt.frozen, record) {
		contradicted, err = true, errL8RuntimeOwnerInvalid
	}
	attempt.contradicted = attempt.contradicted || contradicted
	return record, err
}

func (completion *minimalJailerFinalization) sameClient() bool {
	client, state := completion.client, completion.state
	return client.origin == client && client.minimal == completion && client.expected == state.expected && client.directory == state.directory &&
		(state.correlation == "" || client.correlation == state.correlation) && (state.generation == "" || client.generation == state.generation) &&
		(state.pid == 0 || client.supervisor.PID == state.pid && client.supervisor.StartTime == state.startTime)
}

func sameMinimalJailerFinalizedRecord(frozen, current firecrackerRuntimeOwnerRecordV1) bool {
	if current.State != "finalized" || current.ControllerState != "controlled" && current.ControllerState != "unclaimed" || current.Revision < frozen.Revision {
		return false
	}
	current.Revision, current.ControllerState, current.ReconnectSecret = frozen.Revision, frozen.ControllerState, frozen.ReconnectSecret
	return current == frozen
}

func (completion *minimalJailerFinalization) execute(attempt *minimalJailerFinalizationAttempt, frozen firecrackerRuntimeOwnerRecordV1, ready bool) (result minimalJailerFinalizationResult, resultErr error) {
	client := completion.client
	defer func() {
		if recover() != nil {
			attempt.contradicted = true
			resultErr = errL8RuntimeOwnerInvalid
		}
		if attempt.closeStream() != nil {
			attempt.contradicted = true
			resultErr = errL8RuntimeOwnerInvalid
		}
		if client.socket != nil {
			if client.socket.Close() != nil {
				attempt.contradicted = true
				resultErr = errL8RuntimeOwnerInvalid
			}
			client.socket = nil
		}
		client.session = ""
	}()
	if !completion.sameClient() {
		attempt.contradicted = true
		return result, errL8RuntimeOwnerInvalid
	}
	if !minimalJailerCallerCurrent(attempt.ctx) {
		return result, errL8RuntimeOwnerInvalid
	}
	if client.socket == nil {
		if client.authenticateWithMinimal(attempt.ctx, attempt) != nil {
			return result, errL8RuntimeOwnerInvalid
		}
	} else if attempt.attach(client.socket, client.ops.minimalIO) != nil {
		return result, errL8RuntimeOwnerInvalid
	}
	record, err := attempt.readRecord(client)
	if err != nil || !minimalJailerCallerCurrent(attempt.ctx) {
		return result, errL8RuntimeOwnerInvalid
	}
	if record != client.record || ready && !sameMinimalJailerFinalizedRecord(frozen, record) {
		attempt.contradicted = true
		return result, errL8RuntimeOwnerInvalid
	}
	sequence := uint64(1)
	switch record.State {
	case "running", "stopping", "uncertain":
		body, err := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: client.session})
		if err != nil {
			return result, errL8RuntimeOwnerInvalid
		}
		response, err := attempt.stream.exchange(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: sequence, Body: body})
		if err != nil {
			return result, errL8RuntimeOwnerInvalid
		}
		absence, err := decodeL8RuntimeOwnerResponse(response.Body)
		if err != nil || absence.State != l8RuntimeOwnerStateAbsent || absence.AbsenceKind != l8RuntimeOwnerAbsenceKindWait {
			return result, errL8RuntimeOwnerInvalid
		}
		record, err = attempt.readRecord(client)
		if err != nil || record.State != "absent" || record.ControllerState != "controlled" || record.Revision != absence.RecordRevision || record.AbsenceObservedAtUnixNano != absence.ObservedAtUnixNano || !minimalJailerCallerCurrent(attempt.ctx) {
			return result, errL8RuntimeOwnerInvalid
		}
		sequence++
	case "absent", "finalizing", "finalized":
	default:
		return result, errL8RuntimeOwnerInvalid
	}
	body, err := encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: client.session, AbsenceRevision: record.AbsenceRevision, ObservedAtUnixNano: record.AbsenceObservedAtUnixNano})
	if err != nil {
		return result, errL8RuntimeOwnerInvalid
	}
	response, err := attempt.stream.exchange(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: sequence, Body: body})
	if err != nil {
		return result, errL8RuntimeOwnerInvalid
	}
	ack, err := decodeL8RuntimeOwnerFinalizeAck(response.Body)
	if err != nil {
		return result, errL8RuntimeOwnerInvalid
	}
	current, err := attempt.readRecord(client)
	expected := l8RuntimeOwnerFinalizeAckV1{CommitID: current.FinalizedCommitID, FinalizedRevision: current.FinalizeTargetRevision}
	if err != nil || !minimalJailerCallerCurrent(attempt.ctx) {
		return result, errL8RuntimeOwnerInvalid
	}
	if current.State != "finalized" || current.ControllerState != "controlled" || ack != expected || current.AbsenceRevision != record.AbsenceRevision || current.AbsenceObservedAtUnixNano != record.AbsenceObservedAtUnixNano || ready && !sameMinimalJailerFinalizedRecord(frozen, current) {
		attempt.contradicted = true
		return result, errL8RuntimeOwnerInvalid
	}
	result.record, result.finalized = current, true
	if !attempt.commit {
		return result, nil
	}
	body, err = encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: client.session, CommitID: current.FinalizedCommitID, FinalizedRevision: current.FinalizeTargetRevision})
	if err != nil {
		return result, errL8RuntimeOwnerInvalid
	}
	response, err = attempt.stream.exchange(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: sequence + 1, Body: body})
	if len(response.Body) != 8 || binary.BigEndian.Uint64(response.Body) != current.FinalizeTargetRevision {
		return result, errL8RuntimeOwnerInvalid
	}
	result.acknowledged = true
	if err != nil || !minimalJailerCallerCurrent(attempt.ctx) {
		return result, errL8RuntimeOwnerInvalid
	}
	return result, nil
}

func (completion *minimalJailerFinalization) close() error {
	if !completion.valid() {
		return errL8RuntimeOwnerInvalid
	}
	state := completion.state
	state.mu.Lock()
	if state.closing {
		done := state.closeDone
		state.mu.Unlock()
		<-done
		return state.closeErr
	}
	state.closing = true
	active := state.active
	state.mu.Unlock()
	if active != nil {
		active.cancel()
		<-active.done
	}
	client := completion.client
	client.mu.Lock()
	client.closed = true
	directory, socket, supervisor := client.directory, client.socket, client.supervisor
	client.mu.Unlock()
	failed := supervisor.Close() != nil
	if socket != nil {
		failed = socket.Close() != nil || failed
	}
	if directory != nil {
		failed = directory.Close() != nil || failed
	}
	if failed {
		state.closeErr = errL8RuntimeOwnerInvalid
	}
	client.mu.Lock()
	client.directory, client.socket, client.session = nil, nil, ""
	client.supervisor = l8RuntimeOwnerProcessObservation{}
	client.closeErr = state.closeErr
	client.mu.Unlock()
	close(state.closeDone)
	return state.closeErr
}
