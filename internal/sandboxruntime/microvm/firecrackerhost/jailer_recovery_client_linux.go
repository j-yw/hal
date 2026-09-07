//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
)

// Only the surviving supervisor's retained coordinator can perform cleanup.
// This client holds no launch, identity-release or replacement-owner authority.
type jailerRecoveryClient struct {
	mu                      sync.Mutex
	origin                  *jailerRecoveryClient
	minimal                 *minimalJailerFinalization
	legacyAdmitted          bool
	expected                jailerRecoveryJob
	correlation, generation string
	directory, socket       *os.File
	ops                     jailerRecoveryReconnectOps
	supervisor              l8RuntimeOwnerProcessObservation
	session                 string
	record                  firecrackerRuntimeOwnerRecordV1
	closed, committed       bool
	closeErr                error
}

func (client *jailerRecoveryClient) close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	if client.minimal != nil {
		completion := client.minimal
		valid := client.origin == client
		client.mu.Unlock()
		if !valid {
			return errL8RuntimeOwnerInvalid
		}
		return completion.close()
	}
	defer client.mu.Unlock()
	if client.closed {
		return client.closeErr
	}
	client.closed = true
	client.closeErr = client.supervisor.Close()
	if client.socket != nil {
		client.closeErr = errors.Join(client.closeErr, client.socket.Close())
		client.socket = nil
	}
	if client.directory != nil {
		client.closeErr = errors.Join(client.closeErr, client.directory.Close())
		client.directory = nil
	}
	return client.closeErr
}

func (client *jailerRecoveryClient) stopAndCommit(ctx context.Context) error {
	if client == nil || ctx == nil {
		return errL8RuntimeOwnerInvalid
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.directory == nil || ctx.Err() != nil || client.minimal != nil {
		return errL8RuntimeOwnerInvalid
	}
	client.legacyAdmitted = true
	if client.committed {
		return nil
	}
	if client.socket == nil && client.authenticate(ctx) != nil {
		return errL8RuntimeOwnerInvalid
	}
	// Any uncertain exchange ends this one-use session. A later caller must
	// authenticate again from the current record; missing record is not success.
	defer func() { _ = client.socket.Close(); client.socket = nil; client.session = "" }()
	fd := int(client.socket.Fd())
	record, err := client.readRecord()
	if err != nil || record != client.record {
		return errL8RuntimeOwnerInvalid
	}
	sequence := uint64(1)
	switch record.State {
	case "running", "stopping", "uncertain":
		body, err := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: client.session})
		if err != nil {
			return errL8RuntimeOwnerInvalid
		}
		response, err := jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: sequence, Body: body})
		if err != nil {
			return errL8RuntimeOwnerInvalid
		}
		absence, err := decodeL8RuntimeOwnerResponse(response.Body)
		if err != nil || absence.State != l8RuntimeOwnerStateAbsent || absence.AbsenceKind != l8RuntimeOwnerAbsenceKindWait {
			return errL8RuntimeOwnerInvalid
		}
		record, err = client.readRecord()
		if err != nil || record.State != "absent" || record.ControllerState != "controlled" || record.Revision != absence.RecordRevision || record.AbsenceObservedAtUnixNano != absence.ObservedAtUnixNano {
			return errL8RuntimeOwnerInvalid
		}
		sequence++
	case "absent", "finalizing", "finalized":
	default:
		return errL8RuntimeOwnerInvalid
	}
	body, err := encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: client.session, AbsenceRevision: record.AbsenceRevision, ObservedAtUnixNano: record.AbsenceObservedAtUnixNano})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	response, err := jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: sequence, Body: body})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	finalized, err := decodeL8RuntimeOwnerFinalizeAck(response.Body)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	current, err := client.readRecord()
	expected := l8RuntimeOwnerFinalizeAckV1{CommitID: current.FinalizedCommitID, FinalizedRevision: current.FinalizeTargetRevision}
	if err != nil || current.State != "finalized" || finalized != expected || current.AbsenceRevision != record.AbsenceRevision {
		return errL8RuntimeOwnerInvalid
	}
	body, err = encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: client.session, CommitID: current.FinalizedCommitID, FinalizedRevision: current.FinalizeTargetRevision})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	response, err = jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: sequence + 1, Body: body})
	if err != nil || len(response.Body) != 8 || binary.BigEndian.Uint64(response.Body) != finalized.FinalizedRevision {
		return errL8RuntimeOwnerInvalid
	}
	client.committed = true
	return nil
}

func jailerRecoveryClientExchange(ctx context.Context, fd int, packet l8RuntimeOwnerPacketV1) (l8RuntimeOwnerPacketV1, error) {
	if ctx == nil || ctx.Err() != nil || sendL8RuntimeOwnerSeqpacket(fd, packet, nil) != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	response, err := receiveL8RuntimeOwnerSeqpacket(fd)
	defer closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || ctx.Err() != nil || validateL8RuntimeOwnerPacketRole(response.Packet, true, len(response.Files)) != nil || response.Packet.Opcode != packet.Opcode || response.Packet.Sequence != packet.Sequence || response.Packet.Status != l8RuntimeOwnerStatusOK {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	return response.Packet, nil
}
