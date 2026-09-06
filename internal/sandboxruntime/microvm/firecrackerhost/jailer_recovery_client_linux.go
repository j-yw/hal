//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// A client can reconnect and request cleanup; only the surviving supervisor's
// retained coordinator can carry it out. This object has no path-delete,
// identity-release, replacement-owner, or credential-proof operation.
type jailerRecoveryClient struct {
	mu                sync.Mutex
	config            jailerRecoverySupervisorConfig
	directory         *os.File
	supervisor        l8RuntimeOwnerProcessObservation
	closed, committed bool
}

func (client *jailerRecoveryClient) close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil
	}
	client.closed = true
	err := client.supervisor.Close()
	if client.directory != nil && client.directory.Close() != nil {
		err = errL8RuntimeOwnerInvalid
	}
	client.directory = nil
	return err
}

func (client *jailerRecoveryClient) stopAndCommit(ctx context.Context) error {
	if client == nil || ctx == nil {
		return errL8RuntimeOwnerInvalid
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.directory == nil || ctx.Err() != nil {
		return errL8RuntimeOwnerInvalid
	}
	if client.committed {
		return nil
	}
	file, err := openJailerRecoveryRecordFile(int(client.directory.Fd()))
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	record, _, _, readErr := readJailerRecoveryRecordFile(file, client.config)
	_ = file.Close()
	if readErr != nil || record.SupervisorPID != client.supervisor.PID || record.SupervisorStartTime != client.supervisor.StartTime {
		return errL8RuntimeOwnerInvalid
	}
	actual, err := inspectL8RuntimeOwnerProcess(record.SupervisorPID)
	defer actual.Close()
	boot, bootErr := readL8RuntimeOwnerHostBootID()
	if err != nil || bootErr != nil || boot != record.HostBootID || actual.StartTime != record.SupervisorStartTime {
		return errL8RuntimeOwnerInvalid
	}
	name := l8RuntimeOwnerReconnectPrefix + record.ReconnectListenerIdentity + l8RuntimeOwnerReconnectSuffix
	var before unix.Stat_t
	if unix.Fstatat(int(client.directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Mode&0o777 != 0o600 || before.Uid != client.config.DaemonUID {
		return errL8RuntimeOwnerInvalid
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer unix.Close(fd)
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(client.directory.Fd()), 10) + "/" + name
	if len(path) >= len(unix.RawSockaddrUnix{}.Path) || ctx.Err() != nil || setL8RuntimeOwnerSocketTimeout(fd, l8RuntimeOwnerHandshakeTimeout) != nil || unix.Connect(fd, &unix.SockaddrUnix{Name: path}) != nil {
		return errL8RuntimeOwnerInvalid
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	var after unix.Stat_t
	if err != nil || peer.Uid != client.config.DaemonUID || peer.Pid != int32(record.SupervisorPID) || unix.Fstatat(int(client.directory.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
		return errL8RuntimeOwnerInvalid
	}
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	response, err := jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	ack, err := decodeL8RuntimeOwnerHandshakeAck(response.Body)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	body, err = encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: ack.ControllerSessionGeneration})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	response, err = jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: body})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	absence, err := decodeL8RuntimeOwnerResponse(response.Body)
	if err != nil || absence.State != l8RuntimeOwnerStateAbsent || absence.AbsenceKind != l8RuntimeOwnerAbsenceKindWait {
		return errL8RuntimeOwnerInvalid
	}
	body, err = encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: ack.ControllerSessionGeneration, AbsenceRevision: absence.RecordRevision, ObservedAtUnixNano: absence.ObservedAtUnixNano})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	response, err = jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: 2, Body: body})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	finalized, err := decodeL8RuntimeOwnerFinalizeAck(response.Body)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	body, err = encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: ack.ControllerSessionGeneration, CommitID: finalized.CommitID, FinalizedRevision: finalized.FinalizedRevision})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if _, err = jailerRecoveryClientExchange(ctx, fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: 3, Body: body}); err != nil {
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
