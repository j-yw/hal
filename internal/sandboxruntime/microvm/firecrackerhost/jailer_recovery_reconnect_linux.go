//go:build linux

package firecrackerhost

import (
	"context"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Observations are private and per-client. Production uses authoritative Linux
// checks; ordinary-file tests explicitly inject ownership/peer observations.
type jailerRecoveryReconnectOps struct {
	directory      func(*os.File) error
	bootID         func() (string, error)
	inspect        func(uint32) (l8RuntimeOwnerProcessObservation, error)
	connect        func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error)
	connectMinimal func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error)
	minimalIO      *minimalJailerSocketOps
}

func reconnectJailerRecoverySupervisor(ctx context.Context, directory *os.File, expected jailerRecoveryJob) (*jailerRecoveryClient, error) {
	return reconnectJailerRecoverySupervisorWithOps(ctx, directory, expected, jailerRecoveryLinuxReconnectOps())
}

func reconnectJailerRecoverySupervisorWithOps(ctx context.Context, directory *os.File, expected jailerRecoveryJob, ops jailerRecoveryReconnectOps) (*jailerRecoveryClient, error) {
	if ctx == nil || ctx.Err() != nil || directory == nil || ops.directory == nil || ops.bootID == nil || ops.inspect == nil || ops.connect == nil || ops.directory(directory) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	retained, err := duplicateJailerRecoveryFile(directory)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	client := &jailerRecoveryClient{expected: expected, directory: retained, ops: ops}
	client.origin = client
	if client.authenticate(ctx) != nil {
		_ = client.close()
		return nil, errL8RuntimeOwnerInvalid
	}
	return client, nil
}

func jailerRecoveryLinuxReconnectOps() jailerRecoveryReconnectOps {
	return jailerRecoveryReconnectOps{
		directory: func(file *os.File) error {
			if os.Geteuid() != 0 || file == nil || validateL8RuntimeOwnerDirectoryFD(int(file.Fd())) != nil {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		bootID:         readL8RuntimeOwnerHostBootID,
		inspect:        inspectL8RuntimeOwnerProcess,
		connect:        connectJailerRecoveryOwner,
		connectMinimal: connectMinimalJailerRecoveryOwner,
	}
}

func (client *jailerRecoveryClient) readRecord() (firecrackerRuntimeOwnerRecordV1, error) {
	record, _, err := client.readRecordObservation()
	return record, err
}

// Legacy error/result semantics stay unchanged. Only the selected attempt
// retains the distinction between unavailable I/O and contradictory bytes.
func (client *jailerRecoveryClient) readRecordObservation() (firecrackerRuntimeOwnerRecordV1, bool, error) {
	if client.ops.directory(client.directory) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, true, errL8RuntimeOwnerInvalid
	}
	file, err := openJailerRecoveryRecordFile(int(client.directory.Fd()))
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	defer file.Close()
	payload, err := io.ReadAll(io.NewSectionReader(file, 0, l8RuntimeOwnerRecordLimit+1))
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	record, err := decodeJailerRecoveryCleanupRecord(payload, client.expected)
	if err != nil || client.correlation != "" && record.SeedCorrelationDigest != client.correlation || client.generation != "" && record.SupervisorGeneration != client.generation || client.supervisor.PID != 0 && (record.SupervisorPID != client.supervisor.PID || record.SupervisorStartTime != client.supervisor.StartTime) {
		return firecrackerRuntimeOwnerRecordV1{}, true, errL8RuntimeOwnerInvalid
	}
	return record, false, nil
}

func (client *jailerRecoveryClient) authenticate(ctx context.Context) error {
	return client.authenticateWithMinimal(ctx, nil)
}

// The legacy caller passes nil and retains the original checks/exchange. The
// selected attempt owns cancellation-aware connect and its retained I/O copy.
func (client *jailerRecoveryClient) authenticateWithMinimal(ctx context.Context, attempt *minimalJailerFinalizationAttempt) error {
	var record firecrackerRuntimeOwnerRecordV1
	var err error
	if attempt == nil {
		record, err = client.readRecord()
	} else {
		record, err = attempt.readRecord(client)
	}
	if err != nil || ctx.Err() != nil || record.ControllerState != "unclaimed" {
		return errL8RuntimeOwnerInvalid
	}
	boot, bootErr := client.ops.bootID()
	actual, inspectErr := client.ops.inspect(record.SupervisorPID)
	defer actual.Close()
	if bootErr != nil || inspectErr != nil || boot != record.HostBootID || actual.PID != record.SupervisorPID || actual.StartTime != record.SupervisorStartTime || actual.state == 'Z' {
		return errL8RuntimeOwnerInvalid
	}
	var socket *os.File
	if attempt == nil {
		socket, err = client.ops.connect(client.directory, record)
	} else {
		if client.ops.connectMinimal == nil || !minimalJailerCallerCurrent(ctx) {
			return errL8RuntimeOwnerInvalid
		}
		socket, err = client.ops.connectMinimal(ctx, client.directory, record)
	}
	if err != nil || socket == nil {
		if socket != nil {
			if attempt != nil {
				_ = unix.Shutdown(int(socket.Fd()), unix.SHUT_RDWR)
			}
			if socket.Close() != nil && attempt != nil {
				attempt.contradicted = true
			}
		}
		return errL8RuntimeOwnerInvalid
	}
	keep := false
	defer func() {
		if !keep {
			if attempt != nil {
				_ = attempt.closeStream()
			}
			if socket.Close() != nil && attempt != nil {
				attempt.contradicted = true
			}
		}
	}()
	if validateL8RuntimeOwnerSeqpacketFD(int(socket.Fd())) != nil || setL8RuntimeOwnerSocketTimeout(int(socket.Fd()), l8RuntimeOwnerHandshakeTimeout) != nil {
		return errL8RuntimeOwnerInvalid
	}
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}
	var response l8RuntimeOwnerPacketV1
	if attempt == nil {
		response, err = jailerRecoveryClientExchange(ctx, int(socket.Fd()), packet)
	} else {
		if attempt.attach(socket, client.ops.minimalIO) != nil {
			return errL8RuntimeOwnerInvalid
		}
		response, err = attempt.stream.exchange(packet)
	}
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	ack, err := decodeL8RuntimeOwnerHandshakeAck(response.Body)
	if err != nil || record.Revision == ^uint64(0) || ack.RecordRevision != record.Revision+1 {
		return errL8RuntimeOwnerInvalid
	}
	var current firecrackerRuntimeOwnerRecordV1
	if attempt == nil {
		current, err = client.readRecord()
	} else {
		current, err = attempt.readRecord(client)
	}
	if err != nil || current.Revision != ack.RecordRevision || current.ControllerState != "controlled" || current.HostBootID != record.HostBootID || current.SupervisorGeneration != record.SupervisorGeneration || current.SupervisorPID != record.SupervisorPID || current.SupervisorStartTime != record.SupervisorStartTime || current.SeedCorrelationDigest != record.SeedCorrelationDigest || current.ReconnectListenerIdentity != record.ReconnectListenerIdentity || current.ReconnectSecret == record.ReconnectSecret {
		return errL8RuntimeOwnerInvalid
	}
	if ctx.Err() != nil || attempt != nil && !minimalJailerCallerCurrent(ctx) {
		return errL8RuntimeOwnerInvalid
	}
	if client.supervisor.Close() != nil {
		return errL8RuntimeOwnerInvalid
	}
	client.supervisor = actual
	actual.pidfdOwned = false
	client.correlation, client.generation = current.SeedCorrelationDigest, current.SupervisorGeneration
	client.socket, client.session, client.record = socket, ack.ControllerSessionGeneration, current
	keep = true
	return nil
}

func connectJailerRecoveryOwner(directory *os.File, record firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
	return connectJailerRecoveryOwnerWithContext(nil, directory, record)
}

func connectMinimalJailerRecoveryOwner(ctx context.Context, directory *os.File, record firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
	if !minimalJailerCallerCurrent(ctx) {
		return nil, errL8RuntimeOwnerInvalid
	}
	return connectJailerRecoveryOwnerWithContext(ctx, directory, record)
}

func connectJailerRecoveryOwnerWithContext(ctx context.Context, directory *os.File, record firecrackerRuntimeOwnerRecordV1) (_ *os.File, resultErr error) {
	name := l8RuntimeOwnerReconnectPrefix + record.ReconnectListenerIdentity + l8RuntimeOwnerReconnectSuffix
	var before unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Mode&0o777 != 0o600 || before.Uid != 0 {
		return nil, errL8RuntimeOwnerInvalid
	}
	flags := unix.SOCK_SEQPACKET | unix.SOCK_CLOEXEC
	if ctx != nil {
		flags |= unix.SOCK_NONBLOCK
	}
	fd, err := unix.Socket(unix.AF_UNIX, flags, 0)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "jailer-owner-reconnect")
	keep := false
	defer func() {
		if ctx != nil && recover() != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
		if !keep {
			if ctx != nil {
				_ = unix.Shutdown(fd, unix.SHUT_RDWR)
			}
			_ = file.Close()
		}
	}()
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10) + "/" + name
	if len(path) >= len(unix.RawSockaddrUnix{}.Path) {
		return nil, errL8RuntimeOwnerInvalid
	}
	if ctx == nil {
		if setL8RuntimeOwnerSocketTimeout(fd, l8RuntimeOwnerHandshakeTimeout) != nil || unix.Connect(fd, &unix.SockaddrUnix{Name: path}) != nil {
			return nil, errL8RuntimeOwnerInvalid
		}
	} else if connectMinimalJailerSocket(ctx, fd, path) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	var after unix.Stat_t
	if err != nil || peer.Uid != 0 || peer.Pid != int32(record.SupervisorPID) || unix.Fstatat(int(directory.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
		return nil, errL8RuntimeOwnerInvalid
	}
	if ctx != nil && !minimalJailerCallerCurrent(ctx) {
		return nil, errL8RuntimeOwnerInvalid
	}
	keep = true
	return file, nil
}
