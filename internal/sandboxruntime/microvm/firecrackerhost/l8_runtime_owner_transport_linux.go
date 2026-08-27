//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type l8RuntimeOwnerNamespaceCorrelationV1 struct {
	UserDevice    uint64
	UserInode     uint64
	NetworkDevice uint64
	NetworkInode  uint64
}

type l8RuntimeOwnerReceivedPacketV1 struct {
	Packet l8RuntimeOwnerPacketV1
	Files  []*os.File
}

func encodeL8RuntimeOwnerNamespaceCorrelation(value l8RuntimeOwnerNamespaceCorrelationV1) []byte {
	body := make([]byte, 32)
	binary.BigEndian.PutUint64(body[0:8], value.UserDevice)
	binary.BigEndian.PutUint64(body[8:16], value.UserInode)
	binary.BigEndian.PutUint64(body[16:24], value.NetworkDevice)
	binary.BigEndian.PutUint64(body[24:32], value.NetworkInode)
	return body
}

func decodeL8RuntimeOwnerNamespaceCorrelation(body []byte) (l8RuntimeOwnerNamespaceCorrelationV1, error) {
	if len(body) != 32 {
		return l8RuntimeOwnerNamespaceCorrelationV1{}, errL8RuntimeOwnerProtocol
	}
	return l8RuntimeOwnerNamespaceCorrelationV1{
		UserDevice:    binary.BigEndian.Uint64(body[0:8]),
		UserInode:     binary.BigEndian.Uint64(body[8:16]),
		NetworkDevice: binary.BigEndian.Uint64(body[16:24]),
		NetworkInode:  binary.BigEndian.Uint64(body[24:32]),
	}, nil
}

func sendL8RuntimeOwnerSeqpacket(fd int, packet l8RuntimeOwnerPacketV1, files []*os.File) error {
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil {
		return errL8RuntimeOwnerProtocol
	}
	var oob []byte
	if len(files) != 0 {
		rights := make([]int, len(files))
		for index, file := range files {
			if file == nil {
				return errL8RuntimeOwnerProtocol
			}
			rights[index] = int(file.Fd())
		}
		oob = unix.UnixRights(rights...)
	}
	if err := unix.Sendmsg(fd, wire, oob, nil, 0); err != nil {
		return errL8RuntimeOwnerProtocol
	}
	return nil
}

func receiveL8RuntimeOwnerSeqpacket(fd int) (l8RuntimeOwnerReceivedPacketV1, error) {
	buf := make([]byte, l8RuntimeOwnerPacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	files, fileErr := l8RuntimeOwnerFilesFromControl(oob[:oobn])
	if err != nil || flags&unix.MSG_TRUNC != 0 || flags&unix.MSG_CTRUNC != 0 || n < l8RuntimeOwnerPacketHeaderSize {
		closeL8RuntimeOwnerFiles(files)
		return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
	}
	packet, packetErr := decodeL8RuntimeOwnerPacket(buf[:n])
	if fileErr != nil || packetErr != nil {
		closeL8RuntimeOwnerFiles(files)
		return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
	}
	return l8RuntimeOwnerReceivedPacketV1{Packet: packet, Files: files}, nil
}

func l8RuntimeOwnerFilesFromControl(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, errL8RuntimeOwnerProtocol
	}
	allRights := make([]int, 0, 4)
	valid := len(messages) == 1
	for index := range messages {
		if messages[index].Header.Level != unix.SOL_SOCKET || messages[index].Header.Type != unix.SCM_RIGHTS {
			valid = false
			continue
		}
		rights, parseErr := unix.ParseUnixRights(&messages[index])
		if parseErr != nil {
			valid = false
			continue
		}
		allRights = append(allRights, rights...)
	}
	if !valid {
		for _, fd := range allRights {
			_ = unix.Close(fd)
		}
		return nil, errL8RuntimeOwnerProtocol
	}
	files := make([]*os.File, 0, len(allRights))
	failed := true
	defer func() {
		if failed {
			closeL8RuntimeOwnerFiles(files)
			for _, fd := range allRights[len(files):] {
				_ = unix.Close(fd)
			}
		}
	}()
	for _, fd := range allRights {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			return nil, errL8RuntimeOwnerProtocol
		}
		file := os.NewFile(uintptr(fd), "runtime-owner-fd")
		if file == nil {
			return nil, errL8RuntimeOwnerProtocol
		}
		files = append(files, file)
	}
	failed = false
	return files, nil
}

func closeL8RuntimeOwnerFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func validateL8RuntimeOwnerNamespaceFiles(files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) error {
	if len(files) != 2 || files[0] == nil || files[1] == nil || files[0] == files[1] {
		return errL8RuntimeOwnerInvalid
	}
	user, err := l8RuntimeOwnerStatNamespace(files[0])
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	network, err := l8RuntimeOwnerStatNamespace(files[1])
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if user.device != correlation.UserDevice || user.inode != correlation.UserInode ||
		network.device != correlation.NetworkDevice || network.inode != correlation.NetworkInode ||
		(user.device == network.device && user.inode == network.inode) {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

type l8RuntimeOwnerNSIdentity struct {
	device uint64
	inode  uint64
}

func l8RuntimeOwnerStatNamespace(file *os.File) (l8RuntimeOwnerNSIdentity, error) {
	var stat unix.Stat_t
	var statfs unix.Statfs_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || unix.Fstatfs(int(file.Fd()), &statfs) != nil || statfs.Type != unix.NSFS_MAGIC {
		return l8RuntimeOwnerNSIdentity{}, errL8RuntimeOwnerInvalid
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return l8RuntimeOwnerNSIdentity{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func l8RuntimeOwnerPeerUID(fd int) (uint32, error) {
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || credentials == nil {
		return 0, errL8RuntimeOwnerInvalid
	}
	return credentials.Uid, nil
}

func parseL8RuntimeOwnerProcIdentity(payload []byte, expectedPID uint32) (uint32, uint64, byte, error) {
	value := strings.TrimSuffix(string(payload), "\n")
	open := strings.IndexByte(value, '(')
	close := strings.LastIndexByte(value, ')')
	if open <= 0 || close <= open || strings.TrimSpace(value[close+1:]) == "" {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	parsedPID, err := strconv.ParseUint(strings.TrimSpace(value[:open]), 10, 32)
	fields := strings.Fields(value[close+1:])
	if err != nil || uint32(parsedPID) != expectedPID || len(fields) < 20 || len(fields[0]) != 1 {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	parent, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	return uint32(parent), startTime, fields[0][0], nil
}

func signalL8RuntimeOwnerProcess(observation l8RuntimeOwnerProcessObservation, signal os.Signal) error {
	if !observation.pidfdOwned || observation.pidfd < 0 {
		return errL8RuntimeOwnerInvalid
	}
	sysSignal, ok := signal.(syscall.Signal)
	if !ok {
		return errL8RuntimeOwnerInvalid
	}
	if err := unix.PidfdSendSignal(observation.pidfd, sysSignal, nil, 0); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func waitL8RuntimeOwnerProcessTerminal(ctx context.Context, observation l8RuntimeOwnerProcessObservation) error {
	if ctx == nil || !observation.pidfdOwned || observation.pidfd < 0 {
		return errL8RuntimeOwnerInvalid
	}
	for {
		if err := ctx.Err(); err != nil {
			return errL8RuntimeOwnerInvalid
		}
		timeout := 100
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return errL8RuntimeOwnerInvalid
			}
			timeout = int(remaining / time.Millisecond)
			if timeout <= 0 {
				timeout = 1
			}
		}
		poll := []unix.PollFd{{Fd: int32(observation.pidfd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return errL8RuntimeOwnerInvalid
		}
		if ready > 0 && poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return nil
		}
	}
}

func inspectL8RuntimeOwnerProcessAbsent(pid uint32) (bool, error) {
	if pid == 0 || uint64(pid) > uint64(^uint(0)>>1) {
		return false, errL8RuntimeOwnerInvalid
	}
	procfd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, errL8RuntimeOwnerInvalid
	}
	defer unix.Close(procfd)
	processfd, err := unix.Openat(procfd, strconv.FormatUint(uint64(pid), 10), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, errL8RuntimeOwnerInvalid
	}
	_ = unix.Close(processfd)
	return false, nil
}
