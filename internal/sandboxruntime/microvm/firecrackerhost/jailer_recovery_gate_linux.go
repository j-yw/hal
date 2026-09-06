//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The descriptor, not its path, supplies both inode identity and measured bytes.
// The caller separately verifies the trusted mount destination and root owner.
func verifyJailerRecoveryMountedFile(file *os.File, expected jailerRecoveryMountedExecutable) error {
	if validateStrictJailerExecutableSnapshot(file) != nil {
		return errL8RuntimeOwnerInvalid
	}
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || uint64(stat.Dev) != expected.Device || stat.Ino != expected.Inode || stat.Size != expected.Size {
		return errL8RuntimeOwnerInvalid
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < stat.Size; {
		limit := min(int64(len(buffer)), stat.Size-offset)
		n, err := unix.Pread(int(file.Fd()), buffer[:limit], offset)
		if err != nil || n <= 0 {
			return errL8RuntimeOwnerInvalid
		}
		_, _ = hash.Write(buffer[:n])
		offset += int64(n)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func verifyJailerRecoveryMountedPath(expected jailerRecoveryMountedExecutable) error {
	if validateStrictJailerExecutableMountPath(expected.Path) != nil {
		return errL8RuntimeOwnerInvalid
	}
	fd, err := unix.Open(expected.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "jailer-gate-mounted-executable")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 {
		return errL8RuntimeOwnerInvalid
	}
	return verifyJailerRecoveryMountedFile(file, expected)
}

func runJailerRecoveryGateLinux(fds [2]int, closeFD func(int) error) error {
	if closeFD == nil || validateL8RuntimeOwnerSeqpacketFD(fds[0]) != nil {
		return errL8RuntimeOwnerInvalid
	}
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fds[1], jailerRecoveryGateConfigLimit)
	if err != nil || identity.Size <= 0 {
		return errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, identity.Size)
	n, err := unix.Pread(fds[1], payload, 0)
	if err != nil || n != len(payload) {
		return errL8RuntimeOwnerInvalid
	}
	config, err := decodeJailerRecoveryGateConfig(payload)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	// Pdeathsig is per-thread. Keep this thread through parent verification and
	// exec, while the supervisor retains the corresponding creating thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil {
		return errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerHandshakeTimeout)
	defer cancel()
	return runJailerRecoveryGate(ctx, config, jailerRecoveryGateOps{
		verifyParent: func() error {
			var signal int32
			if os.Getppid() != int(config.ParentPID) || unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0) != nil || signal != int32(unix.SIGKILL) {
				return errL8RuntimeOwnerInvalid
			}
			parent, err := inspectL8RuntimeOwnerProcess(config.ParentPID)
			defer parent.Close()
			if err != nil || parent.StartTime != config.ParentStartTime || os.Getppid() != int(config.ParentPID) {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		verifyMounted: verifyJailerRecoveryMountedPath,
		sendArmed: func() error {
			return sendL8RuntimeOwnerSeqpacket(fds[0], l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, nil)
		},
		awaitRelease: func() error {
			if setL8RuntimeOwnerSocketTimeout(fds[0], l8RuntimeOwnerHandshakeTimeout) != nil {
				return errL8RuntimeOwnerInvalid
			}
			received, err := receiveL8RuntimeOwnerSeqpacket(fds[0])
			if err != nil {
				return errL8RuntimeOwnerInvalid
			}
			defer closeL8RuntimeOwnerFiles(received.Files)
			if validateL8RuntimeOwnerPacketRole(received.Packet, true, len(received.Files)) != nil || received.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		closeFiles: func() error {
			// Remove owned os.File aliases through the executable's close callback.
			// Mark any runtime-owned descriptors CLOEXEC without closing Go's poll
			// descriptors underneath it if exec itself fails.
			firstErr := closeFD(fds[1])
			secondErr := closeFD(fds[0])
			if firstErr != nil || secondErr != nil || unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) != nil {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		exec: func(path string, args []string) error { return unix.Exec(path, args, []string{}) },
	})
}
