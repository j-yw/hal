//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"golang.org/x/sys/unix"
)

// The existing coordinator/lifecycle owns the process, cgroup and staged root.
// This single-use starter owns only the pre-exec barrier and pidfd observation.
type jailerRecoveryStarter struct {
	mu                        sync.Mutex
	gate                      *os.File
	observation               l8RuntimeOwnerProcessObservation
	started, released, closed bool
	closeErr                  error
}

func (starter *jailerRecoveryStarter) startStrictJailerNamespaceProcess(ctx context.Context, request strictJailerNamespaceProcessStartRequest) (process HostProcess, resultErr error) {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if starter.started || starter.closed || ctx == nil || ctx.Err() != nil || validateStrictJailerNamespaceProcessStartRequest(request) != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	starter.started = true
	parsed, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{Executable: request.executable, Args: request.args})
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	lease, err := request.executables.duplicateForLaunch(parsed)
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	defer func() {
		if lease.close() != nil {
			resultErr = errStrictJailerNamespaceCleanupIncomplete
		}
	}()
	parent, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	defer parent.Close()
	config := jailerRecoveryGateConfig{Version: jailerRecoveryGateRole, ParentPID: parent.PID, ParentStartTime: parent.StartTime, Args: append([]string(nil), request.args...)}
	for index, entry := range lease.entries {
		var stat unix.Stat_t
		if unix.Fstat(int(entry.file.Fd()), &stat) != nil {
			return nil, errStrictJailerNamespaceStartFailed
		}
		measured := jailerRecoveryMountedExecutable{Path: entry.path, Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size, SHA256: hex.EncodeToString(entry.digest[:])}
		if verifyJailerRecoveryMountedFile(entry.file, measured) != nil {
			return nil, errStrictJailerNamespaceStartFailed
		}
		if index == 0 {
			config.Jailer = measured
		} else {
			config.Firecracker = measured
		}
	}
	payload, err := json.Marshal(config)
	if err != nil || validateJailerRecoveryGateConfig(config) != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	configFile, err := sealJailerRecoveryBytes(ctx, payload)
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	defer configFile.Close()
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	starter.gate = os.NewFile(uintptr(sockets[0]), "jailer-owner-gate")
	childGate := os.NewFile(uintptr(sockets[1]), "jailer-child-gate")
	defer childGate.Close()
	// Failure returns the exact process to the existing namespace runner for
	// containment. Never discard a created child merely because arming failed.
	process, err = startJailerRecoveryGateCommand(ctx, request, lease, parsed.runtimeID, childGate, configFile)
	if err != nil || interfaceValueIsNil(process) {
		return process, errStrictJailerNamespaceStartFailed
	}
	pidProcess, ok := process.(interface{ HostPID() int })
	if !ok || pidProcess.HostPID() <= 1 {
		return process, errStrictJailerNamespaceStartFailed
	}
	observation, err := inspectL8RuntimeOwnerProcess(uint32(pidProcess.HostPID()))
	starter.observation = observation
	if err != nil || observation.ParentPID != parent.PID || ctx.Err() != nil || setL8RuntimeOwnerSocketTimeout(int(starter.gate.Fd()), l8RuntimeOwnerHandshakeTimeout) != nil {
		return process, errStrictJailerNamespaceStartFailed
	}
	armed, err := receiveL8RuntimeOwnerSeqpacket(int(starter.gate.Fd()))
	defer closeL8RuntimeOwnerFiles(armed.Files)
	if err != nil || ctx.Err() != nil || validateL8RuntimeOwnerPacketRole(armed.Packet, false, len(armed.Files)) != nil || armed.Packet.Opcode != l8RuntimeOwnerOpcodeChildArmed {
		return process, errStrictJailerNamespaceStartFailed
	}
	return process, nil
}

func (starter *jailerRecoveryStarter) release() error {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if !starter.started || starter.closed || starter.released || starter.gate == nil || !starter.observation.pidfdOwned {
		return errL8RuntimeOwnerInvalid
	}
	if sendL8RuntimeOwnerSeqpacket(int(starter.gate.Fd()), l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease}, nil) != nil {
		return errL8RuntimeOwnerInvalid
	}
	starter.released = true
	return nil
}

func (starter *jailerRecoveryStarter) close() error {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if starter.closed {
		return starter.closeErr
	}
	starter.closed = true
	failed := starter.observation.Close() != nil
	if starter.gate != nil {
		failed = starter.gate.Close() != nil || failed
		starter.gate = nil
	}
	if failed {
		starter.closeErr = errL8RuntimeOwnerInvalid
	}
	return starter.closeErr
}
