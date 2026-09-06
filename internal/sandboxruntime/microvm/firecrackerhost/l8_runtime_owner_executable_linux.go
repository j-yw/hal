//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type l8RuntimeOwnerLinuxChild struct {
	mu          sync.Mutex
	command     *exec.Cmd
	gate        *os.File
	observation l8RuntimeOwnerProcessObservation
	waitDone    chan struct{}
	waitErr     error
	released    bool
	closed      bool
}

func runPrivateL8RuntimeOwnerExecutable(arguments []string, file func(uintptr, string) *os.File) int {
	_ = launchPrivateL8RuntimeOwnerLinuxChild
	openedFiles := make(map[int]*os.File)
	return runPrivateL8RuntimeOwnerExecutableWithOps(arguments, l8RuntimeOwnerExecutableOps{
		OpenFD: func(fd uintptr, role string) (int, error) {
			if file == nil {
				return -1, errL8RuntimeOwnerInvalid
			}
			opened := file(fd, role)
			if opened == nil {
				return -1, errL8RuntimeOwnerInvalid
			}
			openedFD := int(opened.Fd())
			if openedFD < 0 {
				_ = opened.Close()
				return -1, errL8RuntimeOwnerInvalid
			}
			if _, err := unix.FcntlInt(opened.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
				_ = opened.Close()
				return -1, errL8RuntimeOwnerInvalid
			}
			openedFiles[openedFD] = opened
			return openedFD, nil
		},
		CloseFD: func(fd int) error {
			if fd < 0 {
				return nil
			}
			opened := openedFiles[fd]
			delete(openedFiles, fd)
			if opened == nil || opened.Close() != nil {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		RunSupervisor: runL8RuntimeOwnerSupervisorLinux,
		RunChildGate:  runL8RuntimeOwnerChildGateLinux,
	})
}

func launchPrivateL8RuntimeOwnerLinuxChild(command *exec.Cmd) error {
	if command == nil {
		return errL8RuntimeOwnerInvalid
	}
	runtime.LockOSThread()
	command.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	startErr := command.Start()
	var waitErr error
	if startErr == nil {
		waitErr = command.Wait()
	}
	runtime.UnlockOSThread()
	if startErr != nil || waitErr != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func startL8RuntimeOwnerLinuxChild(configFD int, namespaces [2]*os.File, assetFDs [2]int) (*l8RuntimeOwnerLinuxChild, error) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	parentGate := os.NewFile(uintptr(sockets[0]), "runtime-owner-parent-gate")
	childGate := os.NewFile(uintptr(sockets[1]), "runtime-owner-child-gate")
	if parentGate == nil || childGate == nil {
		if parentGate != nil {
			_ = parentGate.Close()
		} else {
			_ = unix.Close(sockets[0])
		}
		if childGate != nil {
			_ = childGate.Close()
		} else {
			_ = unix.Close(sockets[1])
		}
		return nil, errL8RuntimeOwnerInvalid
	}
	extra := []*os.File{childGate}
	failed := true
	defer func() {
		for _, file := range extra {
			if file != nil {
				_ = file.Close()
			}
		}
		if failed {
			_ = parentGate.Close()
		}
	}()
	for _, source := range []int{configFD, int(namespaces[0].Fd()), int(namespaces[1].Fd()), assetFDs[0], assetFDs[1]} {
		fd, err := unix.FcntlInt(uintptr(source), unix.F_DUPFD_CLOEXEC, 9)
		if err != nil {
			return nil, errL8RuntimeOwnerInvalid
		}
		file := os.NewFile(uintptr(fd), "runtime-owner-child-input")
		if file == nil {
			_ = unix.Close(fd)
			return nil, errL8RuntimeOwnerInvalid
		}
		extra = append(extra, file)
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return nil, errL8RuntimeOwnerInvalid
	}
	command := exec.Command(executable, l8RuntimeOwnerExecutableChildGate)
	command.Env = []string{}
	command.ExtraFiles = extra
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	child := &l8RuntimeOwnerLinuxChild{command: command, gate: parentGate, waitDone: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		startErr := command.Start()
		started <- startErr
		if startErr != nil {
			child.mu.Lock()
			child.waitErr = startErr
			child.mu.Unlock()
			close(child.waitDone)
			return
		}
		waitErr := command.Wait()
		child.mu.Lock()
		child.waitErr = waitErr
		child.mu.Unlock()
		close(child.waitDone)
	}()
	if err := <-started; err != nil || command.Process == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	for index, file := range extra {
		_ = file.Close()
		extra[index] = nil
	}
	observation, err := inspectL8RuntimeOwnerProcess(uint32(command.Process.Pid))
	if err != nil || observation.ParentPID != uint32(os.Getpid()) {
		_ = observation.Close()
		_ = child.abort()
		return nil, errL8RuntimeOwnerInvalid
	}
	child.observation = observation
	if setL8RuntimeOwnerSocketTimeout(int(parentGate.Fd()), l8RuntimeOwnerHandshakeTimeout) != nil {
		_ = child.abort()
		return nil, errL8RuntimeOwnerInvalid
	}
	armed, err := receiveL8RuntimeOwnerSeqpacket(int(parentGate.Fd()))
	if err != nil {
		_ = child.abort()
		return nil, errL8RuntimeOwnerInvalid
	}
	closeL8RuntimeOwnerFiles(armed.Files)
	if validateL8RuntimeOwnerPacketRole(armed.Packet, false, len(armed.Files)) != nil || armed.Packet.Opcode != l8RuntimeOwnerOpcodeChildArmed {
		_ = child.abort()
		return nil, errL8RuntimeOwnerInvalid
	}
	failed = false
	return child, nil
}

func (child *l8RuntimeOwnerLinuxChild) release() error {
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.closed || child.released || child.gate == nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := sendL8RuntimeOwnerSeqpacket(int(child.gate.Fd()), l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease}, nil); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	child.released = true
	return nil
}

func (child *l8RuntimeOwnerLinuxChild) signal(signal os.Signal) error {
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.command == nil || child.command.Process == nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := child.command.Process.Signal(signal); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (child *l8RuntimeOwnerLinuxChild) wait(ctx context.Context) (bool, error) {
	if child == nil || child.waitDone == nil {
		return false, errL8RuntimeOwnerInvalid
	}
	select {
	case <-child.waitDone:
		return true, nil
	case <-ctx.Done():
		return false, nil
	}
}

func (child *l8RuntimeOwnerLinuxChild) abort() error {
	if child == nil {
		return nil
	}
	_ = child.signal(syscall.SIGKILL)
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerContainmentBudget)
	defer cancel()
	reaped, err := child.wait(ctx)
	if err != nil || !reaped {
		return errL8RuntimeOwnerInvalid
	}
	return child.close()
}

func (child *l8RuntimeOwnerLinuxChild) close() error {
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.closed {
		return nil
	}
	child.closed = true
	var failed bool
	if child.gate != nil {
		failed = child.gate.Close() != nil
		child.gate = nil
	}
	failed = child.observation.Close() != nil || failed
	if failed {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
