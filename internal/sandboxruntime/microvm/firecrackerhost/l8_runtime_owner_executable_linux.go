//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	closeFD := func(fd int) error {
		if fd < 0 {
			return nil
		}
		opened := openedFiles[fd]
		delete(openedFiles, fd)
		if opened == nil || opened.Close() != nil {
			return errL8RuntimeOwnerInvalid
		}
		return nil
	}
	openFD := func(fd uintptr, role string) (int, error) {
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
	}
	return runPrivateL8RuntimeOwnerExecutableWithOps(arguments, l8RuntimeOwnerExecutableOps{
		OpenFD:        openFD,
		CloseFD:       closeFD,
		RunSupervisor: runL8RuntimeOwnerSupervisorLinux,
		RunChildGate:  runL8RuntimeOwnerChildGateLinux,
		RunJailerGate: func(fds [2]int) error { return runJailerRecoveryGateLinux(fds, closeFD) },

		SelectSupervisor: func(fds [6]int) (bool, error) {
			return withMinimalControlSupervisorAdmission(fds, openFD, closeFD, 0, unavailableMinimalControlSupervisor)
		},
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

// The selected gate uses the accepted locked-thread namespace/mount launcher,
// including clone-time cgroup placement and its additive parent-death signal.
// Only these two descriptors enter the gate; none enters the eventual Jailer.
func startJailerRecoveryGateCommand(ctx context.Context, request strictJailerNamespaceProcessStartRequest, executables *strictJailerExecutableLease, runtimeID string, gate, config *os.File) (process HostProcess, resultErr error) {
	if gate == nil || config == nil || prepareStrictJailerNetworkNamespaceForExec(request.networkNamespace) != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	command := exec.Command("/proc/self/exe", jailerRecoveryGateRole)
	command.Env = []string{}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{gate, config}
	err := request.cgroup.withLaunchFD(ctx, runtimeID, func(cgroup *os.File) error {
		if configureStrictJailerCgroup(command, cgroup) != nil || ctx.Err() != nil {
			return errStrictJailerNamespaceStartFailed
		}
		var err error
		process, err = startStrictJailerOSExecCommand(command, request.networkNamespace, executables)
		return err
	})
	if err != nil {
		return process, errStrictJailerNamespaceStartFailed
	}
	return process, nil
}

func startJailerRecoverySupervisorCommand(ctx context.Context, config jailerRecoverySupervisorConfig, executable, configFile *os.File, inputs [5]*os.File, namespaces [2]*os.File) (*jailerRecoveryClient, error) {
	if ctx == nil || ctx.Err() != nil || executable == nil || configFile == nil || validateStrictJailerExecutableSnapshot(executable) != nil || validateL8RuntimeOwnerDirectoryFD(int(inputs[0].Fd())) != nil || namespaces[0] == nil || namespaces[1] == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	if validateL8RuntimeOwnerNamespacePair(int(namespaces[0].Fd()), int(namespaces[1].Fd())) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	parent := os.NewFile(uintptr(sockets[0]), "jailer-owner-bootstrap")
	defer parent.Close()
	child := os.NewFile(uintptr(sockets[1]), "jailer-owner-bootstrap-child")
	defer child.Close()
	directory, err := duplicateJailerRecoveryFile(inputs[0])
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	client := &jailerRecoveryClient{expected: config.Job, correlation: jailerRecoveryConfigDigest(config), directory: directory, ops: jailerRecoveryLinuxReconnectOps()}
	// Resolve the immutable executable through the producer's retained FD. It
	// is not an inherited extra role and stays open through bootstrap reply.
	path := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(executable.Fd()), 10)
	command := exec.Command(path, l8RuntimeOwnerExecutableSupervise)
	command.Env = []string{}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{child, inputs[0], configFile, inputs[1], inputs[2], inputs[3], inputs[4]}
	// The supervisor intentionally survives daemon loss; only its Jailer child
	// uses Pdeathsig. A Wait goroutine reaps it while this daemon remains alive.
	if ctx.Err() != nil || command.Start() != nil {
		_ = client.close()
		return nil, errL8RuntimeOwnerInvalid
	}
	go func() { _ = command.Wait() }()
	supervisorObservation, err := inspectL8RuntimeOwnerProcess(uint32(command.Process.Pid))
	client.supervisor = supervisorObservation
	if err != nil || supervisorObservation.ParentPID != uint32(os.Getpid()) {
		return client, errL8RuntimeOwnerInvalid
	}
	user, userErr := l8RuntimeOwnerStatNamespaceFD(int(namespaces[0].Fd()))
	network, networkErr := l8RuntimeOwnerStatNamespaceFD(int(namespaces[1].Fd()))
	if userErr != nil || networkErr != nil || setL8RuntimeOwnerSocketTimeout(int(parent.Fd()), l8RuntimeOwnerHandshakeTimeout) != nil {
		return client, errL8RuntimeOwnerInvalid
	}
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(l8RuntimeOwnerNamespaceCorrelationV1{UserDevice: user.device, UserInode: user.inode, NetworkDevice: network.device, NetworkInode: network.inode})}
	if ctx.Err() != nil || sendL8RuntimeOwnerSeqpacket(int(parent.Fd()), packet, namespaces[:]) != nil {
		return client, errL8RuntimeOwnerInvalid
	}
	response, err := receiveL8RuntimeOwnerSeqpacket(int(parent.Fd()))
	closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || ctx.Err() != nil || validateL8RuntimeOwnerPacketRole(response.Packet, true, len(response.Files)) != nil || response.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished {
		// Never kill the owner to simulate cleanup. Ask that exact owner to
		// finalize; if unavailable return the retained client for quarantine.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerContainmentBudget)
		defer cancel()
		_ = client.stopAndCommit(cleanupCtx)
		return client, errL8RuntimeOwnerInvalid
	}
	return client, nil
}
