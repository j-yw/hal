//go:build linux

package linuxtopology

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

type execBoundary struct{}

type execProcess struct {
	process *os.Process
	done    chan struct{}
	once    sync.Once
}

func platformDependencies() (bool, ProcessStarter, CommandRunner, NamespaceOpener) {
	boundary := &execBoundary{}
	return true, boundary, boundary, openLinuxNamespaces
}

func executableToolPaths(tools ToolPaths) bool {
	for _, path := range []string{tools.Unshare, tools.Pasta, tools.Nsenter, tools.IP, tools.Keeper} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return false
		}
	}
	return true
}

func (e *execBoundary) Start(_ context.Context, spec ProcessSpec) (ProcessHandle, error) {
	stdout := newBoundedBuffer(spec.OutputLimit)
	stderr := newBoundedBuffer(spec.OutputLimit)
	command := exec.Command(spec.Path, spec.Args...)
	command.Env = append([]string(nil), spec.Env...)
	command.ExtraFiles = append([]*os.File(nil), spec.ExtraFiles...)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	handle := &execProcess{process: command.Process, done: make(chan struct{})}
	go func() {
		_ = command.Wait()
		handle.once.Do(func() { close(handle.done) })
	}()
	return handle, nil
}

func (e *execBoundary) Run(ctx context.Context, spec ProcessSpec) ([]byte, error) {
	stdout := newBoundedBuffer(spec.OutputLimit)
	stderr := newBoundedBuffer(spec.OutputLimit)
	command := exec.CommandContext(ctx, spec.Path, spec.Args...)
	command.Env = append([]string(nil), spec.Env...)
	command.ExtraFiles = append([]*os.File(nil), spec.ExtraFiles...)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, err
	}
	if stdout.Truncated() || stderr.Truncated() {
		return nil, errors.New("command output exceeded bound")
	}
	return stdout.Bytes(), nil
}

func (p *execProcess) PID() int {
	if p == nil || p.process == nil {
		return 0
	}
	return p.process.Pid
}

func (p *execProcess) Done() <-chan struct{} {
	if p == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return p.done
}

func (p *execProcess) Terminate(ctx context.Context) error {
	if p == nil || p.process == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		if err := p.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case <-p.done:
			return nil
		default:
			return ctx.Err()
		}
	}
}

func openLinuxNamespaces(pid int) (*NamespaceHandle, error) {
	if pid <= 0 {
		return nil, ErrStartFailed
	}
	user, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "ns", "user"))
	if err != nil {
		return nil, err
	}
	network, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "ns", "net"))
	if err != nil {
		_ = user.Close()
		return nil, err
	}
	handle, err := NewNamespaceHandle(user, network)
	if err != nil {
		_ = user.Close()
		_ = network.Close()
		return nil, err
	}
	selfUser, err := os.Open("/proc/self/ns/user")
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	selfNetwork, err := os.Open("/proc/self/ns/net")
	if err != nil {
		_ = selfUser.Close()
		_ = handle.Close()
		return nil, err
	}
	self, err := NewNamespaceHandle(selfUser, selfNetwork)
	if err != nil {
		_ = selfUser.Close()
		_ = selfNetwork.Close()
		_ = handle.Close()
		return nil, err
	}
	distinct := handle.distinctFrom(self)
	_ = self.Close()
	if !distinct {
		_ = handle.Close()
		return nil, ErrStartFailed
	}
	return handle, nil
}

type boundedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int64
	truncated bool
}

func newBoundedBuffer(limit int64) *boundedBuffer { return &boundedBuffer{limit: limit} }

func (b *boundedBuffer) Write(input []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(input)
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		b.truncated = b.truncated || original > 0
		return original, nil
	}
	if int64(len(input)) > remaining {
		input = input[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(input)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *boundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
