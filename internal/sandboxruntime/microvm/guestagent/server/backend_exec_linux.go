//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

func (backend *linuxBackend) Exec(ctx context.Context, plan ExecPlan) (ExecResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ExecResult{}, linuxContextError(guestagent.OperationExec, err)
	}
	if len(plan.Args) == 0 || strings.TrimSpace(plan.Args[0]) == "" {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest command is invalid", nil)
	}
	if len(plan.Stdin) > int(DefaultExecStdinBytes) {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationExec, "stdin", "guest command input exceeds the server limit", nil)
	}

	workRelative, err := backend.guestRelative(guestagent.OperationExec, "workDir", plan.WorkDir, true)
	if err != nil {
		return ExecResult{}, err
	}
	workFD, err := backend.openWorkspace(workRelative, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "workDir", "guest working directory is unavailable", err)
	}
	workFile := os.NewFile(uintptr(workFD), "guest-workdir")
	if workFile == nil {
		_ = unix.Close(workFD)
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "workDir", "guest working directory is unavailable", nil)
	}
	defer workFile.Close()

	executableFD, err := backend.openExecutable(plan.Args[0])
	if err != nil {
		return ExecResult{}, err
	}
	executableFile := os.NewFile(uintptr(executableFD), "guest-executable")
	if executableFile == nil {
		_ = unix.Close(executableFD)
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", nil)
	}
	defer executableFile.Close()

	interpreterScript, err := backend.linuxExecutableIsInterpreterScript(executableFD)
	if err != nil {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", err)
	}
	commandPath := procSelfFDPath(executableFD)
	extraFiles := []*os.File{workFile}
	if interpreterScript {
		childExecutableFD := 3 + len(extraFiles)
		extraFiles = append(extraFiles, executableFile)
		commandPath = procSelfFDPath(childExecutableFD)
	}

	environment, err := mergeLinuxEnvironment(backend.baseEnv, plan.Environment)
	if err != nil {
		return ExecResult{}, err
	}
	stdoutLimit := effectiveLinuxLimit(plan.StdoutMaxBytes, DefaultExecStdoutBytes)
	stderrLimit := effectiveLinuxLimit(plan.StderrMaxBytes, DefaultExecStderrBytes)
	stdout := newLinuxBoundedWriter(stdoutLimit)
	stderr := newLinuxBoundedWriter(stderrLimit)
	stdoutPipe, err := newLinuxOutputPipe()
	if err != nil {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "stdout", "guest command output is unavailable", err)
	}
	stderrPipe, err := newLinuxOutputPipe()
	if err != nil {
		stdoutPipe.close()
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "stderr", "guest command output is unavailable", err)
	}

	command := &exec.Cmd{
		Path:       commandPath,
		Args:       append([]string(nil), plan.Args...),
		Env:        environment,
		Dir:        procSelfFDPath(workFD),
		ExtraFiles: extraFiles,
		Stdin:      bytes.NewReader(plan.Stdin),
		Stdout:     stdoutPipe.writer,
		Stderr:     stderrPipe.writer,
		WaitDelay:  backend.termGrace,
		SysProcAttr: &syscall.SysProcAttr{
			Setpgid: true,
		},
	}
	backend.runBeforeExecStartTestHook()
	if err := ctx.Err(); err != nil {
		stdoutPipe.close()
		stderrPipe.close()
		return ExecResult{}, linuxContextError(guestagent.OperationExec, err)
	}
	if err := startLinuxCommandWithoutPrivilegeGain(command); err != nil {
		stdoutPipe.close()
		stderrPipe.close()
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest command could not start", err)
	}
	_ = stdoutPipe.writer.Close()
	_ = stderrPipe.writer.Close()
	outputDone := make(chan error, 2)
	stdoutPipe.drain(stdout, outputDone)
	stderrPipe.drain(stderr, outputDone)
	outputComplete := false
	defer func() {
		if !outputComplete {
			stdoutPipe.closeReaders()
			stderrPipe.closeReaders()
			<-outputDone
			<-outputDone
		}
		stdoutPipe.close()
		stderrPipe.close()
	}()
	backend.runAfterExecStartTestHook()

	pgid := command.Process.Pid
	if err := backend.registerProcessGroup(pgid); err != nil {
		_ = unix.Kill(-pgid, unix.SIGKILL)
		_ = command.Wait()
		return ExecResult{}, err
	}
	defer backend.unregisterProcessGroup(pgid)

	waitID := make(chan error, 1)
	go func() {
		waitID <- waitForLinuxLeader(pgid)
	}()

	var contextErr error
	select {
	case err := <-waitID:
		waitID = nil
		if err != nil {
			_ = unix.Kill(-pgid, unix.SIGKILL)
			_ = command.Wait()
			return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command supervision failed", err)
		}
	case <-ctx.Done():
		contextErr = ctx.Err()
	}

	_ = unix.Kill(-pgid, unix.SIGTERM)
	timer := newLinuxGraceTimer(backend.termGrace)
	if waitID != nil {
		contextDone := ctx.Done()
		if contextErr != nil {
			contextDone = nil
		}
		select {
		case err := <-waitID:
			waitID = nil
			if err != nil && contextErr == nil {
				contextErr = err
			}
		case <-timer.C:
		case <-contextDone:
			contextErr = ctx.Err()
		}
	} else {
		contextDone := ctx.Done()
		if contextErr != nil {
			contextDone = nil
		}
		select {
		case <-timer.C:
		case <-contextDone:
			contextErr = ctx.Err()
		}
	}
	stopLinuxTimer(timer)
	_ = unix.Kill(-pgid, unix.SIGKILL)
	if waitID != nil {
		if err := <-waitID; err != nil && contextErr == nil {
			contextErr = err
		}
	}

	waitErr := command.Wait()
	outputContext := ctx
	if contextErr != nil {
		outputContext = context.Background()
	}
	outputForced, outputErr := waitForLinuxOutputPipes(
		stdoutPipe,
		stderrPipe,
		outputDone,
		backend.termGrace,
		outputContext,
	)
	outputComplete = true
	if contextErr == nil {
		contextErr = ctx.Err()
	}
	result := ExecResult{
		ExitCode:        linuxExitCode(command.ProcessState),
		Stdout:          stdout.Bytes(),
		Stderr:          stderr.Bytes(),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
	}
	if contextErr != nil {
		if errors.Is(contextErr, context.Canceled) || errors.Is(contextErr, context.DeadlineExceeded) {
			return ExecResult{}, linuxContextError(guestagent.OperationExec, contextErr)
		}
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command supervision failed", contextErr)
	}
	if outputErr != nil {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command output cleanup failed", outputErr)
	}
	if outputForced {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command output cleanup exceeded the server limit", nil)
	}
	if errors.Is(waitErr, exec.ErrWaitDelay) {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command pipe cleanup exceeded the server limit", waitErr)
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return ExecResult{}, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "process", "guest command cleanup failed", waitErr)
	}
	return result, nil
}

type linuxOutputPipe struct {
	reader *os.File
	writer *os.File
}

func newLinuxOutputPipe() (*linuxOutputPipe, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	return &linuxOutputPipe{reader: reader, writer: writer}, nil
}

func (pipe *linuxOutputPipe) drain(destination io.Writer, done chan<- error) {
	go func() {
		_, err := io.Copy(destination, pipe.reader)
		done <- err
	}()
}

func (pipe *linuxOutputPipe) closeReaders() {
	if pipe != nil && pipe.reader != nil {
		_ = pipe.reader.Close()
	}
}

func (pipe *linuxOutputPipe) close() {
	if pipe == nil {
		return
	}
	pipe.closeReaders()
	if pipe.writer != nil {
		_ = pipe.writer.Close()
	}
}

func waitForLinuxOutputPipes(
	stdout *linuxOutputPipe,
	stderr *linuxOutputPipe,
	done <-chan error,
	grace time.Duration,
	ctx context.Context,
) (bool, error) {
	timer := newLinuxGraceTimer(grace)
	defer stopLinuxTimer(timer)

	pending := 2
	for pending > 0 {
		select {
		case err := <-done:
			pending--
			if err != nil {
				stdout.closeReaders()
				stderr.closeReaders()
				for pending > 0 {
					<-done
					pending--
				}
				return false, err
			}
		case <-timer.C:
			stdout.closeReaders()
			stderr.closeReaders()
			for pending > 0 {
				<-done
				pending--
			}
			return true, nil
		case <-ctx.Done():
			stdout.closeReaders()
			stderr.closeReaders()
			for pending > 0 {
				<-done
				pending--
			}
			return false, ctx.Err()
		}
	}
	return false, nil
}

func (backend *linuxBackend) openExecutable(requested string) (int, error) {
	if strings.IndexByte(requested, 0) >= 0 {
		return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is invalid", nil)
	}
	if filepath.IsAbs(requested) {
		clean := filepath.Clean(requested)
		if clean != requested {
			return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is invalid", nil)
		}
		for _, root := range backend.executableRoot {
			if clean == root.path || !strings.HasPrefix(clean, root.path+string(filepath.Separator)) {
				continue
			}
			relative := strings.TrimPrefix(clean, root.path+string(filepath.Separator))
			fd, err := openLinuxExecutableAt(root.fd, relative)
			if err != nil {
				return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", err)
			}
			return fd, nil
		}
		return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", nil)
	}
	if filepath.Base(requested) != requested || requested == "." || requested == ".." {
		return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is invalid", nil)
	}
	for _, root := range backend.executableRoot {
		fd, err := openLinuxExecutableAt(root.fd, requested)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EACCES) {
			return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", err)
		}
	}
	return -1, linuxBackendError(guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "args", "guest executable is unavailable", nil)
}

func openLinuxExecutableAt(rootFD int, relative string) (int, error) {
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(linuxResolveFlags),
	})
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o111 == 0 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		_ = unix.Close(fd)
		return -1, unix.EACCES
	}
	return fd, nil
}

func startLinuxCommandWithoutPrivilegeGain(command *exec.Cmd) error {
	if command == nil {
		return unix.EINVAL
	}
	// no_new_privs is inherited from the calling OS thread across fork/exec and
	// permanently prevents set-ID bits and file capabilities from increasing
	// the child's privileges. Locking keeps the thread state bound to this start.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return command.Start()
}

func (backend *linuxBackend) linuxExecutableIsInterpreterScript(executableFD int) (bool, error) {
	readFD, err := unix.Openat(
		backend.procSelfFD,
		strconv.Itoa(executableFD),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.EACCES) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(readFD)

	var header [2]byte
	n, err := unix.Pread(readFD, header[:], 0)
	if err != nil {
		return false, err
	}
	return n == len(header) && header[0] == '#' && header[1] == '!', nil
}

func (backend *linuxBackend) registerProcessGroup(pgid int) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return linuxBackendError(guestagent.ErrorCodeBackendUnavailable, guestagent.OperationExec, "backend", "guest backend is unavailable", nil)
	}
	backend.processGroups[pgid] = struct{}{}
	return nil
}

func (backend *linuxBackend) unregisterProcessGroup(pgid int) {
	backend.mu.Lock()
	delete(backend.processGroups, pgid)
	backend.mu.Unlock()
}

func waitForLinuxLeader(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func linuxExitCode(state *os.ProcessState) int {
	if state == nil {
		return 1
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		if code := state.ExitCode(); code >= 0 {
			return code
		}
		return 1
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

func effectiveLinuxLimit(requested, maximum int64) int64 {
	if requested <= 0 || requested > maximum {
		return maximum
	}
	return requested
}

type linuxBoundedWriter struct {
	mu        sync.Mutex
	data      []byte
	limit     int64
	truncated bool
}

func newLinuxBoundedWriter(limit int64) *linuxBoundedWriter {
	return &linuxBoundedWriter{limit: limit}
}

func (writer *linuxBoundedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	remaining := writer.limit - int64(len(writer.data))
	if remaining > 0 {
		retain := int64(len(data))
		if retain > remaining {
			retain = remaining
		}
		writer.data = append(writer.data, data[:int(retain)]...)
	}
	if int64(len(data)) > remaining {
		writer.truncated = true
	}
	return len(data), nil
}

func (writer *linuxBoundedWriter) Bytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.data...)
}

func (writer *linuxBoundedWriter) Truncated() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.truncated
}

func newLinuxGraceTimer(duration time.Duration) *time.Timer {
	if duration <= 0 {
		duration = defaultLinuxTermGrace
	}
	return time.NewTimer(duration)
}

func stopLinuxTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

var _ io.Writer = (*linuxBoundedWriter)(nil)
