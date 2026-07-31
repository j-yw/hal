//go:build linux

package linuxrules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

type ProductionExecutorOptions struct {
	NSenterPath string
	NFTPath     string
}

type productionExecutor struct {
	nsenterPath string
	nftPath     string
}

func NewProductionExecutor(options ProductionExecutorOptions) (NFTExecutor, error) {
	executor, err := newProductionExecutor(options)
	if err != nil {
		return nil, err
	}
	return executor, nil
}

func newProductionExecutor(options ProductionExecutorOptions) (*productionExecutor, error) {
	if !validAbsoluteToolPath(options.NSenterPath) || !validAbsoluteToolPath(options.NFTPath) {
		return nil, ErrInvalidConfiguration
	}
	return &productionExecutor{nsenterPath: options.NSenterPath, nftPath: options.NFTPath}, nil
}

func (e *productionExecutor) ApplyBatch(ctx context.Context, namespace NamespaceHandle, batch []byte) error {
	if !namespace.valid() || len(batch) == 0 || len(batch) > defaultMaxBatchBytes {
		return ErrInvalidConfiguration
	}
	command, namespaceFiles, err := e.namespaceCommand(ctx, namespace, "-f", "-")
	if err != nil {
		return ErrApplyFailed
	}
	defer closeNamespaceFiles(namespaceFiles)
	command.Stdin = bytes.NewReader(batch)
	command.Stdout = io.Discard
	command.Stderr = &boundedBuffer{max: 4096}
	if err := command.Run(); err != nil {
		return ErrApplyFailed
	}
	return nil
}

func (e *productionExecutor) ListTableJSON(ctx context.Context, namespace NamespaceHandle, query TableQuery, maxBytes int64) ([]byte, error) {
	if !namespace.valid() || query.family != tableFamily || !validNFTIdentifier(query.name, 32) || maxBytes <= 0 || maxBytes > hardMaxInspectionBytes {
		return nil, ErrInvalidConfiguration
	}
	command, namespaceFiles, err := e.namespaceCommand(ctx, namespace, "--json", "list", "table", query.family, query.name)
	if err != nil {
		return nil, ErrInspectionFailed
	}
	defer closeNamespaceFiles(namespaceFiles)
	stdout := &boundedBuffer{max: maxBytes}
	stderr := &boundedBuffer{max: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	if stdout.exceeded {
		return nil, ErrInspectionTooLarge
	}
	if err != nil {
		lower := strings.ToLower(stderr.buffer.String())
		if strings.Contains(lower, "no such file") || strings.Contains(lower, "does not exist") {
			return nil, ErrTableNotFound
		}
		return nil, ErrInspectionFailed
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

func (e *productionExecutor) namespaceCommand(ctx context.Context, namespace NamespaceHandle, args ...string) (*exec.Cmd, []*os.File, error) {
	userFile, err := duplicateNamespaceFile(namespace.userFD, "user-namespace")
	if err != nil {
		return nil, nil, err
	}
	networkFile, err := duplicateNamespaceFile(namespace.networkFD, "network-namespace")
	if err != nil {
		userFile.Close()
		return nil, nil, errors.New("namespace descriptor unavailable")
	}
	commandArgs := []string{
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--preserve-credentials",
		"--",
		e.nftPath,
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, e.nsenterPath, commandArgs...)
	command.ExtraFiles = []*os.File{userFile, networkFile}
	command.Env = []string{}
	runtime.KeepAlive(namespace)
	return command, command.ExtraFiles, nil
}

func duplicateNamespaceFile(fd int, label string) (*os.File, error) {
	duplicated, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicated), label)
	if file == nil {
		_ = unix.Close(duplicated)
		return nil, errors.New("namespace descriptor unavailable")
	}
	return file, nil
}

func closeNamespaceFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func validAbsoluteToolPath(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\x00\r\n") &&
		filepath.IsAbs(value) && filepath.Clean(value) == value
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	max      int64
	exceeded bool
}

func (w *boundedBuffer) Write(payload []byte) (int, error) {
	if w.max <= 0 || int64(w.buffer.Len())+int64(len(payload)) > w.max {
		remaining := w.max - int64(w.buffer.Len())
		if remaining > 0 {
			_, _ = w.buffer.Write(payload[:remaining])
		}
		w.exceeded = true
		return len(payload), nil
	}
	return w.buffer.Write(payload)
}
