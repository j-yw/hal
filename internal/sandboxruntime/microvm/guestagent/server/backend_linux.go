//go:build linux

package server

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

const (
	linuxResolveFlags = unix.RESOLVE_BENEATH |
		unix.RESOLVE_NO_MAGICLINKS |
		unix.RESOLVE_NO_XDEV |
		unix.RESOLVE_NO_SYMLINKS

	defaultLinuxTermGrace = 250 * time.Millisecond
)

type linuxExecutableRoot struct {
	path string
	fd   int
}

type linuxBackend struct {
	mu sync.Mutex

	workspaceFD    int
	procSelfFD     int
	guestRoot      string
	baseEnv        []string
	executableRoot []linuxExecutableRoot
	termGrace      time.Duration
	processGroups  map[int]struct{}
	closed         bool
}

// NewLinuxBackend constructs the fail-closed production Linux operation
// backend. All request paths are resolved from pinned descriptors.
func NewLinuxBackend(options LinuxBackendOptions) (Backend, error) {
	workspaceRoot, guestRoot, err := validateLinuxRoots(options.WorkspaceRoot, options.GuestRoot)
	if err != nil {
		return nil, err
	}
	workspaceFD, err := unix.Openat2(unix.AT_FDCWD, workspaceRoot, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS),
	})
	if err != nil {
		return nil, linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "workspaceRoot", "guest workspace is unavailable", err)
	}

	backend := &linuxBackend{
		workspaceFD:   workspaceFD,
		procSelfFD:    -1,
		guestRoot:     guestRoot,
		termGrace:     options.TermGrace,
		processGroups: make(map[int]struct{}),
	}
	if backend.termGrace < 0 {
		err = linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "termGrace", "process termination grace is invalid", nil)
		return nil, err
	}
	if backend.termGrace == 0 {
		backend.termGrace = defaultLinuxTermGrace
	}
	defer func() {
		if err != nil {
			backend.closeDescriptors()
		}
	}()

	probeFD, probeErr := backend.openWorkspace(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if probeErr != nil {
		err = linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "workspaceRoot", "required Linux containment is unavailable", probeErr)
		return nil, err
	}
	_ = unix.Close(probeFD)

	backend.procSelfFD, err = unix.Open("/proc/self/fd", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		err = linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "procfd", "required descriptor bridge is unavailable", err)
		return nil, err
	}
	if err = backend.verifyProcDescriptorBridge(); err != nil {
		return nil, err
	}

	backend.baseEnv, err = normalizeLinuxEnvironment(options.BaseEnvironment, true)
	if err != nil {
		return nil, err
	}
	backend.executableRoot, err = openLinuxExecutableRoots(options.ExecutablePaths)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

func (backend *linuxBackend) Ready(context.Context) error {
	if backend == nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), guestagent.OperationReadiness, "backend", "guest backend is unavailable", nil)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), guestagent.OperationReadiness, "backend", "guest backend is unavailable", nil)
	}
	var workspaceStat unix.Stat_t
	var procStat unix.Stat_t
	if err := unix.Fstat(backend.workspaceFD, &workspaceStat); err != nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), guestagent.OperationReadiness, "backend", "guest backend is unavailable", err)
	}
	if err := unix.Fstat(backend.procSelfFD, &procStat); err != nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), guestagent.OperationReadiness, "backend", "guest backend is unavailable", err)
	}
	return nil
}

func (backend *linuxBackend) Close(ctx context.Context) error {
	if backend == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	backend.mu.Lock()
	if backend.closed {
		backend.mu.Unlock()
		return nil
	}
	backend.closed = true
	groups := make([]int, 0, len(backend.processGroups))
	for pgid := range backend.processGroups {
		groups = append(groups, pgid)
	}
	backend.mu.Unlock()

	for _, pgid := range groups {
		_ = unix.Kill(-pgid, unix.SIGTERM)
	}
	if len(groups) > 0 {
		timer := time.NewTimer(backend.termGrace)
		select {
		case <-ctx.Done():
			stopLinuxTimer(timer)
		case <-timer.C:
		}
		for _, pgid := range groups {
			_ = unix.Kill(-pgid, unix.SIGKILL)
		}
	}
	backend.closeDescriptors()
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (backend *linuxBackend) closeDescriptors() {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	for _, root := range backend.executableRoot {
		if root.fd >= 0 {
			_ = unix.Close(root.fd)
		}
	}
	backend.executableRoot = nil
	if backend.procSelfFD >= 0 {
		_ = unix.Close(backend.procSelfFD)
		backend.procSelfFD = -1
	}
	if backend.workspaceFD >= 0 {
		_ = unix.Close(backend.workspaceFD)
		backend.workspaceFD = -1
	}
}

func (backend *linuxBackend) openWorkspace(relative string, flags int, mode uint32) (int, error) {
	if relative == "" {
		relative = "."
	}
	return unix.Openat2(backend.workspaceFD, relative, &unix.OpenHow{
		Flags:   uint64(flags),
		Mode:    uint64(mode),
		Resolve: uint64(linuxResolveFlags),
	})
}

func (backend *linuxBackend) guestRelative(operation guestagent.Operation, field, value string, allowRoot bool) (string, error) {
	clean := path.Clean(value)
	if value == "" || !strings.HasPrefix(value, "/") || clean != value {
		return "", linuxBackendError(guestagent.ErrorCodeMalformedPath, operation, field, "guest path is invalid", nil)
	}
	if clean == backend.guestRoot {
		if allowRoot {
			return ".", nil
		}
		return "", linuxBackendError(guestagent.ErrorCodeMalformedPath, operation, field, "guest path is invalid", nil)
	}
	prefix := backend.guestRoot + "/"
	if !strings.HasPrefix(clean, prefix) {
		return "", linuxBackendError(guestagent.ErrorCodeMalformedPath, operation, field, "guest path is outside the workspace", nil)
	}
	relative := strings.TrimPrefix(clean, prefix)
	if relative == "" || relative == "." || strings.HasPrefix(relative, "../") {
		return "", linuxBackendError(guestagent.ErrorCodeMalformedPath, operation, field, "guest path is invalid", nil)
	}
	return relative, nil
}

func (backend *linuxBackend) verifyProcDescriptorBridge() error {
	reopened, err := unix.Openat(backend.procSelfFD, strconv.Itoa(backend.workspaceFD), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "procfd", "required descriptor bridge is unavailable", err)
	}
	defer unix.Close(reopened)
	var originalStat, reopenedStat unix.Stat_t
	if err := unix.Fstat(backend.workspaceFD, &originalStat); err != nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "procfd", "required descriptor bridge is unavailable", err)
	}
	if err := unix.Fstat(reopened, &reopenedStat); err != nil {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "procfd", "required descriptor bridge is unavailable", err)
	}
	if originalStat.Dev != reopenedStat.Dev || originalStat.Ino != reopenedStat.Ino {
		return linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "procfd", "required descriptor bridge is unavailable", errors.New("descriptor identity mismatch"))
	}
	return nil
}

func validateLinuxRoots(workspaceRoot, guestRoot string) (string, string, error) {
	workspaceRoot = filepath.Clean(workspaceRoot)
	if workspaceRoot == "." || !filepath.IsAbs(workspaceRoot) || workspaceRoot == string(filepath.Separator) {
		return "", "", linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "workspaceRoot", "guest workspace configuration is invalid", nil)
	}
	guestRoot = path.Clean(guestRoot)
	if guestRoot == "." || guestRoot == "/" || !strings.HasPrefix(guestRoot, "/") {
		return "", "", linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "guestRoot", "guest workspace configuration is invalid", nil)
	}
	return workspaceRoot, guestRoot, nil
}

func normalizeLinuxEnvironment(entries []string, defaults bool) ([]string, error) {
	if len(entries) == 0 && defaults {
		entries = []string{
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"LANG=C",
			"LC_ALL=C",
		}
	}
	result := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if strings.IndexByte(entry, 0) >= 0 {
			return nil, linuxBackendError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationExec, "env", "environment assignment is invalid", nil)
		}
		name, _, ok := strings.Cut(entry, "=")
		if !ok || !validLinuxEnvironmentName(name) {
			return nil, linuxBackendError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationExec, "env", "environment assignment is invalid", nil)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, linuxBackendError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationExec, "env", "environment name is duplicated", nil)
		}
		seen[name] = struct{}{}
		result = append(result, entry)
	}
	return result, nil
}

func mergeLinuxEnvironment(base, additions []string) ([]string, error) {
	all := make([]string, 0, len(base)+len(additions))
	all = append(all, base...)
	all = append(all, additions...)
	return normalizeLinuxEnvironment(all, false)
}

func validLinuxEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		switch {
		case char >= 'A' && char <= 'Z':
		case char == '_':
		case index > 0 && char >= '0' && char <= '9':
		default:
			return false
		}
	}
	return true
}

func openLinuxExecutableRoots(paths []string) ([]linuxExecutableRoot, error) {
	useDefaults := len(paths) == 0
	if len(paths) == 0 {
		paths = []string{"/usr/local/bin", "/usr/bin", "/bin"}
	}
	roots := make([]linuxExecutableRoot, 0, len(paths))
	closeRoots := func() {
		for _, root := range roots {
			_ = unix.Close(root.fd)
		}
	}
	for _, configured := range paths {
		clean := filepath.Clean(configured)
		if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
			closeRoots()
			return nil, linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "executablePaths", "executable root configuration is invalid", nil)
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			if useDefaults && errors.Is(err, unix.ENOENT) {
				continue
			}
			closeRoots()
			return nil, linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "executablePaths", "executable root is unavailable", err)
		}
		fd, err := unix.Open(resolved, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			closeRoots()
			return nil, linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "executablePaths", "executable root is unavailable", err)
		}
		roots = append(roots, linuxExecutableRoot{path: clean, fd: fd})
	}
	if len(roots) == 0 {
		return nil, linuxBackendError(guestagent.ErrorCode("backend_unavailable"), "", "executablePaths", "no executable root is available", nil)
	}
	return roots, nil
}

func linuxBackendError(code guestagent.ErrorCode, operation guestagent.Operation, field, message string, cause error) *guestagent.ProtocolError {
	if cause == nil {
		cause = errors.New(message)
	}
	return &guestagent.ProtocolError{
		Code:      code,
		Operation: operation,
		Field:     field,
		Message:   message,
		Err:       cause,
	}
}

func linuxContextError(operation guestagent.Operation, err error) error {
	if err == nil {
		return nil
	}
	code := guestagent.ErrorCodeRequestCanceled
	message := "guest operation canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = guestagent.ErrorCodeRequestTimeout
		message = "guest operation timed out"
	}
	return linuxBackendError(code, operation, "context", message, err)
}

func procSelfFDPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}
