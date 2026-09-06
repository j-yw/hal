package sandboxexecution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const executionLockFileName = "finalization.lock"

type executionFileLock struct {
	file *os.File
}

type executionLockScope struct {
	executionID string
	mu          sync.RWMutex
	active      bool
}

// WithExecutionLock holds an OS advisory lock for executionID while callback
// runs. Closing the descriptor, including on process exit, releases the lock.
func (s Store) WithExecutionLock(executionID string, callback func() error) (err error) {
	if callback == nil {
		return fmt.Errorf("sandbox execution lock callback is required")
	}
	return s.WithLockedExecution(executionID, func(Store) error {
		return callback()
	})
}

// WithLockedExecution supplies a callback-scoped Store that may perform
// retry-safe manifest updates for executionID without reacquiring the already
// held OS lock. A scoped Store used after the callback returns loses this
// bypass and resumes ordinary lock acquisition.
func (s Store) WithLockedExecution(executionID string, callback func(Store) error) (err error) {
	if callback == nil {
		return fmt.Errorf("sandbox execution locked-store callback is required")
	}
	executionID = strings.TrimSpace(executionID)
	executionDir, err := s.executionDir(executionID)
	if err != nil {
		return err
	}
	if err := validatePrivateStoreRoot(s.root); err != nil {
		return err
	}
	if err := validatePrivateDirectory(executionDir, "sandbox execution"); err != nil {
		return err
	}

	lock, err := lockExecutionFile(filepath.Join(executionDir, executionLockFileName))
	if err != nil {
		return fmt.Errorf("lock sandbox execution %q: %w", executionID, err)
	}
	defer func() {
		err = errors.Join(err, lock.Close())
	}()
	scope := &executionLockScope{
		executionID: executionID,
		active:      true,
	}
	locked := s
	locked.lockScope = scope
	defer scope.deactivate()
	return callback(locked)
}

func (s Store) enterLockScope(executionID string) func() {
	scope := s.lockScope
	if scope == nil || scope.executionID != strings.TrimSpace(executionID) {
		return nil
	}
	scope.mu.RLock()
	if !scope.active {
		scope.mu.RUnlock()
		return nil
	}
	return scope.mu.RUnlock
}

func (scope *executionLockScope) deactivate() {
	if scope == nil {
		return
	}
	scope.mu.Lock()
	scope.active = false
	scope.mu.Unlock()
}

func lockExecutionFile(path string) (*executionFileLock, error) {
	if err := validateOptionalPrivateRegularFile(path, "sandbox execution lock"); err != nil {
		return nil, err
	}
	file, err := openContainedFileNoFollow(filepath.Dir(path), []string{filepath.Base(path)}, os.O_RDWR|os.O_CREATE, privateFileMode)
	if err != nil {
		return nil, filesystemUnavailable("sandbox execution lock", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sandbox execution lock cannot be verified")
	}
	if err := validatePrivateRegularFileInfo(info, "sandbox execution lock"); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := lockExecutionFileHandle(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		_ = unlockExecutionFileHandle(file)
		_ = file.Close()
		return nil, fmt.Errorf("sandbox execution lock changed while opening")
	}
	return &executionFileLock{file: file}, nil
}

func (lock *executionFileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockExecutionFileHandle(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
