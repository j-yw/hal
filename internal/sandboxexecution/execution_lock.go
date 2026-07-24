package sandboxexecution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const executionLockFileName = "finalization.lock"

type executionFileLock struct {
	file *os.File
}

// WithExecutionLock holds an OS advisory lock for executionID while callback
// runs. Closing the descriptor, including on process exit, releases the lock.
func (s Store) WithExecutionLock(executionID string, callback func() error) (err error) {
	if callback == nil {
		return fmt.Errorf("sandbox execution lock callback is required")
	}
	executionDir, err := s.executionDir(executionID)
	if err != nil {
		return err
	}
	info, err := os.Stat(executionDir)
	if err != nil {
		return fmt.Errorf("stat sandbox execution %q for lock: %w", executionID, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("sandbox execution %q is not a directory", executionID)
	}

	lock, err := lockExecutionFile(filepath.Join(executionDir, executionLockFileName))
	if err != nil {
		return fmt.Errorf("lock sandbox execution %q: %w", executionID, err)
	}
	defer func() {
		err = errors.Join(err, lock.Close())
	}()
	return callback()
}

func lockExecutionFile(path string) (*executionFileLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockExecutionFileHandle(file); err != nil {
		_ = file.Close()
		return nil, err
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
