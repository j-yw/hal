package sandboxworker

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const jobStateLockFileName = ".manager.lock"

type jobStateLock struct {
	mu   sync.Mutex
	file *os.File
}

func acquireJobStateLock(root string) (*jobStateLock, error) {
	path := filepath.Join(root, jobStateLockFileName)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("job state ownership file is invalid")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect job state ownership file: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open job state ownership file: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("job state ownership file is invalid")
	}
	if err := tryLockJobStateFileHandle(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("job state directory is already owned")
	}
	return &jobStateLock{file: file}, nil
}

func (lock *jobStateLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return nil
	}
	unlockErr := unlockJobStateFileHandle(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
