package sandboxworkspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LockManager acquires local direct-workspace locks by resource key.
type LockManager struct {
	Dir string
}

// NewLockManager returns a lock manager rooted at dir.
func NewLockManager(dir string) LockManager {
	return LockManager{Dir: dir}
}

// DirectLock is an active direct workspace lock.
type DirectLock struct {
	ResourceKey string
	Path        string

	released bool
}

// Acquire creates an exclusive active lock for resourceKey.
func (m LockManager) Acquire(resourceKey string) (*DirectLock, error) {
	resourceKey = strings.TrimSpace(resourceKey)
	if resourceKey == "" {
		return nil, fmt.Errorf("direct workspace lock: resource key is required")
	}
	dir := strings.TrimSpace(m.Dir)
	if dir == "" {
		return nil, fmt.Errorf("direct workspace lock: lock directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("direct workspace lock: create lock directory: %w", err)
	}

	path := filepath.Join(dir, directLockFilename(resourceKey))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, planningError(ErrDirectLockActive, Request{ResourceKey: resourceKey}, DirtyState{}, err)
		}
		return nil, fmt.Errorf("direct workspace lock: acquire: %w", err)
	}
	if _, err := file.WriteString(resourceKey + "\n"); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("direct workspace lock: write lock file: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("direct workspace lock: close lock file: %w", err)
	}

	return &DirectLock{ResourceKey: resourceKey, Path: path}, nil
}

// Release releases this lock. Repeated releases are no-ops.
func (l *DirectLock) Release() error {
	if l == nil || l.released {
		return nil
	}
	l.released = true
	if strings.TrimSpace(l.Path) == "" {
		return nil
	}
	if err := os.Remove(l.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("direct workspace lock: release: %w", err)
	}
	return nil
}

func directLockFilename(resourceKey string) string {
	sum := sha256.Sum256([]byte(resourceKey))
	return hex.EncodeToString(sum[:]) + ".lock"
}
