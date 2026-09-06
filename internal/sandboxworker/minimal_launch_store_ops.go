package sandboxworker

import "os"

// The selected store retains the original directory and manager lock. Only
// rename/sync have a private per-store fault seam; no caller configures it.
type minimalLaunchStoreOps struct {
	owner     *jobStoreV2
	root      *os.Root
	directory *os.File
	lock      *jobStateLock
	rename    func(string, string) error
	sync      func() error
}

func newMinimalLaunchStoreOps(store *jobStoreV2, root *os.Root, directory *os.File, lock *jobStateLock) *minimalLaunchStoreOps {
	return &minimalLaunchStoreOps{owner: store, root: root, directory: directory, lock: lock, rename: root.Rename, sync: directory.Sync}
}

func (store *jobStoreV2) checkMinimalAuthority(lock *jobStateLock) error {
	if store == nil || store.minimalOps == nil || store.minimalOps.owner != store || store.minimalOps.root == nil || store.minimalOps.directory == nil || lock == nil || store.minimalOps.lock != lock || store.minimalOps.rename == nil || store.minimalOps.sync == nil {
		return errMinimalLaunchState
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return errMinimalLaunchState
	}
	info, err := store.minimalOps.directory.Stat()
	root, rootErr := store.minimalOps.root.Lstat(".")
	current, currentErr := os.Lstat(store.root)
	heldLock, heldErr := lock.file.Stat()
	currentLock, lockErr := store.minimalOps.root.Lstat(jobStateLockFileName)
	if err != nil || rootErr != nil || currentErr != nil || heldErr != nil || lockErr != nil ||
		!info.IsDir() || info.Mode().Perm() != 0o700 || !minimalLaunchFileOwned(info) ||
		!os.SameFile(info, root) || !os.SameFile(info, current) || root.Mode() != info.Mode() || current.Mode() != info.Mode() ||
		!heldLock.Mode().IsRegular() || heldLock.Mode().Perm() != 0o600 || !minimalLaunchFileOwned(heldLock) ||
		!os.SameFile(heldLock, currentLock) || currentLock.Mode() != heldLock.Mode() {
		return errMinimalLaunchState
	}
	return nil
}

func (store *jobStoreV2) closeMinimalStore() {
	if store == nil || store.minimalOps == nil || store.minimalOps.owner != store {
		return
	}
	ops := store.minimalOps
	store.minimalOps = nil
	_ = ops.root.Close()
	_ = ops.directory.Close()
}

func (store *jobStoreV2) removeMinimalTemporary(name string, file *os.File) error {
	if store.checkMinimalAuthority(store.minimalOps.lock) != nil {
		return errMinimalLaunchState
	}
	held, err := file.Stat()
	current, currentErr := store.minimalOps.root.Lstat(name)
	if err != nil || currentErr != nil || !os.SameFile(held, current) || !validMinimalLaunchStoredFile(current) || store.minimalOps.root.Remove(name) != nil {
		return errMinimalLaunchState
	}
	return nil
}
