package sandboxworker

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func validateWorkerSocketPath(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("worker server socket path must be absolute")
	}
	socketPath = filepath.Clean(socketPath)
	parent := filepath.Dir(socketPath)
	if err := validateWorkerSocketParentComponents(parent); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() {
		return errors.New("worker server socket parent is unavailable")
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("worker server socket parent must not be a symlink")
	}
	if parentInfo.Mode().Perm() != 0o700 {
		return errors.New("worker server socket parent permissions are unsafe")
	}
	if err := validateWorkerSocketParentOwner(parentInfo); err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath); err == nil {
		return errors.New("worker server socket path already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errors.New("worker server socket path is unavailable")
	}
	return nil
}

func validateWorkerSocketParentComponents(parent string) error {
	current := filepath.Clean(parent)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("worker server socket parent is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("worker server socket parent components must not be symlinks")
		}
		if !info.IsDir() {
			return errors.New("worker server socket parent components must be directories")
		}
		next := filepath.Dir(current)
		if next == current {
			return nil
		}
		current = next
	}
}

func removeWorkerSocketIfSame(socketPath string, createdInfo os.FileInfo) {
	if createdInfo == nil {
		return
	}
	currentInfo, err := os.Lstat(socketPath)
	if err != nil || currentInfo.Mode()&os.ModeSocket == 0 || !os.SameFile(createdInfo, currentInfo) {
		return
	}
	_ = os.Remove(socketPath)
}
