//go:build windows

package sandboxexecution

import (
	"io/fs"
	"os"
	"path/filepath"
)

func fileOwnedByCurrentUser(fs.FileInfo) bool {
	return true
}

func filePermissionsPrivate(fs.FileInfo) bool {
	return true
}

func openFileNoFollow(path string, flag int, perm fs.FileMode) (*os.File, error) {
	before, err := os.Lstat(path)
	if err == nil && before.Mode()&fs.ModeSymlink != 0 {
		return nil, fs.ErrInvalid
	}
	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fs.ErrInvalid
	}
	return file, nil
}

func openContainedFileNoFollow(root string, components []string, flag int, perm fs.FileMode) (*os.File, error) {
	current := root
	if err := validatePrivateDirectory(current, "sandbox execution store"); err != nil {
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		current = filepath.Join(current, component)
		if err := validatePrivateDirectory(current, "sandbox execution directory"); err != nil {
			return nil, err
		}
	}
	return openFileNoFollow(filepath.Join(current, components[len(components)-1]), flag, perm)
}
