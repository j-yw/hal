//go:build windows

package sandboxexecution

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func fileOwnedByCurrentUser(fs.FileInfo) bool {
	// L3 has no Windows owner/DACL verifier. Unix mode bits do not describe
	// Windows ownership, so accepting an unproved value would turn the
	// durable store's private-ownership check into a false security claim.
	return false
}

func filePermissionsPrivate(fs.FileInfo) bool {
	// os.FileMode permissions cannot prove a restrictive Windows DACL. Keep
	// the execution store unavailable until a later adapter can verify both
	// owner identity and effective ACL privacy.
	return false
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
	if err := validatePrivateStoreRoot(root); err != nil {
		return nil, err
	}
	current := root
	for _, component := range components[:len(components)-1] {
		current = filepath.Join(current, component)
		if err := validatePrivateDirectory(current, "sandbox execution directory"); err != nil {
			return nil, err
		}
	}
	return openFileNoFollow(filepath.Join(current, components[len(components)-1]), flag, perm)
}

func validatePrivateStoreRoot(root string) error {
	return walkPrivateStoreRoot(root, false)
}

func ensurePrivateStoreRoot(root string) error {
	return walkPrivateStoreRoot(root, true)
}

// Windows lacks openat-style component-relative traversal in the standard
// library. Walk every existing component conservatively, rejecting symlinks
// and reparse-like mode entries before using the final root.
func walkPrivateStoreRoot(root string, createFinal bool) error {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("sandbox execution store is not accessible")
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute[len(volume):], string(filepath.Separator))
	components := strings.Split(relative, string(filepath.Separator))
	creatingSuffix := false
	for index, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) && createFinal {
			creatingSuffix = true
			if mkdirErr := os.Mkdir(current, privateDirMode); mkdirErr != nil {
				return filesystemUnavailable("sandbox execution store", mkdirErr)
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return filesystemUnavailable("sandbox execution store", statErr)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("sandbox execution store is not accessible")
		}
		if creatingSuffix {
			if err := validatePrivateDirectoryInfo(info, "sandbox execution store"); err != nil {
				return err
			}
		}
		if index == len(components)-1 {
			return validatePrivateDirectoryInfo(info, "sandbox execution store")
		}
	}
	return fmt.Errorf("sandbox execution store is not accessible")
}
