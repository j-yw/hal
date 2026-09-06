//go:build windows

package sandboxexecution

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Windows does not expose openat/renameat through the standard library. Keep a
// conservative fallback that records parent identities before the write,
// rechecks them immediately before publication, and fails closed when a
// replacement is observed.
func publishStoreFileAtomic(
	root string,
	components []string,
	displayPath string,
	mode fs.FileMode,
	createParents bool,
	write atomicStoreFileWriter,
) (fs.FileInfo, error) {
	if len(components) < 2 || write == nil {
		return nil, fs.ErrInvalid
	}
	if err := validatePrivateStoreRoot(root); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	parent := root
	parentPaths := []string{root}
	parentInfos := []fs.FileInfo{rootInfo}
	for _, component := range components[:len(components)-1] {
		parent = filepath.Join(parent, component)
		if createParents {
			if err := ensurePrivateDirectory(parent, "sandbox execution store directory"); err != nil {
				return nil, err
			}
		} else if err := validatePrivateDirectory(parent, "sandbox execution store directory"); err != nil {
			return nil, err
		}
		info, err := os.Lstat(parent)
		if err != nil {
			return nil, err
		}
		parentPaths = append(parentPaths, parent)
		parentInfos = append(parentInfos, info)
	}
	if err := validateOptionalPrivateRegularFile(displayPath, "sandbox execution store file"); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(parent, ".hal-tmp-*")
	if err != nil {
		return nil, err
	}
	tempPath := temp.Name()
	// Do not remove tempPath by pathname on failures: a replaced parent could
	// redirect cleanup outside the verified store. A failed fallback may leave
	// a private temp file for later maintenance, but it will not chase a new
	// parent path.
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := write(temp); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return nil, err
	}
	info, err := temp.Stat()
	if err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}

	runAtomicStoreFileBeforePublish(tempPath, displayPath)
	for index, parentPath := range parentPaths {
		currentInfo, err := os.Lstat(parentPath)
		if err != nil || !os.SameFile(parentInfos[index], currentInfo) {
			return nil, fs.ErrInvalid
		}
	}
	if err := renameStoreFile(tempPath, displayPath); err != nil {
		return nil, err
	}
	return info, nil
}

func renameStoreFile(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	} else if !isRenameNoReplaceError(err) {
		return err
	}

	backupPath := path + backupFileSuffix
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if restoreErr := os.Rename(backupPath, path); restoreErr != nil {
			return fmt.Errorf("%w (restore failed: %v)", err, restoreErr)
		}
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}

func isRenameNoReplaceError(err error) bool {
	return errors.Is(err, fs.ErrExist) || os.IsExist(err)
}
