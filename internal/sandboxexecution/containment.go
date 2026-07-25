package sandboxexecution

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const (
	privateDirMode  fs.FileMode = 0o700
	privateFileMode fs.FileMode = 0o600
)

func ensurePrivateDirectory(path, description string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, privateDirMode); err != nil {
			return fmt.Errorf("create %s dir", description)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return filesystemUnavailable(description, err)
	}
	return validatePrivateDirectoryInfo(info, description)
}

func validatePrivateDirectory(path, description string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return filesystemUnavailable(description, err)
	}
	return validatePrivateDirectoryInfo(info, description)
}

func validatePrivateDirectoryInfo(info fs.FileInfo, description string) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", description)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", description)
	}
	if !fileOwnedByCurrentUser(info) {
		return fmt.Errorf("%s is not owned by the current user", description)
	}
	if !filePermissionsPrivate(info) {
		return fmt.Errorf("%s permissions are not private", description)
	}
	return nil
}

func validatePrivateRegularFile(path, description string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, filesystemUnavailable(description, err)
	}
	if err := validatePrivateRegularFileInfo(info, description); err != nil {
		return nil, err
	}
	return info, nil
}

func validateOptionalPrivateRegularFile(path, description string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return filesystemUnavailable(description, err)
	}
	_, err = validatePrivateRegularFile(path, description)
	return err
}

func validatePrivateRegularFileInfo(info fs.FileInfo, description string) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", description)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", description)
	}
	if !fileOwnedByCurrentUser(info) {
		return fmt.Errorf("%s is not owned by the current user", description)
	}
	if !filePermissionsPrivate(info) {
		return fmt.Errorf("%s permissions are not private", description)
	}
	return nil
}

func openVerifiedContainedPrivateRegularFile(root string, components []string, description string) (*os.File, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("%s path is invalid", description)
	}
	file, err := openContainedFileNoFollow(root, components, os.O_RDONLY, 0)
	if err != nil {
		return nil, filesystemUnavailable(description, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s cannot be verified", description)
	}
	if err := validatePrivateRegularFileInfo(info, description); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func filesystemUnavailable(description string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s does not exist: %w", description, fs.ErrNotExist)
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%s is not accessible: %w", description, fs.ErrPermission)
	}
	return fmt.Errorf("%s is not accessible", description)
}
