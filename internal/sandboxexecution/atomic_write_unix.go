//go:build !windows

package sandboxexecution

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

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
	parentFD, err := openStoreParentDirectory(root, components[:len(components)-1], createParents)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)

	destinationName := components[len(components)-1]
	if err := validateOptionalStoreFileAt(parentFD, destinationName); err != nil {
		return nil, err
	}
	tempName, tempFD, err := createStoreTempFileAt(parentFD, mode)
	if err != nil {
		return nil, err
	}
	temp := os.NewFile(uintptr(tempFD), tempName)
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(parentFD, tempName, 0)
		}
	}()

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
	if err := validatePrivateRegularFileInfo(info, "sandbox execution store file"); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}

	displayTempPath := filepath.Join(filepath.Dir(displayPath), tempName)
	runAtomicStoreFileBeforePublish(displayTempPath, displayPath)
	if err := unix.Renameat(parentFD, tempName, parentFD, destinationName); err != nil {
		return nil, err
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil && !errors.Is(err, unix.EINVAL) {
		return nil, err
	}
	return info, nil
}

func openStoreParentDirectory(root string, components []string, create bool) (int, error) {
	dirFD, err := openAbsoluteDirectoryNoFollow(root, false)
	if err != nil {
		return -1, err
	}
	for _, component := range components {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(dirFD, component, uint32(privateDirMode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(dirFD)
				return -1, mkdirErr
			}
			nextFD, openErr = unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		_ = unix.Close(dirFD)
		if openErr != nil {
			return -1, openErr
		}
		dirFD = nextFD
		if err := validatePrivateDirectoryFD(dirFD); err != nil {
			_ = unix.Close(dirFD)
			return -1, err
		}
	}
	return dirFD, nil
}

func validateOptionalStoreFileAt(parentFD int, name string) error {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	return validatePrivateRegularFileInfo(info, "sandbox execution store file")
}

func createStoreTempFileAt(parentFD int, mode fs.FileMode) (string, int, error) {
	for range 32 {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", -1, err
		}
		name := ".hal-tmp-" + hex.EncodeToString(random)
		fd, err := unix.Openat(
			parentFD,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			uint32(mode.Perm()),
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return name, fd, err
	}
	return "", -1, fs.ErrExist
}
