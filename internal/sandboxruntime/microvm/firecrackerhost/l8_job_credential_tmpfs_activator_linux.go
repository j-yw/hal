//go:build linux

package firecrackerhost

import (
	"io"
	"os"
	"path/filepath"
)

func materializeL8JobCredentialFileTmpfsPayload(rootDir string, payload []byte) (dir, filePath string, file *os.File, err error) {
	if rootDir == "" || len(payload) == 0 {
		return "", "", nil, ErrL8JobCredentialRuntimeInvalid
	}
	dir, err = os.MkdirTemp(rootDir, "l8-file-")
	if err != nil {
		return "", "", nil, ErrL8JobCredentialRuntimeUnavailable
	}
	if err := os.Chmod(dir, l8JobCredentialFileTmpfsDirMode); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", nil, ErrL8JobCredentialRuntimeUnavailable
	}
	filePath = filepath.Join(dir, "payload")
	file, err = os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, l8JobCredentialFileTmpfsFileMode)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", nil, ErrL8JobCredentialRuntimeUnavailable
	}
	wrote, writeErr := file.Write(payload)
	if writeErr != nil || wrote != len(payload) {
		abandonL8JobCredentialFileTmpfsPayload(file, filePath, dir, uint32(len(payload)))
		return "", "", nil, ErrL8JobCredentialRuntimeUnavailable
	}
	if err := file.Sync(); err != nil {
		abandonL8JobCredentialFileTmpfsPayload(file, filePath, dir, uint32(len(payload)))
		return "", "", nil, ErrL8JobCredentialRuntimeUnavailable
	}
	return dir, filePath, file, nil
}

func abandonL8JobCredentialFileTmpfsPayload(file *os.File, filePath, dir string, size uint32) {
	leftover, _ := wipeL8JobCredentialFileTmpfsMaterialization(file, filePath, dir, size)
	if leftover != nil {
		_ = leftover.Close()
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func wipeL8JobCredentialFileTmpfsMaterialization(file *os.File, filePath, dir string, size uint32) (*os.File, error) {
	var firstErr error
	if file != nil {
		if _, err := file.Seek(0, io.SeekStart); err != nil && firstErr == nil {
			firstErr = err
		}
		if size > 0 {
			zeros := make([]byte, size)
			if _, err := file.Write(zeros); err != nil && firstErr == nil {
				firstErr = err
			}
			clear(zeros)
		}
		if err := file.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		if firstErr != nil {
			return file, firstErr
		}
	}
	if filePath != "" {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return file, err
		}
	}
	if dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			return file, err
		}
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return file, err
		}
	}
	return nil, nil
}
