package factory

import "os"

type storeFileLock struct {
	file *os.File
}

func lockStoreFile(path string) (*storeFileLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockStoreFileHandle(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &storeFileLock{file: file}, nil
}

func (l *storeFileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}

	unlockErr := unlockStoreFileHandle(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
