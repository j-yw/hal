package sandbox

import "os"

const sandboxLeaseLockFileName = "sandbox-leases.lock"

type sandboxLeaseStoreFileLock struct {
	file *os.File
}

func lockSandboxLeaseStoreFile(path string) (*sandboxLeaseStoreFileLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockSandboxLeaseStoreFileHandle(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &sandboxLeaseStoreFileLock{file: file}, nil
}

func (l *sandboxLeaseStoreFileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}

	unlockErr := unlockSandboxLeaseStoreFileHandle(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
