//go:build !linux

package credentialmemory

func NewLockedMapping(capacity int) (*LockedMapping, error) {
	if capacity <= 0 || capacity > MaxLockedMappingBytes {
		return nil, ErrCredentialMemoryCapacity
	}
	return nil, ErrCredentialMemoryUnsupported
}

func HardenCredentialProcess() error {
	return ErrCredentialMemoryUnsupported
}
