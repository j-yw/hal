//go:build !linux

package credentialsource

func NewRegistry(RegistryConfig) (*Registry, error) {
	return nil, ErrCredentialSourceUnsupported
}
