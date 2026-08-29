//go:build !linux

package firecrackerhost

func openL8JobCredentialHandleStore(string) (l8JobCredentialHandleStore, error) {
	return nil, ErrL8JobCredentialRuntimeUnsupported
}
