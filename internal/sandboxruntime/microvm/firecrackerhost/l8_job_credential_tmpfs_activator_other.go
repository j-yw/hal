//go:build !linux

package firecrackerhost

import "os"

func materializeL8JobCredentialFileTmpfsPayload(string, []byte) (string, string, *os.File, error) {
	return "", "", nil, ErrL8JobCredentialRuntimeUnsupported
}

func wipeL8JobCredentialFileTmpfsMaterialization(*os.File, string, string, uint32) (*os.File, error) {
	return nil, ErrL8JobCredentialRuntimeUnsupported
}
