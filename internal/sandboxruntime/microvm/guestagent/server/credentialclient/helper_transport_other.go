//go:build !linux

package credentialclient

func revalidateVerifiedHelperStream(VerifiedHelperStream) error {
	return ErrClientControlDependencyUnaccepted
}
