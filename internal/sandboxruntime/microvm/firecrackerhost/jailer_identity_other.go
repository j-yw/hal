//go:build !linux

package firecrackerhost

func openLinuxJailerIdentityFilesystem(string) (strictJailerIdentityFilesystem, error) {
	return nil, errJailerIdentity
}
