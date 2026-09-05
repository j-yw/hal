//go:build !linux

package firecrackerhost

func newLinuxJailerStagingFilesystem(jailerStagingAuthority) (jailerStagingFilesystem, error) {
	return nil, newJailerStagingError(errJailerStagingFailed, "filesystem")
}
