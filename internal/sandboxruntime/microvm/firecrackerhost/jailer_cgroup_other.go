//go:build !linux

package firecrackerhost

func newLinuxJailerCgroupFilesystem(string) (strictJailerCgroupFilesystem, error) {
	return nil, errJailerCgroup
}
