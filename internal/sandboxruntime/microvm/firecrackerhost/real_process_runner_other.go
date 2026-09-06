//go:build !linux

package firecrackerhost

func startOSExecCommandWithPrivateUmask(start func() error) error {
	return start()
}
