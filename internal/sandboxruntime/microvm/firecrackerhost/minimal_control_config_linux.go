//go:build linux

package firecrackerhost

// Compiling RED adapter at the actual supervisor import boundary. The current
// selected decoder rejects the new discriminator before importing its extra
// roles. GREEN will replace this legacy admission only, never enable a runtime.
func withMinimalControlSupervisorAdmission(fds [6]int, openFD func(uintptr, string) (int, error), closeFD func(int) error, expectedSeedUID uint32, consume func(*minimalControlSupervisorAdmission) error) (bool, error) {
	_, _, err := readJailerRecoverySelectedConfigFD(fds[2])
	if err != nil {
		return true, errL8RuntimeOwnerInvalid
	}
	return false, nil
}
