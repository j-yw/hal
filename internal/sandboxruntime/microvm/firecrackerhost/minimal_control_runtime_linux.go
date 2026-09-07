//go:build linux

package firecrackerhost

import "os"

// This private selected constructor is not connected to the executable. The
// compiling RED preserves the real root gate and leaves assembly unavailable.
func newMinimalControlLinuxRuntime(admission *minimalControlSupervisorAdmission) (*l8RuntimeOwnerLinuxRuntime, error) {
	if os.Geteuid() != 0 || admission == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	return nil, errL8RuntimeOwnerInvalid
}
