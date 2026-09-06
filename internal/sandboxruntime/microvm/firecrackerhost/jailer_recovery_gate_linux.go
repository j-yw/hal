//go:build linux

package firecrackerhost

import "os"

// Fail-closed declaration for mounted-snapshot descriptor readback RED.
func verifyJailerRecoveryMountedFile(*os.File, jailerRecoveryMountedExecutable) error {
	return errL8RuntimeOwnerInvalid
}
