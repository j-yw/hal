//go:build linux

package firecrackerhost

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// The caller retains the already seal/identity-checked FD. Positional reads
// neither seek nor wrap/close that borrowed descriptor; only the bounded owned
// snapshot crosses the existing strict measured-config parser boundary.
func readMinimalControlFirecrackerConfig(fd int, asset jailerRecoveryAsset) (strictJailerConfigFile, error) {
	if asset.Size <= 0 || asset.Size > maxStrictJailerConfigBytes {
		return strictJailerConfigFile{}, errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, asset.Size)
	if n, err := unix.Pread(fd, payload, 0); err != nil || n != len(payload) {
		return strictJailerConfigFile{}, errL8RuntimeOwnerInvalid
	}
	config, err := readStrictJailerConfig(jailerStagingResourceInput{Source: bytes.NewReader(payload), SizeBytes: asset.Size, SHA256: asset.SHA256})
	if err != nil {
		return strictJailerConfigFile{}, errL8RuntimeOwnerInvalid
	}
	return config, nil
}
