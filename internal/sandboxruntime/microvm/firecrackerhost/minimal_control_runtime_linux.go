//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"golang.org/x/sys/unix"
)

// This private selected constructor is not connected to the executable. It
// assembles retained resources only, inside the original admission callback.
func newMinimalControlLinuxRuntime(admission *minimalControlSupervisorAdmission) (*l8RuntimeOwnerLinuxRuntime, error) {
	if os.Geteuid() != 0 || admission == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	config, err := validateMinimalControlRuntimeAdmission(admission)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	var fds [6]int
	copy(fds[:], admission.borrowed[:6])
	return assembleJailerRecoveryLinuxRuntime(fds, config.jailerRecoverySupervisorConfig, admission.borrowed[6], admission)
}

// Re-read the original bounded sealed public bytes independently of mutable
// callback metadata. This is admission consistency, not live L7/launch proof.
func validateMinimalControlRuntimeAdmission(admission *minimalControlSupervisorAdmission) (minimalControlSupervisorConfig, error) {
	if admission == nil || !minimalControlAdmissionFDsDistinct(admission.borrowed[:]) ||
		validateL8RuntimeOwnerSeqpacketFD(admission.borrowed[0]) != nil || validateL8RuntimeOwnerDirectoryFD(admission.borrowed[1]) != nil {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	fd := admission.borrowed[2]
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, l8RuntimeOwnerSupervisorConfigLimit)
	if err != nil || identity.Size <= 0 {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, identity.Size)
	if n, err := unix.Pread(fd, payload, 0); err != nil || n != len(payload) || sha256.Sum256(payload) != admission.configDigest {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	config, public, err := decodeMinimalControlSupervisorConfig(payload)
	if err != nil {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	callback, err := json.Marshal(admission.config)
	if err != nil || !bytes.Equal(callback, payload) || len(admission.controllerKey) != ed25519.PrivateKeySize {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	derived := ed25519.NewKeyFromSeed(admission.controllerKey[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, admission.controllerKey) || !bytes.Equal(derived[ed25519.SeedSize:], public) {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	correlation := hex.EncodeToString(admission.configDigest[:])
	recovery := minimalControlRecoveryProjection{configCorrelation: correlation, job: config.Job,
		uid: config.Policy.UID, gid: config.Policy.GID, firecrackerConfigSHA256: config.Config.SHA256}
	namespace := minimalControlNamespaceProjection{configCorrelation: correlation, namespaces: config.Control.Namespace}
	request, err := captureMinimalControlConfigExpectation(config, public, admission.configDigest)
	if err != nil || admission.recovery != recovery || admission.namespace != namespace || admission.request != request {
		return minimalControlSupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	return config, nil
}
