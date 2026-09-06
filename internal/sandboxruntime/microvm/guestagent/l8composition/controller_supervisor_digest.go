package l8composition

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	controllerSupervisorReadyDomain         = "hal/l8/controller-supervisor/supervisor-ready/v1"
	controllerSupervisorMonitorConfigDomain = "hal/l8/controller-supervisor/monitor-config/v1"
	controllerSupervisorCgroupConfigDomain  = "hal/l8/controller-supervisor/cgroup-config/v1"
	controllerSupervisorCreateJobDomain     = "hal/l8/controller-supervisor/create-job/v1"
	controllerSupervisorMonitorReadyDomain  = "hal/l8/controller-monitor/monitor-ready/v1"
	controllerSupervisorLaunchShimDomain    = "hal/l8/controller-supervisor/launch-shim/v1"
)

func controllerSupervisorDigest(domain string, parts ...[]byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(opaque16(domain))
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func controllerSupervisorDigestToken(value credentialprotocol.SafeID) ([]byte, error) {
	return encodeControllerSupervisorSafeID(value)
}

func ControllerSupervisorReadySHA256(boot, helper, supervisor, limit credentialprotocol.SafeID) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateControllerSupervisorLimitSet(limit); err != nil {
		return zero, err
	}
	parts := make([][]byte, 0, 4)
	for _, value := range []credentialprotocol.SafeID{boot, helper, supervisor, limit} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	return controllerSupervisorDigest(controllerSupervisorReadyDomain, parts...), nil
}

func ControllerSupervisorMonitorConfigSHA256(jobIdentity [sha256.Size]byte, job, monitor, mount, limit credentialprotocol.SafeID) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if controllerSupervisorZero32(jobIdentity) {
		return zero, ErrControllerSupervisorDigestZero
	}
	if err := validateControllerSupervisorLimitSet(limit); err != nil {
		return zero, err
	}
	parts := [][]byte{jobIdentity[:]}
	for _, value := range []credentialprotocol.SafeID{job, monitor, mount, limit} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	return controllerSupervisorDigest(controllerSupervisorMonitorConfigDomain, parts...), nil
}

func ControllerSupervisorCgroupConfigSHA256(jobIdentity [sha256.Size]byte, job, cgroup, limit credentialprotocol.SafeID) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if controllerSupervisorZero32(jobIdentity) {
		return zero, ErrControllerSupervisorDigestZero
	}
	if err := validateControllerSupervisorLimitSet(limit); err != nil {
		return zero, err
	}
	parts := [][]byte{jobIdentity[:]}
	for _, value := range []credentialprotocol.SafeID{job, cgroup, limit} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	return controllerSupervisorDigest(controllerSupervisorCgroupConfigDomain, parts...), nil
}

func ControllerSupervisorCreateJobSHA256(jobIdentity [sha256.Size]byte, body ControllerSupervisorCreateJobBody) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if controllerSupervisorZero32(jobIdentity) {
		return zero, ErrControllerSupervisorDigestZero
	}
	if _, err := EncodeControllerSupervisorCreateJobBody(body); err != nil {
		return zero, err
	}
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, body.Revision)
	parts := [][]byte{jobIdentity[:], revision}
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	parts = append(parts, body.MonitorConfigSHA256[:], body.CgroupConfigSHA256[:])
	return controllerSupervisorDigest(controllerSupervisorCreateJobDomain, parts...), nil
}

func ControllerSupervisorMonitorReadySHA256(jobIdentity [sha256.Size]byte, body ControllerSupervisorJobCreatedBody) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if controllerSupervisorZero32(jobIdentity) {
		return zero, ErrControllerSupervisorDigestZero
	}
	if _, err := EncodeControllerSupervisorJobCreatedBody(body); err != nil {
		return zero, err
	}
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, body.Revision)
	parts := [][]byte{jobIdentity[:], revision}
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	parts = append(parts, body.CreateJobSHA256[:])
	return controllerSupervisorDigest(controllerSupervisorMonitorReadyDomain, parts...), nil
}

func ControllerSupervisorLaunchShimSHA256(jobIdentity [sha256.Size]byte, body ControllerSupervisorLaunchShimBody) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if controllerSupervisorZero32(jobIdentity) {
		return zero, ErrControllerSupervisorDigestZero
	}
	if _, err := EncodeControllerSupervisorLaunchShimBody(body); err != nil {
		return zero, err
	}
	revision := make([]byte, 8)
	binary.BigEndian.PutUint64(revision, body.Revision)
	parts := [][]byte{jobIdentity[:], revision}
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LaunchID, body.LimitSetID} {
		encoded, err := controllerSupervisorDigestToken(value)
		if err != nil {
			return zero, err
		}
		parts = append(parts, encoded)
	}
	parts = append(parts, body.ExecutableSHA256[:], body.LaunchBlockSHA256[:])
	return controllerSupervisorDigest(controllerSupervisorLaunchShimDomain, parts...), nil
}
