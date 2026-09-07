//go:build linux

package firecrackerhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"golang.org/x/sys/unix"
)

// Select from the bounded immutable config, never from FD presence. The
// callback grants only byte admission; production still returns unavailable.
func withMinimalControlSupervisorAdmission(fds [6]int, openFD func(uintptr, string) (int, error), closeFD func(int) error, expectedSeedUID uint32, consume func(*minimalControlSupervisorAdmission) error) (selected bool, resultErr error) {
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fds[2], l8RuntimeOwnerSupervisorConfigLimit)
	if err != nil || identity.Size <= 0 {
		return true, errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, identity.Size)
	if n, err := unix.Pread(fds[2], payload, 0); err != nil || n != len(payload) {
		return true, errL8RuntimeOwnerInvalid
	}
	var marker struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(payload, &marker) != nil {
		return true, errL8RuntimeOwnerInvalid
	}
	switch marker.Version {
	case "":
		_, err := decodeL8RuntimeOwnerSupervisorConfig(payload)
		return err != nil, err
	case jailerRecoveryConfigVersion:
		_, err := decodeJailerRecoverySupervisorConfig(payload)
		return err != nil, err
	case minimalControlSupervisorConfigVersion:
	default:
		return true, errL8RuntimeOwnerInvalid
	}
	if openFD == nil || closeFD == nil || consume == nil {
		return true, errL8RuntimeOwnerInvalid
	}
	selected = true
	var imported []int
	defer func() {
		// The injected observer cannot bypass owned FD cleanup by panicking.
		// Convert only this selected boundary to its existing sanitized error.
		if recover() != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
		for i := len(imported) - 1; i >= 0; i-- {
			if closeFD(imported[i]) != nil {
				resultErr = errL8RuntimeOwnerInvalid
			}
		}
	}()
	for i, role := range []string{"firecracker-config", "minimal-controller-key"} {
		fd, err := openFD(uintptr(i+9), role)
		if err != nil {
			return true, errL8RuntimeOwnerInvalid
		}
		if fd < 0 || slices.Contains(fds[:], fd) || slices.Contains(imported, fd) {
			return true, errL8RuntimeOwnerInvalid
		}
		imported = append(imported, fd)
		if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			return true, errL8RuntimeOwnerInvalid
		}
	}
	// Both additional inherited numbers are now owned/CLOEXEC. No descriptor
	// duplication occurs in admission; later runtime construction is unavailable.
	config, public, err := decodeMinimalControlSupervisorConfig(payload)
	if err != nil || validateL8RuntimeOwnerSeqpacketFD(fds[0]) != nil || validateL8RuntimeOwnerDirectoryFD(fds[1]) != nil {
		return true, errL8RuntimeOwnerInvalid
	}
	all := append(slices.Clone(fds[:]), imported...)
	if !minimalControlAdmissionFDsDistinct(all) {
		return true, errL8RuntimeOwnerInvalid
	}
	for i, fd := range []int{fds[3], fds[4], imported[0]} {
		asset := []jailerRecoveryAsset{config.Kernel, config.Rootfs, config.Config}[i]
		actual, err := validateL8RuntimeOwnerSealedRegularFD(fd, asset.Size)
		if err != nil || actual.Size != asset.Size || validateL8RuntimeOwnerAssetFD(fd, l8RuntimeOwnerDescriptorIdentityV1{Kind: asset.Kind, Device: asset.Device, Inode: asset.Inode, Digest: asset.SHA256}) != nil {
			return true, errL8RuntimeOwnerInvalid
		}
	}
	// Transfer consumption before calling the seed helper: it always closes.
	seedFD := imported[1]
	imported = imported[:1]
	key, err := loadMinimalControllerKey(seedFD, expectedSeedUID, public, unix.Pread, closeFD)
	if err != nil {
		return true, errL8RuntimeOwnerInvalid
	}
	defer clear(key)
	digest := sha256.Sum256(payload)
	admission := &minimalControlSupervisorAdmission{config: config, configDigest: digest, controllerKey: key,
		borrowed: [7]int{fds[0], fds[1], fds[2], fds[3], fds[4], fds[5], imported[0]},
		recovery: minimalControlRecoveryProjection{configCorrelation: hex.EncodeToString(digest[:]), job: config.Job,
			uid: config.Policy.UID, gid: config.Policy.GID, firecrackerConfigSHA256: config.Config.SHA256}}
	if consume(admission) != nil {
		return true, errL8RuntimeOwnerInvalid
	}
	return true, nil
}

func minimalControlAdmissionFDsDistinct(fds []int) bool {
	identities := make(map[[2]uint64]bool, len(fds))
	for _, fd := range fds {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if identities[identity] {
			return false
		}
		identities[identity] = true
	}
	return true
}
