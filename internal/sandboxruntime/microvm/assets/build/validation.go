package build

import (
	"errors"
	"strings"
)

var (
	errInvalidDistribution = errors.New("microVM distribution metadata is invalid")
	errInvalidProvenance   = errors.New("microVM image provenance is invalid")
	errLockMismatch        = errors.New("microVM dependency lock mismatch")
)

var requiredFeatures = []string{"copy_in", "copy_out", "exec", "readiness"}
var requiredL7NetworkFeatures = []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"}

var requiredVersions = Versions{
	Buildroot:   "2026.05.1",
	Linux:       "6.1.178",
	BusyBox:     "1.38.0",
	E2fsprogs:   "1.47.4",
	Go:          "1.25.7",
	Firecracker: "v1.15.1",
}

// ValidateDistributionManifest validates the stable L5 distribution shape.
func ValidateDistributionManifest(manifest DistributionManifest) error {
	if manifest.SchemaVersion != SchemaVersionV1 ||
		manifest.Architecture != "x86_64" ||
		!validVersions(manifest.Versions) ||
		manifest.GuestAgent.Protocol != "guest-agent-v1" ||
		!equalStrings(manifest.GuestAgent.Features, requiredFeatures) ||
		!validImageNetworkProfile(manifest.ImageProfile, manifest.GuestNetwork) {
		return errInvalidDistribution
	}
	if len(manifest.Assets) != 2 {
		return errInvalidDistribution
	}

	required := map[string]struct {
		id   string
		kind string
	}{
		"rootfs.ext4": {id: "rootfs", kind: "rootfs_image"},
		"vmlinux":     {id: "kernel", kind: "kernel_image"},
	}
	seenIDs := make(map[string]bool, len(manifest.Assets))
	seenKeys := make(map[string]bool, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		want, ok := required[asset.Key]
		if !ok ||
			seenKeys[asset.Key] ||
			seenIDs[asset.ID] ||
			asset.ID != want.id ||
			asset.Kind != want.kind ||
			asset.SizeBytes <= 0 ||
			!validSHA256(asset.SHA256) ||
			!safeRelativeKey(asset.Key) {
			return errInvalidDistribution
		}
		seenKeys[asset.Key] = true
		seenIDs[asset.ID] = true
	}
	return nil
}

// ValidateProvenance validates the path-free deterministic provenance shape.
func ValidateProvenance(provenance Provenance) error {
	if provenance.SchemaVersion != SchemaVersionV1 ||
		!validHex(provenance.SourceRevision, 40) ||
		!safeSourceTree(provenance.SourceTree) ||
		provenance.SourceDateEpoch <= 0 ||
		!strings.HasPrefix(provenance.BuildImageDigest, "sha256:") ||
		!validSHA256(strings.TrimPrefix(provenance.BuildImageDigest, "sha256:")) ||
		provenance.Architecture != "x86_64" ||
		!validVersions(provenance.Versions) ||
		provenance.GuestAgent.Protocol != "guest-agent-v1" ||
		!equalStrings(provenance.GuestAgent.Features, requiredFeatures) ||
		!validImageNetworkProfile(provenance.ImageProfile, provenance.GuestNetwork) ||
		len(provenance.Outputs) != 2 {
		return errInvalidProvenance
	}

	seenKeys := make(map[string]bool, len(provenance.Outputs))
	seenIDs := make(map[string]bool, len(provenance.Outputs))
	for _, output := range provenance.Outputs {
		if !safeRelativeKey(output.Key) ||
			output.ID == "" ||
			output.Kind == "" ||
			output.SizeBytes <= 0 ||
			!validSHA256(output.SHA256) ||
			seenKeys[output.Key] ||
			seenIDs[output.ID] {
			return errInvalidProvenance
		}
		seenKeys[output.Key] = true
		seenIDs[output.ID] = true
	}
	return nil
}

// ValidateProvenanceAgainstManifest requires every duplicated fact to match.
func ValidateProvenanceAgainstManifest(provenance Provenance, manifest DistributionManifest) error {
	if err := ValidateProvenance(provenance); err != nil {
		return err
	}
	if err := ValidateDistributionManifest(manifest); err != nil {
		return err
	}
	if provenance.Architecture != manifest.Architecture ||
		provenance.ImageProfile != manifest.ImageProfile ||
		provenance.Versions != manifest.Versions ||
		provenance.GuestAgent.Protocol != manifest.GuestAgent.Protocol ||
		!equalStrings(provenance.GuestAgent.Features, manifest.GuestAgent.Features) ||
		!equalGuestNetwork(provenance.GuestNetwork, manifest.GuestNetwork) {
		return errInvalidProvenance
	}

	assets := make(map[string]DistributionAsset, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		assets[asset.Key] = asset
	}
	for _, output := range provenance.Outputs {
		asset, ok := assets[output.Key]
		if !ok ||
			output.ID != asset.ID ||
			output.Kind != asset.Kind ||
			output.SizeBytes != asset.SizeBytes ||
			output.SHA256 != asset.SHA256 {
			return errInvalidProvenance
		}
	}
	return nil
}

func validImageNetworkProfile(profile string, network *GuestNetwork) bool {
	switch profile {
	case "":
		return network == nil
	case ImageProfileL7Network:
		return network != nil &&
			network.Mode == GuestNetworkModeStaticProxy &&
			equalStrings(network.Features, requiredL7NetworkFeatures)
	default:
		return false
	}
}

func equalGuestNetwork(left, right *GuestNetwork) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Mode == right.Mode && equalStrings(left.Features, right.Features)
}

// VerifyDependencyLocks compares an exact observed cache inventory to its lock.
func VerifyDependencyLocks(locks []DependencyLock, files []DependencyFile) error {
	if len(locks) == 0 || len(locks) != len(files) {
		return errLockMismatch
	}
	expected := make(map[string]DependencyLock, len(locks))
	for _, lock := range locks {
		if lock.Name == "" ||
			lock.Version == "" ||
			!safeRelativeKey(lock.Filename) ||
			!strings.HasPrefix(lock.URL, "https://") ||
			lock.SizeBytes <= 0 ||
			!validSHA256(lock.SHA256) {
			return errLockMismatch
		}
		if _, exists := expected[lock.Filename]; exists {
			return errLockMismatch
		}
		expected[lock.Filename] = lock
	}

	seen := make(map[string]bool, len(files))
	for _, file := range files {
		lock, ok := expected[file.Filename]
		if !ok ||
			seen[file.Filename] ||
			file.SizeBytes != lock.SizeBytes ||
			file.SHA256 != lock.SHA256 {
			return errLockMismatch
		}
		seen[file.Filename] = true
	}
	return nil
}

func validVersions(versions Versions) bool {
	return versions == requiredVersions
}

func safeRelativeKey(value string) bool {
	return value != "" &&
		value != "." &&
		!strings.Contains(value, "/") &&
		!strings.Contains(value, "\\") &&
		!strings.Contains(value, "..") &&
		strings.TrimSpace(value) == value
}

func safeSourceTree(value string) bool {
	if !strings.HasPrefix(value, "tree-") {
		return false
	}
	suffix := strings.TrimPrefix(value, "tree-")
	return len(suffix) >= 16 && len(suffix) <= 64 && validLowerHex(suffix)
}

func validSHA256(value string) bool {
	return validHex(value, 64)
}

func validHex(value string, length int) bool {
	return len(value) == length && validLowerHex(value)
}

func validLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
