package localresolver

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

const (
	distributionManifestName     = "distribution-manifest.json"
	distributionProvenanceName   = "provenance.json"
	distributionChecksumsName    = "SHA256SUMS"
	maxDistributionMetadataBytes = 1 << 20
)

var l5RequiredDistributionOutputs = []string{
	distributionChecksumsName,
	distributionManifestName,
	distributionProvenanceName,
	"rootfs.ext4",
	"vmlinux",
}

// DistributionRequest identifies one installed L5 distribution.
type DistributionRequest struct {
	RootDir            string
	LockedAtUnixMillis int64
}

// VerifiedDistribution is a fully correlated installed L5 distribution.
type VerifiedDistribution struct {
	Manifest   assetbuild.DistributionManifest
	Provenance assetbuild.Provenance
	Descriptor assets.LaunchDescriptor
}

// ResolveDistribution verifies the manifest and installed launch assets, then
// materializes the existing absolute-path runtime descriptor.
func ResolveDistribution(request DistributionRequest) (assets.LaunchDescriptor, error) {
	root, cleanRoot, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return assets.LaunchDescriptor{}, err
	}
	defer root.Close()

	manifest, err := readDistributionManifest(root)
	if err != nil {
		return assets.LaunchDescriptor{}, err
	}
	return resolveDistributionFromRoot(root, cleanRoot, request.LockedAtUnixMillis, manifest)
}

// VerifyDistributionBundle validates the exact five-file distribution,
// provenance correlation, checksums, and materialized launch assets.
func VerifyDistributionBundle(request DistributionRequest) (VerifiedDistribution, error) {
	root, cleanRoot, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return VerifiedDistribution{}, err
	}
	defer root.Close()

	if err := verifyDistributionEntrySet(root); err != nil {
		return VerifiedDistribution{}, err
	}
	manifest, err := readDistributionManifest(root)
	if err != nil {
		return VerifiedDistribution{}, err
	}
	provenance, err := readDistributionProvenance(root)
	if err != nil {
		return VerifiedDistribution{}, err
	}
	if err := assetbuild.ValidateProvenanceAgainstManifest(provenance, manifest); err != nil {
		return VerifiedDistribution{}, newResolverError(
			ErrorCodeManifestInvalid,
			"provenance",
			"",
			"distribution provenance does not match the manifest",
			ErrManifestInvalid,
		)
	}
	if err := verifyDistributionChecksums(root); err != nil {
		return VerifiedDistribution{}, err
	}
	descriptor, err := resolveDistributionFromRoot(root, cleanRoot, request.LockedAtUnixMillis, manifest)
	if err != nil {
		return VerifiedDistribution{}, err
	}
	return VerifiedDistribution{
		Manifest:   manifest,
		Provenance: provenance,
		Descriptor: descriptor,
	}, nil
}

func openRequestedDistributionRoot(raw string) (*os.File, string, error) {
	clean, err := validateLocalHostPath(raw, "rootDir", "")
	if err != nil {
		return nil, "", err
	}
	root, err := openDistributionRootNoFollow(clean)
	if err != nil {
		return nil, "", newResolverError(
			ErrorCodeUnsupportedFileType,
			"rootDir",
			"",
			"distribution root must be a real directory",
			ErrUnsupportedFileType,
		)
	}
	return root, clean, nil
}

func readDistributionManifest(root *os.File) (assetbuild.DistributionManifest, error) {
	var manifest assetbuild.DistributionManifest
	if err := decodeDistributionJSON(root, distributionManifestName, &manifest); err != nil {
		return assetbuild.DistributionManifest{}, err
	}
	if err := assetbuild.ValidateDistributionManifest(manifest); err != nil {
		return assetbuild.DistributionManifest{}, newResolverError(
			ErrorCodeManifestInvalid,
			"distributionManifest",
			"",
			"distribution manifest is invalid",
			ErrManifestInvalid,
		)
	}
	return manifest, nil
}

func readDistributionProvenance(root *os.File) (assetbuild.Provenance, error) {
	var provenance assetbuild.Provenance
	if err := decodeDistributionJSON(root, distributionProvenanceName, &provenance); err != nil {
		return assetbuild.Provenance{}, err
	}
	if err := assetbuild.ValidateProvenance(provenance); err != nil {
		return assetbuild.Provenance{}, newResolverError(
			ErrorCodeManifestInvalid,
			"provenance",
			"",
			"distribution provenance is invalid",
			ErrManifestInvalid,
		)
	}
	return provenance, nil
}

func decodeDistributionJSON(root *os.File, name string, destination any) error {
	file, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return newResolverError(
			ErrorCodeFileUnavailable,
			distributionField(name),
			"",
			"distribution metadata file is unavailable",
			ErrFileUnavailable,
		)
	}
	defer file.Close()

	reader := io.LimitReader(file, maxDistributionMetadataBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newResolverError(
			ErrorCodeManifestInvalid,
			distributionField(name),
			"",
			"distribution metadata file is invalid",
			ErrManifestInvalid,
		)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return newResolverError(
			ErrorCodeManifestInvalid,
			distributionField(name),
			"",
			"distribution metadata file has trailing data",
			ErrManifestInvalid,
		)
	}
	return nil
}

func verifyDistributionEntrySet(root *os.File) error {
	clone, err := duplicateDistributionRoot(root)
	if err != nil {
		return newResolverError(ErrorCodeFileUnavailable, "rootDir", "", "distribution root is unavailable", ErrFileUnavailable)
	}
	defer clone.Close()

	entries, err := clone.ReadDir(-1)
	if err != nil {
		return newResolverError(ErrorCodeFileUnavailable, "rootDir", "", "distribution root cannot be read", ErrFileUnavailable)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return newResolverError(
				ErrorCodeUnsupportedFileType,
				"distributionFiles",
				"",
				"distribution files must be regular files",
				ErrUnsupportedFileType,
			)
		}
		got = append(got, entry.Name())
	}
	sort.Strings(got)
	if !equalDistributionNames(got, l5RequiredDistributionOutputs) {
		return newResolverError(
			ErrorCodeManifestInvalid,
			"distributionFiles",
			"",
			"distribution file set is invalid",
			ErrManifestInvalid,
		)
	}
	return nil
}

func verifyDistributionChecksums(root *os.File) error {
	file, err := openDistributionFileNoFollow(root, distributionChecksumsName)
	if err != nil {
		return newResolverError(ErrorCodeFileUnavailable, "checksums", "", "distribution checksums are unavailable", ErrFileUnavailable)
	}
	defer file.Close()

	expectedNames := []string{
		distributionManifestName,
		distributionProvenanceName,
		"rootfs.ext4",
		"vmlinux",
	}
	records := make(map[string]string, len(expectedNames))
	scanner := bufio.NewScanner(io.LimitReader(file, maxDistributionMetadataBytes+1))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return checksumMismatch()
		}
		digest := line[:64]
		name := line[66:]
		if !validDistributionDigest(digest) || !safeDistributionName(name) {
			return checksumMismatch()
		}
		if _, exists := records[name]; exists {
			return checksumMismatch()
		}
		records[name] = digest
	}
	if err := scanner.Err(); err != nil {
		return checksumMismatch()
	}
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	sort.Strings(names)
	if !equalDistributionNames(names, expectedNames) {
		return checksumMismatch()
	}

	for _, name := range expectedNames {
		_, digest, err := digestDistributionFile(root, name)
		if err != nil || digest != records[name] {
			return checksumMismatch()
		}
	}
	return nil
}

func resolveDistributionFromRoot(
	root *os.File,
	cleanRoot string,
	lockedAtUnixMillis int64,
	manifest assetbuild.DistributionManifest,
) (assets.LaunchDescriptor, error) {
	if lockedAtUnixMillis < 0 {
		return assets.LaunchDescriptor{}, newResolverError(
			ErrorCodeInvalidRequest,
			"lockedAtUnixMillis",
			"",
			"lock timestamp must be non-negative",
			ErrInvalidRequest,
		)
	}
	descriptor := assets.LaunchDescriptor{
		ID:     "l5-image",
		Labels: []assets.SafeLabel{"firecracker", "reproducible"},
		Assets: make([]assets.LaunchAsset, 0, len(manifest.Assets)),
	}
	for _, asset := range manifest.Assets {
		size, digest, err := digestDistributionFile(root, asset.Key)
		if err != nil {
			return assets.LaunchDescriptor{}, err
		}
		if size != asset.SizeBytes || digest != asset.SHA256 {
			return assets.LaunchDescriptor{}, newResolverError(
				ErrorCodeAssetLockMismatch,
				"assets",
				"",
				"installed distribution asset does not match its lock",
				ErrAssetLockMismatch,
			)
		}
		role, kind, ok := distributionLaunchRole(asset)
		if !ok {
			return assets.LaunchDescriptor{}, newResolverError(
				ErrorCodeManifestInvalid,
				"assets",
				"",
				"distribution asset role is invalid",
				ErrManifestInvalid,
			)
		}
		descriptor.Assets = append(descriptor.Assets, assets.LaunchAsset{
			ID:   assets.SafeID(asset.ID),
			Role: role,
			Kind: kind,
			Source: assets.AssetSource{
				Type: assets.SourceTypeLocalFile,
				HostPath: &assets.HostPathMetadata{
					Path: filepath.Join(cleanRoot, asset.Key),
					Role: assets.HostPathRoleResolvedLocalAsset,
				},
			},
			Lock: assets.LockMetadata{
				Digest: assets.DigestMetadata{
					Algorithm: assets.DigestAlgorithmSHA256,
					Value:     asset.SHA256,
				},
				SizeBytes:          asset.SizeBytes,
				LockedAtUnixMillis: lockedAtUnixMillis,
			},
		})
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(descriptor)
	if !result.Valid || result.Normalized == nil {
		return assets.LaunchDescriptor{}, newResolverError(
			ErrorCodeManifestInvalid,
			"assets",
			"",
			"materialized launch descriptor is invalid",
			ErrManifestInvalid,
		)
	}
	return *result.Normalized, nil
}

func digestDistributionFile(root *os.File, name string) (int64, string, error) {
	file, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return 0, "", newResolverError(
			ErrorCodeFileUnavailable,
			distributionField(name),
			"",
			"distribution file is unavailable",
			ErrFileUnavailable,
		)
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return 0, "", newResolverError(
			ErrorCodeFileUnavailable,
			distributionField(name),
			"",
			"distribution file cannot be read",
			ErrFileUnavailable,
		)
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func distributionLaunchRole(entry assetbuild.DistributionAsset) (assets.AssetRole, assets.AssetKind, bool) {
	switch entry.Key {
	case "vmlinux":
		return assets.AssetRoleKernel, assets.AssetKindKernelImage, true
	case "rootfs.ext4":
		return assets.AssetRoleRootfs, assets.AssetKindRootfsImage, true
	default:
		return "", "", false
	}
}

func checksumMismatch() error {
	return newResolverError(
		ErrorCodeAssetLockMismatch,
		"checksums",
		"",
		"distribution checksums do not match",
		ErrAssetLockMismatch,
	)
}

func distributionField(name string) string {
	switch name {
	case distributionManifestName:
		return "distributionManifest"
	case distributionProvenanceName:
		return "provenance"
	case distributionChecksumsName:
		return "checksums"
	case "rootfs.ext4":
		return "assets.rootfs"
	case "vmlinux":
		return "assets.kernel"
	default:
		return "distributionFiles"
	}
}

func safeDistributionName(name string) bool {
	return name != "" &&
		!strings.Contains(name, "/") &&
		!strings.Contains(name, "\\") &&
		!strings.Contains(name, "..") &&
		filepath.Base(name) == name
}

func validDistributionDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func equalDistributionNames(left, right []string) bool {
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
