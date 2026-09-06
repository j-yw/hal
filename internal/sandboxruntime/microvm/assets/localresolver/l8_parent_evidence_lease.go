package localresolver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

type l8RetainedFileMeasurement struct {
	size   int64
	digest string
}

// measureL8ParentEvidence binds L8 parent evidence to the files retained by
// the L7 lease. The lease mutex covers both currentness checks and every read;
// no evidence byte is obtained by reopening the mutable parent root path.
func (lease *VerifiedL7AssetLease) measureL8ParentEvidence(
	manifest assetbuild.DistributionManifest,
	provenance assetbuild.Provenance,
	descriptor assets.LaunchDescriptor,
) (result assetbuild.L8ParentL7Evidence, retErr error) {
	if lease == nil || manifest.ImageProfile != assetbuild.ImageProfileL7Network || provenance.ImageProfile != assetbuild.ImageProfileL7Network {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return assetbuild.L8ParentL7Evidence{}, ErrFileUnavailable
	}
	fingerprint, ok := l7DescriptorFingerprint(descriptor)
	if !ok || fingerprint != lease.sourceFingerprint {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	if err := confirmL8RetainedParentSourceIdentity(lease); err != nil {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}

	metadata := make(map[string]*os.File, 3)
	defer func() {
		for _, name := range []string{distributionManifestName, distributionProvenanceName, distributionChecksumsName} {
			if file := metadata[name]; file != nil {
				if err := file.Close(); err != nil {
					retErr = errors.Join(retErr, ErrFileUnavailable)
				}
			}
		}
	}()
	for _, name := range []string{distributionManifestName, distributionProvenanceName, distributionChecksumsName} {
		file, err := openDistributionFileNoFollow(lease.root, name)
		if err != nil {
			return assetbuild.L8ParentL7Evidence{}, ErrFileUnavailable
		}
		metadata[name] = file
	}

	files := map[string]*os.File{
		distributionManifestName:   metadata[distributionManifestName],
		distributionProvenanceName: metadata[distributionProvenanceName],
		distributionChecksumsName:  metadata[distributionChecksumsName],
		"vmlinux":                  lease.kernel,
		"rootfs.ext4":              lease.rootfs,
	}
	first, err := measureL8RetainedParentFiles(files)
	if err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	if err := validateL8RetainedParentAssetLocks(lease.sourceDescriptor, first); err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	var currentManifest assetbuild.DistributionManifest
	if err := decodeL8RetainedParentJSON(metadata[distributionManifestName], &currentManifest); err != nil ||
		assetbuild.ValidateDistributionManifest(currentManifest) != nil || !l8JSONEqual(currentManifest, manifest) {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	var currentProvenance assetbuild.Provenance
	if err := decodeL8RetainedParentJSON(metadata[distributionProvenanceName], &currentProvenance); err != nil ||
		assetbuild.ValidateProvenanceAgainstManifest(currentProvenance, currentManifest) != nil || !l8JSONEqual(currentProvenance, provenance) {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	if err := verifyL8RetainedParentChecksums(metadata[distributionChecksumsName], first); err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	second, err := measureL8RetainedParentFiles(files)
	if err != nil || !l8RetainedParentMeasurementsEqual(first, second) {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	if err := confirmL8RetainedParentMetadata(lease.root, metadata); err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	if err := confirmL8RetainedParentSourceIdentity(lease); err != nil {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}

	result = assetbuild.L8ParentL7Evidence{
		ImageProfile:     assetbuild.ImageProfileL7Network,
		ManifestSHA256:   first[distributionManifestName].digest,
		ProvenanceSHA256: first[distributionProvenanceName].digest,
		ChecksumsSHA256:  first[distributionChecksumsName].digest,
		KernelSizeBytes:  first["vmlinux"].size,
		KernelSHA256:     first["vmlinux"].digest,
		RootfsSizeBytes:  first["rootfs.ext4"].size,
		RootfsSHA256:     first["rootfs.ext4"].digest,
	}
	result.EvidenceSHA256 = calculateL8ParentEvidenceSHA256(result)
	return result, nil
}

func confirmL8RetainedParentSourceIdentity(lease *VerifiedL7AssetLease) error {
	if lease == nil || lease.root == nil || lease.kernel == nil || lease.rootfs == nil {
		return ErrFileUnavailable
	}
	currentRoot, _, err := openRequestedDistributionRoot(lease.rootDir)
	if err != nil {
		return ErrAssetLockMismatch
	}
	retainedRootInfo, retainedRootErr := lease.root.Stat()
	currentRootInfo, currentRootErr := currentRoot.Stat()
	rootCloseErr := currentRoot.Close()
	if retainedRootErr != nil || currentRootErr != nil || rootCloseErr != nil || !os.SameFile(retainedRootInfo, currentRootInfo) {
		return ErrAssetLockMismatch
	}
	for _, entry := range []struct {
		name     string
		retained *os.File
	}{
		{name: "vmlinux", retained: lease.kernel},
		{name: "rootfs.ext4", retained: lease.rootfs},
	} {
		current, err := openDistributionFileNoFollow(lease.root, entry.name)
		if err != nil {
			return ErrAssetLockMismatch
		}
		retainedInfo, retainedErr := entry.retained.Stat()
		currentInfo, currentErr := current.Stat()
		closeErr := current.Close()
		if retainedErr != nil || currentErr != nil || closeErr != nil || !os.SameFile(retainedInfo, currentInfo) {
			return ErrAssetLockMismatch
		}
	}
	return nil
}

func validateL8RetainedParentAssetLocks(
	descriptor assets.LaunchDescriptor,
	measured map[string]l8RetainedFileMeasurement,
) error {
	for _, role := range []assets.AssetRole{assets.AssetRoleKernel, assets.AssetRoleRootfs} {
		asset, name, ok := l7LeaseAsset(descriptor, role)
		measurement := measured[name]
		if !ok || asset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 ||
			asset.Lock.SizeBytes != measurement.size || asset.Lock.Digest.Value != measurement.digest {
			return ErrAssetLockMismatch
		}
	}
	return nil
}

func measureL8RetainedParentFiles(files map[string]*os.File) (map[string]l8RetainedFileMeasurement, error) {
	result := make(map[string]l8RetainedFileMeasurement, len(files))
	for _, name := range []string{distributionManifestName, distributionProvenanceName, distributionChecksumsName, "vmlinux", "rootfs.ext4"} {
		maximum := int64(maxDistributionMetadataBytes)
		if name == "vmlinux" || name == "rootfs.ext4" {
			maximum = l8MaxPinnedAssetBytes
		}
		measurement, err := measureL8RetainedParentFile(files[name], maximum)
		if err != nil {
			return nil, err
		}
		result[name] = measurement
	}
	return result, nil
}

func measureL8RetainedParentFile(file *os.File, maximum int64) (l8RetainedFileMeasurement, error) {
	if file == nil || maximum <= 0 {
		return l8RetainedFileMeasurement{}, ErrFileUnavailable
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return l8RetainedFileMeasurement{}, ErrFileUnavailable
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return l8RetainedFileMeasurement{}, ErrFileUnavailable
	}
	if before.Size() <= 0 || before.Size() > maximum {
		return l8RetainedFileMeasurement{}, ErrAssetLockMismatch
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, before.Size())
	if err != nil || written != before.Size() {
		return l8RetainedFileMeasurement{}, ErrFileUnavailable
	}
	var trailing [1]byte
	if count, readErr := file.Read(trailing[:]); count != 0 || readErr != io.EOF {
		return l8RetainedFileMeasurement{}, ErrAssetLockMismatch
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !os.SameFile(before, after) {
		return l8RetainedFileMeasurement{}, ErrAssetLockMismatch
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return l8RetainedFileMeasurement{}, ErrFileUnavailable
	}
	return l8RetainedFileMeasurement{size: written, digest: hex.EncodeToString(hash.Sum(nil))}, nil
}

func decodeL8RetainedParentJSON(file *os.File, destination any) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrFileUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(file, l8MaxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrAssetLockMismatch
	}
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return ErrFileUnavailable
	}
	return nil
}

func verifyL8RetainedParentChecksums(file *os.File, measured map[string]l8RetainedFileMeasurement) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrFileUnavailable
	}
	records := make(map[string]string, 4)
	scanner := bufio.NewScanner(io.LimitReader(file, l8MaxMetadataBytes+1))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return ErrAssetLockMismatch
		}
		name, digest := line[66:], line[:64]
		if !validDistributionDigest(digest) || !safeDistributionName(name) {
			return ErrAssetLockMismatch
		}
		if _, exists := records[name]; exists {
			return ErrAssetLockMismatch
		}
		records[name] = digest
	}
	if scanner.Err() != nil || len(records) != 4 {
		return ErrAssetLockMismatch
	}
	for _, name := range []string{distributionManifestName, distributionProvenanceName, "vmlinux", "rootfs.ext4"} {
		if records[name] != measured[name].digest {
			return ErrAssetLockMismatch
		}
	}
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return ErrFileUnavailable
	}
	return nil
}

func confirmL8RetainedParentMetadata(root *os.File, retained map[string]*os.File) error {
	for _, name := range []string{distributionManifestName, distributionProvenanceName, distributionChecksumsName} {
		current, err := openDistributionFileNoFollow(root, name)
		if err != nil {
			return ErrAssetLockMismatch
		}
		retainedInfo, retainedErr := retained[name].Stat()
		currentInfo, currentErr := current.Stat()
		closeErr := current.Close()
		if retainedErr != nil || currentErr != nil || closeErr != nil || !os.SameFile(retainedInfo, currentInfo) {
			return ErrAssetLockMismatch
		}
	}
	return nil
}

func l8RetainedParentMeasurementsEqual(left, right map[string]l8RetainedFileMeasurement) bool {
	if len(left) != len(right) {
		return false
	}
	for name, measurement := range left {
		if right[name] != measurement {
			return false
		}
	}
	return true
}

func calculateL8ParentEvidenceSHA256(result assetbuild.L8ParentL7Evidence) string {
	var preimage bytes.Buffer
	l8WriteToken(&preimage, "hal/l8/image-profile/parent-l7-evidence/v1")
	l8WriteToken(&preimage, result.ImageProfile)
	for _, digest := range []string{result.ManifestSHA256, result.ProvenanceSHA256, result.ChecksumsSHA256} {
		decoded, err := decodeL8Digest(digest)
		if err != nil {
			return ""
		}
		preimage.Write(decoded[:])
	}
	l8WriteUint64(&preimage, uint64(result.KernelSizeBytes))
	kernel, err := decodeL8Digest(result.KernelSHA256)
	if err != nil {
		return ""
	}
	preimage.Write(kernel[:])
	l8WriteUint64(&preimage, uint64(result.RootfsSizeBytes))
	rootfs, err := decodeL8Digest(result.RootfsSHA256)
	if err != nil {
		return ""
	}
	preimage.Write(rootfs[:])
	digest := sha256.Sum256(preimage.Bytes())
	return hex.EncodeToString(digest[:])
}
