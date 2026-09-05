package localresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

type l8PinnedAsset struct {
	file   *os.File
	size   int64
	digest [sha256.Size]byte
}

const l8MaxPinnedAssetBytes int64 = 1 << 30

func (distribution VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error) {
	if !distribution.l8Profile.seal.active || distribution.l8EvidenceFingerprint == ([32]byte{}) || distribution.rootDir == "" || !VerifiedL8ProfileMatches(&distribution.l8Profile, &distribution.Descriptor) {
		return nil, l8LeaseError(ErrorCodeInvalidRequest, "l8Assets", "verified L8 assets are required", ErrInvalidRequest)
	}
	root, cleanRoot, err := openRequestedDistributionRoot(distribution.rootDir)
	if err != nil {
		return nil, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 assets are unavailable", ErrFileUnavailable)
	}
	files := make(map[string]l8PinnedAsset, len(l8RequiredDistributionOutputs))
	closeResources := func() error {
		causes := make([]error, 0, len(files)+1)
		for _, name := range l8RequiredDistributionOutputs {
			if pinned := files[name]; pinned.file != nil {
				if closeErr := pinned.file.Close(); closeErr != nil {
					causes = append(causes, closeErr)
				}
			}
		}
		if closeErr := root.Close(); closeErr != nil {
			causes = append(causes, closeErr)
		}
		return l8CleanupError(causes...)
	}
	if err := validateCurrentL8Distribution(distribution, root); err != nil {
		return nil, errors.Join(err, closeResources())
	}
	for _, name := range l8RequiredDistributionOutputs {
		file, openErr := openDistributionFileNoFollow(root, name)
		if openErr != nil {
			return nil, errors.Join(l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset is unavailable", ErrFileUnavailable), closeResources())
		}
		size, digest, measureErr := measurePinnedL8File(file)
		if measureErr != nil {
			return nil, errors.Join(measureErr, l8CleanupError(file.Close()), closeResources())
		}
		files[name] = l8PinnedAsset{file: file, size: size, digest: digest}
	}
	return &VerifiedL8AssetLease{
		state: &verifiedL8AssetLeaseState{
			rootDir:          cleanRoot,
			root:             root,
			files:            files,
			sourceDescriptor: cloneL7LaunchDescriptor(distribution.Descriptor),
		},
		correlation: verifiedL8LeaseCorrelation{
			sourceDescriptorFingerprint: distribution.l8Profile.correlation.descriptorFingerprint,
			evidenceFingerprint:         distribution.l8EvidenceFingerprint,
			policyAuthority:             distribution.l8Profile.correlation.policyAuthority,
		},
	}, nil
}

func (lease *VerifiedL8AssetLease) ConfirmCurrent(descriptor *assets.LaunchDescriptor) error {
	if lease == nil || lease.state == nil || descriptor == nil {
		return l8LeaseError(ErrorCodeInvalidRequest, "l8Assets", "verified L8 asset lease is required", ErrInvalidRequest)
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	return lease.confirmCurrentLocked(descriptor)
}

func (lease *VerifiedL8AssetLease) PrepareLaunch(descriptor *assets.LaunchDescriptor, material L8LaunchMaterialWriter) (assets.LaunchDescriptor, VerifiedL8Profile, error) {
	if lease == nil || lease.state == nil || descriptor == nil || l8NilInterface(material) {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeInvalidRequest, "l8Assets", "verified L8 launch material is required", ErrInvalidRequest)
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	if lease.state.closed {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset lease is closed", ErrFileUnavailable)
	}
	if lease.state.material != nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeInvalidRequest, "l8Assets", "verified L8 launch material is already prepared", ErrInvalidRequest)
	}
	if err := lease.confirmCurrentLocked(descriptor); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, err
	}
	prepared := cloneL7LaunchDescriptor(lease.state.sourceDescriptor)
	for index := range prepared.Assets {
		asset := &prepared.Assets[index]
		name, ok := l8AssetName(asset.Role)
		if !ok {
			return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
		}
		pinned := lease.state.files[name]
		path, copyErr := copyPinnedL8Asset(material, pinned, *asset)
		if copyErr != nil {
			return assets.LaunchDescriptor{}, VerifiedL8Profile{}, copyErr
		}
		if filepath.Clean(path) == filepath.Clean(asset.Source.HostPath.Path) {
			return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeUnsafePath, "launchMaterial", "private L8 launch material path is required", ErrUnsafePath)
		}
		asset.Source.HostPath.Path = path
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(prepared)
	if !result.Valid || result.Normalized == nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeInvalidRequest, "launchMaterial", "private L8 launch material is invalid", ErrInvalidRequest)
	}
	if err := validateL8LaunchMaterial(material); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeAssetLockMismatch, "launchMaterial", "private L8 launch material validation failed", ErrAssetLockMismatch)
	}
	if err := lease.confirmSourceLocked(); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, err
	}
	preparedFingerprint, err := buildL8DescriptorFingerprint(*result.Normalized)
	if err != nil {
		return assets.LaunchDescriptor{}, VerifiedL8Profile{}, l8LeaseError(ErrorCodeInvalidRequest, "launchMaterial", "private L8 launch material is invalid", ErrInvalidRequest)
	}
	lease.state.material = material
	lease.state.materialDescriptor = cloneL7LaunchDescriptor(*result.Normalized)
	lease.correlation.preparedDescriptorFingerprint = preparedFingerprint
	lease.correlation.hasPreparedDescriptor = true
	return cloneL7LaunchDescriptor(lease.state.materialDescriptor), VerifiedL8Profile{
		seal: verifiedL8ProfileSeal{active: true},
		correlation: verifiedL8ProfileCorrelation{
			descriptorFingerprint: preparedFingerprint,
			evidenceFingerprint:   lease.correlation.evidenceFingerprint,
			policyAuthority:       lease.correlation.policyAuthority,
		},
	}, nil
}

func (lease *VerifiedL8AssetLease) Close() error {
	if lease == nil || lease.state == nil {
		return nil
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	if lease.state.closed {
		return lease.state.cleanupErr
	}
	lease.state.closed = true
	causes := make([]error, 0, len(lease.state.files)+2)
	if lease.state.material != nil {
		if err := closeL8LaunchMaterial(lease.state.material); err != nil {
			causes = append(causes, err)
		}
	}
	for _, name := range l8RequiredDistributionOutputs {
		if pinned := lease.state.files[name]; pinned.file != nil {
			if err := pinned.file.Close(); err != nil {
				causes = append(causes, err)
			}
		}
	}
	if lease.state.root != nil {
		if err := lease.state.root.Close(); err != nil {
			causes = append(causes, err)
		}
	}
	lease.state.material = nil
	lease.state.files = nil
	lease.state.root = nil
	lease.state.cleanupErr = l8CleanupError(causes...)
	return lease.state.cleanupErr
}

func (lease *VerifiedL8AssetLease) confirmCurrentLocked(descriptor *assets.LaunchDescriptor) error {
	if lease.state.closed {
		return l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset lease is closed", ErrFileUnavailable)
	}
	fingerprint, err := buildL8DescriptorFingerprint(*descriptor)
	if err != nil {
		return l8LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
	}
	if fingerprint == lease.correlation.sourceDescriptorFingerprint {
		return lease.confirmSourceLocked()
	}
	if lease.correlation.hasPreparedDescriptor && fingerprint == lease.correlation.preparedDescriptorFingerprint && lease.state.material != nil {
		if err := validateL8LaunchMaterial(lease.state.material); err != nil {
			return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 launch material changed", ErrAssetLockMismatch)
		}
		return nil
	}
	return l8LeaseError(ErrorCodeAssetLockMismatch, "launchDescriptor", "verified L8 launch descriptor changed", ErrAssetLockMismatch)
}

func (lease *VerifiedL8AssetLease) confirmSourceLocked() (retErr error) {
	currentRoot, _, err := openRequestedDistributionRoot(lease.state.rootDir)
	if err != nil {
		return l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 distribution root is unavailable", ErrFileUnavailable)
	}
	defer func() {
		retErr = errors.Join(retErr, l8CleanupError(currentRoot.Close()))
	}()
	retainedInfo, retainedErr := lease.state.root.Stat()
	currentInfo, currentErr := currentRoot.Stat()
	if retainedErr != nil || currentErr != nil || !os.SameFile(retainedInfo, currentInfo) || verifyL8DistributionEntrySet(currentRoot) != nil {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	for _, name := range l8RequiredDistributionOutputs {
		pinned := lease.state.files[name]
		if pinned.file == nil {
			return l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset is unavailable", ErrFileUnavailable)
		}
		current, openErr := openDistributionFileNoFollow(currentRoot, name)
		if openErr != nil {
			return l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset is unavailable", ErrFileUnavailable)
		}
		retainedFileInfo, retainedFileErr := pinned.file.Stat()
		currentFileInfo, currentFileErr := current.Stat()
		size, digest, measureErr := measurePinnedL8File(current)
		closeErr := current.Close()
		if retainedFileErr != nil || currentFileErr != nil || !os.SameFile(retainedFileInfo, currentFileInfo) || measureErr != nil || closeErr != nil || size != pinned.size || digest != pinned.digest {
			return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 asset changed", ErrAssetLockMismatch)
		}
	}
	return nil
}

func validateCurrentL8Distribution(distribution VerifiedDistribution, root *os.File) error {
	if verifyL8DistributionEntrySet(root) != nil || verifyL8DistributionChecksums(root) != nil {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	manifest, err := decodeL8DistributionManifest(DistributionRequest{RootDir: distribution.rootDir})
	if err != nil || !l8JSONEqual(manifest, distribution.Manifest) {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	provenance, err := decodeL8Provenance(DistributionRequest{RootDir: distribution.rootDir})
	if err != nil || !l8JSONEqual(provenance, distribution.Provenance) {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	sourceLock, err := decodeL8SourceLock(DistributionRequest{RootDir: distribution.rootDir})
	if err != nil {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	inspection, err := decodeL8FinalInspection(DistributionRequest{RootDir: distribution.rootDir})
	if err != nil {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	parentEvidence, err := decodeL8Digest(manifest.L8Profile.ParentL7.EvidenceSHA256)
	if err != nil {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	fingerprint, imageDigest, err := calculateL8EvidenceFingerprint(DistributionRequest{RootDir: distribution.rootDir}, manifest, provenance, sourceLock, inspection, parentEvidence, distribution.l8PolicyComposition)
	if err != nil || fingerprint != distribution.l8EvidenceFingerprint || imageDigest != distribution.l8Profile.correlation.policyAuthority.imageSHA256 {
		return l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 distribution changed", ErrAssetLockMismatch)
	}
	return nil
}

func measurePinnedL8File(file *os.File) (int64, [32]byte, error) {
	if file == nil {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset is unavailable", ErrFileUnavailable)
	}
	info, err := file.Stat()
	if err != nil {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset cannot be inspected", ErrFileUnavailable)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > l8MaxPinnedAssetBytes {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 asset exceeds the bounded size", ErrAssetLockMismatch)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset cannot be read", ErrFileUnavailable)
	}
	hash := sha256.New()
	size, err := io.CopyN(hash, file, info.Size())
	if err != nil || size != info.Size() {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset cannot be read", ErrFileUnavailable)
	}
	var trailing [1]byte
	if n, readErr := file.Read(trailing[:]); n != 0 || readErr != io.EOF {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeAssetLockMismatch, "l8Assets", "verified L8 asset exceeds the bounded size", ErrAssetLockMismatch)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, [32]byte{}, l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset cannot be read", ErrFileUnavailable)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return size, digest, nil
}

func copyPinnedL8Asset(material L8LaunchMaterialWriter, pinned l8PinnedAsset, asset assets.LaunchAsset) (string, error) {
	if pinned.file == nil || asset.Source.HostPath == nil || asset.Lock.SizeBytes != pinned.size || hex.EncodeToString(pinned.digest[:]) != asset.Lock.Digest.Value {
		return "", l8LeaseError(ErrorCodeAssetLockMismatch, "launchMaterial", "private L8 launch material does not match the verified asset", ErrAssetLockMismatch)
	}
	if _, err := pinned.file.Seek(0, io.SeekStart); err != nil {
		return "", l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset cannot be read", ErrFileUnavailable)
	}
	reader, ok := newLockedL7DigestingReader(pinned.file, pinned.size)
	if !ok {
		return "", l8LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
	}
	path, err := writeL8LaunchMaterialAsset(material, asset.Role, reader)
	if err != nil {
		return "", l8LeaseError(ErrorCodeFileUnavailable, "launchMaterial", "private L8 launch material cannot be written", ErrFileUnavailable)
	}
	var trailing [1]byte
	n, readErr := reader.Read(trailing[:])
	if n != 0 || readErr != io.EOF || reader.size != pinned.size || hex.EncodeToString(reader.hash.Sum(nil)) != asset.Lock.Digest.Value {
		return "", l8LeaseError(ErrorCodeAssetLockMismatch, "launchMaterial", "private L8 launch material does not match the verified asset", ErrAssetLockMismatch)
	}
	return validateLocalHostPath(path, "launchMaterial", asset.Role)
}

func l8AssetName(role assets.AssetRole) (string, bool) {
	switch role {
	case assets.AssetRoleKernel:
		return "vmlinux", true
	case assets.AssetRoleRootfs:
		return "rootfs.ext4", true
	default:
		return "", false
	}
}

func writeL8LaunchMaterialAsset(material L8LaunchMaterialWriter, role assets.AssetRole, source io.Reader) (path string, retErr error) {
	defer func() {
		if recover() != nil {
			path = ""
			retErr = ErrFileUnavailable
		}
	}()
	return material.WriteAsset(role, source)
}

func validateL8LaunchMaterial(material L8LaunchMaterialWriter) (retErr error) {
	defer func() {
		if recover() != nil {
			retErr = ErrAssetLockMismatch
		}
	}()
	return material.Validate()
}

func closeL8LaunchMaterial(material L8LaunchMaterialWriter) (retErr error) {
	defer func() {
		if recover() != nil {
			retErr = ErrFileUnavailable
		}
	}()
	return material.Close()
}

func l8CleanupError(causes ...error) error {
	joined := errors.Join(causes...)
	if joined == nil {
		return nil
	}
	return l8LeaseError(ErrorCodeFileUnavailable, "l8Assets", "verified L8 asset lease cleanup failed", sanitizedL8AssetCleanupCause{causes: joined})
}

type sanitizedL8AssetCleanupCause struct {
	causes error
}

func (sanitizedL8AssetCleanupCause) Error() string {
	return ErrFileUnavailable.Error()
}

func (cause sanitizedL8AssetCleanupCause) Is(target error) bool {
	return target == ErrFileUnavailable || errors.Is(cause.causes, target)
}

func (cause sanitizedL8AssetCleanupCause) As(target any) bool {
	return errors.As(cause.causes, target)
}

func l8LeaseError(code ErrorCode, field, message string, cause error) error {
	return newResolverError(code, field, "", message, cause)
}
