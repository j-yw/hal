package localresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

// L7LaunchMaterialWriter is the narrow handoff from resolver-owned verified
// file handles to runtime-owned private launch material. Ownership transfers
// to the lease only after PrepareLaunch succeeds.
type L7LaunchMaterialWriter interface {
	WriteAsset(assets.AssetRole, io.Reader) (string, error)
	Validate() error
	Close() error
}

// VerifiedL7AssetLease pins the verified distribution root and launch assets
// while a runtime prepares and consumes private launch material. It has no
// exported state and must never be serialized or persisted.
type VerifiedL7AssetLease struct {
	mu sync.Mutex

	rootDir             string
	root                *os.File
	sourceDescriptor    assets.LaunchDescriptor
	sourceFingerprint   [sha256.Size]byte
	kernel              *os.File
	rootfs              *os.File
	material            L7LaunchMaterialWriter
	materialDescriptor  assets.LaunchDescriptor
	materialFingerprint [sha256.Size]byte
	closed              bool
	cleanupErr          error
}

// AcquireL7AssetLease opens and pins the currently verified L7 kernel and
// rootfs. It rechecks their locks before returning and fails closed when the
// distribution changed after bundle verification.
func (distribution VerifiedDistribution) AcquireL7AssetLease() (*VerifiedL7AssetLease, error) {
	if distribution.l7Profile.seal != activeVerifiedL7ProfileSeal || strings.TrimSpace(distribution.rootDir) == "" {
		return nil, l7LeaseError(ErrorCodeInvalidRequest, "l7Assets", "verified L7 assets are required", ErrInvalidRequest)
	}
	normalized := assets.ValidateAndNormalizeLaunchDescriptor(distribution.Descriptor)
	if !normalized.Valid || normalized.Normalized == nil || !VerifiedL7ProfileMatches(&distribution.l7Profile, normalized.Normalized) {
		return nil, l7LeaseError(ErrorCodeInvalidRequest, "l7Assets", "verified L7 assets are required", ErrInvalidRequest)
	}
	root, cleanRoot, err := openRequestedDistributionRoot(distribution.rootDir)
	if err != nil {
		return nil, l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 assets are unavailable", ErrFileUnavailable)
	}
	lease := &VerifiedL7AssetLease{
		rootDir:           cleanRoot,
		root:              root,
		sourceDescriptor:  *normalized.Normalized,
		sourceFingerprint: distribution.l7Profile.fingerprint,
	}
	lease.kernel, err = lease.openPinnedAsset(assets.AssetRoleKernel)
	if err == nil {
		lease.rootfs, err = lease.openPinnedAsset(assets.AssetRoleRootfs)
	}
	if err == nil {
		err = lease.confirmSourceLocked()
	}
	if err != nil {
		cleanupErr := lease.closeLocked()
		if cleanupErr != nil {
			return nil, errors.Join(err, cleanupErr)
		}
		return nil, err
	}
	return lease, nil
}

// ConfirmCurrent verifies that descriptor is either the pinned source set or
// lease-owned launch material and that its current bytes remain bound to the
// verified digest locks.
func (lease *VerifiedL7AssetLease) ConfirmCurrent(descriptor *assets.LaunchDescriptor) error {
	if lease == nil || descriptor == nil {
		return l7LeaseError(ErrorCodeInvalidRequest, "l7Assets", "verified L7 asset lease is required", ErrInvalidRequest)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset lease is closed", ErrFileUnavailable)
	}
	fingerprint, ok := l7DescriptorFingerprint(*descriptor)
	if !ok {
		return l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	switch {
	case fingerprint == lease.sourceFingerprint:
		return lease.confirmSourceLocked()
	case lease.material != nil && fingerprint == lease.materialFingerprint:
		if err := lease.material.Validate(); err != nil {
			return l7LeaseError(ErrorCodeAssetLockMismatch, "l7Assets", "verified L7 launch material changed", ErrAssetLockMismatch)
		}
		return nil
	default:
		return l7LeaseError(ErrorCodeAssetLockMismatch, "launchDescriptor", "verified L7 launch descriptor changed", ErrAssetLockMismatch)
	}
}

// PrepareLaunch copies pinned verified bytes into runtime-owned private launch
// material. Source identity and content are checked before and after copying,
// so the returned descriptor never relies on reopening the mutable source
// pathname. The lease retains material through Close.
func (lease *VerifiedL7AssetLease) PrepareLaunch(
	descriptor *assets.LaunchDescriptor,
	material L7LaunchMaterialWriter,
) (assets.LaunchDescriptor, VerifiedL7Profile, error) {
	if lease == nil || descriptor == nil || material == nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(
			ErrorCodeInvalidRequest,
			"l7Assets",
			"verified L7 launch material is required",
			ErrInvalidRequest,
		)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset lease is closed", ErrFileUnavailable)
	}
	if lease.material != nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeInvalidRequest, "l7Assets", "verified L7 launch material is already prepared", ErrInvalidRequest)
	}
	fingerprint, ok := l7DescriptorFingerprint(*descriptor)
	if !ok || fingerprint != lease.sourceFingerprint {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeAssetLockMismatch, "launchDescriptor", "verified L7 launch descriptor changed", ErrAssetLockMismatch)
	}
	if err := lease.confirmSourceLocked(); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, err
	}

	prepared := cloneL7LaunchDescriptor(lease.sourceDescriptor)
	for index := range prepared.Assets {
		asset := &prepared.Assets[index]
		var source *os.File
		switch asset.Role {
		case assets.AssetRoleKernel:
			source = lease.kernel
		case assets.AssetRoleRootfs:
			source = lease.rootfs
		default:
			continue
		}
		path, err := copyPinnedL7Asset(material, source, *asset)
		if err != nil {
			return assets.LaunchDescriptor{}, VerifiedL7Profile{}, err
		}
		if filepath.Clean(path) == filepath.Clean(asset.Source.HostPath.Path) {
			return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeUnsafePath, "launchMaterial", "private L7 launch material path is required", ErrUnsafePath)
		}
		asset.Source.HostPath.Path = path
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(prepared)
	if !result.Valid || result.Normalized == nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeInvalidRequest, "launchMaterial", "private L7 launch material is invalid", ErrInvalidRequest)
	}
	if err := material.Validate(); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeAssetLockMismatch, "launchMaterial", "private L7 launch material validation failed", ErrAssetLockMismatch)
	}
	if err := lease.confirmSourceLocked(); err != nil {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, err
	}
	profile := newVerifiedL7Profile(*result.Normalized)
	if profile.seal != activeVerifiedL7ProfileSeal {
		return assets.LaunchDescriptor{}, VerifiedL7Profile{}, l7LeaseError(ErrorCodeInvalidRequest, "launchMaterial", "private L7 launch material is invalid", ErrInvalidRequest)
	}
	lease.material = material
	lease.materialDescriptor = *result.Normalized
	lease.materialFingerprint = profile.fingerprint
	return cloneL7LaunchDescriptor(lease.materialDescriptor), profile, nil
}

// Close releases every pinned source handle and any runtime-owned launch
// material. It is safe to call more than once.
func (lease *VerifiedL7AssetLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.closeLocked()
}

func (lease *VerifiedL7AssetLease) openPinnedAsset(role assets.AssetRole) (*os.File, error) {
	asset, name, ok := l7LeaseAsset(lease.sourceDescriptor, role)
	if !ok || asset.Source.HostPath == nil || filepath.Clean(asset.Source.HostPath.Path) != filepath.Join(lease.rootDir, name) {
		return nil, l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	file, err := openDistributionFileNoFollow(lease.root, name)
	if err != nil {
		return nil, l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset is unavailable", ErrFileUnavailable)
	}
	if err := verifyPinnedL7Asset(file, asset); err != nil {
		closeErr := closePinnedL7Asset(file)
		return nil, joinL7LeaseCleanup(err, closeErr)
	}
	return file, nil
}

func (lease *VerifiedL7AssetLease) confirmSourceLocked() (retErr error) {
	currentRoot, _, err := openRequestedDistributionRoot(lease.rootDir)
	if err != nil {
		return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 distribution root is unavailable", ErrFileUnavailable)
	}
	defer func() {
		retErr = joinL7LeaseCleanup(retErr, closePinnedL7Asset(currentRoot))
	}()
	retainedRootInfo, retainedErr := lease.root.Stat()
	currentRootInfo, currentErr := currentRoot.Stat()
	if retainedErr != nil || currentErr != nil || !os.SameFile(retainedRootInfo, currentRootInfo) {
		return l7LeaseError(ErrorCodeAssetLockMismatch, "l7Assets", "verified L7 distribution root changed", ErrAssetLockMismatch)
	}
	for _, entry := range []struct {
		role assets.AssetRole
		file *os.File
	}{
		{role: assets.AssetRoleKernel, file: lease.kernel},
		{role: assets.AssetRoleRootfs, file: lease.rootfs},
	} {
		asset, name, ok := l7LeaseAsset(lease.sourceDescriptor, entry.role)
		if !ok || entry.file == nil {
			return l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
		}
		if err := verifyPinnedL7Asset(entry.file, asset); err != nil {
			return err
		}
		current, openErr := openDistributionFileNoFollow(lease.root, name)
		if openErr != nil {
			return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset is unavailable", ErrFileUnavailable)
		}
		retainedInfo, retainedErr := entry.file.Stat()
		currentInfo, currentErr := current.Stat()
		same := retainedErr == nil && currentErr == nil && os.SameFile(retainedInfo, currentInfo)
		verifyErr := verifyPinnedL7Asset(current, asset)
		closeErr := current.Close()
		var currentErrResult error
		if !same || verifyErr != nil {
			currentErrResult = l7LeaseError(ErrorCodeAssetLockMismatch, "l7Assets", "verified L7 asset changed", ErrAssetLockMismatch)
		}
		if closeErr != nil {
			currentErrResult = joinL7LeaseCleanup(
				currentErrResult,
				newL7AssetCleanupError("verified L7 asset cleanup failed", closeErr),
			)
		}
		if currentErrResult != nil {
			return currentErrResult
		}
	}
	return nil
}

func closePinnedL7Asset(file *os.File) error {
	if file == nil {
		return nil
	}
	if err := file.Close(); err != nil {
		return newL7AssetCleanupError("verified L7 asset cleanup failed", err)
	}
	return nil
}

func joinL7LeaseCleanup(primary, cleanupErr error) error {
	if cleanupErr == nil {
		return primary
	}
	if primary == nil {
		return cleanupErr
	}
	return errors.Join(primary, cleanupErr)
}

func (lease *VerifiedL7AssetLease) closeLocked() error {
	if lease.closed {
		return lease.cleanupErr
	}
	lease.closed = true
	cleanupCauses := make([]error, 0, 4)
	if lease.material != nil {
		if err := lease.material.Close(); err != nil {
			cleanupCauses = append(cleanupCauses, err)
		}
	}
	for _, file := range []*os.File{lease.kernel, lease.rootfs, lease.root} {
		if file != nil {
			if err := file.Close(); err != nil {
				cleanupCauses = append(cleanupCauses, err)
			}
		}
	}
	lease.material = nil
	lease.kernel = nil
	lease.rootfs = nil
	lease.root = nil
	if len(cleanupCauses) > 0 {
		lease.cleanupErr = newL7AssetCleanupError("verified L7 asset lease cleanup failed", cleanupCauses...)
	}
	return lease.cleanupErr
}

func newL7AssetCleanupError(message string, causes ...error) error {
	joined := errors.Join(causes...)
	if joined == nil {
		return nil
	}
	return l7LeaseError(
		ErrorCodeFileUnavailable,
		"l7Assets",
		message,
		sanitizedL7AssetCleanupCause{causes: joined},
	)
}

type sanitizedL7AssetCleanupCause struct {
	causes error
}

func (sanitizedL7AssetCleanupCause) Error() string {
	return ErrFileUnavailable.Error()
}

func (cause sanitizedL7AssetCleanupCause) Is(target error) bool {
	return target == ErrFileUnavailable || errors.Is(cause.causes, target)
}

func (cause sanitizedL7AssetCleanupCause) As(target any) bool {
	return errors.As(cause.causes, target)
}

func copyPinnedL7Asset(material L7LaunchMaterialWriter, source *os.File, asset assets.LaunchAsset) (string, error) {
	if source == nil || asset.Source.HostPath == nil {
		return "", l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset cannot be read", ErrFileUnavailable)
	}
	reader, ok := newLockedL7DigestingReader(source, asset.Lock.SizeBytes)
	if !ok {
		return "", l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	path, err := material.WriteAsset(asset.Role, reader)
	if err != nil {
		return "", l7LeaseError(
			ErrorCodeFileUnavailable,
			"launchMaterial",
			"private L7 launch material cannot be written",
			sanitizedL7LaunchMaterialWriteCause{cause: err},
		)
	}
	var trailing [1]byte
	n, readErr := reader.Read(trailing[:])
	if n != 0 || readErr != io.EOF || reader.size != asset.Lock.SizeBytes || hex.EncodeToString(reader.hash.Sum(nil)) != asset.Lock.Digest.Value {
		return "", l7LeaseError(ErrorCodeAssetLockMismatch, "launchMaterial", "private L7 launch material does not match the verified asset", ErrAssetLockMismatch)
	}
	path, err = validateLocalHostPath(path, "launchMaterial", asset.Role)
	if err != nil {
		return "", l7LeaseError(ErrorCodeUnsafePath, "launchMaterial", "private L7 launch material path is invalid", ErrUnsafePath)
	}
	return path, nil
}

type sanitizedL7LaunchMaterialWriteCause struct {
	cause error
}

func (sanitizedL7LaunchMaterialWriteCause) Error() string {
	return ErrFileUnavailable.Error()
}

func (cause sanitizedL7LaunchMaterialWriteCause) Is(target error) bool {
	return target == ErrFileUnavailable || errors.Is(cause.cause, target)
}

func (cause sanitizedL7LaunchMaterialWriteCause) As(target any) bool {
	return errors.As(cause.cause, target)
}

func verifyPinnedL7Asset(file *os.File, asset assets.LaunchAsset) error {
	if file == nil || asset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 {
		return l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset cannot be read", ErrFileUnavailable)
	}
	reader, ok := newLockedL7DigestingReader(file, asset.Lock.SizeBytes)
	if !ok {
		return l7LeaseError(ErrorCodeInvalidRequest, "launchDescriptor", "verified L7 launch descriptor is invalid", ErrInvalidRequest)
	}
	size, err := io.Copy(io.Discard, reader)
	if err != nil {
		return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset cannot be read", ErrFileUnavailable)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return l7LeaseError(ErrorCodeFileUnavailable, "l7Assets", "verified L7 asset cannot be read", ErrFileUnavailable)
	}
	if size != asset.Lock.SizeBytes || hex.EncodeToString(reader.hash.Sum(nil)) != asset.Lock.Digest.Value {
		return l7LeaseError(ErrorCodeAssetLockMismatch, "l7Assets", "verified L7 asset changed", ErrAssetLockMismatch)
	}
	return nil
}

func l7LeaseAsset(descriptor assets.LaunchDescriptor, role assets.AssetRole) (assets.LaunchAsset, string, bool) {
	name := ""
	switch role {
	case assets.AssetRoleKernel:
		name = "vmlinux"
	case assets.AssetRoleRootfs:
		name = "rootfs.ext4"
	default:
		return assets.LaunchAsset{}, "", false
	}
	for _, asset := range descriptor.Assets {
		if asset.Role == role {
			return asset, name, true
		}
	}
	return assets.LaunchAsset{}, "", false
}

func cloneL7LaunchDescriptor(source assets.LaunchDescriptor) assets.LaunchDescriptor {
	clone := source
	clone.Labels = append([]assets.SafeLabel(nil), source.Labels...)
	clone.Assets = make([]assets.LaunchAsset, len(source.Assets))
	for index := range source.Assets {
		clone.Assets[index] = source.Assets[index]
		clone.Assets[index].Labels = append([]assets.SafeLabel(nil), source.Assets[index].Labels...)
		clone.Assets[index].Resources = append([]assets.ResourceMetadata(nil), source.Assets[index].Resources...)
		if source.Assets[index].Source.HostPath != nil {
			hostPath := *source.Assets[index].Source.HostPath
			clone.Assets[index].Source.HostPath = &hostPath
		}
	}
	return clone
}

func l7LeaseError(code ErrorCode, field, message string, cause error) error {
	return newResolverError(code, field, "", message, cause)
}

type l7DigestingReader struct {
	source io.Reader
	hash   hash.Hash
	size   int64
}

func newLockedL7DigestingReader(source io.Reader, lockedSize int64) (*l7DigestingReader, bool) {
	if source == nil || lockedSize < 0 || lockedSize == int64(^uint64(0)>>1) {
		return nil, false
	}
	return &l7DigestingReader{
		source: io.LimitReader(source, lockedSize+1),
		hash:   sha256.New(),
	}, true
}

func (reader *l7DigestingReader) Read(output []byte) (int, error) {
	n, err := reader.source.Read(output)
	if n > 0 {
		_, _ = reader.hash.Write(output[:n])
		reader.size += int64(n)
	}
	return n, err
}
