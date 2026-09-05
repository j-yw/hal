package localresolver

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

// L8MinimalExpectedIdentity must come from the caller's trusted build/source
// pins, never from the candidate bundle being verified. Inspection and source
// lock digests authenticate the producer's measurements, not live execution.
type L8MinimalExpectedIdentity struct {
	SourceRevision        string
	RootfsSHA256          string
	GuestInitSHA256       string
	GuestAgentSHA256      string
	Runtime               assetbuild.L8RuntimeFacts
	SourceLockSHA256      string
	FinalInspectionSHA256 string
	ProvenanceSHA256      string
}

type L8MinimalDistributionRequest struct {
	DistributionRequest
	ParentL7 VerifiedDistribution
	Expected L8MinimalExpectedIdentity
}

// VerifiedL8MinimalDistribution retains candidate and parent file ownership.
// It is deliberately not VerifiedDistribution and cannot issue L7/legacy L8
// launch authority. Copies share one idempotently closable state.
type VerifiedL8MinimalDistribution struct{ state *minimalDistributionState }

type minimalDistributionState struct {
	mu             sync.Mutex
	rootDir        string
	root           *os.File
	files          map[string]l8PinnedAsset
	descriptor     assets.LaunchDescriptor
	parent         VerifiedDistribution
	parentLease    *VerifiedL7AssetLease
	parentMetadata map[string]l8PinnedAsset
	parentEvidence assetbuild.L8ParentL7Evidence
	closed         bool
	closeErr       error
}

func (VerifiedL8MinimalDistribution) String() string   { return "<verified minimal image files>" }
func (VerifiedL8MinimalDistribution) GoString() string { return "<verified minimal image files>" }
func (VerifiedL8MinimalDistribution) MarshalJSON() ([]byte, error) {
	return nil, minimalDistributionError(ErrInvalidRequest)
}
func (VerifiedL8MinimalDistribution) MarshalText() ([]byte, error) {
	return nil, minimalDistributionError(ErrInvalidRequest)
}

// VerifyL8MinimalDistributionBundle verifies one exact seven-file candidate
// against trusted expected identities and a currently resolver-issued L7
// parent. It reads no offline policy evidence and never claims runtime safety.
func VerifyL8MinimalDistributionBundle(request L8MinimalDistributionRequest) (result VerifiedL8MinimalDistribution, retErr error) {
	state := &minimalDistributionState{files: make(map[string]l8PinnedAsset), parentMetadata: make(map[string]l8PinnedAsset)}
	result = VerifiedL8MinimalDistribution{state: state}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(minimalDistributionError(retErr), result.Close())
			result = VerifiedL8MinimalDistribution{}
		}
	}()
	if request.LockedAtUnixMillis < 0 {
		return result, ErrInvalidRequest
	}
	var err error
	state.parentLease, err = request.ParentL7.AcquireL7AssetLease()
	if err != nil {
		return result, ErrAssetLockMismatch
	}
	// Copy public metadata so later caller mutations cannot alter correlation.
	state.parent, err = cloneMinimalParent(request.ParentL7)
	if err != nil {
		return result, err
	}
	state.parentEvidence, err = state.parentLease.measureL8ParentEvidence(state.parent.Manifest, state.parent.Provenance, state.parent.Descriptor)
	if err != nil {
		return result, err
	}
	for _, name := range []string{distributionManifestName, distributionProvenanceName, distributionChecksumsName} {
		pinned, err := pinMinimalFile(state.parentLease.root, name)
		if err != nil {
			return result, err
		}
		state.parentMetadata[name] = pinned
	}
	state.root, state.rootDir, err = openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return result, err
	}
	if err := verifyMinimalEntrySet(state.root); err != nil {
		return result, err
	}
	for _, name := range l8RequiredDistributionOutputs {
		pinned, err := pinMinimalFile(state.root, name)
		if err != nil {
			return result, err
		}
		state.files[name] = pinned
	}
	var manifest assetbuild.L8MinimalDistributionManifest
	var provenance assetbuild.L8MinimalProvenance
	var sources assetbuild.L8MinimalSourceLock
	var inspection assetbuild.L8MinimalFinalInspection
	for _, document := range []struct {
		name        string
		destination any
	}{
		{distributionManifestName, &manifest}, {distributionProvenanceName, &provenance}, {l8SourceLockName, &sources}, {l8FinalInspectionName, &inspection},
	} {
		if err := decodeL8RetainedParentJSON(state.files[document.name].file, document.destination); err != nil {
			return result, err
		}
	}
	if err := assetbuild.ValidateL8MinimalDocuments(manifest, provenance, sources, inspection); err != nil {
		return result, ErrManifestInvalid
	}
	facts := manifest.MinimalProfile
	actual := L8MinimalExpectedIdentity{SourceRevision: provenance.SourceRevision, RootfsSHA256: inspection.RootfsSHA256, GuestInitSHA256: facts.GuestInitSHA256, GuestAgentSHA256: facts.GuestAgentSHA256, Runtime: facts.Runtime, SourceLockSHA256: facts.SourceLockSHA256, FinalInspectionSHA256: facts.FinalInspectionSHA256, ProvenanceSHA256: minimalPinnedDigest(state.files[distributionProvenanceName])}
	if actual != request.Expected || facts.ParentL7 != state.parentEvidence ||
		minimalPinnedDigest(state.files[l8SourceLockName]) != facts.SourceLockSHA256 || minimalPinnedDigest(state.files[l8FinalInspectionName]) != facts.FinalInspectionSHA256 ||
		minimalPinnedDigest(state.files["rootfs.ext4"]) != inspection.RootfsSHA256 {
		return result, ErrAssetLockMismatch
	}
	if err := verifyMinimalChecksums(state.files); err != nil {
		return result, err
	}
	// Reuse descriptor normalization and digest checking, but explicitly set the
	// minimal planning identity. No generic profile dispatch or seal is used.
	state.descriptor, err = resolveDistributionFromRootWithDigester(state.root, state.rootDir, request.LockedAtUnixMillis,
		assetbuild.DistributionManifest{Assets: manifest.Assets}, func(_ *os.File, asset assetbuild.DistributionAsset) (int64, string, error) {
			pinned, ok := state.files[asset.Key]
			if !ok {
				return 0, "", ErrAssetLockMismatch
			}
			return pinned.size, minimalPinnedDigest(pinned), nil
		})
	if err != nil {
		return result, err
	}
	state.descriptor.ID = "l8-minimal-credentials-image"
	state.descriptor.Labels = []assets.SafeLabel{"firecracker", "reproducible", "network-profile", "minimal-credentials-profile"}
	if err := state.confirmCurrent(); err != nil {
		return result, err
	}
	return result, nil
}

// SelectL8MinimalDistribution returns a fresh planning descriptor only after
// retained bytes and parent authority are rechecked. This is NOT a runtime
// launch handoff: a future launcher must consume retained bytes through a
// separately reviewed asset-transfer seam, never blindly reopen these paths.
func SelectL8MinimalDistribution(verified VerifiedL8MinimalDistribution) (assets.LaunchDescriptor, error) {
	if verified.state == nil {
		return assets.LaunchDescriptor{}, minimalDistributionError(ErrInvalidRequest)
	}
	state := verified.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.confirmCurrent(); err != nil {
		return assets.LaunchDescriptor{}, minimalDistributionError(err)
	}
	return cloneL7LaunchDescriptor(state.descriptor), nil
}

func (verified VerifiedL8MinimalDistribution) Close() error {
	if verified.state == nil {
		return nil
	}
	state := verified.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return state.closeErr
	}
	state.closed = true
	var causes []error
	for _, files := range []map[string]l8PinnedAsset{state.files, state.parentMetadata} {
		for _, pinned := range files {
			if pinned.file != nil {
				causes = append(causes, pinned.file.Close())
			}
		}
	}
	if state.root != nil {
		causes = append(causes, state.root.Close())
	}
	if state.parentLease != nil {
		causes = append(causes, state.parentLease.Close())
	}
	if errors.Join(causes...) != nil {
		state.closeErr = minimalDistributionError(ErrFileUnavailable)
	}
	state.files, state.parentMetadata, state.root = nil, nil, nil
	return state.closeErr
}

func (state *minimalDistributionState) confirmCurrent() error {
	if state.closed || state.root == nil || state.parentLease == nil {
		return ErrFileUnavailable
	}
	current, _, err := openRequestedDistributionRoot(state.rootDir)
	if err != nil {
		return ErrAssetLockMismatch
	}
	oldInfo, oldErr := state.root.Stat()
	newInfo, newErr := current.Stat()
	entryErr := verifyMinimalEntrySet(current)
	closeErr := current.Close()
	if oldErr != nil || newErr != nil || entryErr != nil || closeErr != nil || !os.SameFile(oldInfo, newInfo) {
		return ErrAssetLockMismatch
	}
	if err := confirmMinimalFiles(state.root, state.files); err != nil {
		return err
	}
	if err := confirmMinimalFiles(state.parentLease.root, state.parentMetadata); err != nil {
		return err
	}
	parent, err := state.parentLease.measureL8ParentEvidence(state.parent.Manifest, state.parent.Provenance, state.parent.Descriptor)
	if err != nil || parent != state.parentEvidence {
		return ErrAssetLockMismatch
	}
	return nil
}

func pinMinimalFile(root *os.File, name string) (l8PinnedAsset, error) {
	file, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return l8PinnedAsset{}, ErrFileUnavailable
	}
	maximum := l8MaxMetadataBytes
	if name == "vmlinux" || name == "rootfs.ext4" {
		maximum = l8MaxPinnedAssetBytes
	}
	measurement, err := measureL8RetainedParentFile(file, maximum)
	if err != nil {
		_ = file.Close()
		return l8PinnedAsset{}, err
	}
	digest, err := decodeL8Digest(measurement.digest)
	if err != nil {
		_ = file.Close()
		return l8PinnedAsset{}, err
	}
	return l8PinnedAsset{file: file, size: measurement.size, digest: digest}, nil
}

// One extra entry suffices to reject an oversized directory. Do not enumerate
// an unbounded attacker-controlled directory just to establish the exact set.
func verifyMinimalEntrySet(root *os.File) error {
	clone, err := duplicateDistributionRoot(root)
	if err != nil {
		return ErrFileUnavailable
	}
	entries, readErr := clone.ReadDir(len(l8RequiredDistributionOutputs) + 1)
	closeErr := clone.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) != len(l8RequiredDistributionOutputs) {
		return ErrManifestInvalid
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsupportedFileType
		}
		seen[entry.Name()] = true
	}
	for _, name := range l8RequiredDistributionOutputs {
		if !seen[name] {
			return ErrManifestInvalid
		}
	}
	return nil
}

func confirmMinimalFiles(root *os.File, files map[string]l8PinnedAsset) error {
	for name, pinned := range files {
		current, err := openDistributionFileNoFollow(root, name)
		if err != nil {
			return ErrAssetLockMismatch
		}
		oldInfo, oldErr := pinned.file.Stat()
		newInfo, newErr := current.Stat()
		measured, measureErr := measureL8RetainedParentFile(current, pinned.size)
		closeErr := current.Close()
		if oldErr != nil || newErr != nil || measureErr != nil || closeErr != nil || !os.SameFile(oldInfo, newInfo) || measured.size != pinned.size || measured.digest != minimalPinnedDigest(pinned) {
			return ErrAssetLockMismatch
		}
	}
	return nil
}

func verifyMinimalChecksums(files map[string]l8PinnedAsset) error {
	file := files[distributionChecksumsName].file
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrFileUnavailable
	}
	scanner := bufio.NewScanner(io.LimitReader(file, l8MaxMetadataBytes+1))
	for _, name := range l8RequiredDistributionOutputs {
		if name == distributionChecksumsName {
			continue
		}
		if !scanner.Scan() || scanner.Text() != minimalPinnedDigest(files[name])+"  "+name {
			return ErrAssetLockMismatch
		}
	}
	if scanner.Scan() || scanner.Err() != nil {
		return ErrAssetLockMismatch
	}
	return nil
}

func minimalPinnedDigest(pinned l8PinnedAsset) string { return hex.EncodeToString(pinned.digest[:]) }

func cloneMinimalParent(parent VerifiedDistribution) (VerifiedDistribution, error) {
	manifest, err := json.Marshal(parent.Manifest)
	if err != nil {
		return VerifiedDistribution{}, ErrManifestInvalid
	}
	provenance, err := json.Marshal(parent.Provenance)
	if err != nil {
		return VerifiedDistribution{}, ErrManifestInvalid
	}
	parent.Manifest = assetbuild.DistributionManifest{}
	parent.Provenance = assetbuild.Provenance{}
	if json.Unmarshal(manifest, &parent.Manifest) != nil || json.Unmarshal(provenance, &parent.Provenance) != nil {
		return VerifiedDistribution{}, ErrManifestInvalid
	}
	parent.Descriptor = cloneL7LaunchDescriptor(parent.Descriptor)
	return parent, nil
}

func minimalDistributionError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "minimalProfile", "", "minimal image evidence is missing, invalid, or changed", ErrAssetLockMismatch)
}
