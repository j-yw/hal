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
	"sort"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

const (
	l8SourceLockName               = "sources.lock.json"
	l8FinalInspectionName          = "final-inspection.json"
	l8MaxMetadataBytes       int64 = 4 << 20
	l8MaxPinnedEvidenceBytes       = 16 << 20
)

var l8RequiredDistributionOutputs = []string{
	distributionChecksumsName,
	distributionManifestName,
	l8FinalInspectionName,
	distributionProvenanceName,
	"rootfs.ext4",
	l8SourceLockName,
	"vmlinux",
}

func decodeL8PolicyCompositionDigests(facts assetbuild.L8ProcessCompositionFacts) (l8VerifiedPolicyCompositionDigests, error) {
	values := [6]string{
		facts.WorkloadSnapshotSHA256,
		facts.RuntimeProfileSHA256,
		facts.PolicyArtifactSHA256,
		facts.PolicySourceLockSHA256,
		facts.PolicyBinaryBindingSetSHA256,
		facts.PinnedCallsiteEvidenceSHA256,
	}
	var decoded [6][32]byte
	for index, value := range values {
		bytes, err := hex.DecodeString(value)
		if err != nil || len(bytes) != 32 || hex.EncodeToString(bytes) != value {
			return l8VerifiedPolicyCompositionDigests{}, l8PolicyCompositionCorrelationMismatch()
		}
		copy(decoded[index][:], bytes)
	}
	return l8VerifiedPolicyCompositionDigests{
		workloadSnapshotSHA256:       decoded[0],
		runtimeProfileSHA256:         decoded[1],
		policyArtifactSHA256:         decoded[2],
		policySourceLockSHA256:       decoded[3],
		policyBinaryBindingSetSHA256: decoded[4],
		pinnedCallsiteEvidenceSHA256: decoded[5],
	}, nil
}

func decodeL8DistributionManifest(request DistributionRequest) (assetbuild.DistributionManifest, error) {
	var result assetbuild.DistributionManifest
	if err := decodeL8DistributionJSON(request, distributionManifestName, &result); err != nil {
		return assetbuild.DistributionManifest{}, err
	}
	if err := assetbuild.ValidateL8DistributionManifest(result); err != nil {
		return assetbuild.DistributionManifest{}, err
	}
	return result, nil
}

func decodeL8Provenance(request DistributionRequest) (assetbuild.Provenance, error) {
	var result assetbuild.Provenance
	if err := decodeL8DistributionJSON(request, distributionProvenanceName, &result); err != nil {
		return assetbuild.Provenance{}, err
	}
	if err := assetbuild.ValidateL8Provenance(result); err != nil {
		return assetbuild.Provenance{}, err
	}
	return result, nil
}

func decodeL8SourceLock(request DistributionRequest) (assetbuild.L8SourceLock, error) {
	var result assetbuild.L8SourceLock
	if err := decodeL8DistributionJSON(request, l8SourceLockName, &result); err != nil {
		return assetbuild.L8SourceLock{}, err
	}
	if err := assetbuild.ValidateL8SourceLock(result); err != nil {
		return assetbuild.L8SourceLock{}, err
	}
	return result, nil
}

func decodeL8FinalInspection(request DistributionRequest) (assetbuild.L8FinalInspection, error) {
	var result assetbuild.L8FinalInspection
	if err := decodeL8DistributionJSON(request, l8FinalInspectionName, &result); err != nil {
		return assetbuild.L8FinalInspection{}, err
	}
	if err := assetbuild.ValidateL8FinalInspection(result); err != nil {
		return assetbuild.L8FinalInspection{}, err
	}
	return result, nil
}

func decodeL8DistributionJSON(request DistributionRequest, name string, destination any) error {
	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return decodeL8DistributionJSONFromRoot(root, name, destination)
}

func decodeL8DistributionJSONFromRoot(root *os.File, name string, destination any) error {
	file, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return ErrFileUnavailable
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, l8MaxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrManifestInvalid
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrManifestInvalid
	}
	return nil
}

func validateL8BundleState(
	request DistributionRequest,
	manifest assetbuild.DistributionManifest,
	provenance assetbuild.Provenance,
	sourceLock assetbuild.L8SourceLock,
	finalInspection assetbuild.L8FinalInspection,
	parentManifest assetbuild.DistributionManifest,
	parentProvenance assetbuild.Provenance,
	parentDescriptor assets.LaunchDescriptor,
	parentRootDir string,
	parentProfile VerifiedL7Profile,
	parentLease *VerifiedL7AssetLease,
) (descriptor assets.LaunchDescriptor, rootDir string, parentL7EvidenceSHA256 [32]byte, retErr error) {
	if parentLease == nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	defer func() {
		if closeErr := parentLease.Close(); closeErr != nil {
			retErr = errors.Join(retErr, ErrFileUnavailable)
		}
	}()
	if !VerifiedL7ProfileMatches(&parentProfile, &parentDescriptor) || parentLease.ConfirmCurrent(&parentDescriptor) != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	parentEvidence, err := measureL8ParentEvidence(parentManifest, parentProvenance, parentRootDir)
	if err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	parentL7EvidenceSHA256, err = decodeL8Digest(parentEvidence.EvidenceSHA256)
	if err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	if manifest.L8Profile == nil || provenance.L8Profile == nil ||
		!l8JSONEqual(manifest.L8Profile.ParentL7, parentEvidence) ||
		!l8JSONEqual(provenance.L8Profile.ParentL7, parentEvidence) ||
		!l8JSONEqual(sourceLock.ParentL7, parentEvidence) ||
		!l8JSONEqual(finalInspection.ParentL7, parentEvidence) {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	if err := assetbuild.ValidateL8ProvenanceAgainstManifest(provenance, manifest); err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	if !l8JSONEqual(manifest.L8Profile.Runtime, sourceLock.Runtime) ||
		!l8JSONEqual(manifest.L8Profile.Runtime, finalInspection.Runtime) ||
		!l8JSONEqual(manifest.L8Profile.ProcessComposition, finalInspection.ProcessComposition) {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	root, cleanRoot, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	defer root.Close()
	if err := verifyL8DistributionEntrySet(root); err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	if err := verifyL8DistributionChecksums(root); err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	_, sourceLockDigest, err := digestL8DistributionFile(root, l8SourceLockName)
	if err != nil || sourceLockDigest != manifest.L8Profile.SourceLockSHA256 || sourceLockDigest != finalInspection.SourceLockSHA256 {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	_, inspectionDigest, err := digestL8DistributionFile(root, l8FinalInspectionName)
	if err != nil || inspectionDigest != manifest.L8Profile.FinalInspectionSHA256 {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	_, rootfsDigest, err := digestL8DistributionFile(root, "rootfs.ext4")
	if err != nil || rootfsDigest != finalInspection.RootfsSHA256 {
		return assets.LaunchDescriptor{}, "", [32]byte{}, ErrAssetLockMismatch
	}
	descriptor, err = resolveDistributionFromRoot(root, cleanRoot, request.LockedAtUnixMillis, manifest)
	if err != nil {
		return assets.LaunchDescriptor{}, "", [32]byte{}, err
	}
	return descriptor, cleanRoot, parentL7EvidenceSHA256, nil
}

func verifyL8DistributionEntrySet(root *os.File) error {
	clone, err := duplicateDistributionRoot(root)
	if err != nil {
		return ErrFileUnavailable
	}
	defer clone.Close()
	entries, err := clone.ReadDir(-1)
	if err != nil {
		return ErrFileUnavailable
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return ErrUnsupportedFileType
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if !equalDistributionNames(names, l8RequiredDistributionOutputs) {
		return ErrManifestInvalid
	}
	return nil
}

func verifyL8DistributionChecksums(root *os.File) error {
	file, err := openDistributionFileNoFollow(root, distributionChecksumsName)
	if err != nil {
		return ErrFileUnavailable
	}
	defer file.Close()
	wantNames := []string{distributionManifestName, l8FinalInspectionName, distributionProvenanceName, "rootfs.ext4", l8SourceLockName, "vmlinux"}
	lines := make([]string, 0, len(wantNames))
	scanner := bufio.NewScanner(io.LimitReader(file, maxDistributionMetadataBytes+1))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil || len(lines) != len(wantNames) {
		return ErrAssetLockMismatch
	}
	for index, name := range wantNames {
		line := lines[index]
		if len(line) != 66+len(name) || line[64:66] != "  " || line[66:] != name || !validDistributionDigest(line[:64]) {
			return ErrAssetLockMismatch
		}
		_, digest, err := digestL8DistributionFile(root, name)
		if err != nil || digest != line[:64] {
			return ErrAssetLockMismatch
		}
	}
	return nil
}

func measureL8ParentEvidence(manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, rootDir string) (assetbuild.L8ParentL7Evidence, error) {
	if manifest.ImageProfile != assetbuild.ImageProfileL7Network || provenance.ImageProfile != assetbuild.ImageProfileL7Network {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	root, _, err := openRequestedDistributionRoot(rootDir)
	if err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	defer root.Close()
	manifestSize, manifestDigest, err := digestL8DistributionFile(root, distributionManifestName)
	if err != nil || manifestSize <= 0 {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	provenanceSize, provenanceDigest, err := digestL8DistributionFile(root, distributionProvenanceName)
	if err != nil || provenanceSize <= 0 {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	checksumsSize, checksumsDigest, err := digestL8DistributionFile(root, distributionChecksumsName)
	if err != nil || checksumsSize <= 0 {
		return assetbuild.L8ParentL7Evidence{}, ErrAssetLockMismatch
	}
	kernelSize, kernelDigest, err := digestL8DistributionFile(root, "vmlinux")
	if err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	rootfsSize, rootfsDigest, err := digestL8DistributionFile(root, "rootfs.ext4")
	if err != nil {
		return assetbuild.L8ParentL7Evidence{}, err
	}
	result := assetbuild.L8ParentL7Evidence{
		ImageProfile: assetbuild.ImageProfileL7Network, ManifestSHA256: manifestDigest,
		ProvenanceSHA256: provenanceDigest, ChecksumsSHA256: checksumsDigest,
		KernelSizeBytes: kernelSize, KernelSHA256: kernelDigest,
		RootfsSizeBytes: rootfsSize, RootfsSHA256: rootfsDigest,
	}
	var preimage bytes.Buffer
	l8WriteToken(&preimage, "hal/l8/image-profile/parent-l7-evidence/v1")
	l8WriteToken(&preimage, result.ImageProfile)
	for _, digest := range []string{result.ManifestSHA256, result.ProvenanceSHA256, result.ChecksumsSHA256} {
		decoded, decodeErr := decodeL8Digest(digest)
		if decodeErr != nil {
			return assetbuild.L8ParentL7Evidence{}, decodeErr
		}
		preimage.Write(decoded[:])
	}
	l8WriteUint64(&preimage, uint64(result.KernelSizeBytes))
	kernel, _ := decodeL8Digest(result.KernelSHA256)
	preimage.Write(kernel[:])
	l8WriteUint64(&preimage, uint64(result.RootfsSizeBytes))
	rootfs, _ := decodeL8Digest(result.RootfsSHA256)
	preimage.Write(rootfs[:])
	evidenceDigest := sha256.Sum256(preimage.Bytes())
	result.EvidenceSHA256 = hex.EncodeToString(evidenceDigest[:])
	return result, nil
}

func buildL8EvidenceFingerprint(request DistributionRequest, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, sourceLock assetbuild.L8SourceLock, finalInspection assetbuild.L8FinalInspection, parentL7EvidenceSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) ([32]byte, [32]byte, error) {
	return calculateL8EvidenceFingerprint(request, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, policyComposition)
}

func calculateL8EvidenceFingerprint(request DistributionRequest, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, sourceLock assetbuild.L8SourceLock, finalInspection assetbuild.L8FinalInspection, parentL7EvidenceSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) ([32]byte, [32]byte, error) {
	if request.LockedAtUnixMillis < 0 || manifest.L8Profile == nil || provenance.L8Profile == nil || parentL7EvidenceSHA256 == ([32]byte{}) ||
		assetbuild.ValidateL8ProvenanceAgainstManifest(provenance, manifest) != nil || assetbuild.ValidateL8SourceLock(sourceLock) != nil || assetbuild.ValidateL8FinalInspection(finalInspection) != nil {
		return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
	}
	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	defer root.Close()
	var preimage bytes.Buffer
	l8WriteToken(&preimage, "hal/l8/image-profile/evidence/v1")
	var imageSHA256 [32]byte
	type measuredFile struct {
		size   int64
		digest [32]byte
	}
	measurements := make(map[string]measuredFile, len(l8RequiredDistributionOutputs))
	for _, name := range l8RequiredDistributionOutputs {
		size, digestText, digestErr := digestL8DistributionFile(root, name)
		if digestErr != nil || size < 0 {
			return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
		}
		digest, decodeErr := decodeL8Digest(digestText)
		if decodeErr != nil {
			return [32]byte{}, [32]byte{}, decodeErr
		}
		l8WriteToken(&preimage, name)
		l8WriteUint64(&preimage, uint64(size))
		preimage.Write(digest[:])
		measurements[name] = measuredFile{size: size, digest: digest}
		if name == "rootfs.ext4" {
			imageSHA256 = digest
		}
	}
	preimage.Write(parentL7EvidenceSHA256[:])
	for _, digestText := range []string{
		manifest.L8Profile.SourceLockSHA256,
		manifest.L8Profile.FinalInspectionSHA256,
		manifest.L8Profile.Runtime.NodeSHA256,
		manifest.L8Profile.Runtime.PiLauncherSHA256,
		manifest.L8Profile.Runtime.PiDependencyTreeSHA256,
		manifest.L8Profile.ProcessComposition.HelperDescriptorSHA256,
		manifest.L8Profile.ProcessComposition.ClientDescriptorSHA256,
		manifest.L8Profile.ProcessComposition.CompositionSHA256,
	} {
		digest, decodeErr := decodeL8Digest(digestText)
		if decodeErr != nil {
			return [32]byte{}, [32]byte{}, decodeErr
		}
		preimage.Write(digest[:])
	}
	for _, digest := range [][32]byte{
		policyComposition.workloadSnapshotSHA256,
		policyComposition.runtimeProfileSHA256,
		policyComposition.policyArtifactSHA256,
		policyComposition.policySourceLockSHA256,
		policyComposition.policyBinaryBindingSetSHA256,
		policyComposition.pinnedCallsiteEvidenceSHA256,
	} {
		if digest == ([32]byte{}) {
			return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
		}
		preimage.Write(digest[:])
	}
	if imageSHA256 == ([32]byte{}) {
		return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
	}
	var currentManifest assetbuild.DistributionManifest
	var currentProvenance assetbuild.Provenance
	var currentSourceLock assetbuild.L8SourceLock
	var currentFinalInspection assetbuild.L8FinalInspection
	for _, current := range []struct {
		name        string
		destination any
	}{
		{name: distributionManifestName, destination: &currentManifest},
		{name: distributionProvenanceName, destination: &currentProvenance},
		{name: l8SourceLockName, destination: &currentSourceLock},
		{name: l8FinalInspectionName, destination: &currentFinalInspection},
	} {
		if err := decodeL8DistributionJSONFromRoot(root, current.name, current.destination); err != nil {
			return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
		}
	}
	if !l8JSONEqual(currentManifest, manifest) || !l8JSONEqual(currentProvenance, provenance) ||
		!l8JSONEqual(currentSourceLock, sourceLock) || !l8JSONEqual(currentFinalInspection, finalInspection) ||
		verifyL8DistributionEntrySet(root) != nil || verifyL8DistributionChecksums(root) != nil {
		return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
	}
	for _, name := range l8RequiredDistributionOutputs {
		size, digestText, digestErr := digestL8DistributionFile(root, name)
		digest, decodeErr := decodeL8Digest(digestText)
		if digestErr != nil || decodeErr != nil || measurements[name] != (measuredFile{size: size, digest: digest}) {
			return [32]byte{}, [32]byte{}, ErrAssetLockMismatch
		}
	}
	return sha256.Sum256(preimage.Bytes()), imageSHA256, nil
}

func decodeL8Digest(value string) ([32]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [32]byte{}, ErrAssetLockMismatch
	}
	var result [32]byte
	copy(result[:], decoded)
	return result, nil
}

func digestL8DistributionFile(root *os.File, name string) (size int64, digest string, retErr error) {
	maxBytes := l8MaxMetadataBytes
	if name == "vmlinux" || name == "rootfs.ext4" {
		maxBytes = l8MaxPinnedAssetBytes
	}
	file, err := openDistributionFileNoFollow(root, name)
	if err != nil {
		return 0, "", ErrFileUnavailable
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			retErr = errors.Join(retErr, ErrFileUnavailable)
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, "", ErrFileUnavailable
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return 0, "", ErrAssetLockMismatch
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, info.Size())
	if err != nil || written != info.Size() {
		return 0, "", ErrFileUnavailable
	}
	var trailing [1]byte
	if count, readErr := file.Read(trailing[:]); count != 0 || readErr != io.EOF {
		return 0, "", ErrAssetLockMismatch
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func l8JSONEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
