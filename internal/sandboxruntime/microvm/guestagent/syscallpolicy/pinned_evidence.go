package syscallpolicy

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
)

type expectedEvidenceIssuer struct{ issued bool }
type evidenceOwner struct{}

type pinnedBinaryBinding struct {
	role                 Role
	kind                 BinaryBindingKind
	textLength           uint64
	sourceLockSHA256     [32]byte
	toolchainSHA256      [32]byte
	binarySHA256         [32]byte
	executableTextSHA256 [32]byte
	sha256               [32]byte
}

type pinnedCallsiteEvidence struct {
	callsiteSHA256            [32]byte
	binaryBindingSHA256       [32]byte
	observedInstructionSHA256 [32]byte
	instructionOffset         uint64
	sha256                    [32]byte
}

type PinnedBinaryBindingView struct{ binding *pinnedBinaryBinding }
type PinnedBinaryBindingSet struct {
	sha256   [32]byte
	bindings []PinnedBinaryBindingView
	owner    *evidenceOwner
}
type PinnedCallsiteEvidenceView struct{ evidence *pinnedCallsiteEvidence }
type ExpectedPinnedCallsiteEvidence struct {
	sha256 [32]byte
	issuer expectedEvidenceIssuer
}
type PinnedCallsiteEvidenceSet struct {
	sha256           [32]byte
	artifactSHA256   [32]byte
	sourceLockSHA256 [32]byte
	binaries         PinnedBinaryBindingSet
	evidence         []PinnedCallsiteEvidenceView
	owner            *evidenceOwner
}

func (expected ExpectedPinnedCallsiteEvidence) SHA256() [32]byte { return expected.sha256 }
func (set PinnedCallsiteEvidenceSet) SHA256() [32]byte           { return set.sha256 }
func (set PinnedCallsiteEvidenceSet) ArtifactSHA256() [32]byte   { return set.artifactSHA256 }
func (set PinnedCallsiteEvidenceSet) SourceLockSHA256() [32]byte { return set.sourceLockSHA256 }
func (set PinnedCallsiteEvidenceSet) BinaryBindings() PinnedBinaryBindingSet {
	result := set.binaries
	result.bindings = append([]PinnedBinaryBindingView(nil), set.binaries.bindings...)
	return result
}
func (set PinnedCallsiteEvidenceSet) Evidence() []PinnedCallsiteEvidenceView {
	return append([]PinnedCallsiteEvidenceView(nil), set.evidence...)
}
func (bindings PinnedBinaryBindingSet) SHA256() [32]byte { return bindings.sha256 }
func (bindings PinnedBinaryBindingSet) Bindings() []PinnedBinaryBindingView {
	return append([]PinnedBinaryBindingView(nil), bindings.bindings...)
}

func (binding PinnedBinaryBindingView) Role() Role {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.role
}
func (binding PinnedBinaryBindingView) Kind() BinaryBindingKind {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.kind
}
func (binding PinnedBinaryBindingView) TextLength() uint64 {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.textLength
}
func (binding PinnedBinaryBindingView) SourceLockSHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.sourceLockSHA256
}
func (binding PinnedBinaryBindingView) ToolchainSHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.toolchainSHA256
}
func (binding PinnedBinaryBindingView) BinarySHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.binarySHA256
}
func (binding PinnedBinaryBindingView) ExecutableTextSHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.executableTextSHA256
}
func (binding PinnedBinaryBindingView) SHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.sha256
}

func (evidence PinnedCallsiteEvidenceView) CallsiteSHA256() [32]byte {
	if evidence.evidence == nil {
		return [32]byte{}
	}
	return evidence.evidence.callsiteSHA256
}
func (evidence PinnedCallsiteEvidenceView) BinaryBindingSHA256() [32]byte {
	if evidence.evidence == nil {
		return [32]byte{}
	}
	return evidence.evidence.binaryBindingSHA256
}
func (evidence PinnedCallsiteEvidenceView) ObservedInstructionSHA256() [32]byte {
	if evidence.evidence == nil {
		return [32]byte{}
	}
	return evidence.evidence.observedInstructionSHA256
}
func (evidence PinnedCallsiteEvidenceView) InstructionOffset() uint64 {
	if evidence.evidence == nil {
		return 0
	}
	return evidence.evidence.instructionOffset
}
func (evidence PinnedCallsiteEvidenceView) SHA256() [32]byte {
	if evidence.evidence == nil {
		return [32]byte{}
	}
	return evidence.evidence.sha256
}

func ImportPinnedCallsiteEvidence(encoded []byte, artifact VerifiedPolicyArtifact, expected ExpectedPinnedCallsiteEvidence) (PinnedCallsiteEvidenceSet, error) {
	if !expected.issuer.issued || zeroDigest(expected.sha256) {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeOwnership)
	}
	if artifact.artifact == nil || zeroDigest(artifact.sha256) {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeOwnership)
	}
	if len(encoded) == 0 || len(encoded) > MaxPinnedCallsiteEvidenceBytes {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeBounds)
	}
	snapshot := append([]byte(nil), encoded...)
	digest := framedSHA256("hal/l8/pinned-callsite-evidence/linux-amd64/v1", snapshot)
	if subtle.ConstantTimeCompare(digest[:], expected.sha256[:]) != 1 {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDigestMismatch)
	}
	if len(snapshot) < 108 || string(snapshot[:4]) != "HL8E" || snapshot[4] != 1 || snapshot[5] != 0 || binary.BigEndian.Uint16(snapshot[10:12]) != 0 {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeEncoding)
	}
	bindingCount := int(binary.BigEndian.Uint16(snapshot[6:8]))
	evidenceCount := int(binary.BigEndian.Uint16(snapshot[8:10]))
	if bindingCount == 0 || evidenceCount == 0 || bindingCount > MaxPinnedBinaryBindings || evidenceCount > MaxPinnedCallsiteEvidenceRecords {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeBounds)
	}
	wantLength := 108 + bindingCount*140 + evidenceCount*104
	if len(snapshot) != wantLength {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeEncoding)
	}
	var artifactSHA256, sourceLockSHA256, encodedBindingSetSHA256 [32]byte
	copy(artifactSHA256[:], snapshot[12:44])
	copy(sourceLockSHA256[:], snapshot[44:76])
	copy(encodedBindingSetSHA256[:], snapshot[76:108])
	if zeroDigest(artifactSHA256) || zeroDigest(sourceLockSHA256) || zeroDigest(encodedBindingSetSHA256) {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDigestMismatch)
	}

	cursor := 108
	bindings := make([]PinnedBinaryBindingView, 0, bindingCount)
	bindingByDigest := make(map[[32]byte]*pinnedBinaryBinding, bindingCount)
	var previousBinding []byte
	bindingSetPreimage := make([]byte, 4, 4+bindingCount*140)
	binary.BigEndian.PutUint16(bindingSetPreimage[:2], uint16(bindingCount))
	for bindingIndex := 0; bindingIndex < bindingCount; bindingIndex++ {
		record := snapshot[cursor : cursor+140]
		if binary.BigEndian.Uint16(record[2:4]) != 0 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeEncoding)
		}
		role := Role(record[0])
		kind := BinaryBindingKind(record[1])
		textLength := binary.BigEndian.Uint64(record[4:12])
		if ValidateRole(role) != nil || ValidateBinaryBindingKind(kind) != nil {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeCatalog)
		}
		if textLength == 0 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeBounds)
		}
		if bindingIndex > 0 && bytes.Compare(previousBinding[:2], record[:2]) >= 0 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDuplicate)
		}
		binding := &pinnedBinaryBinding{role: role, kind: kind, textLength: textLength}
		copy(binding.sourceLockSHA256[:], record[12:44])
		copy(binding.toolchainSHA256[:], record[44:76])
		copy(binding.binarySHA256[:], record[76:108])
		copy(binding.executableTextSHA256[:], record[108:140])
		if zeroDigest(binding.sourceLockSHA256) || zeroDigest(binding.toolchainSHA256) || zeroDigest(binding.binarySHA256) || zeroDigest(binding.executableTextSHA256) {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeCatalog)
		}
		binding.sha256 = framedSHA256("hal/l8/pinned-binary-binding/linux-amd64/v1", record)
		if _, exists := bindingByDigest[binding.sha256]; exists {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDuplicate)
		}
		bindingByDigest[binding.sha256] = binding
		bindings = append(bindings, PinnedBinaryBindingView{binding: binding})
		bindingSetPreimage = append(bindingSetPreimage, record...)
		previousBinding = record
		cursor += 140
	}
	computedBindingSetSHA256 := framedSHA256("hal/l8/pinned-binary-binding-set/linux-amd64/v1", bindingSetPreimage)
	if subtle.ConstantTimeCompare(computedBindingSetSHA256[:], encodedBindingSetSHA256[:]) != 1 {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDigestMismatch)
	}

	evidenceViews := make([]PinnedCallsiteEvidenceView, 0, evidenceCount)
	var previousEvidence []byte
	for evidenceIndex := 0; evidenceIndex < evidenceCount; evidenceIndex++ {
		record := snapshot[cursor : cursor+104]
		evidence := &pinnedCallsiteEvidence{instructionOffset: binary.BigEndian.Uint64(record[96:104])}
		copy(evidence.callsiteSHA256[:], record[0:32])
		copy(evidence.binaryBindingSHA256[:], record[32:64])
		copy(evidence.observedInstructionSHA256[:], record[64:96])
		if zeroDigest(evidence.callsiteSHA256) || zeroDigest(evidence.binaryBindingSHA256) || zeroDigest(evidence.observedInstructionSHA256) {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeCatalog)
		}
		if evidenceIndex > 0 && bytes.Compare(previousEvidence, record) >= 0 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDuplicate)
		}
		evidence.sha256 = framedSHA256("hal/l8/pinned-callsite-evidence-record/linux-amd64/v1", record)
		evidenceViews = append(evidenceViews, PinnedCallsiteEvidenceView{evidence: evidence})
		previousEvidence = record
		cursor += 104
	}
	if cursor != len(snapshot) {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeEncoding)
	}

	if subtle.ConstantTimeCompare(artifactSHA256[:], artifact.sha256[:]) != 1 || subtle.ConstantTimeCompare(sourceLockSHA256[:], artifact.artifact.sourceLockSHA256[:]) != 1 {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
	}
	for _, bindingView := range bindings {
		binding := bindingView.binding
		if subtle.ConstantTimeCompare(binding.sourceLockSHA256[:], sourceLockSHA256[:]) != 1 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
		}
	}
	if len(artifact.artifact.pinnedCallsites) == 0 {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
	}
	type bindingPair struct {
		role Role
		kind BinaryBindingKind
	}
	requiredBindings := make(map[bindingPair]struct{})
	requirementsByDigest := make(map[[32]byte]*pinnedCallsiteRequirement, len(artifact.artifact.pinnedCallsites))
	for _, requirement := range artifact.artifact.pinnedCallsites {
		kind := BinaryBindingKindNativeBootstrap
		if requirement.origin == RuleOriginRuntime {
			kind = BinaryBindingKindPinnedGoRuntime
		}
		requiredBindings[bindingPair{role: requirement.role, kind: kind}] = struct{}{}
		requirementsByDigest[requirement.sha256] = requirement
	}
	if len(requiredBindings) != len(bindings) || len(requirementsByDigest) != len(evidenceViews) {
		return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
	}
	for _, bindingView := range bindings {
		binding := bindingView.binding
		if _, ok := requiredBindings[bindingPair{role: binding.role, kind: binding.kind}]; !ok {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
		}
	}
	seenCallsites := make(map[[32]byte]struct{}, len(evidenceViews))
	for _, evidenceView := range evidenceViews {
		evidence := evidenceView.evidence
		requirement := requirementsByDigest[evidence.callsiteSHA256]
		binding := bindingByDigest[evidence.binaryBindingSHA256]
		if requirement == nil || binding == nil {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
		}
		if _, duplicate := seenCallsites[evidence.callsiteSHA256]; duplicate {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeDuplicate)
		}
		seenCallsites[evidence.callsiteSHA256] = struct{}{}
		wantKind := BinaryBindingKindNativeBootstrap
		if requirement.origin == RuleOriginRuntime {
			wantKind = BinaryBindingKindPinnedGoRuntime
		}
		if binding.role != requirement.role || binding.kind != wantKind || subtle.ConstantTimeCompare(binding.toolchainSHA256[:], requirement.toolchainSHA256[:]) != 1 || subtle.ConstantTimeCompare(evidence.observedInstructionSHA256[:], requirement.instructionTemplateSHA256[:]) != 1 {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
		}
		end := evidence.instructionOffset + uint64(requirement.instructionLength)
		if end < evidence.instructionOffset || end > binding.textLength {
			return PinnedCallsiteEvidenceSet{}, contractError(ErrorCodeContradiction)
		}
	}
	owner := &evidenceOwner{}
	return PinnedCallsiteEvidenceSet{
		sha256:           digest,
		artifactSHA256:   artifactSHA256,
		sourceLockSHA256: sourceLockSHA256,
		binaries: PinnedBinaryBindingSet{
			sha256:   computedBindingSetSHA256,
			bindings: bindings,
			owner:    owner,
		},
		evidence: evidenceViews,
		owner:    owner,
	}, nil
}
