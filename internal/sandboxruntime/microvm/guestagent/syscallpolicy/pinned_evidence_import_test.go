package syscallpolicy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPinnedCallsiteEvidenceDefaultExpectationIsUnavailable(t *testing.T) {
	t.Parallel()

	expected, err := EmbeddedExpectedPinnedCallsiteEvidence()
	if expected.SHA256() != ([32]byte{}) || contractErrorCode(err) != ErrorCodeMissingSection {
		t.Fatalf("EmbeddedExpectedPinnedCallsiteEvidence() = (%x, %v), want zero/missing-section", expected.SHA256(), err)
	}
}

func TestImportPinnedCallsiteEvidenceRejectsReservedBindingEncoding(t *testing.T) {
	t.Parallel()

	artifact := VerifiedPolicyArtifact{
		sha256: [32]byte{1},
		artifact: &verifiedArtifact{
			sourceLockSHA256: [32]byte{2},
		},
	}
	encoded := pinnedEvidenceTestEnvelope(artifact, 1)
	expected := ExpectedPinnedCallsiteEvidence{
		sha256: pinnedEvidenceTestDigest(encoded),
		issuer: expectedEvidenceIssuer{issued: true},
	}
	set, err := ImportPinnedCallsiteEvidence(encoded, artifact, expected)
	if set.owner != nil || set.SHA256() != ([32]byte{}) {
		t.Fatal("reserved binding encoding returned evidence authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("reserved binding encoding error = %v, want encoding", got)
	}
}

func TestImportPinnedCallsiteEvidenceRejectsCallsiteSubstitution(t *testing.T) {
	t.Parallel()

	artifact := pinnedEvidenceTestArtifact(t)
	encoded := pinnedEvidenceCanonicalEnvelope(artifact, true)
	expected := ExpectedPinnedCallsiteEvidence{
		sha256: pinnedEvidenceTestDigest(encoded),
		issuer: expectedEvidenceIssuer{issued: true},
	}
	set, err := ImportPinnedCallsiteEvidence(encoded, artifact, expected)
	if set.owner != nil || set.SHA256() != ([32]byte{}) {
		t.Fatal("substituted callsite returned evidence authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeContradiction {
		t.Fatalf("substituted callsite error = %v, want contradiction", got)
	}
}

func TestImportPinnedCallsiteEvidenceAcceptsCompleteEvidenceAndCopiesInput(t *testing.T) {
	t.Parallel()

	artifact := pinnedEvidenceTestArtifact(t)
	encoded := pinnedEvidenceCanonicalEnvelope(artifact, false)
	expected := ExpectedPinnedCallsiteEvidence{
		sha256: pinnedEvidenceTestDigest(encoded),
		issuer: expectedEvidenceIssuer{issued: true},
	}
	set, err := ImportPinnedCallsiteEvidence(encoded, artifact, expected)
	if err != nil {
		t.Fatalf("ImportPinnedCallsiteEvidence() error = %v", err)
	}
	if set.owner == nil || set.SHA256() != expected.SHA256() || set.ArtifactSHA256() != artifact.SHA256() || set.SourceLockSHA256() != artifact.SourceLockSHA256() {
		t.Fatal("complete evidence did not return correlated authority")
	}
	bindings := set.BinaryBindings().Bindings()
	evidence := set.Evidence()
	if len(bindings) != 1 || bindings[0].Role() != RoleLaunchBase || bindings[0].Kind() != BinaryBindingKindPinnedGoRuntime || len(evidence) != 1 {
		t.Fatal("evidence views do not preserve the exact binding/callsite set")
	}
	before := set.SHA256()
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	bindings[0] = PinnedBinaryBindingView{}
	evidence[0] = PinnedCallsiteEvidenceView{}
	if set.SHA256() != before || len(set.BinaryBindings().Bindings()) != 1 || set.BinaryBindings().Bindings()[0].Role() != RoleLaunchBase || len(set.Evidence()) != 1 || set.Evidence()[0].CallsiteSHA256() == ([32]byte{}) {
		t.Fatal("caller or view mutation changed imported evidence")
	}
}

func TestImportPinnedCallsiteEvidenceRejectsAuthorityBoundsDigestAndEnvelopeInOrder(t *testing.T) {
	t.Parallel()

	badMagic := []byte("not-an-hl8e-envelope")
	validArtifact := VerifiedPolicyArtifact{sha256: [32]byte{1}, artifact: &verifiedArtifact{}}
	badMagicExpected := ExpectedPinnedCallsiteEvidence{
		sha256: pinnedEvidenceTestDigest(badMagic),
		issuer: expectedEvidenceIssuer{issued: true},
	}
	for _, test := range []struct {
		name     string
		encoded  []byte
		artifact VerifiedPolicyArtifact
		expected ExpectedPinnedCallsiteEvidence
		want     ErrorCode
	}{
		{
			name:     "zero expected authority",
			encoded:  badMagic,
			artifact: validArtifact,
			want:     ErrorCodeOwnership,
		},
		{
			name:     "foreign artifact",
			encoded:  badMagic,
			artifact: VerifiedPolicyArtifact{},
			expected: badMagicExpected,
			want:     ErrorCodeOwnership,
		},
		{
			name:     "empty evidence",
			artifact: validArtifact,
			expected: ExpectedPinnedCallsiteEvidence{sha256: [32]byte{1}, issuer: expectedEvidenceIssuer{issued: true}},
			want:     ErrorCodeBounds,
		},
		{
			name:     "oversized evidence",
			encoded:  make([]byte, MaxPinnedCallsiteEvidenceBytes+1),
			artifact: validArtifact,
			expected: ExpectedPinnedCallsiteEvidence{sha256: [32]byte{1}, issuer: expectedEvidenceIssuer{issued: true}},
			want:     ErrorCodeBounds,
		},
		{
			name:     "digest mismatch",
			encoded:  badMagic,
			artifact: validArtifact,
			expected: ExpectedPinnedCallsiteEvidence{sha256: [32]byte{1}, issuer: expectedEvidenceIssuer{issued: true}},
			want:     ErrorCodeDigestMismatch,
		},
		{
			name:     "bad magic",
			encoded:  badMagic,
			artifact: validArtifact,
			expected: badMagicExpected,
			want:     ErrorCodeEncoding,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set, err := ImportPinnedCallsiteEvidence(test.encoded, test.artifact, test.expected)
			if set.owner != nil || set.SHA256() != ([32]byte{}) {
				t.Fatal("rejected evidence import returned authority")
			}
			if got := contractErrorCode(err); got != test.want {
				t.Fatalf("ImportPinnedCallsiteEvidence() error = %v, want %v", got, test.want)
			}
		})
	}
}

func pinnedEvidenceTestDigest(encoded []byte) [32]byte {
	return framedSHA256("hal/l8/pinned-callsite-evidence/linux-amd64/v1", encoded)
}

func pinnedEvidenceTestEnvelope(artifact VerifiedPolicyArtifact, bindingReserved uint16) []byte {
	binding := new(bytes.Buffer)
	binding.WriteByte(byte(RoleLaunchBootstrap))
	binding.WriteByte(byte(BinaryBindingKindNativeBootstrap))
	_ = binary.Write(binding, binary.BigEndian, bindingReserved)
	_ = binary.Write(binding, binary.BigEndian, uint64(64))
	artifactSourceLock := artifact.SourceLockSHA256()
	binding.Write(artifactSourceLock[:])
	for value := byte(3); value <= 5; value++ {
		digest := [32]byte{value}
		binding.Write(digest[:])
	}
	bindingDigest := framedSHA256("hal/l8/pinned-binary-binding/linux-amd64/v1", binding.Bytes())

	bindingSetPreimage := new(bytes.Buffer)
	_ = binary.Write(bindingSetPreimage, binary.BigEndian, uint16(1))
	_ = binary.Write(bindingSetPreimage, binary.BigEndian, uint16(0))
	bindingSetPreimage.Write(binding.Bytes())
	bindingSetDigest := framedSHA256("hal/l8/pinned-binary-binding-set/linux-amd64/v1", bindingSetPreimage.Bytes())

	evidence := new(bytes.Buffer)
	callsite := [32]byte{6}
	observed := [32]byte{7}
	evidence.Write(callsite[:])
	evidence.Write(bindingDigest[:])
	evidence.Write(observed[:])
	_ = binary.Write(evidence, binary.BigEndian, uint64(0))

	envelope := new(bytes.Buffer)
	envelope.WriteString("HL8E")
	envelope.WriteByte(1)
	envelope.WriteByte(0)
	_ = binary.Write(envelope, binary.BigEndian, uint16(1))
	_ = binary.Write(envelope, binary.BigEndian, uint16(1))
	_ = binary.Write(envelope, binary.BigEndian, uint16(0))
	artifactDigest := artifact.SHA256()
	envelope.Write(artifactDigest[:])
	envelope.Write(artifactSourceLock[:])
	envelope.Write(bindingSetDigest[:])
	envelope.Write(binding.Bytes())
	envelope.Write(evidence.Bytes())
	return envelope.Bytes()
}

func pinnedEvidenceTestArtifact(t *testing.T) VerifiedPolicyArtifact {
	t.Helper()
	encoded := artifactTestCoherentEnvelopeWithTopology(
		artifactTestRolesBodyWithPinnedAndExactTransitions(),
		artifactTestExactAncestryBody(),
		9,
		1,
	)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	})
	if err != nil {
		t.Fatalf("import evidence test artifact: %v", err)
	}
	return artifact
}

func pinnedEvidenceCanonicalEnvelope(artifact VerifiedPolicyArtifact, substituteCallsite bool) []byte {
	requirement := artifact.artifact.pinnedCallsites[0]
	binding := new(bytes.Buffer)
	binding.WriteByte(byte(requirement.role))
	binding.WriteByte(byte(BinaryBindingKindPinnedGoRuntime))
	_ = binary.Write(binding, binary.BigEndian, uint16(0))
	_ = binary.Write(binding, binary.BigEndian, uint64(64))
	artifactSourceLock := artifact.SourceLockSHA256()
	binding.Write(artifactSourceLock[:])
	binding.Write(requirement.toolchainSHA256[:])
	for value := byte(12); value <= 13; value++ {
		digest := [32]byte{value}
		binding.Write(digest[:])
	}
	bindingDigest := framedSHA256("hal/l8/pinned-binary-binding/linux-amd64/v1", binding.Bytes())
	bindingSetPreimage := new(bytes.Buffer)
	_ = binary.Write(bindingSetPreimage, binary.BigEndian, uint16(1))
	_ = binary.Write(bindingSetPreimage, binary.BigEndian, uint16(0))
	bindingSetPreimage.Write(binding.Bytes())
	bindingSetDigest := framedSHA256("hal/l8/pinned-binary-binding-set/linux-amd64/v1", bindingSetPreimage.Bytes())

	callsite := requirement.sha256
	if substituteCallsite {
		callsite = [32]byte{0xff}
	}
	evidence := new(bytes.Buffer)
	evidence.Write(callsite[:])
	evidence.Write(bindingDigest[:])
	evidence.Write(requirement.instructionTemplateSHA256[:])
	_ = binary.Write(evidence, binary.BigEndian, uint64(0))

	envelope := new(bytes.Buffer)
	envelope.WriteString("HL8E")
	envelope.WriteByte(1)
	envelope.WriteByte(0)
	_ = binary.Write(envelope, binary.BigEndian, uint16(1))
	_ = binary.Write(envelope, binary.BigEndian, uint16(1))
	_ = binary.Write(envelope, binary.BigEndian, uint16(0))
	artifactDigest := artifact.SHA256()
	envelope.Write(artifactDigest[:])
	envelope.Write(artifactSourceLock[:])
	envelope.Write(bindingSetDigest[:])
	envelope.Write(binding.Bytes())
	envelope.Write(evidence.Bytes())
	return envelope.Bytes()
}
