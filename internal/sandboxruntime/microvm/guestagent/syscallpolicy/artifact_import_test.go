package syscallpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestImportVerifiedPolicyArtifactRejectsInvalidAuthorityAndEnvelopeInOrder(t *testing.T) {
	t.Parallel()

	badMagic := []byte("not-an-hl8q-artifact")
	badMagicExpected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(badMagic),
		issuer: expectedIssuer{issued: true},
	}

	for _, test := range []struct {
		name     string
		encoded  []byte
		expected ExpectedPolicyArtifact
		want     ErrorCode
	}{
		{
			name:     "zero expected authority",
			encoded:  badMagic,
			expected: ExpectedPolicyArtifact{},
			want:     ErrorCodeOwnership,
		},
		{
			name:     "issued marker with zero digest",
			encoded:  badMagic,
			expected: ExpectedPolicyArtifact{issuer: expectedIssuer{issued: true}},
			want:     ErrorCodeOwnership,
		},
		{
			name:     "empty artifact",
			encoded:  nil,
			expected: ExpectedPolicyArtifact{sha256: [32]byte{1}, issuer: expectedIssuer{issued: true}},
			want:     ErrorCodeBounds,
		},
		{
			name:     "oversized artifact",
			encoded:  make([]byte, MaxVerifiedPolicyArtifactBytes+1),
			expected: ExpectedPolicyArtifact{sha256: [32]byte{1}, issuer: expectedIssuer{issued: true}},
			want:     ErrorCodeBounds,
		},
		{
			name:     "digest mismatch precedes envelope parsing",
			encoded:  badMagic,
			expected: ExpectedPolicyArtifact{sha256: [32]byte{1}, issuer: expectedIssuer{issued: true}},
			want:     ErrorCodeDigestMismatch,
		},
		{
			name:     "bad magic after matching digest",
			encoded:  badMagic,
			expected: badMagicExpected,
			want:     ErrorCodeEncoding,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			artifact, err := ImportVerifiedPolicyArtifact(test.encoded, test.expected)
			if artifact.SHA256() != ([32]byte{}) || artifact.artifact != nil {
				t.Fatal("rejected import returned artifact authority")
			}
			if got := contractErrorCode(err); got != test.want {
				t.Fatalf("ImportVerifiedPolicyArtifact() error code = %v, want %v", got, test.want)
			}
		})
	}
}

func TestImportVerifiedPolicyArtifactRejectsMissingRequiredSectionRows(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEmptyEnvelope()
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("empty required sections returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeMissingSection {
		t.Fatalf("empty required sections error = %v, want missing-section", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedCatalogBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{{1}, {1}, {1}, {1}, {1}, {1}},
	)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated catalog returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated catalog error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedRolesBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{artifactTestCatalogBody(), {1}, {1}, {1}, {1}, {1}},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated roles returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated roles error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedAncestryBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{artifactTestCatalogBody(), artifactTestRolesBody(), {1}, {1}, {1}, {1}},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated ancestry returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated ancestry error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedWorkloadBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{artifactTestCatalogBody(), artifactTestRolesBody(), artifactTestAncestryBody(), {1}, {1}, {1}},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated workload returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated workload error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedRuntimeBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{artifactTestCatalogBody(), artifactTestRolesBody(), artifactTestAncestryBody(), artifactTestWorkloadBody(), {1}, {1}},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated runtime returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated runtime error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsTruncatedProvenanceBody(t *testing.T) {
	t.Parallel()

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{artifactTestCatalogBody(), artifactTestRolesBody(), artifactTestAncestryBody(), artifactTestWorkloadBody(), artifactTestRuntimeBody(), {1}},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("truncated provenance returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("truncated provenance error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsWorkloadAndRuntimeOriginSubstitution(t *testing.T) {
	t.Parallel()

	encoded := artifactTestCoherentWrongOriginEnvelope()
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("wrong-origin workload/runtime indexes returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeUnsafeWidening {
		t.Fatalf("wrong-origin workload/runtime error = %v, want unsafe-widening", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsScalarClauseReservedBytes(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBody()
	roles[64] = 1
	clause := make([]byte, policyScalarClauseBytes)
	clause[0] = 0
	clause[1] = byte(ScalarEqual)
	clause[2] = 1
	clause[3] = 1
	binary.BigEndian.PutUint32(clause[4:8], uint32(ActionErrnoEPERM))
	clause[8] = byte(ReasonScalarMismatch)
	mutatedRoles := append([]byte(nil), roles[:68]...)
	mutatedRoles = append(mutatedRoles, clause...)
	mutatedRoles = append(mutatedRoles, roles[68:]...)

	encoded := artifactTestCoherentEnvelopeWithRoles(mutatedRoles)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("reserved scalar bytes returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeEncoding {
		t.Fatalf("reserved scalar bytes error = %v, want encoding", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsUnverifiedAncestryUnion(t *testing.T) {
	t.Parallel()

	encoded := artifactTestCoherentEnvelope(artifactTestRolesBodyWithExactOrigins(), 9, 1)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("unverified ancestry union returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeInvalidAncestry {
		t.Fatalf("unverified ancestry union error = %v, want invalid-ancestry", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsMissingCrossRoleTransitions(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBodyWithExactOrigins()
	encoded := artifactTestCoherentEnvelopeWithTopology(roles, artifactTestExactAncestryBody(), 9, 1)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("missing cross-role transitions returned artifact authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeInvalidAncestry {
		t.Fatalf("missing cross-role transitions error = %v, want invalid-ancestry", got)
	}
}

func TestImportVerifiedPolicyArtifactRejectsReorderedTransitions(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBodyWithPinnedAndExactTransitions()
	cursor := artifactTestRoleSectionOffset(roles, RoleLaunchBase)
	stageCount := int(roles[cursor+1])
	transitionStart := cursor + policyRoleHeaderBytes + stageCount*policyStageRowBytes
	first := append([]byte(nil), roles[transitionStart:transitionStart+policyTransitionRowBytes]...)
	copy(roles[transitionStart:transitionStart+policyTransitionRowBytes], roles[transitionStart+policyTransitionRowBytes:transitionStart+2*policyTransitionRowBytes])
	copy(roles[transitionStart+policyTransitionRowBytes:transitionStart+2*policyTransitionRowBytes], first)
	encoded := artifactTestCoherentEnvelopeWithTopology(roles, artifactTestExactAncestryBody(), 9, 1)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	})
	if artifact.artifact != nil || contractErrorCode(err) != ErrorCodeDuplicate {
		t.Fatalf("reordered transitions = (%v, %v), want zero/duplicate", artifact.artifact, err)
	}
}

func TestImportVerifiedPolicyArtifactRejectsDuplicateCanonicalRules(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBodyWithPinnedAndExactTransitions()
	roleStart := artifactTestRoleSectionOffset(roles, RoleLaunchBootstrap)
	ruleStart := roleStart + policyRoleHeaderBytes + policyStageRowBytes + policyTransitionRowBytes
	ruleEnd := ruleStart + policyRuleHeaderBytes
	duplicate := append([]byte(nil), roles[ruleStart:ruleEnd]...)
	mutated := append([]byte(nil), roles[:ruleEnd]...)
	mutated = append(mutated, duplicate...)
	mutated = append(mutated, roles[ruleEnd:]...)
	binary.BigEndian.PutUint32(mutated[roleStart+4:roleStart+8], 2)
	encoded := artifactTestCoherentEnvelopeWithTopology(mutated, artifactTestExactAncestryBody(), 10, 2)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	})
	if artifact.artifact != nil || contractErrorCode(err) != ErrorCodeDuplicate {
		t.Fatalf("duplicate canonical rules returned authority or wrong error: %v", err)
	}
}

func TestImportVerifiedPolicyArtifactRejectsMissingPinnedCallsiteAuthority(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBodyWithExactTransitionsAndOrigins()
	encoded := artifactTestCoherentEnvelopeWithTopology(roles, artifactTestExactAncestryBody(), 9, 1)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if artifact.artifact != nil || artifact.SHA256() != ([32]byte{}) {
		t.Fatal("artifact without pinned callsites returned authority")
	}
	if got := contractErrorCode(err); got != ErrorCodeMissingSection {
		t.Fatalf("artifact without pinned callsites error = %v, want missing-section", got)
	}
}

func TestImportVerifiedPolicyArtifactAcceptsCompleteCanonicalEnvelopeAndCopiesInput(t *testing.T) {
	t.Parallel()

	roles := artifactTestRolesBodyWithPinnedAndExactTransitions()
	encoded := artifactTestCoherentEnvelopeWithTopology(roles, artifactTestExactAncestryBody(), 9, 1)
	expected := ExpectedPolicyArtifact{
		sha256: artifactTestDigest(encoded),
		issuer: expectedIssuer{issued: true},
	}
	artifact, err := ImportVerifiedPolicyArtifact(encoded, expected)
	if err != nil {
		t.Fatalf("ImportVerifiedPolicyArtifact() error = %v", err)
	}
	if artifact.artifact == nil || artifact.SHA256() != expected.SHA256() || artifact.SourceLockSHA256() == ([32]byte{}) {
		t.Fatal("complete canonical envelope did not return bound artifact authority")
	}
	if catalog := artifact.Catalog(); len(catalog) != 1 || catalog[0].Number() != 0 || catalog[0].Name() != "read" || catalog[0].Class() != SyscallClassOrdinary {
		t.Fatalf("catalog view = %#v, want one ordinary read row", catalog)
	}
	if artifact.Workload().SHA256() == ([32]byte{}) || artifact.Runtime().SHA256() == ([32]byte{}) || artifact.Runtime().GoVersion() != "go1.25.7" {
		t.Fatal("workload/runtime immutable views are incomplete")
	}
	if rules := artifact.Rules(); len(rules) != 10 || rules[9].Role() != RoleWorkload || rules[9].Origin() != RuleOriginWorkload || len(rules[1].PinnedCallsiteRequirements()) != 1 {
		t.Fatal("semantic rule views do not preserve role/origin/pinned authority")
	}
	if transitions := artifact.Transitions(); len(transitions) != 9 {
		t.Fatalf("transition views = %d, want 9", len(transitions))
	}
	if workloadRules := artifact.Workload().Rules(); len(workloadRules) != 1 || workloadRules[0].Rule().Origin() != RuleOriginWorkload {
		t.Fatal("workload view is not bound to its exact semantic row")
	}
	if runtimeRules := artifact.Runtime().Rules(); len(runtimeRules) != 1 || runtimeRules[0].Origin() != RuleOriginRuntime {
		t.Fatal("runtime view is not bound to its exact semantic row")
	}
	before := artifact.SHA256()
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	if artifact.SHA256() != before || artifact.Catalog()[0].Name() != "read" {
		t.Fatal("caller mutation changed imported artifact")
	}
	catalog := artifact.Catalog()
	catalog[0] = CatalogEntryView{}
	if artifact.Catalog()[0].Name() != "read" {
		t.Fatal("catalog slice mutation escaped immutable view")
	}
}

func TestVerifiedPolicySemanticRulePathsRejectUnsafeAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*verifiedArtifact)
		want   ErrorCode
	}{
		{
			name: "fatal catalog rule",
			mutate: func(artifact *verifiedArtifact) {
				artifact.catalog[0].class = SyscallClassFatal
			},
			want: ErrorCodeFatalAllow,
		},
		{
			name: "narrow direct rule",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].requiredFacts = StateFactPrepared
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "direct live requirement",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].pointers = []*pointerRequirement{{argumentIndex: 0, class: PointerClassFixedImage}}
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "pinned workload rule",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[9].enforcementPath = EnforcementPathPinnedDirect
				artifact.rules[9].pinnedCallsites = artifact.rules[1].pinnedCallsites
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "adapter proceed failure",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].enforcementPath = EnforcementPathAdapter
				artifact.rules[0].adapterFailure = AdapterOutcomeProceed
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "adapter missing state observation",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].enforcementPath = EnforcementPathAdapter
				artifact.rules[0].adapterFailure = AdapterOutcomeRejectCleanup
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "adapter invalid descriptor checks",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].enforcementPath = EnforcementPathAdapter
				artifact.rules[0].adapterFailure = AdapterOutcomeRejectCleanup
				artifact.rules[0].stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
				artifact.rules[0].descriptors = []*descriptorRequirement{{
					argumentIndex: 0,
					kind:          DescriptorKindInert,
					access:        DescriptorAccessRead,
				}}
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "descriptor without fd-width scalar",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].enforcementPath = EnforcementPathAdapter
				artifact.rules[0].adapterFailure = AdapterOutcomeRejectCleanup
				artifact.rules[0].stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
				artifact.rules[0].descriptors = []*descriptorRequirement{{
					argumentIndex:  0,
					kind:           DescriptorKindInert,
					access:         DescriptorAccessRead,
					requiredChecks: CheckSet{bits: checkBits(CheckFDKind, CheckFDAccess, CheckFDGeneration)},
				}}
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "descriptor scalar admits values above max int32",
			mutate: func(artifact *verifiedArtifact) {
				artifact.rules[0].enforcementPath = EnforcementPathAdapter
				artifact.rules[0].adapterFailure = AdapterOutcomeRejectCleanup
				artifact.rules[0].stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
				artifact.rules[0].scalarClauses = []*scalarClause{{argumentIndex: 0, operation: ScalarNonzero}}
				artifact.rules[0].descriptors = []*descriptorRequirement{{
					argumentIndex:  0,
					kind:           DescriptorKindInert,
					access:         DescriptorAccessRead,
					requiredChecks: CheckSet{bits: checkBits(CheckFDKind, CheckFDAccess, CheckFDGeneration)},
				}}
			},
			want: ErrorCodeUnsafeWidening,
		},
		{
			name: "conditional mandatory evidence omitted",
			mutate: func(artifact *verifiedArtifact) {
				artifact.catalog[0].class = SyscallClassConditional
				artifact.catalog[0].mandatoryEvidence = []*mandatoryEvidence{{
					kind:            EvidenceKindPointer,
					attachmentIndex: 0,
					requiredChecks:  CheckSet{bits: checkBits(CheckBoundedPointer)},
				}}
			},
			want: ErrorCodeUnsafeWidening,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifact := pinnedEvidenceTestArtifact(t)
			graph := cloneVerifiedArtifact(artifact.artifact)
			test.mutate(graph)
			if got := contractErrorCode(validateVerifiedPolicySemanticRules(graph)); got != test.want {
				t.Fatalf("validateVerifiedPolicySemanticRules() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestVerifiedPolicySemanticTransitionsRejectMissingTargetsAndCycles(t *testing.T) {
	t.Parallel()

	artifact := pinnedEvidenceTestArtifact(t)
	missingTarget := cloneVerifiedArtifact(artifact.artifact)
	missingTarget.transitions[0].to = StageClosed
	if got := contractErrorCode(validateVerifiedPolicySemanticTransitions(missingTarget)); got != ErrorCodeCatalog {
		t.Fatalf("missing target stage error = %v, want catalog", got)
	}

	cyclic := cloneVerifiedArtifact(artifact.artifact)
	cyclic.stages[RoleLaunchBootstrap][StagePreparing] = roleStage{role: RoleLaunchBootstrap, stage: StagePreparing}
	cyclic.stages[RoleLaunchBootstrap][StagePrepared] = roleStage{role: RoleLaunchBootstrap, stage: StagePrepared}
	cyclic.transitions = append(cyclic.transitions,
		&verifiedTransition{role: RoleLaunchBootstrap, from: StagePreparing, toRole: RoleLaunchBootstrap, to: StagePrepared},
		&verifiedTransition{role: RoleLaunchBootstrap, from: StagePrepared, toRole: RoleLaunchBootstrap, to: StagePreparing},
	)
	if got := contractErrorCode(validateVerifiedPolicySemanticTransitions(cyclic)); got != ErrorCodeContradiction {
		t.Fatalf("within-role cycle error = %v, want contradiction", got)
	}
}

func TestVerifiedPolicySemanticOverlapsRejectDirectAdapterAuthority(t *testing.T) {
	t.Parallel()

	artifact := cloneVerifiedArtifact(pinnedEvidenceTestArtifact(t).artifact)
	adapter := artifact.rules[2]
	adapter.enforcementPath = EnforcementPathAdapter
	adapter.adapterFailure = AdapterOutcomeRejectCleanup
	adapter.stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
	if got := contractErrorCode(validateVerifiedPolicyRuleOverlaps(artifact)); got != ErrorCodeUnsafeWidening {
		t.Fatalf("direct/adapter overlap error = %v, want unsafe-widening", got)
	}
}

func artifactTestDigest(encoded []byte) [32]byte {
	const domain = "hal/l8/verified-syscall-policy/linux-amd64/v1"
	framed := make([]byte, 2+len(domain)+len(encoded))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(domain)))
	copy(framed[2:], domain)
	copy(framed[2+len(domain):], encoded)
	return sha256.Sum256(framed)
}

func artifactTestEmptyEnvelope() []byte {
	return artifactTestEnvelope([6]uint16{}, [6][]byte{})
}

func artifactTestEnvelope(counts [6]uint16, bodies [6][]byte) []byte {
	sections := new(bytes.Buffer)
	for sectionIndex := 0; sectionIndex < verifiedPolicySectionCount; sectionIndex++ {
		sectionType := uint8(sectionIndex + 1)
		body := bodies[sectionIndex]
		sectionDigest := sha256.Sum256(body)
		sections.WriteByte(sectionType)
		sections.WriteByte(0)
		_ = binary.Write(sections, binary.BigEndian, counts[sectionIndex])
		_ = binary.Write(sections, binary.BigEndian, uint32(len(body)))
		sections.Write(sectionDigest[:])
		sections.Write(body)
	}

	encoded := make([]byte, verifiedPolicyArtifactHeaderBytes)
	copy(encoded[:4], "HL8Q")
	encoded[4] = 1
	encoded[5] = 1
	binary.BigEndian.PutUint16(encoded[8:10], 6)
	binary.BigEndian.PutUint16(encoded[10:12], 1)
	binary.BigEndian.PutUint16(encoded[12:14], 178)
	binary.BigEndian.PutUint16(encoded[14:16], verifiedPolicySectionCount)
	binary.BigEndian.PutUint32(encoded[16:20], uint32(sections.Len()))
	for index := 20; index < 84; index++ {
		encoded[index] = byte(index)
	}
	return append(encoded, sections.Bytes()...)
}

func artifactTestCatalogBody() []byte {
	const module = "golang.org/x/sys@v0.41.0"
	const sourcePath = "unix/zsysnum_linux_amd64.go"
	body := new(bytes.Buffer)
	body.WriteByte(byte(len(module)))
	body.WriteByte(byte(len(sourcePath)))
	_ = binary.Write(body, binary.BigEndian, uint16(0))
	_ = binary.Write(body, binary.BigEndian, uint32(450))
	body.WriteString(module)
	body.WriteString(sourcePath)
	_ = binary.Write(body, binary.BigEndian, uint32(0))
	body.WriteByte(byte(SyscallClassOrdinary))
	body.WriteByte(byte(len("read")))
	body.WriteByte(0)
	body.WriteByte(0)
	body.WriteString("read")
	return body.Bytes()
}

func artifactTestRolesBody() []byte {
	return artifactTestRolesBodyWithOrigins(nil)
}

func artifactTestRolesBodyWithExactOrigins() []byte {
	return artifactTestRolesBodyWithOrigins(map[Role]RuleOrigin{
		RoleLaunchBase: RuleOriginRuntime,
		RoleWorkload:   RuleOriginWorkload,
	})
}

func artifactTestRoleSectionOffset(body []byte, want Role) int {
	cursor := 0
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		start := cursor
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes + stageCount*policyStageRowBytes + transitionCount*policyTransitionRowBytes
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			cursor += policyRuleHeaderBytes + int(header[32])*policyScalarClauseBytes + int(header[33])*policyDescriptorRequirementBytes + int(header[34])*policyPointerRequirementBytes + int(header[35])*policyObjectRequirementBytes + int(header[5])*policyPinnedRequirementBytes
		}
		if role == want {
			return start
		}
	}
	return -1
}

func artifactTestRolesBodyWithExactTransitionsAndOrigins() []byte {
	return artifactTestRolesBodyWithExactTransitions(false)
}

func artifactTestRolesBodyWithPinnedAndExactTransitions() []byte {
	return artifactTestRolesBodyWithExactTransitions(true)
}

func artifactTestRolesBodyWithExactTransitions(includePinned bool) []byte {
	origins := map[Role]RuleOrigin{
		RoleLaunchBase: RuleOriginRuntime,
		RoleWorkload:   RuleOriginWorkload,
	}
	edges := map[Role][]Role{
		RoleLaunchBootstrap:     {RoleLaunchBase},
		RoleLaunchBase:          {RoleControllerBootstrap, RoleAgentBootstrap, RoleMonitorBootstrap, RoleWorkloadTransition},
		RoleControllerBootstrap: {RoleSteadyController},
		RoleAgentBootstrap:      {RoleSteadyAgent},
		RoleMonitorBootstrap:    {RoleSteadyMonitor},
		RoleWorkloadTransition:  {RoleWorkload},
	}
	body := new(bytes.Buffer)
	for role := RoleLaunchBootstrap; role <= RoleWorkload; role++ {
		body.WriteByte(byte(role))
		body.WriteByte(1)
		_ = binary.Write(body, binary.BigEndian, uint16(len(edges[role])))
		_ = binary.Write(body, binary.BigEndian, uint32(1))
		body.WriteByte(byte(StageActive))
		body.Write(make([]byte, 7))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		for _, toRole := range edges[role] {
			body.WriteByte(byte(StageActive))
			body.WriteByte(byte(toRole))
			body.WriteByte(byte(StageActive))
			body.WriteByte(0)
			for index := 0; index < 4; index++ {
				_ = binary.Write(body, binary.BigEndian, uint64(0))
			}
		}
		body.WriteByte(byte(role))
		body.WriteByte(byte(StageActive))
		origin := RuleOriginRole
		if configured, ok := origins[role]; ok {
			origin = configured
		}
		body.WriteByte(byte(origin))
		path := EnforcementPathDirect
		pinnedCount := byte(0)
		if includePinned && role == RoleLaunchBase {
			path = EnforcementPathPinnedDirect
			pinnedCount = 1
		}
		body.WriteByte(byte(path))
		body.WriteByte(byte(AdapterOutcomeProceed))
		body.WriteByte(pinnedCount)
		_ = binary.Write(body, binary.BigEndian, uint16(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint32(0))
		_ = binary.Write(body, binary.BigEndian, uint32(0))
		body.Write([]byte{0, 0, 0, 0})
		if pinnedCount != 0 {
			_ = binary.Write(body, binary.BigEndian, uint16(0))
			body.WriteByte(byte(PointerClassFixedImage))
			body.WriteByte(0)
			_ = binary.Write(body, binary.BigEndian, uint32(1))
			_ = binary.Write(body, binary.BigEndian, uint32(1))
			checks := uint32(1)<<(CheckCompiledConstant-1) | uint32(1)<<(CheckRuntimeMapping-1)
			_ = binary.Write(body, binary.BigEndian, checks)
			_ = binary.Write(body, binary.BigEndian, uint16(1))
			_ = binary.Write(body, binary.BigEndian, uint16(0))
			for _, value := range []byte{9, 10, 11, 8} {
				digest := [32]byte{value}
				body.Write(digest[:])
			}
		}
	}
	return body.Bytes()
}

func artifactTestRolesBodyWithOrigins(origins map[Role]RuleOrigin) []byte {
	body := new(bytes.Buffer)
	for role := RoleLaunchBootstrap; role <= RoleWorkload; role++ {
		body.WriteByte(byte(role))
		body.WriteByte(1)
		_ = binary.Write(body, binary.BigEndian, uint16(0))
		_ = binary.Write(body, binary.BigEndian, uint32(1))

		body.WriteByte(byte(StageActive))
		body.Write(make([]byte, 7))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))

		body.WriteByte(byte(role))
		body.WriteByte(byte(StageActive))
		origin := RuleOriginRole
		if configured, ok := origins[role]; ok {
			origin = configured
		}
		body.WriteByte(byte(origin))
		body.WriteByte(byte(EnforcementPathDirect))
		body.WriteByte(byte(AdapterOutcomeProceed))
		body.WriteByte(0)
		_ = binary.Write(body, binary.BigEndian, uint16(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint64(0))
		_ = binary.Write(body, binary.BigEndian, uint32(0))
		_ = binary.Write(body, binary.BigEndian, uint32(0))
		body.Write([]byte{0, 0, 0, 0})
	}
	return body.Bytes()
}

func artifactTestAncestryBody() []byte {
	body := new(bytes.Buffer)
	for index, record := range []struct {
		ancestor   Role
		descendant []Role
	}{
		{
			ancestor: RoleLaunchBase,
			descendant: []Role{
				RoleControllerBootstrap,
				RoleSteadyController,
				RoleAgentBootstrap,
				RoleSteadyAgent,
				RoleMonitorBootstrap,
				RoleSteadyMonitor,
				RoleWorkloadTransition,
				RoleWorkload,
			},
		},
		{ancestor: RoleWorkloadTransition, descendant: []Role{RoleWorkload}},
	} {
		body.WriteByte(byte(record.ancestor))
		body.WriteByte(byte(len(record.descendant)))
		_ = binary.Write(body, binary.BigEndian, uint16(0))
		digest := [32]byte{byte(index + 1)}
		body.Write(digest[:])
		for _, role := range record.descendant {
			body.WriteByte(byte(role))
		}
	}
	return body.Bytes()
}

func artifactTestExactAncestryBody() []byte {
	filterBytes := make([]byte, 8)
	preimage := make([]byte, 4, 12)
	binary.BigEndian.PutUint32(preimage[:4], 1)
	preimage = append(preimage, filterBytes...)
	unionDigest := framedSHA256("hal/l8/syscall-filter-projection/linux-amd64/v1", preimage)
	body := new(bytes.Buffer)
	for _, record := range []struct {
		ancestor    Role
		descendants []Role
	}{
		{
			ancestor: RoleLaunchBase,
			descendants: []Role{
				RoleControllerBootstrap,
				RoleSteadyController,
				RoleAgentBootstrap,
				RoleSteadyAgent,
				RoleMonitorBootstrap,
				RoleSteadyMonitor,
				RoleWorkloadTransition,
				RoleWorkload,
			},
		},
		{ancestor: RoleWorkloadTransition, descendants: []Role{RoleWorkload}},
	} {
		body.WriteByte(byte(record.ancestor))
		body.WriteByte(byte(len(record.descendants)))
		_ = binary.Write(body, binary.BigEndian, uint16(0))
		body.Write(unionDigest[:])
		for _, role := range record.descendants {
			body.WriteByte(byte(role))
		}
	}
	return body.Bytes()
}

func artifactTestWorkloadBody() []byte {
	body := new(bytes.Buffer)
	for index := byte(1); index <= 3; index++ {
		digest := [32]byte{index}
		body.Write(digest[:])
	}
	_ = binary.Write(body, binary.BigEndian, uint32(9))
	return body.Bytes()
}

func artifactTestRuntimeBody() []byte {
	body := new(bytes.Buffer)
	body.WriteByte(8)
	body.Write([]byte{0, 0, 0})
	for index := byte(4); index <= 5; index++ {
		digest := [32]byte{index}
		body.Write(digest[:])
	}
	body.WriteString("go1.25.7")
	_ = binary.Write(body, binary.BigEndian, uint32(0))
	return body.Bytes()
}

func artifactTestCoherentWrongOriginEnvelope() []byte {
	return artifactTestCoherentEnvelopeWithRoles(artifactTestRolesBody())
}

func artifactTestCoherentEnvelopeWithRoles(rolesBody []byte) []byte {
	return artifactTestCoherentEnvelope(rolesBody, 9, 0)
}

func artifactTestCoherentEnvelope(rolesBody []byte, workloadRuleIndex, runtimeRuleIndex uint32) []byte {
	return artifactTestCoherentEnvelopeWithTopology(rolesBody, artifactTestAncestryBody(), workloadRuleIndex, runtimeRuleIndex)
}

func artifactTestCoherentEnvelopeWithTopology(rolesBody, ancestryBody []byte, workloadRuleIndex, runtimeRuleIndex uint32) []byte {
	catalogBody := artifactTestCatalogBody()

	phaseHead := [32]byte{1}
	roleFSM := [32]byte{2}
	l4 := [32]byte{3}
	l7 := [32]byte{4}
	runtimeSource := [32]byte{5}
	generatorSource := [32]byte{6}
	generatorExecutable := [32]byte{7}
	toolchain := [32]byte{8}

	workloadLockPreimage := append(append(append(append([]byte(nil), l4[:]...), l7[:]...), roleFSM[:]...), generatorSource[:]...)
	workloadLock := framedSHA256("hal/l8/syscall-workload-source-lock/linux-amd64/v1", workloadLockPreimage)
	workloadBody := new(bytes.Buffer)
	workloadBody.Write(workloadLock[:])
	workloadBody.Write(l4[:])
	workloadBody.Write(l7[:])
	_ = binary.Write(workloadBody, binary.BigEndian, workloadRuleIndex)

	runtimeLockPreimage := []byte{8}
	runtimeLockPreimage = append(runtimeLockPreimage, "go1.25.7"...)
	runtimeLockPreimage = append(runtimeLockPreimage, runtimeSource[:]...)
	runtimeLockPreimage = append(runtimeLockPreimage, roleFSM[:]...)
	runtimeLockPreimage = append(runtimeLockPreimage, generatorSource[:]...)
	runtimeLock := framedSHA256("hal/l8/syscall-runtime-source-lock/linux-amd64/v1", runtimeLockPreimage)
	runtimeBody := new(bytes.Buffer)
	runtimeBody.WriteByte(8)
	runtimeBody.Write([]byte{0, 0, 0})
	runtimeBody.Write(runtimeSource[:])
	runtimeBody.Write(runtimeLock[:])
	runtimeBody.WriteString("go1.25.7")
	_ = binary.Write(runtimeBody, binary.BigEndian, runtimeRuleIndex)

	const module = "golang.org/x/sys@v0.41.0"
	const sourcePath = "unix/zsysnum_linux_amd64.go"
	catalogLockPreimage := []byte{byte(len(module))}
	catalogLockPreimage = append(catalogLockPreimage, module...)
	catalogLockPreimage = append(catalogLockPreimage, byte(len(sourcePath)))
	catalogLockPreimage = append(catalogLockPreimage, sourcePath...)
	ceiling := make([]byte, 4)
	binary.BigEndian.PutUint32(ceiling, 450)
	catalogLockPreimage = append(catalogLockPreimage, ceiling...)
	catalogLockPreimage = append(catalogLockPreimage, pinnedCatalogSourceSHA256[:]...)
	catalogLockPreimage = append(catalogLockPreimage, generatorSource[:]...)
	catalogLock := framedSHA256("hal/l8/syscall-catalog-source-lock/linux-amd64/v1", catalogLockPreimage)

	workloadSectionDigest := sha256.Sum256(workloadBody.Bytes())
	runtimeSectionDigest := sha256.Sum256(runtimeBody.Bytes())
	catalogSectionDigest := sha256.Sum256(catalogBody)
	provenanceBody := new(bytes.Buffer)
	for _, digest := range [11][32]byte{
		phaseHead,
		roleFSM,
		workloadLock,
		runtimeLock,
		catalogLock,
		generatorSource,
		generatorExecutable,
		toolchain,
		workloadSectionDigest,
		runtimeSectionDigest,
		catalogSectionDigest,
	} {
		provenanceBody.Write(digest[:])
	}

	encoded := artifactTestEnvelope(
		[6]uint16{1, 10, 2, 1, 1, 11},
		[6][]byte{catalogBody, rolesBody, ancestryBody, workloadBody.Bytes(), runtimeBody.Bytes(), provenanceBody.Bytes()},
	)
	copy(encoded[20:52], pinnedCatalogSourceSHA256[:])
	sourceLockPreimage := new(bytes.Buffer)
	for _, digest := range [8][32]byte{phaseHead, roleFSM, workloadLock, runtimeLock, catalogLock, generatorSource, generatorExecutable, toolchain} {
		sourceLockPreimage.Write(digest[:])
	}
	sourceLock := framedSHA256("hal/l8/verified-policy-source-lock/linux-amd64/v1", sourceLockPreimage.Bytes())
	copy(encoded[52:84], sourceLock[:])
	return encoded
}
