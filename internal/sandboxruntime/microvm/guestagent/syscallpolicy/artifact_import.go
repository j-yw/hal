package syscallpolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

const (
	verifiedPolicyArtifactDigestDomain = "hal/l8/verified-syscall-policy/linux-amd64/v1"
	verifiedPolicyArtifactHeaderBytes  = 84
	verifiedPolicySectionHeaderBytes   = 40
	verifiedPolicySectionCount         = 6
)

// ImportVerifiedPolicyArtifact verifies and snapshots the canonical HL8Q
// envelope. Section-specific semantic validation is layered on this closed
// envelope before authority is returned.
func ImportVerifiedPolicyArtifact(encoded []byte, expected ExpectedPolicyArtifact) (VerifiedPolicyArtifact, error) {
	if !expected.issuer.issued || zeroDigest(expected.sha256) {
		return VerifiedPolicyArtifact{}, contractError(ErrorCodeOwnership)
	}
	if len(encoded) == 0 || len(encoded) > MaxVerifiedPolicyArtifactBytes {
		return VerifiedPolicyArtifact{}, contractError(ErrorCodeBounds)
	}

	snapshot := append([]byte(nil), encoded...)
	digest := framedSHA256(verifiedPolicyArtifactDigestDomain, snapshot)
	if subtle.ConstantTimeCompare(digest[:], expected.sha256[:]) != 1 {
		return VerifiedPolicyArtifact{}, contractError(ErrorCodeDigestMismatch)
	}
	parsed, err := parseVerifiedPolicyArtifactEnvelope(snapshot)
	if err != nil {
		return VerifiedPolicyArtifact{}, err
	}
	parsed.sha256 = digest
	parsed.encoded = snapshot
	parsed.verified = true
	artifact := VerifiedPolicyArtifact{sha256: digest, artifact: parsed}
	if err := validateVerifiedPolicyPositiveDecisions(artifact); err != nil {
		return VerifiedPolicyArtifact{}, err
	}
	return artifact, nil
}

func parseVerifiedPolicyArtifactEnvelope(encoded []byte) (*verifiedArtifact, error) {
	if len(encoded) < verifiedPolicyArtifactHeaderBytes {
		return nil, contractError(ErrorCodeEncoding)
	}
	if string(encoded[:4]) != "HL8Q" || encoded[4] != 1 || encoded[5] != 1 || binary.BigEndian.Uint16(encoded[6:8]) != 0 {
		return nil, contractError(ErrorCodeEncoding)
	}
	if binary.BigEndian.Uint16(encoded[8:10]) != 6 || binary.BigEndian.Uint16(encoded[10:12]) != 1 || binary.BigEndian.Uint16(encoded[12:14]) != 178 {
		return nil, contractError(ErrorCodeEncoding)
	}
	if binary.BigEndian.Uint16(encoded[14:16]) != verifiedPolicySectionCount {
		return nil, contractError(ErrorCodeMissingSection)
	}
	bodyLength := int(binary.BigEndian.Uint32(encoded[16:20]))
	if bodyLength != len(encoded)-verifiedPolicyArtifactHeaderBytes {
		return nil, contractError(ErrorCodeBounds)
	}

	parsed := &verifiedArtifact{}
	copy(parsed.catalogSourceSHA256[:], encoded[20:52])
	copy(parsed.sourceLockSHA256[:], encoded[52:84])
	if zeroDigest(parsed.catalogSourceSHA256) || zeroDigest(parsed.sourceLockSHA256) {
		return nil, contractError(ErrorCodeCatalog)
	}

	cursor := verifiedPolicyArtifactHeaderBytes
	for sectionIndex := 0; sectionIndex < verifiedPolicySectionCount; sectionIndex++ {
		if len(encoded)-cursor < verifiedPolicySectionHeaderBytes {
			return nil, contractError(ErrorCodeEncoding)
		}
		header := encoded[cursor : cursor+verifiedPolicySectionHeaderBytes]
		wantType := uint8(sectionIndex + 1)
		if header[0] != wantType || header[1] != 0 {
			return nil, contractError(ErrorCodeEncoding)
		}
		itemCount := binary.BigEndian.Uint16(header[2:4])
		sectionLength := int(binary.BigEndian.Uint32(header[4:8]))
		if sectionLength < 0 || sectionLength > len(encoded)-cursor-verifiedPolicySectionHeaderBytes {
			return nil, contractError(ErrorCodeBounds)
		}
		var sectionDigest [32]byte
		copy(sectionDigest[:], header[8:40])
		if zeroDigest(sectionDigest) {
			return nil, contractError(ErrorCodeDigestMismatch)
		}
		bodyStart := cursor + verifiedPolicySectionHeaderBytes
		bodyEnd := bodyStart + sectionLength
		body := encoded[bodyStart:bodyEnd]
		computed := sha256.Sum256(body)
		if subtle.ConstantTimeCompare(computed[:], sectionDigest[:]) != 1 {
			return nil, contractError(ErrorCodeDigestMismatch)
		}
		parsed.sections[sectionIndex] = artifactSection{
			typ:       wantType,
			itemCount: itemCount,
			sha256:    sectionDigest,
			body:      append([]byte(nil), body...),
		}
		cursor = bodyEnd
	}
	if cursor != len(encoded) {
		return nil, contractError(ErrorCodeEncoding)
	}
	if err := validateVerifiedPolicySectionPresence(parsed.sections); err != nil {
		return nil, err
	}
	if err := parseVerifiedPolicyCatalog(parsed); err != nil {
		return nil, err
	}
	if err := validateVerifiedPolicyRolesEncoding(parsed.sections[1]); err != nil {
		return nil, err
	}
	if err := parseVerifiedPolicyAncestry(parsed); err != nil {
		return nil, err
	}
	if err := parseVerifiedPolicyWorkload(parsed); err != nil {
		return nil, err
	}
	if err := parseVerifiedPolicyRuntime(parsed); err != nil {
		return nil, err
	}
	if err := parseAndValidateVerifiedPolicyProvenance(parsed); err != nil {
		return nil, err
	}
	if err := validateVerifiedPolicyRuleIndexOrigins(parsed); err != nil {
		return nil, err
	}
	if err := validateVerifiedPolicyCrossRoleTransitions(parsed.sections[1]); err != nil {
		return nil, err
	}
	if err := validateVerifiedPolicyAncestryDigests(parsed); err != nil {
		return nil, err
	}
	if err := parseAndValidatePinnedCallsiteRequirements(parsed); err != nil {
		return nil, err
	}
	if err := decodeVerifiedPolicySemanticGraph(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

type policyRoleTransition struct {
	from Role
	to   Role
}

func validateVerifiedPolicyCrossRoleTransitions(section artifactSection) error {
	want := map[policyRoleTransition]struct{}{
		{from: RoleLaunchBootstrap, to: RoleLaunchBase}:           {},
		{from: RoleLaunchBase, to: RoleControllerBootstrap}:       {},
		{from: RoleControllerBootstrap, to: RoleSteadyController}: {},
		{from: RoleLaunchBase, to: RoleAgentBootstrap}:            {},
		{from: RoleAgentBootstrap, to: RoleSteadyAgent}:           {},
		{from: RoleLaunchBase, to: RoleMonitorBootstrap}:          {},
		{from: RoleMonitorBootstrap, to: RoleSteadyMonitor}:       {},
		{from: RoleLaunchBase, to: RoleWorkloadTransition}:        {},
		{from: RoleWorkloadTransition, to: RoleWorkload}:          {},
	}
	got := make(map[policyRoleTransition]struct{}, len(want))
	body := section.body
	cursor := 0
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes + stageCount*policyStageRowBytes
		for transitionIndex := 0; transitionIndex < transitionCount; transitionIndex++ {
			row := body[cursor : cursor+policyTransitionRowBytes]
			toRole := Role(row[1])
			if toRole != role {
				transition := policyRoleTransition{from: role, to: toRole}
				if _, exists := got[transition]; exists {
					return contractError(ErrorCodeDuplicate)
				}
				got[transition] = struct{}{}
			}
			cursor += policyTransitionRowBytes
		}
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			cursor += policyRuleHeaderBytes +
				int(header[32])*policyScalarClauseBytes +
				int(header[33])*policyDescriptorRequirementBytes +
				int(header[34])*policyPointerRequirementBytes +
				int(header[35])*policyObjectRequirementBytes +
				int(header[5])*policyPinnedRequirementBytes
		}
	}
	if len(got) != len(want) {
		return contractError(ErrorCodeInvalidAncestry)
	}
	for transition := range want {
		if _, exists := got[transition]; !exists {
			return contractError(ErrorCodeInvalidAncestry)
		}
	}
	return nil
}

var pinnedCatalogSourceSHA256 = [32]byte{
	0xd1, 0x2b, 0xc5, 0x09, 0xfb, 0xe7, 0x9a, 0xfd,
	0x80, 0x4a, 0x66, 0x29, 0x7c, 0x75, 0x17, 0x07,
	0x6e, 0xea, 0x6f, 0x3c, 0x8d, 0x82, 0x78, 0x06,
	0x30, 0xcd, 0x07, 0xf5, 0x61, 0xb0, 0x43, 0xb6,
}

func parseVerifiedPolicyCatalog(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	section := artifact.sections[0]
	body := section.body
	if len(body) < 8 {
		return contractError(ErrorCodeEncoding)
	}
	if subtle.ConstantTimeCompare(artifact.catalogSourceSHA256[:], pinnedCatalogSourceSHA256[:]) != 1 {
		return contractError(ErrorCodeCatalog)
	}
	moduleLength := int(body[0])
	pathLength := int(body[1])
	if binary.BigEndian.Uint16(body[2:4]) != 0 || binary.BigEndian.Uint32(body[4:8]) != 450 {
		return contractError(ErrorCodeCatalog)
	}
	cursor := 8
	if moduleLength == 0 || pathLength == 0 || moduleLength > len(body)-cursor {
		return contractError(ErrorCodeEncoding)
	}
	module := string(body[cursor : cursor+moduleLength])
	cursor += moduleLength
	if pathLength > len(body)-cursor {
		return contractError(ErrorCodeEncoding)
	}
	sourcePath := string(body[cursor : cursor+pathLength])
	cursor += pathLength
	if module != "golang.org/x/sys@v0.41.0" || sourcePath != "unix/zsysnum_linux_amd64.go" {
		return contractError(ErrorCodeCatalog)
	}

	entries := make([]*catalogEntry, 0, section.itemCount)
	var previousNumber SyscallNumber
	for entryIndex := 0; entryIndex < int(section.itemCount); entryIndex++ {
		if len(body)-cursor < 8 {
			return contractError(ErrorCodeEncoding)
		}
		number := SyscallNumber(binary.BigEndian.Uint32(body[cursor : cursor+4]))
		class := SyscallClass(body[cursor+4])
		nameLength := int(body[cursor+5])
		evidenceCount := int(body[cursor+6])
		if body[cursor+7] != 0 {
			return contractError(ErrorCodeEncoding)
		}
		cursor += 8
		if number > 450 || (entryIndex > 0 && number <= previousNumber) {
			return contractError(ErrorCodeDuplicate)
		}
		if ValidateSyscallClass(class) != nil {
			return contractError(ErrorCodeCatalog)
		}
		if nameLength == 0 || nameLength > MaxPolicyNameBytes || nameLength > len(body)-cursor {
			return contractError(ErrorCodeBounds)
		}
		name := string(body[cursor : cursor+nameLength])
		cursor += nameLength
		if !validPolicyCatalogName(number, name) {
			return contractError(ErrorCodeCatalog)
		}
		if (class == SyscallClassConditional) != (evidenceCount > 0) {
			return contractError(ErrorCodeUnsafeWidening)
		}

		entry := &catalogEntry{number: number, name: name, class: class}
		entry.mandatoryEvidence = make([]*mandatoryEvidence, 0, evidenceCount)
		var previousKind EvidenceKind
		var previousIndex uint16
		for evidenceIndex := 0; evidenceIndex < evidenceCount; evidenceIndex++ {
			if len(body)-cursor < 8 {
				return contractError(ErrorCodeEncoding)
			}
			kind := EvidenceKind(body[cursor])
			reserved := body[cursor+1]
			attachmentIndex := binary.BigEndian.Uint16(body[cursor+2 : cursor+4])
			bits := binary.BigEndian.Uint32(body[cursor+4 : cursor+8])
			cursor += 8
			if reserved != 0 {
				return contractError(ErrorCodeEncoding)
			}
			if ValidateEvidenceKind(kind) != nil || bits == 0 || bits&^knownCheckBits() != 0 || !validEvidenceAttachment(kind, attachmentIndex) {
				return contractError(ErrorCodeCatalog)
			}
			if evidenceIndex > 0 && (kind < previousKind || kind == previousKind && attachmentIndex <= previousIndex) {
				return contractError(ErrorCodeDuplicate)
			}
			entry.mandatoryEvidence = append(entry.mandatoryEvidence, &mandatoryEvidence{
				kind:            kind,
				attachmentIndex: attachmentIndex,
				requiredChecks:  CheckSet{bits: bits},
			})
			previousKind = kind
			previousIndex = attachmentIndex
		}
		entries = append(entries, entry)
		previousNumber = number
	}
	if cursor != len(body) {
		return contractError(ErrorCodeEncoding)
	}
	artifact.catalog = entries
	return nil
}

func validPolicyCatalogName(number SyscallNumber, name string) bool {
	if number == 156 {
		return name == "_sysctl"
	}
	if name == "_sysctl" {
		return false
	}
	if len(name) == 0 || len(name) > MaxPolicyNameBytes || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, character := range []byte(name[1:]) {
		if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func knownCheckBits() uint32 { return (uint32(1) << CheckCompiledConstant) - 1 }

func validEvidenceAttachment(kind EvidenceKind, index uint16) bool {
	switch kind {
	case EvidenceKindState:
		return index == 0
	case EvidenceKindDescriptor, EvidenceKindPointer, EvidenceKindArgumentObject:
		return index <= 5
	case EvidenceKindReturnObject:
		return index == 255
	case EvidenceKindPinnedCallsite:
		return true
	default:
		return false
	}
}

const (
	policyRoleHeaderBytes            = 8
	policyStageRowBytes              = 24
	policyTransitionRowBytes         = 36
	policyRuleHeaderBytes            = 36
	policyScalarClauseBytes          = 84
	policyDescriptorRequirementBytes = 44
	policyPointerRequirementBytes    = 16
	policyObjectRequirementBytes     = 44
	policyPinnedRequirementBytes     = 148
)

func validateVerifiedPolicyRolesEncoding(section artifactSection) error {
	body := section.body
	cursor := 0
	totalRules := 0
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		if len(body)-cursor < policyRoleHeaderBytes {
			return contractError(ErrorCodeEncoding)
		}
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes
		if role != Role(roleIndex+1) || ValidateRole(role) != nil {
			return contractError(ErrorCodeCatalog)
		}
		if stageCount == 0 || ruleCount == 0 {
			return contractError(ErrorCodeMissingSection)
		}
		if stageCount > MaxPolicyStagesPerRole || transitionCount > MaxPolicyTransitionsPerRole || ruleCount > MaxPolicyRulesPerRole {
			return contractError(ErrorCodeBounds)
		}
		totalRules += ruleCount
		if totalRules > MaxPolicyRules {
			return contractError(ErrorCodeBounds)
		}

		var previousStage Stage
		stages := make(map[Stage]struct{}, stageCount)
		for stageIndex := 0; stageIndex < stageCount; stageIndex++ {
			if len(body)-cursor < policyStageRowBytes {
				return contractError(ErrorCodeEncoding)
			}
			row := body[cursor : cursor+policyStageRowBytes]
			stage := Stage(row[0])
			if !allZero(row[1:8]) {
				return contractError(ErrorCodeEncoding)
			}
			required := StateFact(binary.BigEndian.Uint64(row[8:16]))
			prohibited := StateFact(binary.BigEndian.Uint64(row[16:24]))
			if ValidateStage(stage) != nil || ValidateStateFacts(required) != nil || ValidateStateFacts(prohibited) != nil {
				return contractError(ErrorCodeCatalog)
			}
			if stageIndex > 0 && stage <= previousStage {
				return contractError(ErrorCodeDuplicate)
			}
			if required&prohibited != 0 {
				return contractError(ErrorCodeContradiction)
			}
			stages[stage] = struct{}{}
			previousStage = stage
			cursor += policyStageRowBytes
		}

		var previousTransition []byte
		for transitionIndex := 0; transitionIndex < transitionCount; transitionIndex++ {
			if len(body)-cursor < policyTransitionRowBytes {
				return contractError(ErrorCodeEncoding)
			}
			row := body[cursor : cursor+policyTransitionRowBytes]
			from := Stage(row[0])
			toRole := Role(row[1])
			to := Stage(row[2])
			if row[3] != 0 {
				return contractError(ErrorCodeEncoding)
			}
			if _, ok := stages[from]; !ok || ValidateRole(toRole) != nil || ValidateStage(to) != nil {
				return contractError(ErrorCodeCatalog)
			}
			masks := [4]StateFact{
				StateFact(binary.BigEndian.Uint64(row[4:12])),
				StateFact(binary.BigEndian.Uint64(row[12:20])),
				StateFact(binary.BigEndian.Uint64(row[20:28])),
				StateFact(binary.BigEndian.Uint64(row[28:36])),
			}
			for _, mask := range masks {
				if ValidateStateFacts(mask) != nil {
					return contractError(ErrorCodeCatalog)
				}
			}
			if masks[0]&masks[1] != 0 || masks[2]&masks[3] != 0 || role == toRole && from == to {
				return contractError(ErrorCodeContradiction)
			}
			if transitionIndex > 0 && bytes.Compare(row, previousTransition) <= 0 {
				return contractError(ErrorCodeDuplicate)
			}
			previousTransition = append(previousTransition[:0], row...)
			cursor += policyTransitionRowBytes
		}

		var previousRuleStage Stage
		var previousRuleNumber SyscallNumber
		var previousRule []byte
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			if len(body)-cursor < policyRuleHeaderBytes {
				return contractError(ErrorCodeEncoding)
			}
			header := body[cursor : cursor+policyRuleHeaderBytes]
			if Role(header[0]) != role || ValidateStage(Stage(header[1])) != nil || ValidateRuleOrigin(RuleOrigin(header[2])) != nil || ValidateEnforcementPath(EnforcementPath(header[3])) != nil || ValidateAdapterOutcome(AdapterOutcome(header[4])) != nil || binary.BigEndian.Uint16(header[6:8]) != 0 {
				return contractError(ErrorCodeCatalog)
			}
			if _, ok := stages[Stage(header[1])]; !ok {
				return contractError(ErrorCodeMissingSection)
			}
			required := StateFact(binary.BigEndian.Uint64(header[8:16]))
			prohibited := StateFact(binary.BigEndian.Uint64(header[16:24]))
			if ValidateStateFacts(required) != nil || ValidateStateFacts(prohibited) != nil || required&prohibited != 0 {
				return contractError(ErrorCodeContradiction)
			}
			if binary.BigEndian.Uint32(header[28:32])&^knownCheckBits() != 0 {
				return contractError(ErrorCodeCatalog)
			}
			counts := [5]int{int(header[32]), int(header[33]), int(header[34]), int(header[35]), int(header[5])}
			limits := [5]int{MaxPolicyScalarClausesPerRule, MaxPolicyDescriptorRequirementsPerRule, MaxPolicyPointerRequirementsPerRule, MaxPolicyObjectRequirementsPerRule, MaxPinnedCallsiteRequirementsPerRule}
			rowSizes := [5]int{policyScalarClauseBytes, policyDescriptorRequirementBytes, policyPointerRequirementBytes, policyObjectRequirementBytes, policyPinnedRequirementBytes}
			rowLength := policyRuleHeaderBytes
			for index, count := range counts {
				if count > limits[index] {
					return contractError(ErrorCodeBounds)
				}
				rowLength += count * rowSizes[index]
			}
			if rowLength > len(body)-cursor {
				return contractError(ErrorCodeEncoding)
			}
			if err := validateVerifiedPolicyRuleAttachments(header, body[cursor+policyRuleHeaderBytes:cursor+rowLength]); err != nil {
				return err
			}
			stage := Stage(header[1])
			number := SyscallNumber(binary.BigEndian.Uint32(header[24:28]))
			encodedRule := body[cursor : cursor+rowLength]
			if ruleIndex > 0 && (stage < previousRuleStage || stage == previousRuleStage && (number < previousRuleNumber || number == previousRuleNumber && bytes.Compare(encodedRule, previousRule) <= 0)) {
				return contractError(ErrorCodeDuplicate)
			}
			previousRuleStage = stage
			previousRuleNumber = number
			previousRule = append(previousRule[:0], encodedRule...)
			cursor += rowLength
		}
	}
	if cursor != len(body) {
		return contractError(ErrorCodeEncoding)
	}
	return nil
}

func validateVerifiedPolicyRuleAttachments(header, attachments []byte) error {
	cursor := 0
	var previousArgument uint8
	for index := 0; index < int(header[32]); index++ {
		row := attachments[cursor : cursor+policyScalarClauseBytes]
		argument := row[0]
		operation := ScalarOperation(row[1])
		valueCount := int(row[2])
		if row[3] != 0 || !allZero(row[9:12]) {
			return contractError(ErrorCodeEncoding)
		}
		if argument > 5 || ValidateScalarOperation(operation) != nil || valueCount > MaxPolicyScalarValuesPerClause {
			return contractError(ErrorCodeCatalog)
		}
		if index > 0 && argument <= previousArgument {
			return contractError(ErrorCodeDuplicate)
		}
		action := Action(binary.BigEndian.Uint32(row[4:8]))
		reason := Reason(row[8])
		if action != ActionKillProcess && action != ActionErrnoEPERM || ValidateReason(reason) != nil || reason == ReasonExactRule {
			return contractError(ErrorCodeCatalog)
		}
		mask := binary.BigEndian.Uint64(row[12:20])
		values := [MaxPolicyScalarValuesPerClause]uint64{}
		for valueIndex := range values {
			values[valueIndex] = binary.BigEndian.Uint64(row[20+valueIndex*8 : 28+valueIndex*8])
		}
		for valueIndex := valueCount; valueIndex < len(values); valueIndex++ {
			if values[valueIndex] != 0 {
				return contractError(ErrorCodeEncoding)
			}
		}
		switch operation {
		case ScalarEqual:
			if valueCount != 1 || mask != 0 {
				return contractError(ErrorCodeContradiction)
			}
		case ScalarMaskedEqual:
			if valueCount != 1 || mask == 0 || values[0]&^mask != 0 {
				return contractError(ErrorCodeContradiction)
			}
		case ScalarOneOf:
			if valueCount < 2 || mask != 0 {
				return contractError(ErrorCodeContradiction)
			}
			for valueIndex := 1; valueIndex < valueCount; valueIndex++ {
				if values[valueIndex] <= values[valueIndex-1] {
					return contractError(ErrorCodeDuplicate)
				}
			}
		case ScalarUnsignedRange:
			if valueCount != 2 || mask != 0 || values[0] > values[1] {
				return contractError(ErrorCodeContradiction)
			}
		case ScalarZero, ScalarNonzero:
			if valueCount != 0 || mask != 0 {
				return contractError(ErrorCodeContradiction)
			}
		}
		previousArgument = argument
		cursor += policyScalarClauseBytes
	}

	previousArgument = 0
	for index := 0; index < int(header[33]); index++ {
		row := attachments[cursor : cursor+policyDescriptorRequirementBytes]
		if err := validateDescriptorLikeRequirement(row[0], DescriptorKind(row[1]), DescriptorAccess(row[2]), row[3], GenerationMode(row[4]), row[5], row[6:8], binary.BigEndian.Uint32(row[8:12]), row[12:44], false); err != nil {
			return err
		}
		if index > 0 && row[0] <= previousArgument {
			return contractError(ErrorCodeDuplicate)
		}
		previousArgument = row[0]
		cursor += policyDescriptorRequirementBytes
	}

	previousArgument = 0
	for index := 0; index < int(header[34]); index++ {
		row := attachments[cursor : cursor+policyPointerRequirementBytes]
		argument := row[0]
		class := PointerClass(row[1])
		minimum := binary.BigEndian.Uint32(row[4:8])
		maximum := binary.BigEndian.Uint32(row[8:12])
		checks := binary.BigEndian.Uint32(row[12:16])
		if !allZero(row[2:4]) {
			return contractError(ErrorCodeEncoding)
		}
		if argument > 5 || ValidatePointerClass(class) != nil || class == PointerClassNone || checks == 0 || checks&^knownCheckBits() != 0 {
			return contractError(ErrorCodeCatalog)
		}
		if minimum == 0 || minimum > maximum || maximum > 1048576 {
			return contractError(ErrorCodeBounds)
		}
		if index > 0 && argument <= previousArgument {
			return contractError(ErrorCodeDuplicate)
		}
		previousArgument = argument
		cursor += policyPointerRequirementBytes
	}

	previousArgument = 0
	for index := 0; index < int(header[35]); index++ {
		row := attachments[cursor : cursor+policyObjectRequirementBytes]
		source := ObjectSource(row[0])
		argument := row[1]
		if ValidateObjectSource(source) != nil || source == ObjectSourceArgument && argument > 5 || source == ObjectSourceReturn && argument != 255 {
			return contractError(ErrorCodeCatalog)
		}
		if err := validateDescriptorLikeRequirement(argument, DescriptorKind(row[2]), DescriptorAccess(row[3]), row[4], GenerationMode(row[5]), row[6], row[7:8], binary.BigEndian.Uint32(row[8:12]), row[12:44], source == ObjectSourceReturn); err != nil {
			return err
		}
		if index > 0 && argument <= previousArgument {
			return contractError(ErrorCodeDuplicate)
		}
		previousArgument = argument
		cursor += policyObjectRequirementBytes
	}

	var previousOrdinal uint16
	for index := 0; index < int(header[5]); index++ {
		row := attachments[cursor : cursor+policyPinnedRequirementBytes]
		ordinal := binary.BigEndian.Uint16(row[0:2])
		class := PointerClass(row[2])
		minimum := binary.BigEndian.Uint32(row[4:8])
		maximum := binary.BigEndian.Uint32(row[8:12])
		checks := binary.BigEndian.Uint32(row[12:16])
		instructionLength := binary.BigEndian.Uint16(row[16:18])
		if row[3] != 0 || !allZero(row[18:20]) {
			return contractError(ErrorCodeEncoding)
		}
		if ValidatePointerClass(class) != nil || class == PointerClassNone || checks == 0 || checks&^knownCheckBits() != 0 {
			return contractError(ErrorCodeCatalog)
		}
		if minimum == 0 || minimum > maximum || maximum > 1048576 || instructionLength == 0 || instructionLength > 4096 {
			return contractError(ErrorCodeBounds)
		}
		if index > 0 && ordinal <= previousOrdinal {
			return contractError(ErrorCodeDuplicate)
		}
		for digestIndex := 0; digestIndex < 4; digestIndex++ {
			var digest [32]byte
			copy(digest[:], row[20+digestIndex*32:52+digestIndex*32])
			if zeroDigest(digest) {
				return contractError(ErrorCodeCatalog)
			}
		}
		previousOrdinal = ordinal
		cursor += policyPinnedRequirementBytes
	}
	if cursor != len(attachments) {
		return contractError(ErrorCodeEncoding)
	}
	return nil
}

func validateDescriptorLikeRequirement(argument uint8, kind DescriptorKind, access DescriptorAccess, fixed uint8, generationMode GenerationMode, bindingSlot uint8, reserved []byte, checks uint32, digestBytes []byte, returned bool) error {
	if !allZero(reserved) {
		return contractError(ErrorCodeEncoding)
	}
	if argument > 5 && !returned || ValidateDescriptorKind(kind) != nil || ValidateDescriptorAccess(access) != nil || fixed > 1 || ValidateGenerationMode(generationMode) != nil || checks == 0 || checks&^knownCheckBits() != 0 {
		return contractError(ErrorCodeCatalog)
	}
	var generation [32]byte
	copy(generation[:], digestBytes)
	switch generationMode {
	case GenerationModeStaticExact:
		if bindingSlot != 0 || zeroDigest(generation) {
			return contractError(ErrorCodeContradiction)
		}
	case GenerationModeLiveBound:
		if returned || bindingSlot == 0 || bindingSlot > MaxAdapterBindings || !zeroDigest(generation) {
			return contractError(ErrorCodeContradiction)
		}
	case GenerationModeFreshReturn:
		if !returned || bindingSlot != 0 || !zeroDigest(generation) {
			return contractError(ErrorCodeContradiction)
		}
	}
	return nil
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func parseVerifiedPolicyAncestry(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	body := artifact.sections[2].body
	cursor := 0
	wantAncestors := [2]Role{RoleLaunchBase, RoleWorkloadTransition}
	wantDescendants := [2][]Role{
		{
			RoleControllerBootstrap,
			RoleSteadyController,
			RoleAgentBootstrap,
			RoleSteadyAgent,
			RoleMonitorBootstrap,
			RoleSteadyMonitor,
			RoleWorkloadTransition,
			RoleWorkload,
		},
		{RoleWorkload},
	}
	for recordIndex := range wantAncestors {
		if len(body)-cursor < 36 {
			return contractError(ErrorCodeEncoding)
		}
		ancestor := Role(body[cursor])
		descendantCount := int(body[cursor+1])
		if binary.BigEndian.Uint16(body[cursor+2:cursor+4]) != 0 {
			return contractError(ErrorCodeEncoding)
		}
		var unionDigest [32]byte
		copy(unionDigest[:], body[cursor+4:cursor+36])
		cursor += 36
		if descendantCount > len(body)-cursor {
			return contractError(ErrorCodeEncoding)
		}
		if ancestor != wantAncestors[recordIndex] || descendantCount != len(wantDescendants[recordIndex]) {
			return contractError(ErrorCodeInvalidAncestry)
		}
		if zeroDigest(unionDigest) {
			return contractError(ErrorCodeDigestMismatch)
		}
		descendants := make([]Role, descendantCount)
		for descendantIndex := 0; descendantIndex < descendantCount; descendantIndex++ {
			descendant := Role(body[cursor+descendantIndex])
			if descendant != wantDescendants[recordIndex][descendantIndex] {
				return contractError(ErrorCodeInvalidAncestry)
			}
			descendants[descendantIndex] = descendant
		}
		cursor += descendantCount
		artifact.ancestry[recordIndex] = ancestryRecord{
			ancestorRole: ancestor,
			unionSHA256:  unionDigest,
			descendants:  descendants,
		}
	}
	if cursor != len(body) {
		return contractError(ErrorCodeEncoding)
	}
	return nil
}

func parseVerifiedPolicyWorkload(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	section := artifact.sections[3]
	body := section.body
	wantLength := 96 + int(section.itemCount)*4
	if len(body) != wantLength {
		return contractError(ErrorCodeEncoding)
	}
	var sourceLock, l4, l7 [32]byte
	copy(sourceLock[:], body[0:32])
	copy(l4[:], body[32:64])
	copy(l7[:], body[64:96])
	if zeroDigest(sourceLock) || zeroDigest(l4) || zeroDigest(l7) {
		return contractError(ErrorCodeCatalog)
	}
	indexes := make([]uint32, section.itemCount)
	var previous uint32
	for index := range indexes {
		value := binary.BigEndian.Uint32(body[96+index*4 : 100+index*4])
		if index > 0 && value <= previous {
			return contractError(ErrorCodeDuplicate)
		}
		indexes[index] = value
		previous = value
	}
	artifact.workload = WorkloadSnapshot{
		sha256:     framedSHA256("hal/l8/syscall-workload-snapshot/linux-amd64/v1", body),
		sourceLock: sourceLock,
		l4:         l4,
		l7:         l7,
	}
	artifact.workloadRuleIndexes = indexes
	return nil
}

func parseVerifiedPolicyRuntime(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	section := artifact.sections[4]
	body := section.body
	if len(body) < 68 {
		return contractError(ErrorCodeEncoding)
	}
	versionLength := int(body[0])
	if versionLength != 8 || !allZero(body[1:4]) {
		return contractError(ErrorCodeCatalog)
	}
	wantLength := 68 + versionLength + int(section.itemCount)*4
	if len(body) != wantLength {
		return contractError(ErrorCodeEncoding)
	}
	var source, sourceLock [32]byte
	copy(source[:], body[4:36])
	copy(sourceLock[:], body[36:68])
	if zeroDigest(source) || zeroDigest(sourceLock) {
		return contractError(ErrorCodeCatalog)
	}
	version := string(body[68 : 68+versionLength])
	if version != "go1.25.7" {
		return contractError(ErrorCodeCatalog)
	}
	indexes := make([]uint32, section.itemCount)
	cursor := 68 + versionLength
	var previous uint32
	for index := range indexes {
		value := binary.BigEndian.Uint32(body[cursor+index*4 : cursor+(index+1)*4])
		if index > 0 && value <= previous {
			return contractError(ErrorCodeDuplicate)
		}
		indexes[index] = value
		previous = value
	}
	artifact.runtime = RuntimeProfileView{
		goVersion:  version,
		sha256:     framedSHA256("hal/l8/syscall-runtime-profile/linux-amd64/v1", body),
		source:     source,
		sourceLock: sourceLock,
	}
	artifact.runtimeRuleIndexes = indexes
	return nil
}

func parseAndValidateVerifiedPolicyProvenance(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	body := artifact.sections[5].body
	if len(body) != 11*sha256.Size {
		return contractError(ErrorCodeEncoding)
	}
	for index := range artifact.provenance {
		copy(artifact.provenance[index][:], body[index*sha256.Size:(index+1)*sha256.Size])
		if zeroDigest(artifact.provenance[index]) {
			return contractError(ErrorCodeCatalog)
		}
	}

	sourceLockPreimage := make([]byte, 0, 8*sha256.Size)
	for index := 0; index < 8; index++ {
		sourceLockPreimage = append(sourceLockPreimage, artifact.provenance[index][:]...)
	}
	wantSourceLock := framedSHA256("hal/l8/verified-policy-source-lock/linux-amd64/v1", sourceLockPreimage)
	if subtle.ConstantTimeCompare(wantSourceLock[:], artifact.sourceLockSHA256[:]) != 1 {
		return contractError(ErrorCodeDigestMismatch)
	}

	workloadPreimage := make([]byte, 0, 4*sha256.Size)
	workloadPreimage = append(workloadPreimage, artifact.workload.l4[:]...)
	workloadPreimage = append(workloadPreimage, artifact.workload.l7[:]...)
	workloadPreimage = append(workloadPreimage, artifact.provenance[1][:]...)
	workloadPreimage = append(workloadPreimage, artifact.provenance[5][:]...)
	wantWorkloadLock := framedSHA256("hal/l8/syscall-workload-source-lock/linux-amd64/v1", workloadPreimage)
	if subtle.ConstantTimeCompare(wantWorkloadLock[:], artifact.workload.sourceLock[:]) != 1 || subtle.ConstantTimeCompare(wantWorkloadLock[:], artifact.provenance[2][:]) != 1 {
		return contractError(ErrorCodeDigestMismatch)
	}

	runtimePreimage := make([]byte, 0, 1+len(artifact.runtime.goVersion)+4*sha256.Size)
	runtimePreimage = append(runtimePreimage, byte(len(artifact.runtime.goVersion)))
	runtimePreimage = append(runtimePreimage, artifact.runtime.goVersion...)
	runtimePreimage = append(runtimePreimage, artifact.runtime.source[:]...)
	runtimePreimage = append(runtimePreimage, artifact.provenance[1][:]...)
	runtimePreimage = append(runtimePreimage, artifact.provenance[5][:]...)
	wantRuntimeLock := framedSHA256("hal/l8/syscall-runtime-source-lock/linux-amd64/v1", runtimePreimage)
	if subtle.ConstantTimeCompare(wantRuntimeLock[:], artifact.runtime.sourceLock[:]) != 1 || subtle.ConstantTimeCompare(wantRuntimeLock[:], artifact.provenance[3][:]) != 1 {
		return contractError(ErrorCodeDigestMismatch)
	}

	const module = "golang.org/x/sys@v0.41.0"
	const sourcePath = "unix/zsysnum_linux_amd64.go"
	catalogPreimage := make([]byte, 0, 2+len(module)+len(sourcePath)+4+2*sha256.Size)
	catalogPreimage = append(catalogPreimage, byte(len(module)))
	catalogPreimage = append(catalogPreimage, module...)
	catalogPreimage = append(catalogPreimage, byte(len(sourcePath)))
	catalogPreimage = append(catalogPreimage, sourcePath...)
	ceiling := make([]byte, 4)
	binary.BigEndian.PutUint32(ceiling, 450)
	catalogPreimage = append(catalogPreimage, ceiling...)
	catalogPreimage = append(catalogPreimage, artifact.catalogSourceSHA256[:]...)
	catalogPreimage = append(catalogPreimage, artifact.provenance[5][:]...)
	wantCatalogLock := framedSHA256("hal/l8/syscall-catalog-source-lock/linux-amd64/v1", catalogPreimage)
	if subtle.ConstantTimeCompare(wantCatalogLock[:], artifact.provenance[4][:]) != 1 {
		return contractError(ErrorCodeDigestMismatch)
	}

	wantSectionDigests := [3][32]byte{
		artifact.sections[3].sha256,
		artifact.sections[4].sha256,
		artifact.sections[0].sha256,
	}
	for index := range wantSectionDigests {
		if subtle.ConstantTimeCompare(wantSectionDigests[index][:], artifact.provenance[index+8][:]) != 1 {
			return contractError(ErrorCodeDigestMismatch)
		}
	}
	return nil
}

type policyRuleIndexMetadata struct {
	role            Role
	origin          RuleOrigin
	enforcementPath EnforcementPath
	requiredFacts   StateFact
	prohibitedFacts StateFact
	stateChecks     uint32
	syscallNumber   SyscallNumber
	scalarCount     uint8
	descriptorCount uint8
	pointerCount    uint8
	objectCount     uint8
	pinnedCount     uint8
}

func validateVerifiedPolicyRuleIndexOrigins(artifact *verifiedArtifact) error {
	rules := decodeVerifiedPolicyRuleIndexMetadata(artifact.sections[1])
	if len(rules) == 0 {
		return contractError(ErrorCodeMissingSection)
	}
	wantWorkload := make([]uint32, 0, len(artifact.workloadRuleIndexes))
	wantRuntime := make([]uint32, 0, len(artifact.runtimeRuleIndexes))
	for index, rule := range rules {
		if rule.origin == RuleOriginWorkload || rule.role == RoleWorkload {
			if rule.role != RoleWorkload || rule.origin != RuleOriginWorkload {
				return contractError(ErrorCodeUnsafeWidening)
			}
			wantWorkload = append(wantWorkload, uint32(index))
		}
		if rule.origin == RuleOriginRuntime {
			wantRuntime = append(wantRuntime, uint32(index))
		}
	}
	if !equalUint32Slices(artifact.workloadRuleIndexes, wantWorkload) || !equalUint32Slices(artifact.runtimeRuleIndexes, wantRuntime) {
		return contractError(ErrorCodeUnsafeWidening)
	}
	for _, index := range artifact.workloadRuleIndexes {
		if int(index) >= len(rules) {
			return contractError(ErrorCodeBounds)
		}
		rule := rules[index]
		if rule.enforcementPath != EnforcementPathDirect || rule.requiredFacts != 0 || rule.prohibitedFacts != 0 || rule.stateChecks != 0 || rule.descriptorCount != 0 || rule.pointerCount != 0 || rule.objectCount != 0 || rule.pinnedCount != 0 {
			return contractError(ErrorCodeUnsafeWidening)
		}
		entry := catalogEntryByNumber(artifact.catalog, rule.syscallNumber)
		if entry == nil || entry.class != SyscallClassOrdinary {
			return contractError(ErrorCodeUnsafeWidening)
		}
	}
	return nil
}

func decodeVerifiedPolicyRuleIndexMetadata(section artifactSection) []policyRuleIndexMetadata {
	body := section.body
	cursor := 0
	result := make([]policyRuleIndexMetadata, 0)
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes + stageCount*policyStageRowBytes + transitionCount*policyTransitionRowBytes
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			metadata := policyRuleIndexMetadata{
				role:            Role(header[0]),
				origin:          RuleOrigin(header[2]),
				enforcementPath: EnforcementPath(header[3]),
				requiredFacts:   StateFact(binary.BigEndian.Uint64(header[8:16])),
				prohibitedFacts: StateFact(binary.BigEndian.Uint64(header[16:24])),
				stateChecks:     binary.BigEndian.Uint32(header[28:32]),
				syscallNumber:   SyscallNumber(binary.BigEndian.Uint32(header[24:28])),
				scalarCount:     header[32],
				descriptorCount: header[33],
				pointerCount:    header[34],
				objectCount:     header[35],
				pinnedCount:     header[5],
			}
			result = append(result, metadata)
			cursor += policyRuleHeaderBytes +
				int(metadata.scalarCount)*policyScalarClauseBytes +
				int(metadata.descriptorCount)*policyDescriptorRequirementBytes +
				int(metadata.pointerCount)*policyPointerRequirementBytes +
				int(metadata.objectCount)*policyObjectRequirementBytes +
				int(metadata.pinnedCount)*policyPinnedRequirementBytes
		}
	}
	return result
}

func equalUint32Slices(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func catalogEntryByNumber(entries []*catalogEntry, number SyscallNumber) *catalogEntry {
	for _, entry := range entries {
		if entry.number == number {
			return entry
		}
	}
	return nil
}

type policyFilterProjectionRow struct {
	role    Role
	encoded []byte
}

func validateVerifiedPolicyAncestryDigests(artifact *verifiedArtifact) error {
	rows := decodeVerifiedPolicyFilterProjectionRows(artifact.sections[1])
	for _, ancestry := range artifact.ancestry {
		included := make(map[Role]struct{}, len(ancestry.descendants)+1)
		included[ancestry.ancestorRole] = struct{}{}
		for _, descendant := range ancestry.descendants {
			included[descendant] = struct{}{}
		}
		projection := make([][]byte, 0, len(rows))
		for _, row := range rows {
			if _, ok := included[row.role]; ok {
				projection = append(projection, row.encoded)
			}
		}
		sortByteSlices(projection)
		deduplicated := projection[:0]
		for _, encoded := range projection {
			if len(deduplicated) == 0 || !bytes.Equal(deduplicated[len(deduplicated)-1], encoded) {
				deduplicated = append(deduplicated, encoded)
			}
		}
		if len(deduplicated) == 0 {
			return contractError(ErrorCodeInvalidAncestry)
		}
		preimage := make([]byte, 4, 4+len(deduplicated)*8)
		binary.BigEndian.PutUint32(preimage[:4], uint32(len(deduplicated)))
		for _, encoded := range deduplicated {
			preimage = append(preimage, encoded...)
		}
		computed := framedSHA256("hal/l8/syscall-filter-projection/linux-amd64/v1", preimage)
		if subtle.ConstantTimeCompare(computed[:], ancestry.unionSHA256[:]) != 1 {
			return contractError(ErrorCodeInvalidAncestry)
		}
	}
	return nil
}

func decodeVerifiedPolicyFilterProjectionRows(section artifactSection) []policyFilterProjectionRow {
	body := section.body
	cursor := 0
	result := make([]policyFilterProjectionRow, 0)
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes + stageCount*policyStageRowBytes + transitionCount*policyTransitionRowBytes
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			scalarBytes := int(header[32]) * policyScalarClauseBytes
			filterBytes := make([]byte, 8, 8+scalarBytes)
			copy(filterBytes[0:4], header[24:28])
			filterBytes[4] = header[32]
			filterBytes = append(filterBytes, body[cursor+policyRuleHeaderBytes:cursor+policyRuleHeaderBytes+scalarBytes]...)
			result = append(result, policyFilterProjectionRow{role: role, encoded: filterBytes})
			cursor += policyRuleHeaderBytes + scalarBytes +
				int(header[33])*policyDescriptorRequirementBytes +
				int(header[34])*policyPointerRequirementBytes +
				int(header[35])*policyObjectRequirementBytes +
				int(header[5])*policyPinnedRequirementBytes
		}
	}
	return result
}

func sortByteSlices(values [][]byte) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && bytes.Compare(values[cursor], values[cursor-1]) < 0; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

func parseAndValidatePinnedCallsiteRequirements(artifact *verifiedArtifact) error {
	body := artifact.sections[1].body
	cursor := 0
	result := make([]*pinnedCallsiteRequirement, 0)
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes + stageCount*policyStageRowBytes + transitionCount*policyTransitionRowBytes
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			origin := RuleOrigin(header[2])
			path := EnforcementPath(header[3])
			pinnedCount := int(header[5])
			attachmentCursor := cursor + policyRuleHeaderBytes +
				int(header[32])*policyScalarClauseBytes +
				int(header[33])*policyDescriptorRequirementBytes +
				int(header[34])*policyPointerRequirementBytes +
				int(header[35])*policyObjectRequirementBytes
			if pinnedCount > 0 {
				if path != EnforcementPathPinnedDirect || origin != RuleOriginRole && origin != RuleOriginRuntime || binary.BigEndian.Uint64(header[8:16]) != 0 || binary.BigEndian.Uint64(header[16:24]) != 0 || binary.BigEndian.Uint32(header[28:32]) != 0 || header[33] != 0 || header[34] != 0 || header[35] != 0 {
					return contractError(ErrorCodeUnsafeWidening)
				}
				if !pinnedPathRoleAllowed(role, origin) {
					return contractError(ErrorCodeUnsafeWidening)
				}
			}
			if path == EnforcementPathPinnedDirect && pinnedCount == 0 {
				return contractError(ErrorCodeMissingSection)
			}
			for pinnedIndex := 0; pinnedIndex < pinnedCount; pinnedIndex++ {
				row := body[attachmentCursor : attachmentCursor+policyPinnedRequirementBytes]
				requirement := &pinnedCallsiteRequirement{
					role:              role,
					origin:            origin,
					callsiteOrdinal:   binary.BigEndian.Uint16(row[0:2]),
					pointerClass:      PointerClass(row[2]),
					minimumBytes:      binary.BigEndian.Uint32(row[4:8]),
					maximumBytes:      binary.BigEndian.Uint32(row[8:12]),
					requiredChecks:    CheckSet{bits: binary.BigEndian.Uint32(row[12:16])},
					instructionLength: binary.BigEndian.Uint16(row[16:18]),
				}
				copy(requirement.sourceUnitSHA256[:], row[20:52])
				copy(requirement.argumentTemplateSHA256[:], row[52:84])
				copy(requirement.instructionTemplateSHA256[:], row[84:116])
				copy(requirement.toolchainSHA256[:], row[116:148])
				requirement.sha256 = framedSHA256("hal/l8/pinned-callsite/linux-amd64/v1", row)
				wantChecks := uint32(1) << (CheckCompiledConstant - 1)
				if origin == RuleOriginRuntime {
					wantChecks |= uint32(1) << (CheckRuntimeMapping - 1)
				}
				if requirement.requiredChecks.bits != wantChecks || subtle.ConstantTimeCompare(requirement.toolchainSHA256[:], artifact.provenance[7][:]) != 1 {
					return contractError(ErrorCodeContradiction)
				}
				result = append(result, requirement)
				attachmentCursor += policyPinnedRequirementBytes
			}
			cursor = attachmentCursor
		}
	}
	if len(result) == 0 {
		return contractError(ErrorCodeMissingSection)
	}
	artifact.pinnedCallsites = result
	return nil
}

func pinnedPathRoleAllowed(role Role, origin RuleOrigin) bool {
	if origin == RuleOriginRole {
		switch role {
		case RoleLaunchBootstrap, RoleControllerBootstrap, RoleAgentBootstrap, RoleMonitorBootstrap, RoleWorkloadTransition:
			return true
		default:
			return false
		}
	}
	if origin == RuleOriginRuntime {
		switch role {
		case RoleLaunchBase, RoleControllerBootstrap, RoleSteadyController, RoleAgentBootstrap, RoleSteadyAgent, RoleMonitorBootstrap, RoleSteadyMonitor, RoleWorkloadTransition:
			return true
		default:
			return false
		}
	}
	return false
}

func validateVerifiedPolicySectionPresence(sections [verifiedPolicySectionCount]artifactSection) error {
	for _, section := range sections {
		if section.itemCount == 0 || len(section.body) == 0 {
			return contractError(ErrorCodeMissingSection)
		}
	}
	if sections[0].itemCount > MaxPolicyCatalogEntries ||
		sections[1].itemCount != 10 ||
		sections[2].itemCount != 2 ||
		sections[3].itemCount > MaxPolicyRulesPerRole ||
		sections[4].itemCount > MaxPolicyRules ||
		sections[5].itemCount != 11 {
		return contractError(ErrorCodeBounds)
	}
	return nil
}

func framedSHA256(domain string, body []byte) [32]byte {
	framed := make([]byte, 2+len(domain)+len(body))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(domain)))
	copy(framed[2:], domain)
	copy(framed[2+len(domain):], body)
	return sha256.Sum256(framed)
}

func zeroDigest(digest [32]byte) bool { return digest == ([32]byte{}) }
