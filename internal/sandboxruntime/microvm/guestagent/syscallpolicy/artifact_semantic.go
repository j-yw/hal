package syscallpolicy

import "encoding/binary"

func decodeVerifiedPolicySemanticGraph(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	body := artifact.sections[1].body
	pinnedByDigest := make(map[[32]byte]*pinnedCallsiteRequirement, len(artifact.pinnedCallsites))
	for _, requirement := range artifact.pinnedCallsites {
		pinnedByDigest[requirement.sha256] = requirement
	}
	artifact.stages = make(map[Role]map[Stage]roleStage, 10)
	artifact.rules = nil
	artifact.transitions = nil
	artifact.roleSections = make(map[Role][]byte, 10)
	cursor := 0
	for roleIndex := 0; roleIndex < 10; roleIndex++ {
		roleStart := cursor
		role := Role(body[cursor])
		stageCount := int(body[cursor+1])
		transitionCount := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		ruleCount := int(binary.BigEndian.Uint32(body[cursor+4 : cursor+8]))
		cursor += policyRoleHeaderBytes
		artifact.stages[role] = make(map[Stage]roleStage, stageCount)
		for stageIndex := 0; stageIndex < stageCount; stageIndex++ {
			row := body[cursor : cursor+policyStageRowBytes]
			stage := roleStage{
				role:            role,
				stage:           Stage(row[0]),
				requiredFacts:   StateFact(binary.BigEndian.Uint64(row[8:16])),
				prohibitedFacts: StateFact(binary.BigEndian.Uint64(row[16:24])),
			}
			artifact.stages[role][stage.stage] = stage
			cursor += policyStageRowBytes
		}
		for transitionIndex := 0; transitionIndex < transitionCount; transitionIndex++ {
			row := body[cursor : cursor+policyTransitionRowBytes]
			preimage := append([]byte{byte(role)}, row...)
			transition := &verifiedTransition{
				role:            role,
				from:            Stage(row[0]),
				toRole:          Role(row[1]),
				to:              Stage(row[2]),
				requiredFacts:   StateFact(binary.BigEndian.Uint64(row[4:12])),
				prohibitedFacts: StateFact(binary.BigEndian.Uint64(row[12:20])),
				setFacts:        StateFact(binary.BigEndian.Uint64(row[20:28])),
				clearFacts:      StateFact(binary.BigEndian.Uint64(row[28:36])),
				sha256:          framedSHA256("hal/l8/syscall-transition/linux-amd64/v1", preimage),
			}
			artifact.transitions = append(artifact.transitions, transition)
			cursor += policyTransitionRowBytes
		}
		for ruleIndex := 0; ruleIndex < ruleCount; ruleIndex++ {
			header := body[cursor : cursor+policyRuleHeaderBytes]
			rowLength := policyRuleHeaderBytes +
				int(header[32])*policyScalarClauseBytes +
				int(header[33])*policyDescriptorRequirementBytes +
				int(header[34])*policyPointerRequirementBytes +
				int(header[35])*policyObjectRequirementBytes +
				int(header[5])*policyPinnedRequirementBytes
			encoded := body[cursor : cursor+rowLength]
			rule := &verifiedRule{
				role:            role,
				stage:           Stage(header[1]),
				origin:          RuleOrigin(header[2]),
				enforcementPath: EnforcementPath(header[3]),
				requiredFacts:   StateFact(binary.BigEndian.Uint64(header[8:16])),
				prohibitedFacts: StateFact(binary.BigEndian.Uint64(header[16:24])),
				stateChecks:     CheckSet{bits: binary.BigEndian.Uint32(header[28:32])},
				syscallNumber:   SyscallNumber(binary.BigEndian.Uint32(header[24:28])),
				adapterFailure:  AdapterOutcome(header[4]),
				sha256:          framedSHA256("hal/l8/syscall-rule/linux-amd64/v1", encoded),
				encoded:         append([]byte(nil), encoded...),
			}
			filterBytes := make([]byte, 8)
			copy(filterBytes[:4], header[24:28])
			filterBytes[4] = header[32]
			attachmentCursor := cursor + policyRuleHeaderBytes
			scalarBytes := int(header[32]) * policyScalarClauseBytes
			filterBytes = append(filterBytes, body[attachmentCursor:attachmentCursor+scalarBytes]...)
			filterRule, err := decodeFilterRule(filterBytes)
			if err != nil {
				return err
			}
			rule.scalarClauses = filterRule.clauses
			attachmentCursor += scalarBytes
			for index := 0; index < int(header[33]); index++ {
				row := body[attachmentCursor : attachmentCursor+policyDescriptorRequirementBytes]
				requirement := &descriptorRequirement{
					argumentIndex:  row[0],
					kind:           DescriptorKind(row[1]),
					access:         DescriptorAccess(row[2]),
					fixed:          row[3] == 1,
					generationMode: GenerationMode(row[4]),
					bindingSlot:    row[5],
					requiredChecks: CheckSet{bits: binary.BigEndian.Uint32(row[8:12])},
				}
				copy(requirement.generationSHA256[:], row[12:44])
				rule.descriptors = append(rule.descriptors, requirement)
				attachmentCursor += policyDescriptorRequirementBytes
			}
			for index := 0; index < int(header[34]); index++ {
				row := body[attachmentCursor : attachmentCursor+policyPointerRequirementBytes]
				rule.pointers = append(rule.pointers, &pointerRequirement{
					argumentIndex:  row[0],
					class:          PointerClass(row[1]),
					minimumBytes:   binary.BigEndian.Uint32(row[4:8]),
					maximumBytes:   binary.BigEndian.Uint32(row[8:12]),
					requiredChecks: CheckSet{bits: binary.BigEndian.Uint32(row[12:16])},
				})
				attachmentCursor += policyPointerRequirementBytes
			}
			for index := 0; index < int(header[35]); index++ {
				row := body[attachmentCursor : attachmentCursor+policyObjectRequirementBytes]
				requirement := &objectRequirement{
					source:         ObjectSource(row[0]),
					argumentIndex:  row[1],
					kind:           DescriptorKind(row[2]),
					access:         DescriptorAccess(row[3]),
					fixed:          row[4] == 1,
					generationMode: GenerationMode(row[5]),
					bindingSlot:    row[6],
					requiredChecks: CheckSet{bits: binary.BigEndian.Uint32(row[8:12])},
				}
				copy(requirement.generationSHA256[:], row[12:44])
				rule.objects = append(rule.objects, requirement)
				attachmentCursor += policyObjectRequirementBytes
			}
			for index := 0; index < int(header[5]); index++ {
				row := body[attachmentCursor : attachmentCursor+policyPinnedRequirementBytes]
				digest := framedSHA256("hal/l8/pinned-callsite/linux-amd64/v1", row)
				requirement := pinnedByDigest[digest]
				if requirement == nil {
					return contractError(ErrorCodeContradiction)
				}
				rule.pinnedCallsites = append(rule.pinnedCallsites, requirement)
				attachmentCursor += policyPinnedRequirementBytes
			}
			artifact.rules = append(artifact.rules, rule)
			cursor += rowLength
		}
		artifact.roleSections[role] = append([]byte(nil), body[roleStart:cursor]...)
	}
	if cursor != len(body) {
		return contractError(ErrorCodeEncoding)
	}

	artifact.workload.rules = make([]WorkloadRuleView, len(artifact.workloadRuleIndexes))
	for index, ruleIndex := range artifact.workloadRuleIndexes {
		if int(ruleIndex) >= len(artifact.rules) {
			return contractError(ErrorCodeBounds)
		}
		artifact.workload.rules[index] = WorkloadRuleView{rule: RuleView{rule: artifact.rules[ruleIndex]}}
	}
	artifact.runtime.rules = make([]RuleView, len(artifact.runtimeRuleIndexes))
	for index, ruleIndex := range artifact.runtimeRuleIndexes {
		if int(ruleIndex) >= len(artifact.rules) {
			return contractError(ErrorCodeBounds)
		}
		artifact.runtime.rules[index] = RuleView{rule: artifact.rules[ruleIndex]}
	}
	if err := validateVerifiedPolicySemanticTransitions(artifact); err != nil {
		return err
	}
	if err := validateVerifiedPolicySemanticRules(artifact); err != nil {
		return err
	}
	return validateVerifiedPolicyRuleOverlaps(artifact)
}

func validateVerifiedPolicySemanticTransitions(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	graphs := make(map[Role]map[Stage][]Stage, len(artifact.stages))
	for _, transition := range artifact.transitions {
		if _, ok := artifact.stages[transition.role][transition.from]; !ok {
			return contractError(ErrorCodeCatalog)
		}
		if _, ok := artifact.stages[transition.toRole][transition.to]; !ok {
			return contractError(ErrorCodeCatalog)
		}
		if transition.role == transition.toRole {
			if graphs[transition.role] == nil {
				graphs[transition.role] = make(map[Stage][]Stage)
			}
			graphs[transition.role][transition.from] = append(graphs[transition.role][transition.from], transition.to)
		}
	}
	for _, graph := range graphs {
		state := make(map[Stage]uint8, len(graph))
		var visit func(Stage) bool
		visit = func(stage Stage) bool {
			if state[stage] == 1 {
				return false
			}
			if state[stage] == 2 {
				return true
			}
			state[stage] = 1
			for _, next := range graph[stage] {
				if !visit(next) {
					return false
				}
			}
			state[stage] = 2
			return true
		}
		for stage := range graph {
			if !visit(stage) {
				return contractError(ErrorCodeContradiction)
			}
		}
	}
	return nil
}

func validateVerifiedPolicySemanticRules(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	for _, rule := range artifact.rules {
		entry := catalogEntryByNumber(artifact.catalog, rule.syscallNumber)
		if entry == nil {
			return contractError(ErrorCodeCatalog)
		}
		if entry.class == SyscallClassFatal {
			return contractError(ErrorCodeFatalAllow)
		}
		switch rule.enforcementPath {
		case EnforcementPathDirect:
			if rule.requiredFacts != 0 || rule.prohibitedFacts != 0 || rule.stateChecks.bits != 0 || len(rule.descriptors) != 0 || len(rule.pointers) != 0 || len(rule.objects) != 0 || len(rule.pinnedCallsites) != 0 || rule.adapterFailure != AdapterOutcomeProceed {
				return contractError(ErrorCodeUnsafeWidening)
			}
			if rule.origin == RuleOriginWorkload && rule.role != RoleWorkload {
				return contractError(ErrorCodeUnsafeWidening)
			}
			if rule.role == RoleWorkload && rule.origin != RuleOriginWorkload {
				return contractError(ErrorCodeUnsafeWidening)
			}
		case EnforcementPathPinnedDirect:
			if !validPinnedDirectRole(rule.role, rule.origin) || rule.requiredFacts != 0 || rule.prohibitedFacts != 0 || rule.stateChecks.bits != 0 || len(rule.descriptors) != 0 || len(rule.pointers) != 0 || len(rule.objects) != 0 || len(rule.pinnedCallsites) == 0 || rule.adapterFailure != AdapterOutcomeProceed {
				return contractError(ErrorCodeUnsafeWidening)
			}
			wantChecks := uint32(1) << (CheckCompiledConstant - 1)
			if rule.origin == RuleOriginRuntime {
				wantChecks |= uint32(1) << (CheckRuntimeMapping - 1)
			}
			for _, requirement := range rule.pinnedCallsites {
				if requirement.requiredChecks.bits != wantChecks {
					return contractError(ErrorCodeUnsafeWidening)
				}
			}
		case EnforcementPathAdapter:
			if rule.role == RoleWorkload || len(rule.pinnedCallsites) != 0 || (rule.adapterFailure != AdapterOutcomeRejectCleanup && rule.adapterFailure != AdapterOutcomeStopVM) || !validCheckMatrix(rule.stateChecks.bits, checkBits(CheckProcessIdentity), checkBits(CheckProcessIdentity, CheckRuntimeMapping, CheckCompiledConstant)) {
				return contractError(ErrorCodeUnsafeWidening)
			}
		default:
			return contractError(ErrorCodeCatalog)
		}
		for _, requirement := range rule.descriptors {
			if !validDescriptorChecks(requirement.kind, requirement.requiredChecks.bits) || !requirementScalarFitsFD(rule, requirement.argumentIndex, requirement.fixed) {
				return contractError(ErrorCodeUnsafeWidening)
			}
		}
		for _, requirement := range rule.pointers {
			if !validPointerChecks(requirement.class, requirement.requiredChecks.bits) {
				return contractError(ErrorCodeUnsafeWidening)
			}
		}
		for _, requirement := range rule.objects {
			if !validObjectChecks(requirement, requirement.requiredChecks.bits) || requirement.source == ObjectSourceArgument && !requirementScalarFitsFD(rule, requirement.argumentIndex, requirement.fixed) {
				return contractError(ErrorCodeUnsafeWidening)
			}
		}
		if entry.class == SyscallClassConditional && !ruleCoversMandatoryEvidence(rule, entry.mandatoryEvidence) {
			return contractError(ErrorCodeUnsafeWidening)
		}
		if !ruleLiveBindingSlotsCompatible(rule) {
			return contractError(ErrorCodeContradiction)
		}
	}
	return nil
}

func ruleLiveBindingSlotsCompatible(rule *verifiedRule) bool {
	type bindingType struct {
		kind   DescriptorKind
		access DescriptorAccess
	}
	bindings := make(map[uint8]bindingType)
	add := func(slot uint8, kind DescriptorKind, access DescriptorAccess) bool {
		if slot == 0 || slot > MaxAdapterBindings {
			return false
		}
		if existing, ok := bindings[slot]; ok && (existing.kind != kind || existing.access != access) {
			return false
		}
		bindings[slot] = bindingType{kind: kind, access: access}
		return true
	}
	for _, requirement := range rule.descriptors {
		if requirement.generationMode == GenerationModeLiveBound && !add(requirement.bindingSlot, requirement.kind, requirement.access) {
			return false
		}
	}
	for _, requirement := range rule.objects {
		if requirement.source == ObjectSourceArgument && requirement.generationMode == GenerationModeLiveBound && !add(requirement.bindingSlot, requirement.kind, requirement.access) {
			return false
		}
	}
	return true
}

func requirementScalarFitsFD(rule *verifiedRule, argumentIndex uint8, fixed bool) bool {
	clause := ruleClauseAt(rule, argumentIndex)
	if clause == nil {
		return false
	}
	if fixed && clause.operation != ScalarEqual {
		return false
	}
	high := &scalarClause{operation: ScalarUnsignedRange, values: []uint64{uint64(^uint32(0)>>1) + 1, ^uint64(0)}}
	return !scalarClausesIntersect(clause, high)
}

func checkBits(checks ...Check) uint32 {
	var result uint32
	for _, check := range checks {
		result |= uint32(1) << (check - 1)
	}
	return result
}

func validCheckMatrix(actual, mandatory, allowed uint32) bool {
	return actual&mandatory == mandatory && actual&^allowed == 0
}

func validDescriptorChecks(kind DescriptorKind, actual uint32) bool {
	mandatory, allowed, ok := descriptorCheckBounds(kind)
	return ok && validCheckMatrix(actual, mandatory, allowed)
}

func descriptorCheckBounds(kind DescriptorKind) (uint32, uint32, bool) {
	base := checkBits(CheckFDKind, CheckFDAccess, CheckFDGeneration)
	switch kind {
	case DescriptorKindInert, DescriptorKindPipeRead, DescriptorKindPipeWrite, DescriptorKindGateRead:
		return base, base, true
	case DescriptorKindRegular, DescriptorKindDirectory, DescriptorKindProcRoot:
		mandatory := base | checkBits(CheckObjectIdentity)
		return mandatory, mandatory | checkBits(CheckContainedBeneath), true
	case DescriptorKindExecutable, DescriptorKindSealedConfig:
		mandatory := base | checkBits(CheckObjectIdentity)
		return mandatory, mandatory, true
	case DescriptorKindPIDFD:
		mandatory := base | checkBits(CheckProcessIdentity)
		return mandatory, mandatory, true
	case DescriptorKindMount, DescriptorKindFSContext, DescriptorKindMountTarget:
		mandatory := base | checkBits(CheckMountIdentity)
		return mandatory, mandatory | checkBits(CheckObjectIdentity), true
	case DescriptorKindUnixConnected, DescriptorKindUnixListening, DescriptorKindVSOCKConnected, DescriptorKindVSOCKListening:
		mandatory := base | checkBits(CheckSocketIdentity)
		return mandatory, mandatory, true
	case DescriptorKindSeqpacket:
		mandatory := base | checkBits(CheckSocketIdentity)
		return mandatory, mandatory | checkBits(CheckAncillaryShape), true
	case DescriptorKindNamespace:
		mandatory := base | checkBits(CheckNamespaceIdentity)
		return mandatory, mandatory, true
	case DescriptorKindCgroupRoot, DescriptorKindCgroupLeaf:
		mandatory := base | checkBits(CheckCgroupIdentity)
		return mandatory, mandatory | checkBits(CheckContainedBeneath), true
	default:
		return 0, 0, false
	}
}

func validPointerChecks(class PointerClass, actual uint32) bool {
	boundedImmutable := checkBits(CheckBoundedPointer, CheckImmutablePointer)
	switch class {
	case PointerClassFixedImage:
		mandatory := boundedImmutable | checkBits(CheckCompiledConstant)
		return validCheckMatrix(actual, mandatory, mandatory)
	case PointerClassBoundedMutable:
		mandatory := checkBits(CheckBoundedPointer, CheckOutputBounds)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckReservedZero))
	case PointerClassBoundedReadOnly:
		return validCheckMatrix(actual, boundedImmutable, boundedImmutable|checkBits(CheckReservedZero))
	case PointerClassRuntimeStack, PointerClassRuntimeTLS:
		mandatory := checkBits(CheckBoundedPointer, CheckRuntimeMapping)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckImmutablePointer))
	case PointerClassCanonicalRelativePath:
		mandatory := boundedImmutable | checkBits(CheckCanonicalPath, CheckContainedBeneath)
		return validCheckMatrix(actual, mandatory, mandatory)
	case PointerClassCompiledPath:
		mandatory := boundedImmutable | checkBits(CheckCanonicalPath, CheckCompiledConstant)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckContainedBeneath))
	case PointerClassOpenHow, PointerClassCloneArgs, PointerClassMountAttributes:
		mandatory := boundedImmutable | checkBits(CheckReservedZero)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckCompiledConstant))
	case PointerClassMessageHeader:
		mandatory := boundedImmutable | checkBits(CheckReservedZero, CheckAncillaryShape)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckOutputBounds))
	case PointerClassSocketAddress:
		mandatory := boundedImmutable | checkBits(CheckReservedZero, CheckSocketIdentity)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckOutputBounds))
	case PointerClassCapabilityData:
		mandatory := boundedImmutable | checkBits(CheckReservedZero, CheckProcessIdentity)
		return validCheckMatrix(actual, mandatory, mandatory)
	case PointerClassSeccompProgram:
		mandatory := boundedImmutable | checkBits(CheckReservedZero, CheckCompiledConstant)
		return validCheckMatrix(actual, mandatory, mandatory)
	case PointerClassArgvEnv:
		mandatory := boundedImmutable | checkBits(CheckFixedArgvEnv)
		return validCheckMatrix(actual, mandatory, mandatory|checkBits(CheckCompiledConstant))
	case PointerClassTimespec, PointerClassSignalSet:
		mandatory := boundedImmutable | checkBits(CheckReservedZero)
		return validCheckMatrix(actual, mandatory, mandatory)
	default:
		return false
	}
}

func validObjectChecks(requirement *objectRequirement, actual uint32) bool {
	if requirement == nil {
		return false
	}
	mandatory, allowed, ok := descriptorCheckBounds(requirement.kind)
	if !ok {
		return false
	}
	mandatory |= checkBits(CheckObjectIdentity)
	allowed |= checkBits(CheckObjectIdentity)
	if requirement.source == ObjectSourceReturn {
		mandatory |= checkBits(CheckPostSuccessReinspection)
		allowed |= checkBits(CheckPostSuccessReinspection)
		if actual&checkBits(CheckOutputBounds) != 0 {
			return false
		}
	}
	return validCheckMatrix(actual, mandatory, allowed)
}

func ruleCoversMandatoryEvidence(rule *verifiedRule, evidence []*mandatoryEvidence) bool {
	for _, required := range evidence {
		var actual uint32
		switch required.kind {
		case EvidenceKindState:
			actual = rule.stateChecks.bits
		case EvidenceKindDescriptor:
			for _, item := range rule.descriptors {
				if uint16(item.argumentIndex) == required.attachmentIndex {
					actual = item.requiredChecks.bits
				}
			}
		case EvidenceKindPointer:
			for _, item := range rule.pointers {
				if uint16(item.argumentIndex) == required.attachmentIndex {
					actual = item.requiredChecks.bits
				}
			}
		case EvidenceKindArgumentObject, EvidenceKindReturnObject:
			for _, item := range rule.objects {
				if uint16(item.argumentIndex) == required.attachmentIndex && (required.kind == EvidenceKindArgumentObject) == (item.source == ObjectSourceArgument) {
					actual = item.requiredChecks.bits
				}
			}
		case EvidenceKindPinnedCallsite:
			for _, item := range rule.pinnedCallsites {
				if item.callsiteOrdinal == required.attachmentIndex {
					actual = item.requiredChecks.bits
				}
			}
		}
		if actual&required.requiredChecks.bits != required.requiredChecks.bits {
			return false
		}
	}
	return true
}

func validateVerifiedPolicyPositiveDecisions(artifact VerifiedPolicyArtifact) error {
	policy, err := NewPolicy(artifact)
	if err != nil {
		return err
	}
	for _, rule := range policy.artifact.rules {
		stage := policy.artifact.stages[rule.role][rule.stage]
		facts := stage.requiredFacts | rule.requiredFacts
		if facts&(stage.prohibitedFacts|rule.prohibitedFacts) != 0 {
			return contractError(ErrorCodeContradiction)
		}
		state, err := NewState(rule.role, rule.stage, facts)
		if err != nil {
			return err
		}
		var arguments [6]uint64
		for _, clause := range rule.scalarClauses {
			switch clause.operation {
			case ScalarEqual, ScalarMaskedEqual, ScalarOneOf, ScalarUnsignedRange:
				arguments[clause.argumentIndex] = clause.values[0]
			case ScalarZero:
				arguments[clause.argumentIndex] = 0
			case ScalarNonzero:
				arguments[clause.argumentIndex] = 1
			}
		}
		input, err := NewFilterInput(state, 0xc000003e, uint32(rule.syscallNumber), arguments)
		if err != nil {
			return err
		}
		decision := policy.Decide(input)
		if !decision.Allowed() || decision.reason != ReasonExactRule || decision.ruleSHA256 != rule.sha256 {
			return contractError(ErrorCodeContradiction)
		}
	}
	return nil
}

func validPinnedDirectRole(role Role, origin RuleOrigin) bool {
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
