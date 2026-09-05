package syscallpolicy

import "crypto/subtle"

type policyOwner struct{ marker byte }

type Policy struct {
	artifact *verifiedArtifact
	owner    *policyOwner
}

type Classification struct {
	abi    ABIClass
	number SyscallNumber
	known  bool
}

func NewPolicy(artifact VerifiedPolicyArtifact) (*Policy, error) {
	if artifact.artifact == nil || zeroDigest(artifact.sha256) || !artifact.artifact.verified {
		return nil, contractError(ErrorCodeOwnership)
	}
	copied := cloneVerifiedArtifact(artifact.artifact)
	digest := framedSHA256(verifiedPolicyArtifactDigestDomain, copied.encoded)
	if subtle.ConstantTimeCompare(digest[:], artifact.sha256[:]) != 1 || subtle.ConstantTimeCompare(digest[:], copied.sha256[:]) != 1 {
		return nil, contractError(ErrorCodeDigestMismatch)
	}
	return &Policy{artifact: copied, owner: &policyOwner{}}, nil
}

func (policy *Policy) Classify(auditArchitecture uint32, rawSyscallNumber uint32) Classification {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return Classification{}
	}
	if auditArchitecture != 0xc000003e {
		return Classification{abi: ABIClassForeign, number: SyscallNumber(rawSyscallNumber)}
	}
	if rawSyscallNumber&0x40000000 != 0 {
		return Classification{abi: ABIClassX32, number: SyscallNumber(rawSyscallNumber)}
	}
	number := SyscallNumber(rawSyscallNumber)
	return Classification{
		abi:    ABIClassNativeAMD64,
		number: number,
		known:  catalogEntryByNumber(policy.artifact.catalog, number) != nil,
	}
}

func (classification Classification) ABI() ABIClass         { return classification.abi }
func (classification Classification) Number() SyscallNumber { return classification.number }
func (classification Classification) Known() bool           { return classification.known }

func cloneVerifiedArtifact(source *verifiedArtifact) *verifiedArtifact {
	if source == nil {
		return nil
	}
	result := *source
	result.encoded = append([]byte(nil), source.encoded...)
	for index := range source.sections {
		result.sections[index] = source.sections[index]
		result.sections[index].body = append([]byte(nil), source.sections[index].body...)
	}
	result.catalog = make([]*catalogEntry, len(source.catalog))
	for index, entry := range source.catalog {
		cloned := *entry
		cloned.mandatoryEvidence = make([]*mandatoryEvidence, len(entry.mandatoryEvidence))
		for evidenceIndex, evidence := range entry.mandatoryEvidence {
			copyValue := *evidence
			cloned.mandatoryEvidence[evidenceIndex] = &copyValue
		}
		result.catalog[index] = &cloned
	}
	for index := range source.ancestry {
		result.ancestry[index] = source.ancestry[index]
		result.ancestry[index].descendants = append([]Role(nil), source.ancestry[index].descendants...)
	}
	result.workload = source.workload
	result.workloadRuleIndexes = append([]uint32(nil), source.workloadRuleIndexes...)
	result.runtime = source.runtime
	result.runtimeRuleIndexes = append([]uint32(nil), source.runtimeRuleIndexes...)
	result.pinnedCallsites = make([]*pinnedCallsiteRequirement, len(source.pinnedCallsites))
	pinnedByDigest := make(map[[32]byte]*pinnedCallsiteRequirement, len(source.pinnedCallsites))
	for index, requirement := range source.pinnedCallsites {
		cloned := *requirement
		result.pinnedCallsites[index] = &cloned
		pinnedByDigest[cloned.sha256] = &cloned
	}
	result.stages = make(map[Role]map[Stage]roleStage, len(source.stages))
	for role, stages := range source.stages {
		result.stages[role] = make(map[Stage]roleStage, len(stages))
		for stage, definition := range stages {
			result.stages[role][stage] = definition
		}
	}
	result.transitions = make([]*verifiedTransition, len(source.transitions))
	for index, transition := range source.transitions {
		cloned := *transition
		result.transitions[index] = &cloned
	}
	result.rules = make([]*verifiedRule, len(source.rules))
	for index, rule := range source.rules {
		cloned := *rule
		cloned.encoded = append([]byte(nil), rule.encoded...)
		cloned.scalarClauses = make([]*scalarClause, len(rule.scalarClauses))
		for clauseIndex, clause := range rule.scalarClauses {
			clonedClause := *clause
			clonedClause.values = append([]uint64(nil), clause.values...)
			cloned.scalarClauses[clauseIndex] = &clonedClause
		}
		cloned.descriptors = cloneDescriptorRequirements(rule.descriptors)
		cloned.pointers = clonePointerRequirements(rule.pointers)
		cloned.objects = cloneObjectRequirements(rule.objects)
		cloned.pinnedCallsites = make([]*pinnedCallsiteRequirement, len(rule.pinnedCallsites))
		for requirementIndex, requirement := range rule.pinnedCallsites {
			clonedRequirement := pinnedByDigest[requirement.sha256]
			if clonedRequirement == nil {
				copyValue := *requirement
				clonedRequirement = &copyValue
			}
			cloned.pinnedCallsites[requirementIndex] = clonedRequirement
		}
		result.rules[index] = &cloned
	}
	result.roleSections = make(map[Role][]byte, len(source.roleSections))
	for role, encoded := range source.roleSections {
		result.roleSections[role] = append([]byte(nil), encoded...)
	}
	result.workload.rules = make([]WorkloadRuleView, len(result.workloadRuleIndexes))
	for index, ruleIndex := range result.workloadRuleIndexes {
		if int(ruleIndex) < len(result.rules) {
			result.workload.rules[index] = WorkloadRuleView{rule: RuleView{rule: result.rules[ruleIndex]}}
		}
	}
	result.runtime.rules = make([]RuleView, len(result.runtimeRuleIndexes))
	for index, ruleIndex := range result.runtimeRuleIndexes {
		if int(ruleIndex) < len(result.rules) {
			result.runtime.rules[index] = RuleView{rule: result.rules[ruleIndex]}
		}
	}
	return &result
}

func cloneDescriptorRequirements(source []*descriptorRequirement) []*descriptorRequirement {
	result := make([]*descriptorRequirement, len(source))
	for index, requirement := range source {
		cloned := *requirement
		result[index] = &cloned
	}
	return result
}

func clonePointerRequirements(source []*pointerRequirement) []*pointerRequirement {
	result := make([]*pointerRequirement, len(source))
	for index, requirement := range source {
		cloned := *requirement
		result[index] = &cloned
	}
	return result
}

func cloneObjectRequirements(source []*objectRequirement) []*objectRequirement {
	result := make([]*objectRequirement, len(source))
	for index, requirement := range source {
		cloned := *requirement
		result[index] = &cloned
	}
	return result
}
