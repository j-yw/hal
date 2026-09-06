package syscallpolicy

import (
	"crypto/subtle"
	"encoding/binary"
)

type scalarClause struct {
	argumentIndex  uint8
	operation      ScalarOperation
	mask           uint64
	values         []uint64
	mismatchAction Action
	mismatchReason Reason
}

type ScalarClauseView struct{ clause *scalarClause }
type filterRule struct {
	syscallNumber SyscallNumber
	clauses       []*scalarClause
	sha256        [32]byte
	encoded       []byte
}
type FilterRuleView struct{ rule *filterRule }
type filterProfile struct {
	role          Role
	kernelCeiling SyscallNumber
	catalog       []*catalogEntry
	rules         []*filterRule
	sha256        [32]byte
}
type FilterProfile struct{ profile *filterProfile }
type FilterDecision struct {
	action     Action
	reason     Reason
	ruleSHA256 [32]byte
}

func (policy *Policy) FilterRules(role Role) ([]FilterRuleView, error) {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return nil, contractError(ErrorCodeOwnership)
	}
	if ValidateRole(role) != nil {
		return nil, contractError(ErrorCodeCatalog)
	}
	rows, digest, err := policyFilterRows(policy.artifact, role)
	if err != nil {
		return nil, err
	}
	_ = digest
	result := make([]FilterRuleView, len(rows))
	for index, row := range rows {
		result[index] = FilterRuleView{rule: row}
	}
	return result, nil
}

func (policy *Policy) FilterProfile(role Role) (FilterProfile, error) {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return FilterProfile{}, contractError(ErrorCodeOwnership)
	}
	if ValidateRole(role) != nil {
		return FilterProfile{}, contractError(ErrorCodeCatalog)
	}
	rules, projectionDigest, err := policyFilterRows(policy.artifact, role)
	if err != nil {
		return FilterProfile{}, err
	}
	catalog := make([]*catalogEntry, len(policy.artifact.catalog))
	copy(catalog, policy.artifact.catalog)
	preimage := make([]byte, 0, 32+1+4+32+32)
	preimage = append(preimage, policy.artifact.sha256[:]...)
	preimage = append(preimage, byte(role))
	ceiling := make([]byte, 4)
	binary.BigEndian.PutUint32(ceiling, 450)
	preimage = append(preimage, ceiling...)
	preimage = append(preimage, policy.artifact.sections[0].sha256[:]...)
	preimage = append(preimage, projectionDigest[:]...)
	profile := &filterProfile{
		role:          role,
		kernelCeiling: 450,
		catalog:       catalog,
		rules:         rules,
		sha256:        framedSHA256("hal/l8/syscall-filter-profile/linux-amd64/v1", preimage),
	}
	return FilterProfile{profile: profile}, nil
}

func policyFilterRows(artifact *verifiedArtifact, role Role) ([]*filterRule, [32]byte, error) {
	projectionRows := decodeVerifiedPolicyFilterProjectionRows(artifact.sections[1])
	included := map[Role]struct{}{role: {}}
	var ancestryDigest [32]byte
	for _, ancestry := range artifact.ancestry {
		if ancestry.ancestorRole != role {
			continue
		}
		ancestryDigest = ancestry.unionSHA256
		for _, descendant := range ancestry.descendants {
			included[descendant] = struct{}{}
		}
	}
	encodedRows := make([][]byte, 0)
	for _, row := range projectionRows {
		if _, ok := included[row.role]; ok {
			encodedRows = append(encodedRows, append([]byte(nil), row.encoded...))
		}
	}
	sortByteSlices(encodedRows)
	deduplicated := encodedRows[:0]
	for _, encoded := range encodedRows {
		if len(deduplicated) == 0 || !equalBytes(deduplicated[len(deduplicated)-1], encoded) {
			deduplicated = append(deduplicated, encoded)
		}
	}
	if len(deduplicated) == 0 {
		return nil, [32]byte{}, contractError(ErrorCodeMissingSection)
	}
	preimage := make([]byte, 4)
	binary.BigEndian.PutUint32(preimage, uint32(len(deduplicated)))
	for _, encoded := range deduplicated {
		preimage = append(preimage, encoded...)
	}
	projectionDigest := framedSHA256("hal/l8/syscall-filter-projection/linux-amd64/v1", preimage)
	if !zeroDigest(ancestryDigest) && subtle.ConstantTimeCompare(projectionDigest[:], ancestryDigest[:]) != 1 {
		return nil, [32]byte{}, contractError(ErrorCodeInvalidAncestry)
	}
	rules := make([]*filterRule, len(deduplicated))
	for index, encoded := range deduplicated {
		rule, err := decodeFilterRule(encoded)
		if err != nil {
			return nil, [32]byte{}, err
		}
		rules[index] = rule
	}
	return rules, projectionDigest, nil
}

func decodeFilterRule(encoded []byte) (*filterRule, error) {
	if len(encoded) < 8 || !allZero(encoded[5:8]) || len(encoded) != 8+int(encoded[4])*policyScalarClauseBytes {
		return nil, contractError(ErrorCodeEncoding)
	}
	rule := &filterRule{
		syscallNumber: SyscallNumber(binary.BigEndian.Uint32(encoded[:4])),
		encoded:       append([]byte(nil), encoded...),
		sha256:        framedSHA256("hal/l8/syscall-filter-rule/linux-amd64/v1", encoded),
	}
	for index := 0; index < int(encoded[4]); index++ {
		row := encoded[8+index*policyScalarClauseBytes : 8+(index+1)*policyScalarClauseBytes]
		clause := &scalarClause{
			argumentIndex:  row[0],
			operation:      ScalarOperation(row[1]),
			mask:           binary.BigEndian.Uint64(row[12:20]),
			mismatchAction: Action(binary.BigEndian.Uint32(row[4:8])),
			mismatchReason: Reason(row[8]),
			values:         make([]uint64, int(row[2])),
		}
		for valueIndex := range clause.values {
			clause.values[valueIndex] = binary.BigEndian.Uint64(row[20+valueIndex*8 : 28+valueIndex*8])
		}
		rule.clauses = append(rule.clauses, clause)
	}
	return rule, nil
}

func (profile FilterProfile) Role() Role {
	if profile.profile == nil {
		return 0
	}
	return profile.profile.role
}
func (profile FilterProfile) KernelCeiling() SyscallNumber {
	if profile.profile == nil {
		return 0
	}
	return profile.profile.kernelCeiling
}
func (profile FilterProfile) Catalog() []CatalogEntryView {
	if profile.profile == nil {
		return nil
	}
	result := make([]CatalogEntryView, len(profile.profile.catalog))
	for index, entry := range profile.profile.catalog {
		result[index] = CatalogEntryView{entry: entry}
	}
	return result
}
func (profile FilterProfile) Rules() []FilterRuleView {
	if profile.profile == nil {
		return nil
	}
	result := make([]FilterRuleView, len(profile.profile.rules))
	for index, rule := range profile.profile.rules {
		result[index] = FilterRuleView{rule: rule}
	}
	return result
}
func (profile FilterProfile) SHA256() [32]byte {
	if profile.profile == nil {
		return [32]byte{}
	}
	return profile.profile.sha256
}

func (profile FilterProfile) Decide(auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) FilterDecision {
	if profile.profile == nil || zeroDigest(profile.profile.sha256) {
		return FilterDecision{action: ActionKillProcess, reason: ReasonImpossibleTransition}
	}
	if auditArchitecture != 0xc000003e {
		return FilterDecision{action: ActionKillProcess, reason: ReasonForeignArchitecture}
	}
	if rawSyscallNumber&0x40000000 != 0 {
		return FilterDecision{action: ActionKillProcess, reason: ReasonX32Encoding}
	}
	number := SyscallNumber(rawSyscallNumber)
	if number > profile.profile.kernelCeiling {
		return FilterDecision{action: ActionKillProcess, reason: ReasonUnknownSyscall}
	}
	entry := catalogEntryByNumber(profile.profile.catalog, number)
	if entry == nil {
		return FilterDecision{action: ActionKillProcess, reason: ReasonUnknownSyscall}
	}
	if entry.class == SyscallClassFatal {
		return FilterDecision{action: ActionKillProcess, reason: ReasonForbiddenAuthority}
	}
	candidates := make([]*filterRule, 0)
	for _, rule := range profile.profile.rules {
		if rule.syscallNumber == number {
			candidates = append(candidates, rule)
		}
	}
	if len(candidates) == 0 {
		return FilterDecision{action: ActionErrnoEPERM, reason: ReasonKnownUnlisted}
	}
	type failedClause struct {
		rule   *filterRule
		clause *scalarClause
	}
	failures := make([]failedClause, 0)
	for _, rule := range candidates {
		matched := true
		for _, clause := range rule.clauses {
			if !clauseMatches(clause, arguments[clause.argumentIndex]) {
				matched = false
				failures = append(failures, failedClause{rule: rule, clause: clause})
			}
		}
		if matched {
			return FilterDecision{action: ActionAllow, reason: ReasonExactRule, ruleSHA256: rule.sha256}
		}
	}
	wantAction := ActionErrnoEPERM
	for _, failure := range failures {
		if failure.clause.mismatchAction == ActionKillProcess {
			wantAction = ActionKillProcess
			break
		}
	}
	for _, failure := range failures {
		if failure.clause.mismatchAction == wantAction {
			return FilterDecision{action: wantAction, reason: failure.clause.mismatchReason, ruleSHA256: failure.rule.sha256}
		}
	}
	return FilterDecision{action: ActionErrnoEPERM, reason: ReasonScalarMismatch}
}

func clauseMatches(clause *scalarClause, value uint64) bool {
	switch clause.operation {
	case ScalarEqual:
		return value == clause.values[0]
	case ScalarMaskedEqual:
		return value&clause.mask == clause.values[0]
	case ScalarOneOf:
		for _, candidate := range clause.values {
			if value == candidate {
				return true
			}
		}
		return false
	case ScalarUnsignedRange:
		return value >= clause.values[0] && value <= clause.values[1]
	case ScalarZero:
		return value == 0
	case ScalarNonzero:
		return value != 0
	default:
		return false
	}
}

func (rule FilterRuleView) SyscallNumber() SyscallNumber {
	if rule.rule == nil {
		return 0
	}
	return rule.rule.syscallNumber
}
func (rule FilterRuleView) ScalarClauses() []ScalarClauseView {
	if rule.rule == nil {
		return nil
	}
	result := make([]ScalarClauseView, len(rule.rule.clauses))
	for index, clause := range rule.rule.clauses {
		result[index] = ScalarClauseView{clause: clause}
	}
	return result
}
func (rule FilterRuleView) SHA256() [32]byte {
	if rule.rule == nil {
		return [32]byte{}
	}
	return rule.rule.sha256
}
func (clause ScalarClauseView) ArgumentIndex() uint8 {
	if clause.clause == nil {
		return 0
	}
	return clause.clause.argumentIndex
}
func (clause ScalarClauseView) Operation() ScalarOperation {
	if clause.clause == nil {
		return 0
	}
	return clause.clause.operation
}
func (clause ScalarClauseView) Mask() uint64 {
	if clause.clause == nil {
		return 0
	}
	return clause.clause.mask
}
func (clause ScalarClauseView) Values() []uint64 {
	if clause.clause == nil {
		return nil
	}
	return append([]uint64(nil), clause.clause.values...)
}
func (clause ScalarClauseView) MismatchAction() Action {
	if clause.clause == nil {
		return 0
	}
	return clause.clause.mismatchAction
}
func (clause ScalarClauseView) MismatchReason() Reason {
	if clause.clause == nil {
		return 0
	}
	return clause.clause.mismatchReason
}

func (decision FilterDecision) Action() Action       { return decision.action }
func (decision FilterDecision) Reason() Reason       { return decision.reason }
func (decision FilterDecision) Allowed() bool        { return decision.action == ActionAllow }
func (decision FilterDecision) RuleSHA256() [32]byte { return decision.ruleSHA256 }

func equalBytes(left, right []byte) bool {
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
