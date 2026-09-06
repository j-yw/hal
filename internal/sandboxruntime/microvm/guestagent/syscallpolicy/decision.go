package syscallpolicy

import (
	"bytes"
	"sort"
)

type adapterTicket struct {
	artifactSHA256          [32]byte
	ruleSHA256              [32]byte
	inputSHA256             [32]byte
	sha256                  [32]byte
	permitCorrelationSHA256 [32]byte
	input                   FilterInput
	rule                    *verifiedRule
}

type AdapterTicket struct {
	ticket *adapterTicket
	owner  *policyOwner
}

type Decision struct {
	action     Action
	reason     Reason
	ruleSHA256 [32]byte
	ticket     AdapterTicket
}

func (policy *Policy) Decide(input FilterInput) Decision {
	denied := Decision{action: ActionKillProcess, reason: ReasonImpossibleTransition}
	if policy == nil || policy.owner == nil || policy.artifact == nil || !input.valid {
		return denied
	}
	if _, ok := policy.artifact.stages[input.state.role][input.state.stage]; !ok {
		return denied
	}
	if input.auditArchitecture != 0xc000003e {
		return Decision{action: ActionKillProcess, reason: ReasonForeignArchitecture}
	}
	if input.rawSyscallNumber&0x40000000 != 0 {
		return Decision{action: ActionKillProcess, reason: ReasonX32Encoding}
	}
	number := SyscallNumber(input.rawSyscallNumber)
	if number > 450 {
		return Decision{action: ActionKillProcess, reason: ReasonUnknownSyscall}
	}
	entry := catalogEntryByNumber(policy.artifact.catalog, number)
	if entry == nil {
		return Decision{action: ActionKillProcess, reason: ReasonUnknownSyscall}
	}
	if entry.class == SyscallClassFatal {
		return Decision{action: ActionKillProcess, reason: ReasonForbiddenAuthority}
	}
	numberRules := rulesForNumber(policy.artifact.rules, number)
	if len(numberRules) == 0 {
		return Decision{action: ActionErrnoEPERM, reason: ReasonKnownUnlisted}
	}
	roleRules := rulesForRole(numberRules, input.state.role)
	if len(roleRules) == 0 {
		return Decision{action: ActionErrnoEPERM, reason: ReasonWrongRole}
	}
	candidates := make([]*verifiedRule, 0, len(roleRules))
	for _, rule := range roleRules {
		if rule.enforcementPath != EnforcementPathAdapter {
			candidates = append(candidates, rule)
			continue
		}
		stage, ok := policy.artifact.stages[rule.role][rule.stage]
		if !ok || rule.stage != input.state.stage {
			continue
		}
		required := stage.requiredFacts | rule.requiredFacts
		prohibited := stage.prohibitedFacts | rule.prohibitedFacts
		if input.state.facts&required != required || input.state.facts&prohibited != 0 {
			continue
		}
		candidates = append(candidates, rule)
	}
	if len(candidates) == 0 {
		return Decision{action: ActionErrnoEPERM, reason: ReasonStateMismatch}
	}
	type failedClause struct {
		rule   *verifiedRule
		clause *scalarClause
	}
	failures := make([]failedClause, 0)
	for _, rule := range candidates {
		matched := true
		for _, clause := range rule.scalarClauses {
			if !clauseMatches(clause, input.arguments[clause.argumentIndex]) {
				matched = false
				failures = append(failures, failedClause{rule: rule, clause: clause})
			}
		}
		if matched {
			decision := Decision{action: ActionAllow, reason: ReasonExactRule, ruleSHA256: rule.sha256}
			if rule.enforcementPath == EnforcementPathAdapter {
				decision.ticket = newAdapterTicket(policy, input, rule)
			}
			return decision
		}
	}
	wantAction := ActionErrnoEPERM
	for _, failure := range failures {
		if failure.clause.mismatchAction == ActionKillProcess {
			wantAction = ActionKillProcess
			break
		}
	}
	sort.SliceStable(failures, func(left, right int) bool {
		comparison := bytes.Compare(failures[left].rule.encoded, failures[right].rule.encoded)
		if comparison != 0 {
			return comparison < 0
		}
		return failures[left].clause.argumentIndex < failures[right].clause.argumentIndex
	})
	for _, failure := range failures {
		if failure.clause.mismatchAction != wantAction {
			continue
		}
		reason := failure.clause.mismatchReason
		if hasFixedDescriptorAt(failure.rule, failure.clause.argumentIndex) {
			reason = ReasonFDMismatch
		}
		return Decision{action: wantAction, reason: reason, ruleSHA256: failure.rule.sha256}
	}
	return Decision{action: ActionErrnoEPERM, reason: ReasonScalarMismatch}
}

func (policy *Policy) Rules(role Role) ([]RuleView, error) {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return nil, contractError(ErrorCodeOwnership)
	}
	if ValidateRole(role) != nil {
		return nil, contractError(ErrorCodeCatalog)
	}
	rules := rulesForRole(policy.artifact.rules, role)
	result := make([]RuleView, len(rules))
	for index, rule := range rules {
		result[index] = RuleView{rule: rule}
	}
	return result, nil
}

func (policy *Policy) Fingerprint(role Role) ([32]byte, error) {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return [32]byte{}, contractError(ErrorCodeOwnership)
	}
	if ValidateRole(role) != nil {
		return [32]byte{}, contractError(ErrorCodeCatalog)
	}
	encoded := policy.artifact.roleSections[role]
	if len(encoded) == 0 {
		return [32]byte{}, contractError(ErrorCodeCatalog)
	}
	return framedSHA256("hal/l8/syscall-role/linux-amd64/v1", encoded), nil
}

func (policy *Policy) ValidateTransition(from, to State) Decision {
	denied := Decision{action: ActionKillProcess, reason: ReasonImpossibleTransition}
	if policy == nil || policy.owner == nil || policy.artifact == nil || !from.valid || !to.valid {
		return denied
	}
	fromStage, ok := policy.artifact.stages[from.role][from.stage]
	if !ok || from.facts&fromStage.requiredFacts != fromStage.requiredFacts || from.facts&fromStage.prohibitedFacts != 0 {
		return denied
	}
	var edge *verifiedTransition
	for _, candidate := range policy.artifact.transitions {
		if candidate.role == from.role && candidate.from == from.stage && candidate.toRole == to.role && candidate.to == to.stage {
			edge = candidate
			break
		}
	}
	if edge == nil || from.facts&edge.requiredFacts != edge.requiredFacts || from.facts&edge.prohibitedFacts != 0 {
		return denied
	}
	expectedFacts := (from.facts | edge.setFacts) &^ edge.clearFacts
	if to.facts != expectedFacts {
		return denied
	}
	toStage, ok := policy.artifact.stages[to.role][to.stage]
	if !ok || to.facts&toStage.requiredFacts != toStage.requiredFacts || to.facts&toStage.prohibitedFacts != 0 {
		return denied
	}
	return Decision{action: ActionAllow, reason: ReasonExactRule}
}

func newAdapterTicket(policy *Policy, input FilterInput, rule *verifiedRule) AdapterTicket {
	inputDigest := input.SHA256()
	preimage := make([]byte, 0, 96)
	preimage = append(preimage, policy.artifact.sha256[:]...)
	preimage = append(preimage, rule.sha256[:]...)
	preimage = append(preimage, inputDigest[:]...)
	ticket := &adapterTicket{
		artifactSHA256: policy.artifact.sha256,
		ruleSHA256:     rule.sha256,
		inputSHA256:    inputDigest,
		input:          input,
		rule:           rule,
	}
	ticket.sha256 = framedSHA256("hal/l8/adapter-ticket/linux-amd64/v1", preimage)
	correlationPreimage := make([]byte, 0, 129)
	correlationPreimage = append(correlationPreimage, policy.artifact.sha256[:]...)
	correlationPreimage = append(correlationPreimage, ticket.sha256[:]...)
	correlationPreimage = append(correlationPreimage, rule.sha256[:]...)
	correlationPreimage = append(correlationPreimage, inputDigest[:]...)
	correlationPreimage = append(correlationPreimage, byte(rule.adapterFailure))
	ticket.permitCorrelationSHA256 = framedSHA256("hal/l8/adapter-permit-correlation/linux-amd64/v1", correlationPreimage)
	return AdapterTicket{ticket: ticket, owner: policy.owner}
}

func rulesForNumber(rules []*verifiedRule, number SyscallNumber) []*verifiedRule {
	result := make([]*verifiedRule, 0)
	for _, rule := range rules {
		if rule.syscallNumber == number {
			result = append(result, rule)
		}
	}
	return result
}

func rulesForRole(rules []*verifiedRule, role Role) []*verifiedRule {
	result := make([]*verifiedRule, 0)
	for _, rule := range rules {
		if rule.role == role {
			result = append(result, rule)
		}
	}
	return result
}

func hasFixedDescriptorAt(rule *verifiedRule, argumentIndex uint8) bool {
	for _, requirement := range rule.descriptors {
		if requirement.argumentIndex == argumentIndex && requirement.fixed {
			return true
		}
	}
	return false
}

func (decision Decision) Action() Action       { return decision.action }
func (decision Decision) Reason() Reason       { return decision.reason }
func (decision Decision) Allowed() bool        { return decision.action == ActionAllow }
func (decision Decision) RuleSHA256() [32]byte { return decision.ruleSHA256 }
func (decision Decision) Ticket() (AdapterTicket, error) {
	if !decision.Allowed() || decision.reason != ReasonExactRule || decision.ruleSHA256 == ([32]byte{}) || decision.ticket.ticket == nil || decision.ticket.owner == nil || decision.ticket.ticket.sha256 == ([32]byte{}) {
		return AdapterTicket{}, contractError(ErrorCodeOwnership)
	}
	return decision.ticket, nil
}

func (ticket AdapterTicket) ArtifactSHA256() [32]byte {
	if ticket.ticket == nil || ticket.owner == nil {
		return [32]byte{}
	}
	return ticket.ticket.artifactSHA256
}
func (ticket AdapterTicket) RuleSHA256() [32]byte {
	if ticket.ticket == nil || ticket.owner == nil {
		return [32]byte{}
	}
	return ticket.ticket.ruleSHA256
}
func (ticket AdapterTicket) InputSHA256() [32]byte {
	if ticket.ticket == nil || ticket.owner == nil {
		return [32]byte{}
	}
	return ticket.ticket.inputSHA256
}
func (ticket AdapterTicket) SHA256() [32]byte {
	if ticket.ticket == nil || ticket.owner == nil {
		return [32]byte{}
	}
	return ticket.ticket.sha256
}
