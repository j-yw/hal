package syscallpolicy

import "encoding/binary"

type adapterPermit struct {
	artifactSHA256          [32]byte
	ticketSHA256            [32]byte
	ruleSHA256              [32]byte
	inputSHA256             [32]byte
	permitCorrelationSHA256 [32]byte
	bindingsSHA256          [32]byte
	failure                 AdapterOutcome
	postQueries             []ObjectQuery
	sha256                  [32]byte
}

type AdapterPermit struct {
	permit    *adapterPermit
	owner     *policyOwner
	operation *adapterBindingOwner
}

type AdapterDecision struct {
	outcome    AdapterOutcome
	reason     AdapterReason
	phase      AdapterPhase
	final      bool
	ruleSHA256 [32]byte
}

func (policy *Policy) AuthorizePre(ticket AdapterTicket, bindings AdapterBindings, source PreObservationSource) (AdapterPermit, AdapterDecision, error) {
	if nilInterface(source) {
		return AdapterPermit{}, AdapterDecision{}, contractError(ErrorCodeTypedNil)
	}
	if !policyOwnsAdapterInputs(policy, ticket, bindings) {
		return AdapterPermit{}, AdapterDecision{}, contractError(ErrorCodeOwnership)
	}
	rule := ticket.ticket.rule
	for _, requirement := range rule.descriptors {
		if requirement.generationMode == GenerationModeLiveBound && !bindingMatches(bindings, requirement.bindingSlot, requirement.kind, requirement.access) {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonFDMismatch), nil
		}
	}
	for _, requirement := range rule.objects {
		if requirement.source == ObjectSourceArgument && requirement.generationMode == GenerationModeLiveBound && !bindingMatches(bindings, requirement.bindingSlot, requirement.kind, requirement.access) {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObjectMismatch), nil
		}
	}
	stage := policy.artifact.stages[rule.role][rule.stage]
	ordinal := uint16(0)
	stateQuery := newStateQuery(policy, ticket, ordinal, stage.requiredFacts|rule.requiredFacts, stage.prohibitedFacts|rule.prohibitedFacts, rule.stateChecks)
	stateObservation, err := observeStateSafely(source, stateQuery)
	if err != nil || stateObservation.observation == nil || stateObservation.owner != policy.owner || stateObservation.observation.querySHA256 != stateQuery.query.authority.sha256 {
		return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObserverFailure), contractError(ErrorCodeObservation)
	}
	if !stateObservationMatches(stateQuery, stateObservation) {
		return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonStateMismatch), nil
	}
	ordinal++
	for _, requirement := range rule.descriptors {
		query := newFDQuery(policy, ticket, bindings, requirement, ordinal)
		observation, observeErr := observeFDSafely(source, query)
		if observeErr != nil || observation.observation == nil || observation.owner != policy.owner || observation.observation.querySHA256 != query.query.authority.sha256 {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObserverFailure), contractError(ErrorCodeObservation)
		}
		if !fdObservationMatches(query, observation) {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonFDMismatch), nil
		}
		ordinal++
	}
	for _, requirement := range rule.pointers {
		query := newPointerQuery(policy, ticket, requirement, ordinal)
		observation, observeErr := observePointerSafely(source, query)
		if observeErr != nil || observation.observation == nil || observation.owner != policy.owner || observation.observation.querySHA256 != query.query.authority.sha256 {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObserverFailure), contractError(ErrorCodeObservation)
		}
		if !pointerObservationMatches(query, observation) {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonPointerMismatch), nil
		}
		ordinal++
	}
	for _, requirement := range rule.objects {
		if requirement.source != ObjectSourceArgument {
			continue
		}
		query := newObjectQuery(policy, ticket, bindings, requirement, AdapterPhasePre, ordinal)
		observation, observeErr := observeObjectSafely(source, query)
		if observeErr != nil || observation.observation == nil || observation.owner != policy.owner || observation.observation.querySHA256 != query.query.authority.sha256 {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObserverFailure), contractError(ErrorCodeObservation)
		}
		if !objectObservationMatches(query, observation) {
			return AdapterPermit{}, adapterFailureDecision(rule, AdapterPhasePre, AdapterReasonObjectMismatch), nil
		}
		ordinal++
	}
	postQueries := make([]ObjectQuery, 0)
	postOrdinal := uint16(0)
	for _, requirement := range rule.objects {
		if requirement.source == ObjectSourceReturn {
			postQueries = append(postQueries, newObjectQuery(policy, ticket, bindings, requirement, AdapterPhasePost, postOrdinal))
			postOrdinal++
		}
	}
	permit := newAdapterPermit(policy, ticket, bindings, postQueries)
	return permit, AdapterDecision{outcome: AdapterOutcomeProceed, reason: AdapterReasonExact, phase: AdapterPhasePre, ruleSHA256: rule.sha256}, nil
}

func (policy *Policy) AuthorizePost(permit AdapterPermit, source PostObservationSource) (AdapterDecision, error) {
	if nilInterface(source) {
		return AdapterDecision{}, contractError(ErrorCodeTypedNil)
	}
	if !policyOwnsPermit(policy, permit) {
		return AdapterDecision{}, contractError(ErrorCodeOwnership)
	}
	if len(permit.permit.postQueries) == 0 {
		return AdapterDecision{}, contractError(ErrorCodeInvalidArgument)
	}
	for _, query := range permit.permit.postQueries {
		observation, err := reinspectObjectSafely(source, query)
		if err != nil || observation.observation == nil || observation.owner != policy.owner || observation.observation.querySHA256 != query.query.authority.sha256 {
			return adapterPermitFailureDecision(permit, AdapterPhasePost, AdapterReasonObserverFailure), contractError(ErrorCodeObservation)
		}
		if !objectObservationMatches(query, observation) {
			return adapterPermitFailureDecision(permit, AdapterPhasePost, AdapterReasonObjectMismatch), nil
		}
	}
	return AdapterDecision{outcome: AdapterOutcomeProceed, reason: AdapterReasonExact, phase: AdapterPhasePost, final: true, ruleSHA256: permit.permit.ruleSHA256}, nil
}

func (policy *Policy) CommitNoObject(permit AdapterPermit) (AdapterDecision, error) {
	if !policyOwnsPermit(policy, permit) {
		return AdapterDecision{}, contractError(ErrorCodeOwnership)
	}
	if len(permit.permit.postQueries) != 0 {
		return AdapterDecision{}, contractError(ErrorCodeInvalidArgument)
	}
	return AdapterDecision{outcome: AdapterOutcomeProceed, reason: AdapterReasonExact, phase: AdapterPhasePost, final: true, ruleSHA256: permit.permit.ruleSHA256}, nil
}

func (policy *Policy) AbortPermit(permit AdapterPermit, phase AdapterPhase) (AdapterDecision, error) {
	if !policyOwnsPermit(policy, permit) {
		return AdapterDecision{}, contractError(ErrorCodeOwnership)
	}
	if ValidateAdapterPhase(phase) != nil {
		return AdapterDecision{}, contractError(ErrorCodeCatalog)
	}
	reason := AdapterReasonPreSyscallAbort
	if phase == AdapterPhasePost {
		reason = AdapterReasonSyscallFailure
	}
	return adapterPermitFailureDecision(permit, phase, reason), nil
}

func newAdapterPermit(policy *Policy, ticket AdapterTicket, bindings AdapterBindings, postQueries []ObjectQuery) AdapterPermit {
	permit := &adapterPermit{artifactSHA256: policy.artifact.sha256, ticketSHA256: ticket.ticket.sha256, ruleSHA256: ticket.ticket.ruleSHA256, inputSHA256: ticket.ticket.inputSHA256, permitCorrelationSHA256: ticket.ticket.permitCorrelationSHA256, bindingsSHA256: bindings.bindings.sha256, failure: ticket.ticket.rule.adapterFailure, postQueries: append([]ObjectQuery(nil), postQueries...)}
	preimage := make([]byte, 0, 66+len(postQueries)*32)
	preimage = append(preimage, permit.permitCorrelationSHA256[:]...)
	preimage = append(preimage, permit.bindingsSHA256[:]...)
	count := make([]byte, 2)
	binary.BigEndian.PutUint16(count, uint16(len(postQueries)))
	preimage = append(preimage, count...)
	for _, query := range postQueries {
		digest := query.SHA256()
		preimage = append(preimage, digest[:]...)
	}
	permit.sha256 = framedSHA256("hal/l8/adapter-permit/linux-amd64/v1", preimage)
	return AdapterPermit{permit: permit, owner: policy.owner, operation: bindings.operation}
}

func policyOwnsAdapterInputs(policy *Policy, ticket AdapterTicket, bindings AdapterBindings) bool {
	return policy != nil && policy.owner != nil && policy.artifact != nil && ticket.ticket != nil && ticket.owner == policy.owner && bindings.bindings != nil && bindings.owner == policy.owner && bindings.operation != nil && bindings.bindings.ticketSHA256 == ticket.ticket.sha256 && bindings.bindings.permitCorrelationSHA256 == ticket.ticket.permitCorrelationSHA256
}
func policyOwnsPermit(policy *Policy, permit AdapterPermit) bool {
	return policy != nil && policy.owner != nil && policy.artifact != nil && permit.permit != nil && permit.owner == policy.owner && permit.operation != nil && permit.permit.artifactSHA256 == policy.artifact.sha256
}
func bindingMatches(bindings AdapterBindings, slot uint8, kind DescriptorKind, access DescriptorAccess) bool {
	if bindings.bindings == nil {
		return false
	}
	for _, binding := range bindings.bindings.records {
		if binding.slot == slot {
			return binding.kind == kind && binding.access == access && !zeroDigest(binding.generationSHA256)
		}
	}
	return false
}
func stateObservationMatches(query StateQuery, observation StateObservation) bool {
	actual := observation.observation.actual
	return actual.role == query.query.expectedRole && actual.stage == query.query.expectedStage && actual.facts&query.query.requiredFacts == query.query.requiredFacts && actual.facts&query.query.prohibitedFacts == 0 && observation.observation.checks.bits == query.query.requiredChecks.bits
}
func fdObservationMatches(query FDQuery, observation FDObservation) bool {
	actual := observation.observation
	return actual.number == query.query.fdNumber && actual.kind == query.query.expectedKind && actual.access == query.query.expectedAccess && actual.generationSHA256 == query.query.expectedGenerationSHA256 && actual.fixed == query.query.fixed && actual.checks.bits == query.query.requiredChecks.bits
}
func pointerObservationMatches(query PointerQuery, observation PointerObservation) bool {
	actual := observation.observation
	return actual.class == query.query.expectedClass && actual.bytes >= query.query.minimumBytes && actual.bytes <= query.query.maximumBytes && actual.checks.bits == query.query.requiredChecks.bits
}
func objectObservationMatches(query ObjectQuery, observation ObjectObservation) bool {
	actual := observation.observation
	numberMatches := query.query.source == ObjectSourceReturn || actual.number == query.query.expectedNumber
	generationMatches := query.query.generationMode == GenerationModeFreshReturn && !zeroDigest(actual.generationSHA256) || actual.generationSHA256 == query.query.expectedGenerationSHA256
	return numberMatches && actual.kind == query.query.expectedKind && actual.access == query.query.expectedAccess && generationMatches && actual.fixed == query.query.fixed && actual.checks.bits == query.query.requiredChecks.bits
}
func adapterFailureDecision(rule *verifiedRule, phase AdapterPhase, reason AdapterReason) AdapterDecision {
	return AdapterDecision{outcome: rule.adapterFailure, reason: reason, phase: phase, final: true, ruleSHA256: rule.sha256}
}
func adapterPermitFailureDecision(permit AdapterPermit, phase AdapterPhase, reason AdapterReason) AdapterDecision {
	return AdapterDecision{outcome: permit.permit.failure, reason: reason, phase: phase, final: true, ruleSHA256: permit.permit.ruleSHA256}
}

func observeStateSafely(source PreObservationSource, query StateQuery) (observation StateObservation, err error) {
	defer recoverObservation(&err)
	return source.ObserveState(query)
}
func observeFDSafely(source PreObservationSource, query FDQuery) (observation FDObservation, err error) {
	defer recoverObservation(&err)
	return source.ObserveFD(query)
}
func observePointerSafely(source PreObservationSource, query PointerQuery) (observation PointerObservation, err error) {
	defer recoverObservation(&err)
	return source.ObservePointer(query)
}
func observeObjectSafely(source PreObservationSource, query ObjectQuery) (observation ObjectObservation, err error) {
	defer recoverObservation(&err)
	return source.ObserveObject(query)
}
func reinspectObjectSafely(source PostObservationSource, query ObjectQuery) (observation ObjectObservation, err error) {
	defer recoverObservation(&err)
	return source.ReinspectObject(query)
}
func recoverObservation(err *error) {
	if recover() != nil {
		*err = contractError(ErrorCodeObservation)
	}
}

func (decision AdapterDecision) Outcome() AdapterOutcome { return decision.outcome }
func (decision AdapterDecision) Reason() AdapterReason   { return decision.reason }
func (decision AdapterDecision) Phase() AdapterPhase     { return decision.phase }
func (decision AdapterDecision) Ready() bool {
	return !decision.final && decision.phase == AdapterPhasePre && decision.outcome == AdapterOutcomeProceed && decision.reason == AdapterReasonExact
}
func (decision AdapterDecision) Final() bool { return decision.final }
func (decision AdapterDecision) Authorized() bool {
	return decision.final && decision.phase == AdapterPhasePost && decision.outcome == AdapterOutcomeProceed && decision.reason == AdapterReasonExact
}
func (decision AdapterDecision) RuleSHA256() [32]byte { return decision.ruleSHA256 }
func (permit AdapterPermit) RuleSHA256() [32]byte {
	if permit.permit == nil || permit.owner == nil || permit.operation == nil {
		return [32]byte{}
	}
	return permit.permit.ruleSHA256
}
func (permit AdapterPermit) TicketSHA256() [32]byte {
	if permit.permit == nil || permit.owner == nil || permit.operation == nil {
		return [32]byte{}
	}
	return permit.permit.ticketSHA256
}
func (permit AdapterPermit) InputSHA256() [32]byte {
	if permit.permit == nil || permit.owner == nil || permit.operation == nil {
		return [32]byte{}
	}
	return permit.permit.inputSHA256
}
func (permit AdapterPermit) PermitCorrelationSHA256() [32]byte {
	if permit.permit == nil || permit.owner == nil || permit.operation == nil {
		return [32]byte{}
	}
	return permit.permit.permitCorrelationSHA256
}
func (permit AdapterPermit) RequiresPost() bool {
	return permit.permit != nil && permit.owner != nil && permit.operation != nil && len(permit.permit.postQueries) != 0
}
func (permit AdapterPermit) SHA256() [32]byte {
	if permit.permit == nil || permit.owner == nil || permit.operation == nil {
		return [32]byte{}
	}
	return permit.permit.sha256
}
