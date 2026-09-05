package syscallpolicy

import "testing"

type adapterBindingSourceFunc func(BindingQuery) (BindingObservation, error)

func (source adapterBindingSourceFunc) ObserveBinding(query BindingQuery) (BindingObservation, error) {
	return source(query)
}

func TestAdapterBindingsAreTicketBoundImmutableAndOperationScoped(t *testing.T) {
	t.Parallel()

	policy, ticket := adapterBindingTestPolicyAndTicket(t)
	if bindings, err := policy.NewAdapterBindings(ticket, nil); bindings.SHA256() != ([32]byte{}) || contractErrorCode(err) != ErrorCodeTypedNil {
		t.Fatalf("NewAdapterBindings(nil) = (%x, %v)", bindings.SHA256(), err)
	}

	generation := [32]byte{9}
	source := adapterBindingSourceFunc(func(query BindingQuery) (BindingObservation, error) {
		if query.Slot() != 1 || query.ExpectedKind() != DescriptorKindInert || query.ExpectedAccess() != DescriptorAccessRead || query.TicketSHA256() != ticket.SHA256() || query.PermitCorrelationSHA256() == ([32]byte{}) {
			t.Fatal("binding query omitted ticket-bound authority")
		}
		return NewBindingObservation(query, DescriptorKindInert, DescriptorAccessRead, generation)
	})
	first, err := policy.NewAdapterBindings(ticket, source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := policy.NewAdapterBindings(ticket, source)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256() == ([32]byte{}) || first.SHA256() != second.SHA256() || first.operation == nil || second.operation == nil || first.operation == second.operation {
		t.Fatal("binding snapshots lost deterministic bytes or private operation identity")
	}
	views := first.Bindings()
	if len(views) != 1 || views[0].Slot() != 1 || views[0].Kind() != DescriptorKindInert || views[0].Access() != DescriptorAccessRead || views[0].GenerationSHA256() != generation || views[0].PermitCorrelationSHA256() != first.PermitCorrelationSHA256() || views[0].SHA256() == ([32]byte{}) {
		t.Fatal("binding view omitted immutable record")
	}
	views[0] = AdapterBindingView{}
	if first.Bindings()[0].GenerationSHA256() != generation {
		t.Fatal("binding view slice mutation escaped")
	}

	mismatch, err := policy.NewAdapterBindings(ticket, adapterBindingSourceFunc(func(query BindingQuery) (BindingObservation, error) {
		return NewBindingObservation(query, DescriptorKindRegular, DescriptorAccessRead, generation)
	}))
	if err != nil || len(mismatch.Bindings()) != 1 || mismatch.Bindings()[0].Kind() != DescriptorKindRegular {
		t.Fatalf("well-formed mismatch evidence = (%v, %v), want retained", mismatch.Bindings(), err)
	}
}

func adapterBindingTestPolicyAndTicket(t *testing.T) (*Policy, AdapterTicket) {
	t.Helper()
	policy, err := NewPolicy(pinnedEvidenceTestArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := policy.artifact.rules[0]
	rule.enforcementPath = EnforcementPathAdapter
	rule.adapterFailure = AdapterOutcomeRejectCleanup
	rule.stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
	rule.descriptors = []*descriptorRequirement{{
		argumentIndex:  0,
		kind:           DescriptorKindInert,
		access:         DescriptorAccessRead,
		generationMode: GenerationModeLiveBound,
		bindingSlot:    1,
		requiredChecks: CheckSet{bits: checkBits(CheckFDKind, CheckFDAccess, CheckFDGeneration)},
	}}
	state, _ := NewState(RoleLaunchBootstrap, StageActive, 0)
	input, _ := NewFilterInput(state, 0xc000003e, 0, [6]uint64{})
	decision := policy.Decide(input)
	ticket, err := decision.Ticket()
	if err != nil {
		t.Fatalf("adapter ticket error = %v", err)
	}
	return policy, ticket
}
