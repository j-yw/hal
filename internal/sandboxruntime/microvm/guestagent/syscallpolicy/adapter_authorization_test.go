package syscallpolicy

import "testing"

type adapterPreSource struct {
	state State
	gen   [32]byte
	kind  DescriptorKind
}

func (source *adapterPreSource) ObserveState(query StateQuery) (StateObservation, error) {
	return NewStateObservation(query, source.state, query.RequiredChecks())
}
func (source *adapterPreSource) ObserveFD(query FDQuery) (FDObservation, error) {
	return NewFDObservation(query, query.FDNumber(), source.kind, query.ExpectedAccess(), source.gen, query.Fixed(), query.RequiredChecks())
}
func (*adapterPreSource) ObservePointer(PointerQuery) (PointerObservation, error) {
	panic("unexpected pointer query")
}
func (*adapterPreSource) ObserveObject(ObjectQuery) (ObjectObservation, error) {
	panic("unexpected object query")
}

func TestAdapterPreAuthorizationAndNoObjectCommitAreClosed(t *testing.T) {
	t.Parallel()

	policy, ticket := adapterBindingTestPolicyAndTicket(t)
	generation := [32]byte{9}
	bindings, err := policy.NewAdapterBindings(ticket, adapterBindingSourceFunc(func(query BindingQuery) (BindingObservation, error) {
		return NewBindingObservation(query, query.ExpectedKind(), query.ExpectedAccess(), generation)
	}))
	if err != nil {
		t.Fatal(err)
	}
	state := ticket.ticket.input.State()
	permit, pre, err := policy.AuthorizePre(ticket, bindings, &adapterPreSource{state: state, gen: generation, kind: DescriptorKindInert})
	if err != nil || !pre.Ready() || pre.Final() || pre.Outcome() != AdapterOutcomeProceed || pre.Reason() != AdapterReasonExact || permit.SHA256() == ([32]byte{}) || permit.PermitCorrelationSHA256() != bindings.PermitCorrelationSHA256() || permit.RequiresPost() {
		t.Fatalf("AuthorizePre(exact) = permit=%x decision=%v/%v ready=%v final=%v err=%v", permit.SHA256(), pre.Outcome(), pre.Reason(), pre.Ready(), pre.Final(), err)
	}
	final, err := policy.CommitNoObject(permit)
	if err != nil || !final.Final() || !final.Authorized() || final.Phase() != AdapterPhasePost || final.Outcome() != AdapterOutcomeProceed || final.Reason() != AdapterReasonExact {
		t.Fatalf("CommitNoObject() = %v/%v/%v err=%v", final.Outcome(), final.Reason(), final.Phase(), err)
	}
	aborted, err := policy.AbortPermit(permit, AdapterPhasePre)
	if err != nil || !aborted.Final() || aborted.Reason() != AdapterReasonPreSyscallAbort || aborted.Outcome() != AdapterOutcomeRejectCleanup {
		t.Fatalf("AbortPermit(pre) = %v/%v err=%v", aborted.Outcome(), aborted.Reason(), err)
	}

	zeroPermit, mismatch, err := policy.AuthorizePre(ticket, bindings, &adapterPreSource{state: state, gen: generation, kind: DescriptorKindRegular})
	if err != nil || zeroPermit.SHA256() != ([32]byte{}) || !mismatch.Final() || mismatch.Reason() != AdapterReasonFDMismatch || mismatch.Outcome() != AdapterOutcomeRejectCleanup {
		t.Fatalf("AuthorizePre(mismatch) = permit=%x decision=%v/%v err=%v", zeroPermit.SHA256(), mismatch.Outcome(), mismatch.Reason(), err)
	}
	if decision, err := policy.AbortPermit(AdapterPermit{}, AdapterPhase(0)); decision.Outcome() != 0 || contractErrorCode(err) != ErrorCodeOwnership {
		t.Fatalf("AbortPermit(zero) = %v/%v", decision.Outcome(), err)
	}
}

type adapterPostSourceFunc func(ObjectQuery) (ObjectObservation, error)

func (source adapterPostSourceFunc) ReinspectObject(query ObjectQuery) (ObjectObservation, error) {
	return source(query)
}

func TestAdapterReturnedObjectRequiresExactPostAuthorization(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(pinnedEvidenceTestArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := policy.artifact.rules[0]
	rule.enforcementPath = EnforcementPathAdapter
	rule.adapterFailure = AdapterOutcomeStopVM
	rule.stateChecks = CheckSet{bits: checkBits(CheckProcessIdentity)}
	rule.objects = []*objectRequirement{{
		source:         ObjectSourceReturn,
		argumentIndex:  255,
		kind:           DescriptorKindInert,
		access:         DescriptorAccessRead,
		generationMode: GenerationModeFreshReturn,
		requiredChecks: CheckSet{bits: checkBits(CheckFDKind, CheckFDAccess, CheckFDGeneration, CheckObjectIdentity, CheckPostSuccessReinspection)},
	}}
	state, _ := NewState(RoleLaunchBootstrap, StageActive, 0)
	input, _ := NewFilterInput(state, 0xc000003e, 0, [6]uint64{})
	decision := policy.Decide(input)
	ticket, err := decision.Ticket()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := policy.NewAdapterBindings(ticket, adapterBindingSourceFunc(func(BindingQuery) (BindingObservation, error) {
		t.Fatal("fresh return must not request a preexisting binding")
		return BindingObservation{}, nil
	}))
	if err != nil || len(bindings.Bindings()) != 0 || bindings.SHA256() == ([32]byte{}) {
		t.Fatalf("empty binding snapshot = (%x, %v)", bindings.SHA256(), err)
	}
	permit, pre, err := policy.AuthorizePre(ticket, bindings, &adapterPreSource{state: state})
	if err != nil || !pre.Ready() || !permit.RequiresPost() {
		t.Fatalf("AuthorizePre(return object) = ready=%v post=%v err=%v", pre.Ready(), permit.RequiresPost(), err)
	}
	if terminal, err := policy.CommitNoObject(permit); terminal.Final() || contractErrorCode(err) != ErrorCodeInvalidArgument {
		t.Fatalf("CommitNoObject(post permit) = (%v, %v)", terminal.Final(), err)
	}
	generation := [32]byte{7}
	post, err := policy.AuthorizePost(permit, adapterPostSourceFunc(func(query ObjectQuery) (ObjectObservation, error) {
		number, numberErr := query.ExpectedNumber()
		if numberErr != nil || number != -1 || query.Source() != ObjectSourceReturn || query.Phase() != AdapterPhasePost || query.Ordinal() != 0 || query.GenerationMode() != GenerationModeFreshReturn || query.ExpectedGenerationSHA256() != ([32]byte{}) {
			t.Fatal("return-object query omitted exact post authority")
		}
		return NewObjectObservation(query, 5, query.ExpectedKind(), query.ExpectedAccess(), generation, query.RequiredChecks(), query.Fixed())
	}))
	if err != nil || !post.Final() || !post.Authorized() {
		t.Fatalf("AuthorizePost(exact) = %v/%v err=%v", post.Outcome(), post.Reason(), err)
	}
	mismatch, err := policy.AuthorizePost(permit, adapterPostSourceFunc(func(query ObjectQuery) (ObjectObservation, error) {
		return NewObjectObservation(query, 5, DescriptorKindRegular, query.ExpectedAccess(), generation, query.RequiredChecks(), query.Fixed())
	}))
	if err != nil || !mismatch.Final() || mismatch.Authorized() || mismatch.Outcome() != AdapterOutcomeStopVM || mismatch.Reason() != AdapterReasonObjectMismatch {
		t.Fatalf("AuthorizePost(mismatch) = %v/%v authorized=%v err=%v", mismatch.Outcome(), mismatch.Reason(), mismatch.Authorized(), err)
	}
}
