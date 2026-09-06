package syscallpolicy

import "testing"

func TestPolicyConstructionAndClassificationAreClosed(t *testing.T) {
	t.Parallel()

	if policy, err := NewPolicy(VerifiedPolicyArtifact{}); policy != nil || contractErrorCode(err) != ErrorCodeOwnership {
		t.Fatalf("NewPolicy(zero) = (%v, %v), want nil/ownership", policy, err)
	}
	foreign := VerifiedPolicyArtifact{sha256: [32]byte{1}, artifact: &verifiedArtifact{sha256: [32]byte{1}}}
	if policy, err := NewPolicy(foreign); policy != nil || contractErrorCode(err) != ErrorCodeOwnership {
		t.Fatalf("NewPolicy(foreign) = (%v, %v), want nil/ownership", policy, err)
	}
	artifact := pinnedEvidenceTestArtifact(t)
	mutated := artifact
	mutated.artifact = cloneVerifiedArtifact(artifact.artifact)
	mutated.artifact.encoded[0] ^= 0xff
	if policy, err := NewPolicy(mutated); policy != nil || contractErrorCode(err) != ErrorCodeDigestMismatch {
		t.Fatalf("NewPolicy(mutated) = (%v, %v), want nil/digest-mismatch", policy, err)
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	for _, test := range []struct {
		name  string
		arch  uint32
		raw   uint32
		abi   ABIClass
		num   SyscallNumber
		known bool
	}{
		{name: "known native", arch: 0xc000003e, raw: 0, abi: ABIClassNativeAMD64, num: 0, known: true},
		{name: "unknown native", arch: 0xc000003e, raw: 451, abi: ABIClassNativeAMD64, num: 451, known: false},
		{name: "x32", arch: 0xc000003e, raw: 0x40000000, abi: ABIClassX32, num: 0x40000000, known: false},
		{name: "foreign", arch: 0, raw: 0, abi: ABIClassForeign, num: 0, known: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			classification := policy.Classify(test.arch, test.raw)
			if classification.ABI() != test.abi || classification.Number() != test.num || classification.Known() != test.known {
				t.Fatalf("classification = %v/%v/%v, want %v/%v/%v", classification.ABI(), classification.Number(), classification.Known(), test.abi, test.num, test.known)
			}
		})
	}
}

func TestPolicyConstructionDeepCopiesSemanticGraph(t *testing.T) {
	t.Parallel()

	artifact := pinnedEvidenceTestArtifact(t)
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.artifact.rules) == 0 || len(policy.artifact.transitions) == 0 || len(policy.artifact.workload.rules) == 0 || len(policy.artifact.runtime.rules) == 0 {
		t.Fatal("NewPolicy() omitted decoded semantic graph")
	}
	if policy.artifact.rules[0] == artifact.artifact.rules[0] || policy.artifact.transitions[0] == artifact.artifact.transitions[0] {
		t.Fatal("NewPolicy() retained source semantic graph pointers")
	}
	if policy.artifact.workload.rules[0].Rule().rule != policy.artifact.rules[policy.artifact.workloadRuleIndexes[0]] {
		t.Fatal("workload view does not bind cloned rule graph")
	}
	if policy.artifact.runtime.rules[0].rule != policy.artifact.rules[policy.artifact.runtimeRuleIndexes[0]] {
		t.Fatal("runtime view does not bind cloned rule graph")
	}

	originalRole := policy.artifact.rules[0].role
	originalTarget := policy.artifact.transitions[0].toRole
	artifact.artifact.rules[0].role = RoleWorkload
	artifact.artifact.transitions[0].toRole = RoleWorkload
	if policy.artifact.rules[0].role != originalRole || policy.artifact.transitions[0].toRole != originalTarget {
		t.Fatal("source graph mutation reached constructed Policy")
	}
}

func TestFilterProfileUsesVerifiedCatalogAndProjection(t *testing.T) {
	t.Parallel()

	artifact := pinnedEvidenceTestArtifact(t)
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := policy.FilterProfile(RoleSteadyAgent)
	if err != nil {
		t.Fatalf("FilterProfile() error = %v", err)
	}
	if profile.Role() != RoleSteadyAgent || profile.KernelCeiling() != 450 || profile.SHA256() == ([32]byte{}) || len(profile.Catalog()) != 1 || len(profile.Rules()) != 1 {
		t.Fatal("FilterProfile() omitted verified catalog/projection state")
	}
	for _, test := range []struct {
		name   string
		arch   uint32
		raw    uint32
		action Action
		reason Reason
	}{
		{name: "exact", arch: 0xc000003e, raw: 0, action: ActionAllow, reason: ReasonExactRule},
		{name: "foreign", arch: 0, raw: 0, action: ActionKillProcess, reason: ReasonForeignArchitecture},
		{name: "x32", arch: 0xc000003e, raw: 0x40000000, action: ActionKillProcess, reason: ReasonX32Encoding},
		{name: "above ceiling", arch: 0xc000003e, raw: 451, action: ActionKillProcess, reason: ReasonUnknownSyscall},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := profile.Decide(test.arch, test.raw, [6]uint64{})
			if decision.Action() != test.action || decision.Reason() != test.reason || decision.Allowed() != (test.action == ActionAllow) {
				t.Fatalf("decision = %v/%v/%v, want %v/%v", decision.Action(), decision.Reason(), decision.Allowed(), test.action, test.reason)
			}
		})
	}
	zero := (FilterProfile{}).Decide(0xc000003e, 0, [6]uint64{})
	if zero.Action() != ActionKillProcess || zero.Reason() != ReasonImpossibleTransition {
		t.Fatal("zero FilterProfile did not fail closed")
	}
}

func TestPolicySemanticDecisionRulesFingerprintAndTransition(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(pinnedEvidenceTestArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewState(RoleLaunchBootstrap, StageActive, 0)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewFilterInput(state, 0xc000003e, 0, [6]uint64{})
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Decide(input)
	if !decision.Allowed() || decision.Action() != ActionAllow || decision.Reason() != ReasonExactRule || decision.RuleSHA256() == ([32]byte{}) {
		t.Fatalf("Decide(exact) = %v/%v/%v/%x", decision.Action(), decision.Reason(), decision.Allowed(), decision.RuleSHA256())
	}
	if ticket, err := decision.Ticket(); err == nil || ticket.SHA256() != ([32]byte{}) {
		t.Fatal("direct decision unexpectedly returned adapter authority")
	}
	foreignInput, _ := NewFilterInput(state, 0, 0, [6]uint64{})
	foreign := policy.Decide(foreignInput)
	if foreign.Action() != ActionKillProcess || foreign.Reason() != ReasonForeignArchitecture {
		t.Fatalf("foreign decision = %v/%v", foreign.Action(), foreign.Reason())
	}

	rules, err := policy.Rules(RoleLaunchBootstrap)
	if err != nil || len(rules) != 1 || rules[0].Role() != RoleLaunchBootstrap {
		t.Fatalf("Rules() = (%v, %v)", rules, err)
	}
	fingerprint, err := policy.Fingerprint(RoleLaunchBootstrap)
	if err != nil || fingerprint == ([32]byte{}) {
		t.Fatalf("Fingerprint() = (%x, %v)", fingerprint, err)
	}
	if _, err := (*Policy)(nil).Rules(RoleLaunchBootstrap); contractErrorCode(err) != ErrorCodeOwnership {
		t.Fatalf("nil Rules() error = %v", err)
	}

	to, _ := NewState(RoleLaunchBase, StageActive, 0)
	transition := policy.ValidateTransition(state, to)
	if !transition.Allowed() || transition.RuleSHA256() != ([32]byte{}) {
		t.Fatalf("ValidateTransition(exact) = %v/%v", transition.Action(), transition.Reason())
	}
	badTo, _ := NewState(RoleLaunchBase, StageActive, StateFactClosed)
	badTransition := policy.ValidateTransition(state, badTo)
	if badTransition.Action() != ActionKillProcess || badTransition.Reason() != ReasonImpossibleTransition {
		t.Fatalf("ValidateTransition(bad facts) = %v/%v", badTransition.Action(), badTransition.Reason())
	}
}
