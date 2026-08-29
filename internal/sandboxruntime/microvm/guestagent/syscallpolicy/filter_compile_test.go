package syscallpolicy

import (
	"testing"
)

func TestCompileFilterProfileRejectsZeroProfile(t *testing.T) {
	t.Parallel()
	if _, err := CompileFilterProfile(FilterProfile{}); err == nil {
		t.Fatal("CompileFilterProfile(zero) succeeded")
	}
	if _, err := CompileIssuedRoleFilter(nil, [32]byte{}, RoleLaunchBase); err == nil {
		t.Fatal("CompileIssuedRoleFilter(zero) succeeded")
	}
}

func TestCompileFilterProfileMatchesDecideActions(t *testing.T) {
	t.Parallel()
	profile := compileTestLaunchBaseProfile()
	compiled, err := CompileFilterProfile(profile)
	if err != nil {
		t.Fatalf("CompileFilterProfile() error = %v", err)
	}
	if compiled.Len() == 0 || compiled.Len() > bpfMaxInsns || compiled.SHA256() == ([32]byte{}) {
		t.Fatalf("compiled filter len/digest = %d/%x", compiled.Len(), compiled.SHA256())
	}
	cases := []struct {
		name string
		arch uint32
		nr   uint32
		args [6]uint64
		want Action
	}{
		{name: "allow read", arch: auditArchX86_64, nr: 0, want: ActionAllow},
		{name: "allow exit_group", arch: auditArchX86_64, nr: 231, want: ActionAllow},
		{name: "eperm unlisted ordinary socket", arch: auditArchX86_64, nr: 41, want: ActionErrnoEPERM},
		{name: "kill fatal clone3", arch: auditArchX86_64, nr: 435, want: ActionKillProcess},
		{name: "kill unknown", arch: auditArchX86_64, nr: 400, want: ActionKillProcess},
		{name: "kill above ceiling", arch: auditArchX86_64, nr: 451, want: ActionKillProcess},
		{name: "kill foreign arch", arch: 0, nr: 0, want: ActionKillProcess},
		{name: "kill x32", arch: auditArchX86_64, nr: 0 | x32SyscallBit, want: ActionKillProcess},
		{name: "allow prctl equal", arch: auditArchX86_64, nr: 157, args: [6]uint64{38}, want: ActionAllow},
		{name: "kill prctl mismatch", arch: auditArchX86_64, nr: 157, args: [6]uint64{1}, want: ActionKillProcess},
		{name: "allow one-of", arch: auditArchX86_64, nr: 3, args: [6]uint64{12}, want: ActionAllow},
		{name: "eperm one-of miss", arch: auditArchX86_64, nr: 3, args: [6]uint64{99}, want: ActionErrnoEPERM},
		{name: "allow range", arch: auditArchX86_64, nr: 292, args: [6]uint64{13}, want: ActionAllow},
		{name: "kill range high", arch: auditArchX86_64, nr: 292, args: [6]uint64{1 << 40}, want: ActionKillProcess},
		{name: "allow masked", arch: auditArchX86_64, nr: 9, args: [6]uint64{0x22}, want: ActionAllow},
		{name: "eperm masked", arch: auditArchX86_64, nr: 9, args: [6]uint64{0x21}, want: ActionErrnoEPERM},
		{name: "allow nonzero", arch: auditArchX86_64, nr: 102, args: [6]uint64{7}, want: ActionAllow},
		{name: "eperm zero vs nonzero", arch: auditArchX86_64, nr: 102, want: ActionErrnoEPERM},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			want := profile.Decide(test.arch, test.nr, test.args).Action()
			if want != test.want {
				t.Fatalf("Decide() = %v, want %v", want, test.want)
			}
			if got := compiled.Action(test.arch, test.nr, test.args); got != want {
				t.Fatalf("compiled Action() = %v, want Decide %v", got, want)
			}
		})
	}
}

func TestCompileFilterProfileMatchesGeneratePlusOneFilterGoldens(t *testing.T) {
	t.Parallel()
	encoded := artifactTestCoherentEnvelopeWithTopology(artifactTestRolesBodyWithPinnedAndExactTransitions(), artifactTestExactAncestryBody(), 9, 1)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{sha256: artifactTestDigest(encoded), issuer: expectedIssuer{issued: true}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := GeneratePlusOne(artifact)
	if err != nil {
		t.Fatal(err)
	}
	compiledByRole := make(map[Role]CompiledFilter)
	for role := RoleLaunchBootstrap; role <= RoleWorkload; role++ {
		profile, profileErr := policy.FilterProfile(role)
		if profileErr != nil {
			t.Fatalf("FilterProfile(%s) error = %v", role, profileErr)
		}
		compiled, compileErr := CompileFilterProfile(profile)
		if compileErr != nil {
			t.Fatalf("CompileFilterProfile(%s) error = %v", role, compileErr)
		}
		compiledByRole[role] = compiled
	}
	checked := 0
	for index, golden := range cases {
		if golden.Kind() != GoldenKindFilter {
			continue
		}
		input := golden.Input()
		compiled := compiledByRole[input.State().Role()]
		if compiled.Len() == 0 {
			t.Fatalf("case %d missing compiled profile for %s", index, input.State().Role())
		}
		got := compiled.Action(input.AuditArchitecture(), input.RawSyscallNumber(), input.arguments)
		if got != golden.Action() {
			t.Fatalf("case %d compiled action = %v, want golden %v", index, got, golden.Action())
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no filter goldens were checked")
	}
}

func compileTestLaunchBaseProfile() FilterProfile {
	catalog := []*catalogEntry{
		{number: 0, name: "read", class: SyscallClassOrdinary},
		{number: 3, name: "close", class: SyscallClassOrdinary},
		{number: 9, name: "mmap", class: SyscallClassOrdinary},
		{number: 41, name: "socket", class: SyscallClassOrdinary},
		{number: 102, name: "getuid", class: SyscallClassOrdinary},
		{number: 157, name: "prctl", class: SyscallClassOrdinary},
		{number: 231, name: "exit_group", class: SyscallClassOrdinary},
		{number: 292, name: "dup3", class: SyscallClassOrdinary},
		{number: 435, name: "clone3", class: SyscallClassFatal},
	}
	return FilterProfile{profile: &filterProfile{
		role:          RoleLaunchBase,
		kernelCeiling: 450,
		catalog:       catalog,
		rules: []*filterRule{
			{syscallNumber: 0},
			{syscallNumber: 231},
			{
				syscallNumber: 157,
				clauses: []*scalarClause{{
					argumentIndex:  0,
					operation:      ScalarEqual,
					values:         []uint64{38},
					mismatchAction: ActionKillProcess,
					mismatchReason: ReasonScalarMismatch,
				}},
			},
			{
				syscallNumber: 3,
				clauses: []*scalarClause{{
					argumentIndex:  0,
					operation:      ScalarOneOf,
					values:         []uint64{12, 13, 14},
					mismatchAction: ActionErrnoEPERM,
					mismatchReason: ReasonScalarMismatch,
				}},
			},
			{
				syscallNumber: 292,
				clauses: []*scalarClause{{
					argumentIndex:  0,
					operation:      ScalarUnsignedRange,
					values:         []uint64{12, 14},
					mismatchAction: ActionKillProcess,
					mismatchReason: ReasonScalarMismatch,
				}},
			},
			{
				syscallNumber: 9,
				clauses: []*scalarClause{{
					argumentIndex:  0,
					operation:      ScalarMaskedEqual,
					mask:           0xff,
					values:         []uint64{0x22},
					mismatchAction: ActionErrnoEPERM,
					mismatchReason: ReasonScalarMismatch,
				}},
			},
			{
				syscallNumber: 102,
				clauses: []*scalarClause{{
					argumentIndex:  0,
					operation:      ScalarNonzero,
					mismatchAction: ActionErrnoEPERM,
					mismatchReason: ReasonScalarMismatch,
				}},
			},
		},
		sha256: [32]byte{1},
	}}
}
