package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2GuestHelperSyscallPolicyArchitectureClosureIsNormative(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, required := range []string{
		"guestagent/syscallpolicy",
		"type VerifiedPolicyArtifact struct",
		"type ExpectedPolicyArtifact struct",
		"func ImportVerifiedPolicyArtifact(encoded []byte, expected ExpectedPolicyArtifact) (VerifiedPolicyArtifact, error)",
		"func EmbeddedVerifiedPolicyArtifact() (VerifiedPolicyArtifact, error)",
		"func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error)",
		"func NewPolicy(artifact VerifiedPolicyArtifact) (*Policy, error)",
		"func NewState(role Role, stage Stage, facts StateFact) (State, error)",
		"func NewFilterInput(state State, auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) (FilterInput, error)",
		"func (policy *Policy) Decide(input FilterInput) Decision",
		"func (policy *Policy) AuthorizePre(ticket AdapterTicket, bindings AdapterBindings, source PreObservationSource) (AdapterPermit, AdapterDecision, error)",
		"func (policy *Policy) AuthorizePost(permit AdapterPermit, source PostObservationSource) (AdapterDecision, error)",
		"func (policy *Policy) CommitNoObject(permit AdapterPermit) (AdapterDecision, error)",
		"func (policy *Policy) AbortPermit(permit AdapterPermit, phase AdapterPhase) (AdapterDecision, error)",
		"func (policy *Policy) ValidateTransition(from, to State) Decision",
		"func (policy *Policy) Fingerprint(role Role) ([32]byte, error)",
		"func (policy *Policy) Rules(role Role) ([]RuleView, error)",
		"func (policy *Policy) FilterRules(role Role) ([]FilterRuleView, error)",
		"func (policy *Policy) FilterProfile(role Role) (FilterProfile, error)",
		"func (profile FilterProfile) Decide(auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) FilterDecision",
		"type FilterDecision struct",
		"func (policy *Policy) GoldenCases() []GoldenCase",
		"func (input FilterInput) SHA256() [32]byte",
		"func (ticket AdapterTicket) SHA256() [32]byte",
		"func (binding AdapterBindingView) SHA256() [32]byte",
		"RoleLaunchBootstrap Role = 1",
		"RoleWorkload Role = 10",
		"ActionKillProcess Action = 0x80000000",
		"ActionErrnoEPERM Action = 0x00050001",
		"ActionAllow Action = 0x7fff0000",
		"ReasonExactRule Reason = 1",
		"ReasonFDMismatch Reason = 13",
		"AUDIT_ARCH_X86_64 = 0xc000003e",
		"X32SyscallBit = 0x40000000",
		"golang.org/x/sys@v0.41.0",
		"d12bc509fbe79afd804a66297c7517076eea6f3c8d82780630cd07f561b043b6",
		"kernel ceiling:u32=450",
		"the exact legacy row `156,_sysctl`",
		"`cgroup.kill` with exactly `O_WRONLY|O_CLOEXEC`",
		"`cgroup.events` with exactly `O_RDONLY|O_CLOEXEC`",
		"`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and mode `0600`",
		"type WorkloadSnapshot struct",
		"type WorkloadRuleView struct",
		"type RuleView struct",
		"type CatalogEntryView struct",
		"type ScalarClauseView struct",
		"type DescriptorRequirementView struct",
		"type TransitionView struct",
		"type FilterRuleView struct",
		"type FilterProfile struct",
		"type AdapterFixtureView struct",
		"GoldenKindSemantic GoldenKind = 1",
		"GoldenKindFilter GoldenKind = 2",
		"type RuleOrigin uint8",
		"RuleOriginRole RuleOrigin = 1",
		"SyscallClassConditional SyscallClass = 3",
		"func ValidateSyscallClass(SyscallClass) error",
		"magic[4] = \"HL8Q\"",
		"hal/l8/verified-syscall-policy/linux-amd64/v1",
		"MaxVerifiedPolicyArtifactBytes = 4194304",
		"MaxPolicyRules = 8192",
		"MaxPinnedCallsiteEvidenceBytes = 16777216",
		"production `NewPolicy` rejects",
		"VerifiedL8Profile",
		"D7 is the sole rule-table author and artifact issuer",
		"RuntimeProfileView",
		"Trace remains verification evidence only",
		"`launch-base` names the",
		"`workload-transition` names",
		"PreObservationSource",
		"PostObservationSource",
		"ObserveState(StateQuery) (StateObservation, error)",
		"ObserveFD(FDQuery) (FDObservation, error)",
		"ObservePointer(PointerQuery) (PointerObservation, error)",
		"ReinspectObject(ObjectQuery) (ObjectObservation, error)",
		"NewStateObservation",
		"NewFDObservation",
		"NewPointerObservation",
		"NewObjectObservation",
		"typed-nil `PreObservationSource`",
		"typed-nil `PostObservationSource`",
		"type AdapterPermit struct",
		"permit is immutable and repeatable",
		"D4 executes exactly one live syscall",
		"D2 never executes or observes the live syscall",
		"D4's sole compiler input",
		"D4 never imports host headers or x/sys",
		"EnforcementPathDirect EnforcementPath = 1",
		"EnforcementPathAdapter EnforcementPath = 2",
		"EnforcementPathPinnedDirect EnforcementPath = 3",
		"type PinnedCallsiteRequirementView struct",
		"type PinnedCallsiteEvidenceView struct",
		"hal/l8/pinned-callsite/linux-amd64/v1",
		"instructionTemplateSHA256:[32]byte | toolchainSHA256:[32]byte",
		"binarySHA256:[32]byte | executableTextSHA256:[32]byte",
		"observedInstructionSHA256:[32]byte",
		"func (requirement PinnedCallsiteRequirementView) InstructionLength() uint16",
		"func (binding PinnedBinaryBindingView) ExecutableTextSHA256() [32]byte",
		"only for `RuleOriginRole` in exactly `RoleLaunchBootstrap`",
		"`RoleControllerBootstrap`, `RoleAgentBootstrap`, `RoleMonitorBootstrap`",
		"scalar-only workload exception",
		"RuleOriginWorkload` rows are never helper pointer-callsite authority",
		"type GenerationMode uint8",
		"GenerationModeStaticExact GenerationMode = 1",
		"GenerationModeLiveBound GenerationMode = 2",
		"GenerationModeFreshReturn GenerationMode = 3",
		"func (query ObjectQuery) GenerationMode() GenerationMode",
		"FreshReturn never compares the query's zero generation for equality",
		"type AdapterBindings struct",
		"type AdapterBindingView struct",
		"func (policy *Policy) NewAdapterBindings(ticket AdapterTicket, source BindingSource) (AdapterBindings, error)",
		"func (bindings AdapterBindings) PermitCorrelationSHA256() [32]byte",
		"permitCorrelationSHA256",
		"PermitCorrelationSHA256() [32]byte",
		"hal/l8/adapter-permit-correlation/linux-amd64/v1",
		"effective required facts are the union",
		"effective prohibited facts are the union",
		"expectedDestinationFacts = (from.Facts() | setFacts) &^ clearFacts",
		"func (transition TransitionView) SetFacts() StateFact",
		"func (transition TransitionView) ClearFacts() StateFact",
		"collects every failing clause from every candidate rule",
		"chooses kill if any collected clause has kill action",
		"dual-action failure fixture",
		"zero or invalid `FilterProfile`",
		"Check admissibility and mandatory matrix",
		"No check bit is fungible",
		"hal/l8/verified-policy-source-lock/linux-amd64/v1",
		"SourceLockSHA256() [32]byte",
		"The provenance section has `itemCount=11`",
		"policySourceLockSHA256",
		"pinnedCallsiteEvidenceSHA256",
		"oracle/golden evidence",
		"minimumBytes:u32, maximumBytes:u32",
		"func (requirement PointerRequirementView) MinimumBytes() uint32",
		"func (query PointerQuery) MinimumBytes() uint32",
		"minimum pointer bytes",
		"`minimumBytes-1` then `maximumBytes+1`",
		"There are no free-floating `preCheckBits` or `postCheckBits`",
		"stateCheckBits:u32",
		"complete runtime section\nbody above as its sole preimage",
		"complete workload\nsection body above as its sole preimage",
		"hal/l8/syscall-transition/linux-amd64/v1",
		"CommitNoObject",
		"AbortPermit",
		"same-ticket authorization is pure and repeatable",
		"transition allow has a zero rule digest and zero ticket",
		"Ticket succeeds only for a nonzero `Policy.Decide`-issued ticket",
		"`Policy.Decide` never calls an observer",
		"constructor failure precedence",
		"unsafe conditional syscall",
		"`ExpectedPolicyArtifact` has no exported constructor",
		"mutations leave the raw filter result unchanged",
		"unknown, unassigned, or newer-than-6.1 syscall number",
		"canonical binary v2",
		"human-readable TSV",
		"GeneratePlusOne",
		"GoldenExpectationConstructorError GoldenExpectation = 2",
		"func (golden GoldenCase) ExpectedErrorCode() (ErrorCode, error)",
		"MutationStage MutationKind = 21",
		"MutationSyscall MutationKind = 1",
		"MutationReinspection=20",
		"canonical diff cardinality is exactly one",
		"MaxPolicyScalarClausesPerRule = 6",
		"scalar argument indexes are unique within a rule",
		"first candidate for which `Policy.Decide` denies",
		"flips the lowest set bit of the clause mask",
		"math.MaxInt32",
		"`ScalarEqual` clause naming its exact fixed descriptor number",
		"type ObjectSource uint8",
		"ObjectSourceArgument ObjectSource = 1",
		"ObjectSourceReturn ObjectSource = 2",
		"sentinel `argumentIndex=255`",
		"D2 never treats a returned FD as an input argument",
		"type QueryKind uint8",
		"QueryKindState QueryKind = 1",
		"QueryKindObject QueryKind = 4",
		"hal/l8/adapter-state-query/linux-amd64/v1",
		"hal/l8/adapter-fd-query/linux-amd64/v1",
		"hal/l8/adapter-pointer-query/linux-amd64/v1",
		"hal/l8/adapter-object-query/linux-amd64/v1",
		"ObjectSourceReturn uses `argumentIndex=255` and `expectedNumber=-1`",
		"hal/l8/pinned-callsite-evidence-record/linux-amd64/v1",
		"type BinaryBindingKind uint8",
		"type PinnedBinaryBindingView struct",
		"type PinnedBinaryBindingSet struct",
		"hal/l8/pinned-binary-binding/linux-amd64/v1",
		"hal/l8/pinned-binary-binding-set/linux-amd64/v1",
		"policyBinaryBindingSetSHA256",
		"Surface 1 — raw `FilterProfile.Decide`",
		"Surface 2 — semantic `Policy.Decide`",
		"Surface 3 — `ValidateTransition`",
		"only `EnforcementPathAdapter` returns a nonzero adapter ticket",
		"Direct, PinnedDirect, and scalar-only workload allows return zero tickets",
		"func (golden GoldenCase) Positive() bool",
		"func (golden GoldenCase) AdapterFixture() AdapterFixtureView",
		"A positive has\n`mutation=0`",
		"The complete opaque set is",
		"`Classification`, `FilterDecision`, `Decision`, `AdapterDecision`",
		"`AdapterTicket`, `AdapterPermit`, `AdapterBindings`, `AdapterBindingView`",
		"`RuntimeProfileView`, `CatalogEntryView`, `MandatoryEvidenceView`, `RuleView`",
		"`FilterRuleView`, `FilterProfile`, `ScalarClauseView`",
		"String() string",
		"GoString() string",
		"Format(fmt.State, rune)",
		"MarshalJSON() ([]byte, error)",
		"MarshalText() ([]byte, error)",
		"MarshalBinary() ([]byte, error)",
		"UnmarshalJSON([]byte) error",
		"UnmarshalText([]byte) error",
		"UnmarshalBinary([]byte) error",
		"formatting a nil pointer emits the static token `<nil>`",
		"`encoding/json` marshals it as `null`",
		"syscallpolicy.live[redacted]",
		"default cross-platform test files have no `syscall`, `unsafe`, or",
		"`golang.org/x/sys/unix` production import",
		"tools/microvm/l8/policy/verified-syscall-policy.hl8q",
		"tools/microvm/l8/policy/verified-syscall-policy.hl8q.sha256",
		"tools/microvm/l8/policy/roles-v1.yaml",
		"artifact_expected_d7_gen.go",
		"pinned_callsite_evidence_expected_d7_gen.go",
		"policyArtifactSHA256",
		"package-internal synthetic artifact",
		"type l8VerifiedPolicyCompositionDigests struct",
		"func deriveL8PolicyCompositionDigests(",
		"artifact.Workload().SHA256()",
		"artifact.Runtime().SHA256()",
		"artifact.SHA256()",
		"artifact.SourceLockSHA256()",
		"evidence.BinaryBindings().SHA256()",
		"evidence.SHA256()",
		"func l8PolicyCompositionDigestsEqual(",
		"func validateL8PolicyCompositionCorrelation(",
		"manifest, provenance, and final-inspection `ProcessComposition`",
		"final inspection independently repeats the complete six-field equality",
		"mere disconnected accessor or comparison marker calls do not satisfy",
		"l8PolicyCompositionCorrelationMismatch",
		"assetbuild.L8ValidationError",
		"localresolver/l8_distribution_verifier.go",
		"contiguous top-level authority block",
		"Protected values are assigned once",
		"localresolver/l8_distribution_verifier_test.go",
		"parsed ordered 3x6 mutation table",
		"Package-wide parsed reference guards have no basename-wide allowlist",
		"[18]struct { document string; field string }",
		"executed count must equal exactly 18",
		"must succeed through the real issuer",
		"all other 17 remain",
		"closed owner\ngraph",
		"matching direct returned result",
		"`go:linkname`",
		"external case references",
		"partial landing is closed",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 syscall-policy architecture closure omits %q", required)
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyAdapterWrapperLifecycleIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, required := range []string{
		"unstarted -> claimed -> executed -> finalized",
		"successful `AuthorizePre` installs the permit into that same wrapper identity",
		"pre-syscall cancellation or wrapper failure transitions `claimed -> finalized`",
		"exactly one phase-explicit `AbortPermit` with `AdapterPhasePre` and zero",
		"exactly one syscall-closure call transitions `claimed -> executed`",
		"successful syscall is finalized by exactly one `AuthorizePost` or `CommitNoObject`",
		"failed syscall is finalized by exactly one phase-explicit `AbortPermit` with",
		"`executed -> finalized`",
		"forbids `unstarted -> executed`, `unstarted -> finalized`, claimed-state reuse",
		"multiple syscall-closure calls, retry, and every method call after `finalized`",
		"wrapperStateUnstarted wrapperState = 1",
		"wrapperStateClaimed   wrapperState = 2",
		"wrapperStateExecuted  wrapperState = 3",
		"wrapperStateFinalized wrapperState = 4",
		"wrapper lifecycle plus-one matrix",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 syscall-policy wrapper lifecycle omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"`unstarted -> executed -> finalized` state",
		"must restart with a new `Decide` ticket and `AuthorizePre` permit",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 syscall-policy wrapper lifecycle retains stale claim %q", forbidden)
		}
	}

	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		l8CredentialVerificationDoc,
	} {
		coordinated := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, required := range []string{
			"unstarted -> claimed -> executed -> finalized",
			"pre-syscall",
			"AbortPermit",
			"zero syscall",
			"exactly one syscall",
			"no retry",
		} {
			if !strings.Contains(coordinated, required) {
				t.Fatalf("L8 syscall-policy wrapper lifecycle document %q omits %q", file, required)
			}
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyInertWrapperConstructionIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, required := range []string{
		"#### Exact inert-wrapper construction and ownership matrix",
		"one private inert `unstarted` wrapper identity before `NewAdapterBindings`",
		"sole production `BindingSource`",
		"has no permit, syscall closure, or live syscall authority",
		"owns the exact `AdapterBindings` snapshot and its private operation token",
		"participates only in exact opaque ownership identity checks by D2 and the sole D4 wrapper",
		"never enters canonical or semantic rule equality, a digest or preimage, formatter, view, serialization, or decision outcome",
		"successful `AuthorizePre` installs the permit into that same wrapper identity",
		"atomically transitions `unstarted -> claimed` before escape",
		"synchronously destroys and discards the inert identity",
		"zero binding or authorization authority, zero syscall-closure calls, and zero terminal D2 calls",
		"No replacement wrapper, cross-wrapper transfer, or foreign bindings",
		"Seeded construction-order negatives",
		"wrapper A's bindings into wrapper B",
		"escape before claim",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 syscall-policy inert-wrapper construction omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"D4 first calls\n`AuthorizePre` without allocating or exposing a live wrapper",
		"When\n`AuthorizePre` succeeds, D4 locally constructs a wrapper in `unstarted`",
		"D4 obtains an `AuthorizePre`\npermit after all state/FD/pointer/input-object queries pass, creates the exact",
		"It never enters\na digest, formatter, view, equality decision, or serialized bytes",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 syscall-policy inert-wrapper construction retains stale order %q", forbidden)
		}
	}
	for _, required := range []string{
		"allocate the inert identity, build and store bindings through that same identity, call `AuthorizePre`, install the returned permit and sole closure in that identity, atomically claim, and only then invoke the closure",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 syscall-policy operational construction order omits %q", required)
		}
	}

	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		l8CredentialVerificationDoc,
	} {
		coordinated := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, required := range []string{
			"inert `unstarted` wrapper",
			"before `NewAdapterBindings`",
			"sole production `BindingSource`",
			"same wrapper identity",
			"no replacement",
			"cross-wrapper",
			"foreign bindings",
			"zero syscall",
		} {
			if !strings.Contains(coordinated, required) {
				t.Fatalf("L8 syscall-policy inert-wrapper document %q omits %q", file, required)
			}
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyTerminalAPIIsPhaseExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, required := range []string{
		"#### Exact terminal API and phase matrix",
		"func (policy *Policy) AbortPermit(permit AdapterPermit, phase AdapterPhase) (AdapterDecision, error)",
		"AdapterReasonPreSyscallAbort=8",
		"`AdapterReasonPreSyscallAbort` is exactly `pre-syscall-abort`",
		"`AbortPermit(permit, AdapterPhasePre)`",
		"`AbortPermit(permit, AdapterPhasePost)`",
		"the exact same nonzero permit returned by `AuthorizePre`",
		"`claimed -> finalized`",
		"`executed -> finalized`",
		"zero syscall-closure calls",
		"exactly one syscall-closure call",
		"final pre/rule-failure/pre-syscall-abort",
		"final post/rule-failure/syscall-failure",
		"wrong-phase, reuse, and duplicate terminal matrix",
		"never calls `AuthorizePost` or `CommitNoObject` on an abort route",
		"never calls `AbortPermit` on a successful-syscall route",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 syscall-policy terminal API omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"func (policy *Policy) AbortPermit(permit AdapterPermit) (AdapterDecision, error)",
		"| abort exact permit after syscall error/panic |",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 syscall-policy terminal API retains ambiguous claim %q", forbidden)
		}
	}

	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		l8CredentialVerificationDoc,
	} {
		coordinated := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, required := range []string{
			"phase-explicit `AbortPermit`",
			"`AdapterPhasePre`",
			"`AdapterPhasePost`",
			"exact same permit",
			"wrong-phase",
			"duplicate",
		} {
			if !strings.Contains(coordinated, required) {
				t.Fatalf("L8 syscall-policy terminal API document %q omits %q", file, required)
			}
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyArchitectureClosureIsCoordinated(t *testing.T) {
	requiredByFile := map[string][]string{
		l8CredentialArchitectureDoc: {
			"guestagent/syscallpolicy",
			"repository baseline contains no L4/L7 workload seccomp artifact",
			"D7 is the sole rule author and issuer",
			"VerifiedL8Profile",
			"D4 and D6",
			"live composition remain disabled",
			"identical policy artifact",
			"guest binary does not receive",
			"FilterRules",
			"FilterProfile",
			"AuthorizePre",
			"CommitNoObject",
			"AdapterBindings",
			"EnforcementPathPinnedDirect",
			"policySourceLockSHA256",
			"pinnedCallsiteEvidenceSHA256",
			"policyBinaryBindingSetSHA256",
			"scalar-only workload exception",
			"owns only generated native callsite/install tables",
			"D7-verified artifact and goldens",
			"never authors policy rows",
		},
		"sandbox-runtime-v2-l8-guest-extension-seams.md": {
			"guestagent/syscallpolicy",
			"standard-library-only neutral leaf",
			"D4 imports",
			"this leaf for filter compilation",
			"no reverse import",
			"VerifiedL8Profile",
			"FilterRules",
			"FilterProfile",
			"AuthorizePre",
			"CommitNoObject",
			"AdapterBindings",
			"EnforcementPathPinnedDirect",
			"policySourceLockSHA256",
			"pinnedCallsiteEvidenceSHA256",
			"policyBinaryBindingSetSHA256",
			"scalar-only workload exception",
		},
		l8CredentialVerificationDoc: {
			"TestL8D2GuestHelperSyscallPolicyArchitectureClosure",
			"WorkloadSnapshot",
			"VerifiedPolicyArtifact",
			"D7 issuance gate",
			"D4/D6 live composition gate",
			"rule/role fingerprints",
			"FilterRules",
			"FilterProfile",
			"two-phase",
			"AdapterBindings",
			"EnforcementPathPinnedDirect",
			"policySourceLockSHA256",
			"pinnedCallsiteEvidenceSHA256",
			"policyBinaryBindingSetSHA256",
			"scalar-only workload exception",
		},
	}

	for file, required := range requiredByFile {
		doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, marker := range required {
			if !strings.Contains(doc, marker) {
				t.Fatalf("L8 syscall-policy closure document %q omits %q", file, marker)
			}
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyImageAuthorityAndFixtureTopologyIsClosed(t *testing.T) {
	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		"sandbox-runtime-v2-l8-helper-syscall-policy.md",
		l8CredentialVerificationDoc,
	} {
		doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, required := range []string{
			"all-build-context",
			"build-tag",
			"recursive",
			"selector",
			"mutually exclusive",
			"deterministic",
			"fixed point",
			"last-writer",
			"l8_distribution_policy_composition_fixture_test.go",
			"runtime.Goexit",
			"non-vacuous",
		} {
			if !strings.Contains(doc, required) {
				t.Fatalf("L8 authority/fixture topology document %q omits %q", file, required)
			}
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyImageAuthorityIsCanonical(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	combined := ""
	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-helper-syscall-policy.md",
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		l8CredentialVerificationDoc,
	} {
		combined += "\n" + readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
	}
	assertL8DocStruct(t, seam, "L8ProcessCompositionFacts", []l8DocField{
		{name: "CatalogVersion", typ: "string", tag: `json:"catalogVersion"`},
		{name: "GuestAgentSHA256", typ: "string", tag: `json:"guestAgentSha256"`},
		{name: "GuestInitSHA256", typ: "string", tag: `json:"guestInitSha256"`},
		{name: "CredentialHelperSHA256", typ: "string", tag: `json:"credentialHelperSha256"`},
		{name: "MountMonitorSHA256", typ: "string", tag: `json:"mountMonitorSha256"`},
		{name: "WorkloadShimSHA256", typ: "string", tag: `json:"workloadShimSha256"`},
		{name: "RoleBootstrapSHA256", typ: "string", tag: `json:"roleBootstrapSha256"`},
		{name: "HelperDescriptorSHA256", typ: "string", tag: `json:"helperDescriptorSha256"`},
		{name: "ClientDescriptorSHA256", typ: "string", tag: `json:"clientDescriptorSha256"`},
		{name: "CompositionSHA256", typ: "string", tag: `json:"compositionSha256"`},
		{name: "WorkloadSnapshotSHA256", typ: "string", tag: `json:"workloadSnapshotSha256"`},
		{name: "RuntimeProfileSHA256", typ: "string", tag: `json:"runtimeProfileSha256"`},
		{name: "PolicyArtifactSHA256", typ: "string", tag: `json:"policyArtifactSha256"`},
		{name: "PolicySourceLockSHA256", typ: "string", tag: `json:"policySourceLockSha256"`},
		{name: "PolicyBinaryBindingSetSHA256", typ: "string", tag: `json:"policyBinaryBindingSetSha256"`},
		{name: "PinnedCallsiteEvidenceSHA256", typ: "string", tag: `json:"pinnedCallsiteEvidenceSha256"`},
	})
	assertL8DocStruct(t, seam, "verifiedL8PolicyAuthorityBindings", []l8DocField{
		{name: "policyArtifactSHA256", typ: "[32]byte"},
		{name: "policySourceLockSHA256", typ: "[32]byte"},
		{name: "policyBinaryBindingSetSHA256", typ: "[32]byte"},
		{name: "pinnedCallsiteEvidenceSHA256", typ: "[32]byte"},
		{name: "imageSHA256", typ: "[32]byte"},
	})
	assertL8DocStruct(t, seam, "verifiedL8ProfileCorrelation", []l8DocField{
		{name: "descriptorFingerprint", typ: "[32]byte"},
		{name: "evidenceFingerprint", typ: "[32]byte"},
		{name: "policyAuthority", typ: "verifiedL8PolicyAuthorityBindings"},
	})
	assertL8DocStruct(t, seam, "verifiedL8LeaseCorrelation", []l8DocField{
		{name: "sourceDescriptorFingerprint", typ: "[32]byte"},
		{name: "preparedDescriptorFingerprint", typ: "[32]byte"},
		{name: "hasPreparedDescriptor", typ: "bool"},
		{name: "evidenceFingerprint", typ: "[32]byte"},
		{name: "policyAuthority", typ: "verifiedL8PolicyAuthorityBindings"},
	})
	assertL8DocStruct(t, seam, "VerifiedL8Profile", []l8DocField{
		{name: "seal", typ: "verifiedL8ProfileSeal"},
		{name: "correlation", typ: "verifiedL8ProfileCorrelation"},
	})
	assertL8DocStruct(t, seam, "VerifiedL8AssetLease", []l8DocField{
		{name: "state", typ: "*verifiedL8AssetLeaseState"},
		{name: "correlation", typ: "verifiedL8LeaseCorrelation"},
	})
	assertL8DocStruct(t, seam, "L8DistributionRequest", []l8DocField{
		{name: "DistributionRequest", typ: "DistributionRequest"},
		{name: "ParentL7", typ: "VerifiedDistribution"},
		{name: "PinnedCallsiteEvidence", typ: "[]byte"},
	})
	if !strings.Contains(seam, "digest32(compositionSha256) || digest32(workloadSnapshotSha256) ||\n  digest32(runtimeProfileSha256) || digest32(policyArtifactSha256) ||\n  digest32(policySourceLockSha256) ||\n  digest32(policyBinaryBindingSetSha256) ||\n  digest32(pinnedCallsiteEvidenceSha256))") {
		t.Fatal("L8 syscall/image reconciliation loses exact policy/evidence preimage order")
	}
	for _, required := range []string{
		"one canonical HL8Q artifact and its external HL8E evidence",
		"WorkloadSnapshotSHA256",
		"RuntimeProfileSHA256",
		"PolicyArtifactSHA256",
		"PolicySourceLockSHA256",
		"PolicyBinaryBindingSetSHA256",
		"PinnedCallsiteEvidenceSHA256",
		"first two fields are immutable views derived from the sole HL8Q artifact",
		"Manifest, provenance, and final inspection carry all six fields in this exact",
		"the evidence fingerprint binds all six in the same exact order",
		"PinnedCallsiteEvidence []byte",
		"non-nil, nonempty, and at most 16 MiB",
		"deep-snapshots `PinnedCallsiteEvidence` before hashing or import",
		"EmbeddedVerifiedPolicyArtifact",
		"EmbeddedExpectedPinnedCallsiteEvidence",
		"retains no caller slice or imported evidence graph after sealing",
		"policyAuthority verifiedL8PolicyAuthorityBindings",
		"measured rootfs image digest",
		"localresolver/l8_distribution_verifier.go",
		"localresolver/l8_distribution_verifier_test.go",
		"classifyL8PolicyCompositionCorrelationError",
		"exact sanitized resolver `asset_lock_mismatch`",
		"parsed ordered 3x6 mutation table",
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("L8 syscall/image reconciliation omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"WorkloadPolicySHA256",
		"RuntimePolicySHA256",
		"SyscallPolicySHA256",
		"workloadPolicySha256",
		"runtimePolicySha256",
		"syscallPolicySha256",
		"three canonical artifacts",
		"D7 embeds the exact expected workload, runtime, and syscall-policy catalog digests",
		"The profile exposes only the safe",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("L8 syscall/image reconciliation retains superseded authority %q", forbidden)
		}
	}
}

func TestL8D2GuestHelperSyscallPolicyArchitectureClosureRejectsFalseReadiness(t *testing.T) {
	for _, file := range []string{
		l8CredentialArchitectureDoc,
		"sandbox-runtime-v2-l8-helper-syscall-policy.md",
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		l8CredentialVerificationDoc,
	} {
		doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, forbidden := range []string{
			"existing L4/L7 workload filter",
			"existing L4/L7 workload policy",
			"D2 issues the production workload snapshot",
			"strace generates the runtime allowlist",
			"host headers generate the syscall catalog",
			"D2 owns its pure types, private immutable rule tables",
			"checked-in D2 `go1257RuntimeProfile`",
			"363 defined native syscall numbers",
			"D2 owns the policy rule",
			"already in the D2 table",
			"D6 may pass an already-verified policy capability",
			"MaxPolicyScalarClausesPerRule = 12",
			"role uses the next role modulo ten",
			"lowest bit excluded by the clause mask",
			"zero/foreign/replayed ticket",
			"func (policy *Policy) Authorize(ticket AdapterTicket",
			"type ObservationSource interface",
			"func (rule RuleView) PreChecks() CheckSet",
			"func (rule RuleView) PostChecks() CheckSet",
			"only an exact scalar rule returns `SECCOMP_RET_ALLOW` and an adapter",
			"The generated decision is exact and applies this precedence",
			"raw-syscall role tables",
		} {
			if strings.Contains(doc, forbidden) {
				t.Fatalf("L8 syscall-policy closure document %q retains false readiness claim %q", file, forbidden)
			}
		}
	}
}
