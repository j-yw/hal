package syscallpolicy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type MutationKind uint8
type GoldenKind uint8
type GoldenExpectation uint8

const (
	GoldenKindSemantic GoldenKind = 1
	GoldenKindFilter   GoldenKind = 2
)

const (
	GoldenExpectationDecision         GoldenExpectation = 1
	GoldenExpectationConstructorError GoldenExpectation = 2
)

const (
	MutationSyscall MutationKind = 1 + iota
	MutationArchitecture
	MutationX32
	MutationRole
	MutationState
	MutationFixedFD
	MutationTransientKind
	MutationGeneration
	MutationFlagBit
	MutationEnum
	MutationCloneField
	MutationMountCommand
	MutationSocketFamilyType
	MutationSignal
	MutationWaitOption
	MutationPathClass
	MutationBounds
	MutationReservedByte
	MutationSequence
	MutationReinspection
	MutationStage
)

func ValidateMutationKind(value MutationKind) error {
	if value < MutationSyscall || value > MutationStage {
		return contractError(ErrorCodeCatalog)
	}
	return nil
}
func ValidateGoldenKind(value GoldenKind) error {
	if value < GoldenKindSemantic || value > GoldenKindFilter {
		return contractError(ErrorCodeCatalog)
	}
	return nil
}
func ValidateGoldenExpectation(value GoldenExpectation) error {
	if value < GoldenExpectationDecision || value > GoldenExpectationConstructorError {
		return contractError(ErrorCodeCatalog)
	}
	return nil
}

type adapterFixtureBinding struct {
	slot       uint8
	kind       DescriptorKind
	access     DescriptorAccess
	generation [32]byte
}
type adapterFixtureFD struct {
	argument   uint8
	kind       DescriptorKind
	access     DescriptorAccess
	fixed      bool
	mode       GenerationMode
	slot       uint8
	number     int32
	checks     CheckSet
	generation [32]byte
}
type adapterFixturePointer struct {
	argument uint8
	class    PointerClass
	bytes    uint32
	checks   CheckSet
}
type adapterFixtureObject struct {
	source     ObjectSource
	argument   uint8
	kind       DescriptorKind
	access     DescriptorAccess
	fixed      bool
	mode       GenerationMode
	slot       uint8
	number     int32
	checks     CheckSet
	generation [32]byte
}
type adapterFixture struct {
	state    State
	checks   CheckSet
	bindings []adapterFixtureBinding
	fds      []adapterFixtureFD
	pointers []adapterFixturePointer
	objects  []adapterFixtureObject
}

type AdapterFixtureView struct{ fixture *adapterFixture }

type goldenCase struct {
	kind           GoldenKind
	mutation       MutationKind
	input          FilterInput
	fixture        *adapterFixture
	syscallName    string
	ruleSHA256     [32]byte
	action         Action
	reason         Reason
	adapterOutcome AdapterOutcome
	adapterReason  AdapterReason
	adapterPhase   AdapterPhase
	adapterFinal   bool
	positive       bool
	expectation    GoldenExpectation
	expectedError  ErrorCode
	requiredChecks CheckSet
	binary         []byte
	sha256         [32]byte
}

type GoldenCase struct{ golden *goldenCase }

func (policy *Policy) GoldenCases() []GoldenCase {
	if policy == nil || policy.owner == nil || policy.artifact == nil {
		return []GoldenCase{}
	}
	result := make([]GoldenCase, 0, len(policy.artifact.rules))
	for _, rule := range policy.artifact.rules {
		golden, err := newSemanticGoldenPositive(policy, rule)
		if err != nil {
			return []GoldenCase{}
		}
		result = append(result, golden)
	}
	return result
}

func GeneratePlusOne(artifact VerifiedPolicyArtifact) ([]GoldenCase, error) {
	policy, err := NewPolicy(artifact)
	if err != nil {
		return nil, err
	}
	result := make([]GoldenCase, 0)
	for _, positive := range policy.GoldenCases() {
		result = append(result, positive)
		result = append(result, semanticGoldenMutations(policy, positive)...)
	}
	for role := RoleLaunchBootstrap; role <= RoleWorkload; role++ {
		profile, profileErr := policy.FilterProfile(role)
		if profileErr != nil {
			continue
		}
		for _, rule := range profile.profile.rules {
			positive, positiveErr := newFilterGoldenPositive(profile, rule)
			if positiveErr != nil {
				return nil, positiveErr
			}
			result = append(result, positive)
			result = append(result, filterGoldenMutations(profile, positive)...)
		}
	}
	return result, nil
}

func newSemanticGoldenPositive(policy *Policy, rule *verifiedRule) (GoldenCase, error) {
	stage := policy.artifact.stages[rule.role][rule.stage]
	facts := (stage.requiredFacts | rule.requiredFacts) &^ (stage.prohibitedFacts | rule.prohibitedFacts)
	state, err := NewState(rule.role, rule.stage, facts)
	if err != nil {
		return GoldenCase{}, err
	}
	arguments, ok := positiveRuleArguments(rule.scalarClauses)
	if !ok {
		return GoldenCase{}, contractError(ErrorCodeContradiction)
	}
	input, err := NewFilterInput(state, 0xc000003e, uint32(rule.syscallNumber), arguments)
	if err != nil {
		return GoldenCase{}, err
	}
	decision := policy.Decide(input)
	if !decision.Allowed() || decision.RuleSHA256() != rule.sha256 {
		return GoldenCase{}, contractError(ErrorCodeContradiction)
	}
	golden := &goldenCase{
		kind: GoldenKindSemantic, input: input, syscallName: syscallName(policy.artifact.catalog, rule.syscallNumber),
		ruleSHA256: rule.sha256, action: decision.action, reason: decision.reason,
		positive: true, expectation: GoldenExpectationDecision,
	}
	if rule.enforcementPath == EnforcementPathAdapter {
		golden.fixture = buildAdapterGoldenFixture(policy.artifact.sha256, rule, input, stage)
		golden.adapterOutcome, golden.adapterReason, golden.adapterPhase, golden.adapterFinal = AdapterOutcomeProceed, AdapterReasonExact, AdapterPhasePost, true
		golden.requiredChecks = unionRuleChecks(rule)
	}
	finalizeGolden(golden)
	return GoldenCase{golden: golden}, nil
}

func newFilterGoldenPositive(profile FilterProfile, rule *filterRule) (GoldenCase, error) {
	arguments, ok := positiveRuleArguments(rule.clauses)
	if !ok {
		return GoldenCase{}, contractError(ErrorCodeContradiction)
	}
	state, _ := NewState(profile.profile.role, StageNativeBootstrap, 0)
	input, _ := NewFilterInput(state, 0xc000003e, uint32(rule.syscallNumber), arguments)
	decision := profile.Decide(input.auditArchitecture, input.rawSyscallNumber, input.arguments)
	if !decision.Allowed() || decision.RuleSHA256() != rule.sha256 {
		return GoldenCase{}, contractError(ErrorCodeContradiction)
	}
	golden := &goldenCase{kind: GoldenKindFilter, input: input, syscallName: syscallName(profile.profile.catalog, rule.syscallNumber), ruleSHA256: rule.sha256, action: decision.action, reason: decision.reason, positive: true, expectation: GoldenExpectationDecision}
	finalizeGolden(golden)
	return GoldenCase{golden: golden}, nil
}

func semanticGoldenMutations(policy *Policy, positive GoldenCase) []GoldenCase {
	if positive.golden == nil {
		return nil
	}
	mutations := make([]GoldenCase, 0, 6)
	add := func(kind MutationKind, input FilterInput) {
		decision := policy.Decide(input)
		if decision.Allowed() {
			return
		}
		mutations = append(mutations, newDecisionMutation(positive, kind, input, decision.action, decision.reason, decision.ruleSHA256))
	}
	base := positive.golden.input
	input := base
	input.rawSyscallNumber = 451
	add(MutationSyscall, input)
	input = base
	input.auditArchitecture = 0
	add(MutationArchitecture, input)
	input = base
	input.rawSyscallNumber |= 0x40000000
	add(MutationX32, input)
	for role := RoleLaunchBootstrap; role <= RoleWorkload; role++ {
		if role != base.state.role {
			input = base
			input.state.role = role
			add(MutationRole, input)
			break
		}
	}
	for fact := StateFact(0); fact <= knownStateFacts; fact++ {
		if fact != base.state.facts && fact&^knownStateFacts == 0 {
			input = base
			input.state.facts = fact
			before := len(mutations)
			add(MutationState, input)
			if len(mutations) != before {
				break
			}
		}
	}
	for stage := StageNativeBootstrap; stage <= StageFinalWorkload; stage++ {
		if stage != base.state.stage {
			input = base
			input.state.stage = stage
			before := len(mutations)
			add(MutationStage, input)
			if len(mutations) != before {
				break
			}
		}
	}
	return mutations
}

func filterGoldenMutations(profile FilterProfile, positive GoldenCase) []GoldenCase {
	if positive.golden == nil {
		return nil
	}
	result := make([]GoldenCase, 0, 3)
	base := positive.golden.input
	for _, candidate := range []struct {
		kind         MutationKind
		arch, number uint32
	}{
		{MutationSyscall, base.auditArchitecture, 451}, {MutationArchitecture, 0, base.rawSyscallNumber}, {MutationX32, base.auditArchitecture, base.rawSyscallNumber | 0x40000000},
	} {
		input := base
		input.auditArchitecture, input.rawSyscallNumber = candidate.arch, candidate.number
		decision := profile.Decide(input.auditArchitecture, input.rawSyscallNumber, input.arguments)
		if !decision.Allowed() {
			result = append(result, newDecisionMutation(positive, candidate.kind, input, decision.action, decision.reason, decision.ruleSHA256))
		}
	}
	return result
}

func newDecisionMutation(positive GoldenCase, kind MutationKind, input FilterInput, action Action, reason Reason, ruleSHA256 [32]byte) GoldenCase {
	copyGolden := *positive.golden
	copyGolden.positive, copyGolden.mutation, copyGolden.input = false, kind, input
	copyGolden.action, copyGolden.reason, copyGolden.ruleSHA256 = action, reason, ruleSHA256
	copyGolden.fixture, copyGolden.adapterOutcome, copyGolden.adapterReason, copyGolden.adapterPhase, copyGolden.adapterFinal = nil, 0, 0, 0, false
	copyGolden.requiredChecks = CheckSet{}
	finalizeGolden(&copyGolden)
	return GoldenCase{golden: &copyGolden}
}

func positiveRuleArguments(clauses []*scalarClause) ([6]uint64, bool) {
	var result [6]uint64
	for _, clause := range clauses {
		var value uint64
		switch clause.operation {
		case ScalarEqual, ScalarMaskedEqual, ScalarOneOf, ScalarUnsignedRange:
			value = clause.values[0]
		case ScalarZero:
			value = 0
		case ScalarNonzero:
			value = 1
		default:
			return [6]uint64{}, false
		}
		result[clause.argumentIndex] = value
	}
	for _, clause := range clauses {
		if !clauseMatches(clause, result[clause.argumentIndex]) {
			return [6]uint64{}, false
		}
	}
	return result, true
}

func buildAdapterGoldenFixture(artifactSHA [32]byte, rule *verifiedRule, input FilterInput, stage roleStage) *adapterFixture {
	fixture := &adapterFixture{state: input.state, checks: rule.stateChecks}
	bindings := make(map[uint8]adapterFixtureBinding)
	addBinding := func(slot uint8, kind DescriptorKind, access DescriptorAccess, ordinal int) [32]byte {
		generation := goldenGeneration(artifactSHA, rule.sha256, GenerationModeLiveBound, EvidenceKindDescriptor, ordinal)
		if existing, ok := bindings[slot]; ok {
			return existing.generation
		}
		bindings[slot] = adapterFixtureBinding{slot: slot, kind: kind, access: access, generation: generation}
		return generation
	}
	for index, requirement := range rule.descriptors {
		generation := requirement.generationSHA256
		if requirement.generationMode == GenerationModeLiveBound {
			generation = addBinding(requirement.bindingSlot, requirement.kind, requirement.access, index)
		}
		fixture.fds = append(fixture.fds, adapterFixtureFD{argument: requirement.argumentIndex, kind: requirement.kind, access: requirement.access, fixed: requirement.fixed, mode: requirement.generationMode, slot: requirement.bindingSlot, number: int32(input.arguments[requirement.argumentIndex]), checks: requirement.requiredChecks, generation: generation})
	}
	for _, requirement := range rule.pointers {
		fixture.pointers = append(fixture.pointers, adapterFixturePointer{argument: requirement.argumentIndex, class: requirement.class, bytes: requirement.minimumBytes, checks: requirement.requiredChecks})
	}
	for index, requirement := range rule.objects {
		generation := requirement.generationSHA256
		if requirement.generationMode == GenerationModeLiveBound {
			generation = addBinding(requirement.bindingSlot, requirement.kind, requirement.access, len(rule.descriptors)+index)
		}
		if requirement.generationMode == GenerationModeFreshReturn {
			generation = goldenGeneration(artifactSHA, rule.sha256, requirement.generationMode, EvidenceKindReturnObject, index)
		}
		number := int32(-1)
		if requirement.source == ObjectSourceArgument {
			number = int32(input.arguments[requirement.argumentIndex])
		}
		fixture.objects = append(fixture.objects, adapterFixtureObject{source: requirement.source, argument: requirement.argumentIndex, kind: requirement.kind, access: requirement.access, fixed: requirement.fixed, mode: requirement.generationMode, slot: requirement.bindingSlot, number: number, checks: requirement.requiredChecks, generation: generation})
	}
	for _, binding := range bindings {
		fixture.bindings = append(fixture.bindings, binding)
	}
	sort.Slice(fixture.bindings, func(i, j int) bool { return fixture.bindings[i].slot < fixture.bindings[j].slot })
	_ = stage
	return fixture
}

func goldenGeneration(artifact, rule [32]byte, mode GenerationMode, kind EvidenceKind, index int) [32]byte {
	preimage := append(append([]byte(nil), artifact[:]...), rule[:]...)
	preimage = append(preimage, byte(mode), byte(kind), byte(index))
	return framedSHA256("hal/l8/golden-generation/linux-amd64/v1", preimage)
}

func unionRuleChecks(rule *verifiedRule) CheckSet {
	bits := rule.stateChecks.bits
	for _, value := range rule.descriptors {
		bits |= value.requiredChecks.bits
	}
	for _, value := range rule.pointers {
		bits |= value.requiredChecks.bits
	}
	for _, value := range rule.objects {
		bits |= value.requiredChecks.bits
	}
	return CheckSet{bits: bits}
}

func finalizeGolden(golden *goldenCase) {
	golden.binary = encodeGolden(golden)
	golden.sha256 = framedSHA256("hal/l8/syscall-golden/linux-amd64/v1", golden.binary)
}

func encodeGolden(golden *goldenCase) []byte {
	fixture := AdapterFixtureView{fixture: golden.fixture}.CanonicalBinary()
	result := make([]byte, 117, 117+len(fixture))
	copy(result[:4], "HL8G")
	result[4] = 2
	result[5] = byte(golden.kind)
	result[6] = byte(golden.mutation)
	result[7], result[8] = byte(golden.input.state.role), byte(golden.input.state.stage)
	binary.BigEndian.PutUint32(result[9:13], golden.input.auditArchitecture)
	binary.BigEndian.PutUint32(result[13:17], golden.input.rawSyscallNumber)
	for index, value := range golden.input.arguments {
		binary.BigEndian.PutUint64(result[17+index*8:25+index*8], value)
	}
	copy(result[65:97], golden.ruleSHA256[:])
	binary.BigEndian.PutUint32(result[97:101], uint32(golden.action))
	result[101], result[102], result[103], result[104] = byte(golden.reason), byte(golden.adapterOutcome), byte(golden.adapterReason), byte(golden.adapterPhase)
	if golden.adapterFinal {
		result[105] = 1
	}
	if golden.positive {
		result[106] = 1
	}
	result[107], result[108] = byte(golden.expectation), byte(golden.expectedError)
	binary.BigEndian.PutUint32(result[109:113], golden.requiredChecks.bits)
	binary.BigEndian.PutUint16(result[113:115], uint16(len(fixture)))
	return append(result, fixture...)
}

func (fixture AdapterFixtureView) CanonicalBinary() []byte {
	if fixture.fixture == nil {
		return nil
	}
	value := fixture.fixture
	result := make([]byte, 16)
	result[0], result[1] = byte(value.state.role), byte(value.state.stage)
	binary.BigEndian.PutUint64(result[4:12], uint64(value.state.facts))
	binary.BigEndian.PutUint32(result[12:16], value.checks.bits)
	result = append(result, byte(len(value.bindings)), byte(len(value.fds)), byte(len(value.pointers)), byte(len(value.objects)))
	for _, record := range value.bindings {
		row := make([]byte, 36)
		row[0], row[1], row[2] = record.slot, byte(record.kind), byte(record.access)
		copy(row[4:], record.generation[:])
		result = append(result, row...)
	}
	for _, record := range value.fds {
		row := make([]byte, 48)
		row[0], row[1], row[2] = record.argument, byte(record.kind), byte(record.access)
		if record.fixed {
			row[3] = 1
		}
		row[4], row[5] = byte(record.mode), record.slot
		binary.BigEndian.PutUint32(row[8:12], uint32(record.number))
		binary.BigEndian.PutUint32(row[12:16], record.checks.bits)
		copy(row[16:], record.generation[:])
		result = append(result, row...)
	}
	for _, record := range value.pointers {
		row := make([]byte, 12)
		row[0], row[1] = record.argument, byte(record.class)
		binary.BigEndian.PutUint32(row[4:8], record.bytes)
		binary.BigEndian.PutUint32(row[8:12], record.checks.bits)
		result = append(result, row...)
	}
	for _, record := range value.objects {
		row := make([]byte, 48)
		row[0], row[1], row[2], row[3] = byte(record.source), record.argument, byte(record.kind), byte(record.access)
		if record.fixed {
			row[4] = 1
		}
		row[5], row[6] = byte(record.mode), record.slot
		binary.BigEndian.PutUint32(row[8:12], uint32(record.number))
		binary.BigEndian.PutUint32(row[12:16], record.checks.bits)
		copy(row[16:], record.generation[:])
		result = append(result, row...)
	}
	return result
}

func (golden GoldenCase) SHA256() [32]byte {
	if golden.golden == nil {
		return [32]byte{}
	}
	return golden.golden.sha256
}
func (golden GoldenCase) Positive() bool { return golden.golden != nil && golden.golden.positive }
func (golden GoldenCase) Kind() GoldenKind {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.kind
}
func (golden GoldenCase) Expectation() GoldenExpectation {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.expectation
}
func (golden GoldenCase) Mutation() MutationKind {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.mutation
}
func (golden GoldenCase) Input() FilterInput {
	if golden.golden == nil {
		return FilterInput{}
	}
	return golden.golden.input
}
func (golden GoldenCase) AdapterFixture() AdapterFixtureView {
	if golden.golden == nil {
		return AdapterFixtureView{}
	}
	return AdapterFixtureView{fixture: golden.golden.fixture}
}
func (golden GoldenCase) SyscallName() string {
	if golden.golden == nil {
		return ""
	}
	return golden.golden.syscallName
}
func (golden GoldenCase) RuleSHA256() [32]byte {
	if golden.golden == nil {
		return [32]byte{}
	}
	return golden.golden.ruleSHA256
}
func (golden GoldenCase) Action() Action {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.action
}
func (golden GoldenCase) Reason() Reason {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.reason
}
func (golden GoldenCase) AdapterOutcome() AdapterOutcome {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.adapterOutcome
}
func (golden GoldenCase) AdapterReason() AdapterReason {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.adapterReason
}
func (golden GoldenCase) AdapterPhase() AdapterPhase {
	if golden.golden == nil {
		return 0
	}
	return golden.golden.adapterPhase
}
func (golden GoldenCase) AdapterFinal() bool {
	return golden.golden != nil && golden.golden.adapterFinal
}
func (golden GoldenCase) ExpectedErrorCode() (ErrorCode, error) {
	if golden.golden == nil || golden.golden.expectation != GoldenExpectationConstructorError {
		return 0, contractError(ErrorCodeInvalidArgument)
	}
	return golden.golden.expectedError, nil
}
func (golden GoldenCase) RequiredChecks() []Check {
	if golden.golden == nil {
		return nil
	}
	return golden.golden.requiredChecks.Values()
}
func (golden GoldenCase) CanonicalBinary() []byte {
	if golden.golden == nil {
		return nil
	}
	return append([]byte(nil), golden.golden.binary...)
}
func (golden GoldenCase) TSV() string {
	if golden.golden == nil {
		return ""
	}
	expectedError := "none"
	if golden.golden.expectedError != 0 {
		expectedError = golden.golden.expectedError.String()
	}
	checks := golden.RequiredChecks()
	checkTokens := make([]string, len(checks))
	for index, check := range checks {
		checkTokens[index] = check.String()
	}
	return strings.Join([]string{hex.EncodeToString(golden.golden.sha256[:]), strconv.Itoa(int(golden.golden.mutation)), golden.golden.expectation.String(), expectedError, golden.golden.input.state.role.String(), golden.golden.input.state.stage.String(), golden.golden.syscallName, strconv.FormatUint(uint64(golden.golden.input.rawSyscallNumber), 10), golden.golden.action.String(), golden.golden.reason.String(), golden.golden.adapterOutcome.String(), golden.golden.adapterReason.String(), strings.Join(checkTokens, ",")}, "\t") + "\n"
}

func syscallName(catalog []*catalogEntry, number SyscallNumber) string {
	entry := catalogEntryByNumber(catalog, number)
	if entry == nil {
		return "unknown"
	}
	return entry.name
}

func (value MutationKind) String() string {
	if ValidateMutationKind(value) != nil {
		return "unknown"
	}
	return []string{"", "syscall", "architecture", "x32", "role", "state", "fixed-fd", "transient-kind", "generation", "flag-bit", "enum", "clone-field", "mount-command", "socket-family-type", "signal", "wait-option", "path-class", "bounds", "reserved-byte", "sequence", "reinspection", "stage"}[value]
}
func (value MutationKind) GoString() string               { return value.String() }
func (value MutationKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value GoldenKind) String() string {
	switch value {
	case GoldenKindSemantic:
		return "semantic"
	case GoldenKindFilter:
		return "filter"
	default:
		return "unknown"
	}
}
func (value GoldenKind) GoString() string               { return value.String() }
func (value GoldenKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value GoldenExpectation) String() string {
	switch value {
	case GoldenExpectationDecision:
		return "decision"
	case GoldenExpectationConstructorError:
		return "constructor-error"
	default:
		return "unknown"
	}
}
func (value GoldenExpectation) GoString() string               { return value.String() }
func (value GoldenExpectation) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (GoldenCase) String() string                         { return opaqueFormat }
func (GoldenCase) GoString() string                       { return opaqueFormat }
func (GoldenCase) Format(state fmt.State, _ rune)         { writeOpaque(state) }
func (GoldenCase) MarshalJSON() ([]byte, error)           { return nil, opaqueError() }
func (GoldenCase) MarshalText() ([]byte, error)           { return nil, opaqueError() }
func (GoldenCase) MarshalBinary() ([]byte, error)         { return nil, opaqueError() }
func (*GoldenCase) UnmarshalJSON([]byte) error            { return opaqueError() }
func (*GoldenCase) UnmarshalText([]byte) error            { return opaqueError() }
func (*GoldenCase) UnmarshalBinary([]byte) error          { return opaqueError() }
func (AdapterFixtureView) String() string                 { return opaqueFormat }
func (AdapterFixtureView) GoString() string               { return opaqueFormat }
func (AdapterFixtureView) Format(state fmt.State, _ rune) { writeOpaque(state) }
func (AdapterFixtureView) MarshalJSON() ([]byte, error)   { return nil, opaqueError() }
func (AdapterFixtureView) MarshalText() ([]byte, error)   { return nil, opaqueError() }
func (AdapterFixtureView) MarshalBinary() ([]byte, error) { return nil, opaqueError() }
func (*AdapterFixtureView) UnmarshalJSON([]byte) error    { return opaqueError() }
func (*AdapterFixtureView) UnmarshalText([]byte) error    { return opaqueError() }
func (*AdapterFixtureView) UnmarshalBinary([]byte) error  { return opaqueError() }
