package syscallpolicy

import "encoding/binary"

type PreObservationSource interface {
	ObserveState(StateQuery) (StateObservation, error)
	ObserveFD(FDQuery) (FDObservation, error)
	ObservePointer(PointerQuery) (PointerObservation, error)
	ObserveObject(ObjectQuery) (ObjectObservation, error)
}

type PostObservationSource interface {
	ReinspectObject(ObjectQuery) (ObjectObservation, error)
}

type queryAuthority struct {
	correlation [32]byte
	phase       AdapterPhase
	kind        QueryKind
	ordinal     uint16
	ruleSHA256  [32]byte
	sha256      [32]byte
}

type stateQuery struct {
	authority       queryAuthority
	expectedRole    Role
	expectedStage   Stage
	requiredFacts   StateFact
	prohibitedFacts StateFact
	requiredChecks  CheckSet
}
type StateQuery struct {
	query *stateQuery
	owner *policyOwner
}

type fdQuery struct {
	authority                queryAuthority
	argumentIndex            uint8
	fdNumber                 int32
	expectedKind             DescriptorKind
	expectedAccess           DescriptorAccess
	expectedGenerationSHA256 [32]byte
	generationMode           GenerationMode
	bindingSlot              uint8
	fixed                    bool
	requiredChecks           CheckSet
}
type FDQuery struct {
	query *fdQuery
	owner *policyOwner
}

type pointerQuery struct {
	authority      queryAuthority
	argumentIndex  uint8
	expectedClass  PointerClass
	minimumBytes   uint32
	maximumBytes   uint32
	requiredChecks CheckSet
}
type PointerQuery struct {
	query *pointerQuery
	owner *policyOwner
}

type objectQuery struct {
	authority                queryAuthority
	source                   ObjectSource
	argumentIndex            uint8
	expectedNumber           int32
	expectedKind             DescriptorKind
	expectedAccess           DescriptorAccess
	expectedGenerationSHA256 [32]byte
	generationMode           GenerationMode
	bindingSlot              uint8
	fixed                    bool
	requiredChecks           CheckSet
}
type ObjectQuery struct {
	query *objectQuery
	owner *policyOwner
}

type stateObservation struct {
	actual      State
	checks      CheckSet
	querySHA256 [32]byte
}
type StateObservation struct {
	observation *stateObservation
	owner       *policyOwner
}
type fdObservation struct {
	number           int32
	kind             DescriptorKind
	access           DescriptorAccess
	generationSHA256 [32]byte
	fixed            bool
	checks           CheckSet
	querySHA256      [32]byte
}
type FDObservation struct {
	observation *fdObservation
	owner       *policyOwner
}
type pointerObservation struct {
	class       PointerClass
	bytes       uint32
	checks      CheckSet
	querySHA256 [32]byte
}
type PointerObservation struct {
	observation *pointerObservation
	owner       *policyOwner
}
type objectObservation struct {
	number           int32
	kind             DescriptorKind
	access           DescriptorAccess
	generationSHA256 [32]byte
	fixed            bool
	checks           CheckSet
	querySHA256      [32]byte
}
type ObjectObservation struct {
	observation *objectObservation
	owner       *policyOwner
}

func newStateQuery(policy *Policy, ticket AdapterTicket, ordinal uint16, required, prohibited StateFact, checks CheckSet) StateQuery {
	query := &stateQuery{expectedRole: ticket.ticket.input.state.role, expectedStage: ticket.ticket.input.state.stage, requiredFacts: required, prohibitedFacts: prohibited, requiredChecks: checks}
	query.authority = newQueryAuthority(ticket, AdapterPhasePre, QueryKindState, ordinal)
	suffix := make([]byte, 24)
	suffix[0], suffix[1] = byte(query.expectedRole), byte(query.expectedStage)
	binary.BigEndian.PutUint64(suffix[4:12], uint64(required))
	binary.BigEndian.PutUint64(suffix[12:20], uint64(prohibited))
	binary.BigEndian.PutUint32(suffix[20:24], checks.bits)
	query.authority.sha256 = framedSHA256("hal/l8/adapter-state-query/linux-amd64/v1", append(queryPrefix(query.authority), suffix...))
	return StateQuery{query: query, owner: policy.owner}
}

func newFDQuery(policy *Policy, ticket AdapterTicket, bindings AdapterBindings, requirement *descriptorRequirement, ordinal uint16) FDQuery {
	generation := requirement.generationSHA256
	if requirement.generationMode == GenerationModeLiveBound {
		generation = bindingGeneration(bindings, requirement.bindingSlot)
	}
	query := &fdQuery{argumentIndex: requirement.argumentIndex, fdNumber: int32(ticket.ticket.input.arguments[requirement.argumentIndex]), expectedKind: requirement.kind, expectedAccess: requirement.access, expectedGenerationSHA256: generation, generationMode: requirement.generationMode, bindingSlot: requirement.bindingSlot, fixed: requirement.fixed, requiredChecks: requirement.requiredChecks}
	query.authority = newQueryAuthority(ticket, AdapterPhasePre, QueryKindFD, ordinal)
	suffix := make([]byte, 48)
	suffix[0], suffix[1], suffix[2] = query.argumentIndex, byte(query.expectedKind), byte(query.expectedAccess)
	if query.fixed {
		suffix[3] = 1
	}
	binary.BigEndian.PutUint32(suffix[4:8], uint32(query.fdNumber))
	suffix[8], suffix[9] = byte(query.generationMode), query.bindingSlot
	binary.BigEndian.PutUint32(suffix[12:16], query.requiredChecks.bits)
	copy(suffix[16:], query.expectedGenerationSHA256[:])
	query.authority.sha256 = framedSHA256("hal/l8/adapter-fd-query/linux-amd64/v1", append(queryPrefix(query.authority), suffix...))
	return FDQuery{query: query, owner: policy.owner}
}

func newPointerQuery(policy *Policy, ticket AdapterTicket, requirement *pointerRequirement, ordinal uint16) PointerQuery {
	query := &pointerQuery{argumentIndex: requirement.argumentIndex, expectedClass: requirement.class, minimumBytes: requirement.minimumBytes, maximumBytes: requirement.maximumBytes, requiredChecks: requirement.requiredChecks}
	query.authority = newQueryAuthority(ticket, AdapterPhasePre, QueryKindPointer, ordinal)
	suffix := make([]byte, 16)
	suffix[0], suffix[1] = query.argumentIndex, byte(query.expectedClass)
	binary.BigEndian.PutUint32(suffix[4:8], query.minimumBytes)
	binary.BigEndian.PutUint32(suffix[8:12], query.maximumBytes)
	binary.BigEndian.PutUint32(suffix[12:16], query.requiredChecks.bits)
	query.authority.sha256 = framedSHA256("hal/l8/adapter-pointer-query/linux-amd64/v1", append(queryPrefix(query.authority), suffix...))
	return PointerQuery{query: query, owner: policy.owner}
}

func newObjectQuery(policy *Policy, ticket AdapterTicket, bindings AdapterBindings, requirement *objectRequirement, phase AdapterPhase, ordinal uint16) ObjectQuery {
	generation := requirement.generationSHA256
	if requirement.generationMode == GenerationModeLiveBound {
		generation = bindingGeneration(bindings, requirement.bindingSlot)
	}
	number := int32(-1)
	if requirement.source == ObjectSourceArgument {
		number = int32(ticket.ticket.input.arguments[requirement.argumentIndex])
	}
	query := &objectQuery{source: requirement.source, argumentIndex: requirement.argumentIndex, expectedNumber: number, expectedKind: requirement.kind, expectedAccess: requirement.access, expectedGenerationSHA256: generation, generationMode: requirement.generationMode, bindingSlot: requirement.bindingSlot, fixed: requirement.fixed, requiredChecks: requirement.requiredChecks}
	query.authority = newQueryAuthority(ticket, phase, QueryKindObject, ordinal)
	suffix := make([]byte, 48)
	suffix[0], suffix[1], suffix[2], suffix[3] = byte(query.source), query.argumentIndex, byte(query.expectedKind), byte(query.expectedAccess)
	if query.fixed {
		suffix[4] = 1
	}
	suffix[5], suffix[6] = byte(query.generationMode), query.bindingSlot
	binary.BigEndian.PutUint32(suffix[8:12], uint32(query.expectedNumber))
	binary.BigEndian.PutUint32(suffix[12:16], query.requiredChecks.bits)
	copy(suffix[16:], query.expectedGenerationSHA256[:])
	query.authority.sha256 = framedSHA256("hal/l8/adapter-object-query/linux-amd64/v1", append(queryPrefix(query.authority), suffix...))
	return ObjectQuery{query: query, owner: policy.owner}
}

func newQueryAuthority(ticket AdapterTicket, phase AdapterPhase, kind QueryKind, ordinal uint16) queryAuthority {
	return queryAuthority{correlation: ticket.ticket.permitCorrelationSHA256, phase: phase, kind: kind, ordinal: ordinal, ruleSHA256: ticket.ticket.ruleSHA256}
}
func queryPrefix(authority queryAuthority) []byte {
	result := make([]byte, 68)
	copy(result[:32], authority.correlation[:])
	result[32], result[33] = byte(authority.phase), byte(authority.kind)
	binary.BigEndian.PutUint16(result[34:36], authority.ordinal)
	copy(result[36:], authority.ruleSHA256[:])
	return result
}
func bindingGeneration(bindings AdapterBindings, slot uint8) [32]byte {
	if bindings.bindings != nil {
		for _, binding := range bindings.bindings.records {
			if binding.slot == slot {
				return binding.generationSHA256
			}
		}
	}
	return [32]byte{}
}

func NewStateObservation(query StateQuery, actual State, checks CheckSet) (StateObservation, error) {
	if query.query == nil || query.owner == nil {
		return StateObservation{}, contractError(ErrorCodeOwnership)
	}
	if !actual.valid || ValidateRole(actual.role) != nil || ValidateStage(actual.stage) != nil || ValidateStateFacts(actual.facts) != nil {
		return StateObservation{}, contractError(ErrorCodeCatalog)
	}
	if checks.bits != query.query.requiredChecks.bits {
		return StateObservation{}, contractError(ErrorCodeInvalidArgument)
	}
	return StateObservation{observation: &stateObservation{actual: actual, checks: checks, querySHA256: query.query.authority.sha256}, owner: query.owner}, nil
}
func NewFDObservation(query FDQuery, number int32, kind DescriptorKind, access DescriptorAccess, generation [32]byte, fixed bool, checks CheckSet) (FDObservation, error) {
	if query.query == nil || query.owner == nil {
		return FDObservation{}, contractError(ErrorCodeOwnership)
	}
	if number < 0 {
		return FDObservation{}, contractError(ErrorCodeBounds)
	}
	if ValidateDescriptorKind(kind) != nil || ValidateDescriptorAccess(access) != nil {
		return FDObservation{}, contractError(ErrorCodeCatalog)
	}
	if zeroDigest(generation) || checks.bits != query.query.requiredChecks.bits {
		return FDObservation{}, contractError(ErrorCodeInvalidArgument)
	}
	return FDObservation{observation: &fdObservation{number: number, kind: kind, access: access, generationSHA256: generation, fixed: fixed, checks: checks, querySHA256: query.query.authority.sha256}, owner: query.owner}, nil
}
func NewPointerObservation(query PointerQuery, class PointerClass, bytes uint32, checks CheckSet) (PointerObservation, error) {
	if query.query == nil || query.owner == nil {
		return PointerObservation{}, contractError(ErrorCodeOwnership)
	}
	if ValidatePointerClass(class) != nil {
		return PointerObservation{}, contractError(ErrorCodeCatalog)
	}
	if checks.bits != query.query.requiredChecks.bits {
		return PointerObservation{}, contractError(ErrorCodeInvalidArgument)
	}
	return PointerObservation{observation: &pointerObservation{class: class, bytes: bytes, checks: checks, querySHA256: query.query.authority.sha256}, owner: query.owner}, nil
}
func NewObjectObservation(query ObjectQuery, number int32, kind DescriptorKind, access DescriptorAccess, generation [32]byte, checks CheckSet, fixed bool) (ObjectObservation, error) {
	if query.query == nil || query.owner == nil {
		return ObjectObservation{}, contractError(ErrorCodeOwnership)
	}
	if number < 0 {
		return ObjectObservation{}, contractError(ErrorCodeBounds)
	}
	if ValidateDescriptorKind(kind) != nil || ValidateDescriptorAccess(access) != nil {
		return ObjectObservation{}, contractError(ErrorCodeCatalog)
	}
	if zeroDigest(generation) || checks.bits != query.query.requiredChecks.bits {
		return ObjectObservation{}, contractError(ErrorCodeInvalidArgument)
	}
	return ObjectObservation{observation: &objectObservation{number: number, kind: kind, access: access, generationSHA256: generation, fixed: fixed, checks: checks, querySHA256: query.query.authority.sha256}, owner: query.owner}, nil
}

func (query StateQuery) ExpectedRole() Role {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedRole
}
func (query StateQuery) ExpectedStage() Stage {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedStage
}
func (query StateQuery) RequiredFacts() StateFact {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.requiredFacts
}
func (query StateQuery) ProhibitedFacts() StateFact {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.prohibitedFacts
}
func (query StateQuery) RequiredChecks() CheckSet {
	if query.query == nil || query.owner == nil {
		return CheckSet{}
	}
	return query.query.requiredChecks
}
func (query StateQuery) RuleSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.ruleSHA256
}
func (query StateQuery) Kind() QueryKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.kind
}
func (query StateQuery) PermitCorrelationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.correlation
}
func (query StateQuery) Phase() AdapterPhase {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.phase
}
func (query StateQuery) Ordinal() uint16 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.ordinal
}
func (query StateQuery) SHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.sha256
}

func (query FDQuery) ArgumentIndex() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.argumentIndex
}
func (query FDQuery) RuleSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.ruleSHA256
}
func (query FDQuery) FDNumber() int32 {
	if query.query == nil || query.owner == nil {
		return -1
	}
	return query.query.fdNumber
}
func (query FDQuery) ExpectedKind() DescriptorKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedKind
}
func (query FDQuery) ExpectedAccess() DescriptorAccess {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedAccess
}
func (query FDQuery) ExpectedGenerationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.expectedGenerationSHA256
}
func (query FDQuery) GenerationMode() GenerationMode {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.generationMode
}
func (query FDQuery) BindingSlot() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.bindingSlot
}
func (query FDQuery) Fixed() bool {
	return query.query != nil && query.owner != nil && query.query.fixed
}
func (query FDQuery) RequiredChecks() CheckSet {
	if query.query == nil || query.owner == nil {
		return CheckSet{}
	}
	return query.query.requiredChecks
}
func (query FDQuery) Kind() QueryKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.kind
}
func (query FDQuery) PermitCorrelationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.correlation
}
func (query FDQuery) Phase() AdapterPhase {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.phase
}
func (query FDQuery) Ordinal() uint16 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.ordinal
}
func (query FDQuery) SHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.sha256
}

func (query PointerQuery) ArgumentIndex() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.argumentIndex
}
func (query PointerQuery) RuleSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.ruleSHA256
}
func (query PointerQuery) ExpectedClass() PointerClass {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedClass
}
func (query PointerQuery) MinimumBytes() uint32 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.minimumBytes
}
func (query PointerQuery) MaximumBytes() uint32 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.maximumBytes
}
func (query PointerQuery) RequiredChecks() CheckSet {
	if query.query == nil || query.owner == nil {
		return CheckSet{}
	}
	return query.query.requiredChecks
}
func (query PointerQuery) Kind() QueryKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.kind
}
func (query PointerQuery) PermitCorrelationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.correlation
}
func (query PointerQuery) Phase() AdapterPhase {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.phase
}
func (query PointerQuery) Ordinal() uint16 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.ordinal
}
func (query PointerQuery) SHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.sha256
}

func (query ObjectQuery) ArgumentIndex() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.argumentIndex
}
func (query ObjectQuery) RuleSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.ruleSHA256
}
func (query ObjectQuery) Source() ObjectSource {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.source
}
func (query ObjectQuery) ExpectedNumber() (int32, error) {
	if query.query == nil || query.owner == nil {
		return 0, contractError(ErrorCodeInvalidArgument)
	}
	return query.query.expectedNumber, nil
}
func (query ObjectQuery) ExpectedKind() DescriptorKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedKind
}
func (query ObjectQuery) ExpectedAccess() DescriptorAccess {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedAccess
}
func (query ObjectQuery) ExpectedGenerationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.expectedGenerationSHA256
}
func (query ObjectQuery) GenerationMode() GenerationMode {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.generationMode
}
func (query ObjectQuery) BindingSlot() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.bindingSlot
}
func (query ObjectQuery) Fixed() bool {
	return query.query != nil && query.owner != nil && query.query.fixed
}
func (query ObjectQuery) RequiredChecks() CheckSet {
	if query.query == nil || query.owner == nil {
		return CheckSet{}
	}
	return query.query.requiredChecks
}
func (query ObjectQuery) Kind() QueryKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.kind
}
func (query ObjectQuery) PermitCorrelationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.correlation
}
func (query ObjectQuery) Phase() AdapterPhase {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.phase
}
func (query ObjectQuery) Ordinal() uint16 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.authority.ordinal
}
func (query ObjectQuery) SHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.authority.sha256
}

func (observation StateObservation) Actual() State {
	if observation.observation == nil || observation.owner == nil {
		return State{}
	}
	return observation.observation.actual
}
func (observation StateObservation) Checks() CheckSet {
	if observation.observation == nil || observation.owner == nil {
		return CheckSet{}
	}
	return observation.observation.checks
}
func (observation StateObservation) QuerySHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.querySHA256
}
func (observation FDObservation) Number() int32 {
	if observation.observation == nil || observation.owner == nil {
		return -1
	}
	return observation.observation.number
}
func (observation FDObservation) Kind() DescriptorKind {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.kind
}
func (observation FDObservation) Access() DescriptorAccess {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.access
}
func (observation FDObservation) GenerationSHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.generationSHA256
}
func (observation FDObservation) Fixed() bool {
	return observation.observation != nil && observation.owner != nil && observation.observation.fixed
}
func (observation FDObservation) Checks() CheckSet {
	if observation.observation == nil || observation.owner == nil {
		return CheckSet{}
	}
	return observation.observation.checks
}
func (observation FDObservation) QuerySHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.querySHA256
}
func (observation PointerObservation) Class() PointerClass {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.class
}
func (observation PointerObservation) Bytes() uint32 {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.bytes
}
func (observation PointerObservation) Checks() CheckSet {
	if observation.observation == nil || observation.owner == nil {
		return CheckSet{}
	}
	return observation.observation.checks
}
func (observation PointerObservation) QuerySHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.querySHA256
}
func (observation ObjectObservation) Number() int32 {
	if observation.observation == nil || observation.owner == nil {
		return -1
	}
	return observation.observation.number
}
func (observation ObjectObservation) Kind() DescriptorKind {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.kind
}
func (observation ObjectObservation) Access() DescriptorAccess {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.access
}
func (observation ObjectObservation) GenerationSHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.generationSHA256
}
func (observation ObjectObservation) Fixed() bool {
	return observation.observation != nil && observation.owner != nil && observation.observation.fixed
}
func (observation ObjectObservation) Checks() CheckSet {
	if observation.observation == nil || observation.owner == nil {
		return CheckSet{}
	}
	return observation.observation.checks
}
func (observation ObjectObservation) QuerySHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.querySHA256
}
