package syscallpolicy

import (
	"encoding/binary"
	"reflect"
	"sort"
)

type BindingSource interface {
	ObserveBinding(BindingQuery) (BindingObservation, error)
}

type bindingQuery struct {
	slot                    uint8
	expectedKind            DescriptorKind
	expectedAccess          DescriptorAccess
	ticketSHA256            [32]byte
	permitCorrelationSHA256 [32]byte
	sha256                  [32]byte
}

type BindingQuery struct {
	query *bindingQuery
	owner *policyOwner
}

type bindingObservation struct {
	slot                    uint8
	kind                    DescriptorKind
	access                  DescriptorAccess
	generationSHA256        [32]byte
	permitCorrelationSHA256 [32]byte
	querySHA256             [32]byte
}

type BindingObservation struct {
	observation *bindingObservation
	owner       *policyOwner
}

type adapterBinding struct {
	slot                    uint8
	kind                    DescriptorKind
	access                  DescriptorAccess
	generationSHA256        [32]byte
	permitCorrelationSHA256 [32]byte
	sha256                  [32]byte
}

type adapterBindings struct {
	artifactSHA256          [32]byte
	ticketSHA256            [32]byte
	permitCorrelationSHA256 [32]byte
	records                 []*adapterBinding
	sha256                  [32]byte
}

type adapterBindingOwner struct{ marker byte }

type AdapterBindings struct {
	bindings  *adapterBindings
	owner     *policyOwner
	operation *adapterBindingOwner
}

type AdapterBindingView struct{ binding *adapterBinding }

func (policy *Policy) NewAdapterBindings(ticket AdapterTicket, source BindingSource) (AdapterBindings, error) {
	if nilInterface(source) {
		return AdapterBindings{}, contractError(ErrorCodeTypedNil)
	}
	if policy == nil || policy.owner == nil || policy.artifact == nil || ticket.ticket == nil || ticket.owner != policy.owner || ticket.ticket.rule == nil || ticket.ticket.artifactSHA256 != policy.artifact.sha256 {
		return AdapterBindings{}, contractError(ErrorCodeOwnership)
	}
	type slotRequirement struct {
		slot   uint8
		kind   DescriptorKind
		access DescriptorAccess
	}
	bySlot := make(map[uint8]slotRequirement)
	add := func(slot uint8, kind DescriptorKind, access DescriptorAccess) error {
		if slot == 0 || slot > MaxAdapterBindings {
			return contractError(ErrorCodeContradiction)
		}
		if existing, ok := bySlot[slot]; ok && (existing.kind != kind || existing.access != access) {
			return contractError(ErrorCodeContradiction)
		}
		bySlot[slot] = slotRequirement{slot: slot, kind: kind, access: access}
		return nil
	}
	for _, requirement := range ticket.ticket.rule.descriptors {
		if requirement.generationMode == GenerationModeLiveBound {
			if err := add(requirement.bindingSlot, requirement.kind, requirement.access); err != nil {
				return AdapterBindings{}, err
			}
		}
	}
	for _, requirement := range ticket.ticket.rule.objects {
		if requirement.source == ObjectSourceArgument && requirement.generationMode == GenerationModeLiveBound {
			if err := add(requirement.bindingSlot, requirement.kind, requirement.access); err != nil {
				return AdapterBindings{}, err
			}
		}
	}
	requirements := make([]slotRequirement, 0, len(bySlot))
	for _, requirement := range bySlot {
		requirements = append(requirements, requirement)
	}
	sort.Slice(requirements, func(left, right int) bool { return requirements[left].slot < requirements[right].slot })
	records := make([]*adapterBinding, 0, len(requirements))
	for _, requirement := range requirements {
		query := newBindingQuery(policy, ticket, requirement.slot, requirement.kind, requirement.access)
		observation, err := observeBindingSafely(source, query)
		if err != nil || observation.observation == nil || observation.owner != policy.owner || observation.observation.querySHA256 != query.query.sha256 || observation.observation.permitCorrelationSHA256 != ticket.ticket.permitCorrelationSHA256 {
			return AdapterBindings{}, contractError(ErrorCodeObservation)
		}
		record := &adapterBinding{
			slot:                    observation.observation.slot,
			kind:                    observation.observation.kind,
			access:                  observation.observation.access,
			generationSHA256:        observation.observation.generationSHA256,
			permitCorrelationSHA256: ticket.ticket.permitCorrelationSHA256,
		}
		record.sha256 = framedSHA256("hal/l8/adapter-binding/linux-amd64/v1", append(ticket.ticket.permitCorrelationSHA256[:], encodeAdapterBinding(record)...))
		records = append(records, record)
	}
	bindings := &adapterBindings{
		artifactSHA256:          policy.artifact.sha256,
		ticketSHA256:            ticket.ticket.sha256,
		permitCorrelationSHA256: ticket.ticket.permitCorrelationSHA256,
		records:                 records,
	}
	preimage := make([]byte, 0, 98+len(records)*36)
	preimage = append(preimage, bindings.artifactSHA256[:]...)
	preimage = append(preimage, bindings.ticketSHA256[:]...)
	preimage = append(preimage, bindings.permitCorrelationSHA256[:]...)
	count := make([]byte, 2)
	binary.BigEndian.PutUint16(count, uint16(len(records)))
	preimage = append(preimage, count...)
	for _, record := range records {
		preimage = append(preimage, encodeAdapterBinding(record)...)
	}
	bindings.sha256 = framedSHA256("hal/l8/adapter-bindings/linux-amd64/v1", preimage)
	return AdapterBindings{bindings: bindings, owner: policy.owner, operation: &adapterBindingOwner{}}, nil
}

func newBindingQuery(policy *Policy, ticket AdapterTicket, slot uint8, kind DescriptorKind, access DescriptorAccess) BindingQuery {
	query := &bindingQuery{
		slot:                    slot,
		expectedKind:            kind,
		expectedAccess:          access,
		ticketSHA256:            ticket.ticket.sha256,
		permitCorrelationSHA256: ticket.ticket.permitCorrelationSHA256,
	}
	preimage := make([]byte, 0, 99)
	preimage = append(preimage, policy.artifact.sha256[:]...)
	preimage = append(preimage, query.ticketSHA256[:]...)
	preimage = append(preimage, query.permitCorrelationSHA256[:]...)
	preimage = append(preimage, slot, byte(kind), byte(access))
	query.sha256 = framedSHA256("hal/l8/adapter-binding-query/linux-amd64/v1", preimage)
	return BindingQuery{query: query, owner: policy.owner}
}

func NewBindingObservation(query BindingQuery, kind DescriptorKind, access DescriptorAccess, generationSHA256 [32]byte) (BindingObservation, error) {
	if query.query == nil || query.owner == nil {
		return BindingObservation{}, contractError(ErrorCodeOwnership)
	}
	if ValidateDescriptorKind(kind) != nil || ValidateDescriptorAccess(access) != nil {
		return BindingObservation{}, contractError(ErrorCodeCatalog)
	}
	if zeroDigest(generationSHA256) {
		return BindingObservation{}, contractError(ErrorCodeInvalidArgument)
	}
	return BindingObservation{observation: &bindingObservation{
		slot:                    query.query.slot,
		kind:                    kind,
		access:                  access,
		generationSHA256:        generationSHA256,
		permitCorrelationSHA256: query.query.permitCorrelationSHA256,
		querySHA256:             query.query.sha256,
	}, owner: query.owner}, nil
}

func observeBindingSafely(source BindingSource, query BindingQuery) (observation BindingObservation, err error) {
	defer func() {
		if recover() != nil {
			observation = BindingObservation{}
			err = contractError(ErrorCodeObservation)
		}
	}()
	return source.ObserveBinding(query)
}

func encodeAdapterBinding(binding *adapterBinding) []byte {
	result := make([]byte, 36)
	result[0] = binding.slot
	result[1] = byte(binding.kind)
	result[2] = byte(binding.access)
	copy(result[4:], binding.generationSHA256[:])
	return result
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (query BindingQuery) Slot() uint8 {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.slot
}
func (query BindingQuery) ExpectedKind() DescriptorKind {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedKind
}
func (query BindingQuery) ExpectedAccess() DescriptorAccess {
	if query.query == nil || query.owner == nil {
		return 0
	}
	return query.query.expectedAccess
}
func (query BindingQuery) TicketSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.ticketSHA256
}
func (query BindingQuery) PermitCorrelationSHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.permitCorrelationSHA256
}
func (query BindingQuery) SHA256() [32]byte {
	if query.query == nil || query.owner == nil {
		return [32]byte{}
	}
	return query.query.sha256
}

func (observation BindingObservation) Slot() uint8 {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.slot
}
func (observation BindingObservation) Kind() DescriptorKind {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.kind
}
func (observation BindingObservation) Access() DescriptorAccess {
	if observation.observation == nil || observation.owner == nil {
		return 0
	}
	return observation.observation.access
}
func (observation BindingObservation) GenerationSHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.generationSHA256
}
func (observation BindingObservation) PermitCorrelationSHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.permitCorrelationSHA256
}
func (observation BindingObservation) QuerySHA256() [32]byte {
	if observation.observation == nil || observation.owner == nil {
		return [32]byte{}
	}
	return observation.observation.querySHA256
}

func (bindings AdapterBindings) TicketSHA256() [32]byte {
	if bindings.bindings == nil || bindings.owner == nil || bindings.operation == nil {
		return [32]byte{}
	}
	return bindings.bindings.ticketSHA256
}
func (bindings AdapterBindings) PermitCorrelationSHA256() [32]byte {
	if bindings.bindings == nil || bindings.owner == nil || bindings.operation == nil {
		return [32]byte{}
	}
	return bindings.bindings.permitCorrelationSHA256
}
func (bindings AdapterBindings) SHA256() [32]byte {
	if bindings.bindings == nil || bindings.owner == nil || bindings.operation == nil {
		return [32]byte{}
	}
	return bindings.bindings.sha256
}
func (bindings AdapterBindings) Bindings() []AdapterBindingView {
	if bindings.bindings == nil || bindings.owner == nil || bindings.operation == nil {
		return nil
	}
	result := make([]AdapterBindingView, len(bindings.bindings.records))
	for index, binding := range bindings.bindings.records {
		result[index] = AdapterBindingView{binding: binding}
	}
	return result
}

func (binding AdapterBindingView) Slot() uint8 {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.slot
}
func (binding AdapterBindingView) Kind() DescriptorKind {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.kind
}
func (binding AdapterBindingView) Access() DescriptorAccess {
	if binding.binding == nil {
		return 0
	}
	return binding.binding.access
}
func (binding AdapterBindingView) GenerationSHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.generationSHA256
}
func (binding AdapterBindingView) PermitCorrelationSHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.permitCorrelationSHA256
}
func (binding AdapterBindingView) SHA256() [32]byte {
	if binding.binding == nil {
		return [32]byte{}
	}
	return binding.binding.sha256
}
