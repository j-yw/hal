package credentialprotocol

import "errors"

var (
	ErrEmptyExtensionDescriptor   = errors.New("credential protocol extension descriptor has no claims")
	ErrExtensionCatalogTooLarge   = errors.New("credential protocol extension catalog exceeds its bound")
	ErrExtensionCatalogDuplicate  = errors.New("credential protocol extension catalog contains a duplicate")
	ErrExtensionCatalogOrder      = errors.New("credential protocol extension catalog is not in canonical order")
	ErrExtensionCoreClaim         = errors.New("credential protocol extension claims a core catalog value")
	ErrExtensionPacketDirection   = errors.New("credential protocol extension claims a packet in the wrong direction")
	ErrLockedExtensionDescriptor  = errors.New("credential protocol extension descriptor differs from its locked catalog")
	ErrExtensionSetTooLarge       = errors.New("credential protocol extension set exceeds its bound")
	ErrExtensionSetDuplicate      = errors.New("credential protocol extension set contains a duplicate ID")
	ErrExtensionSetDuplicateClaim = errors.New("credential protocol extension set contains a duplicate catalog claim")
	ErrExtensionSetOrder          = errors.New("credential protocol extension set is not in canonical ID order")
	ErrExtensionSetMismatch       = errors.New("credential protocol extension sets do not match")
)

// ExtensionDescriptor is safe, data-only process composition metadata. It has
// no durable serialization contract; callers must clone values they retain.
type ExtensionDescriptor struct {
	ID                       ExtensionID
	Modes                    []DeliveryMode
	AgentToHelperPacketTypes []PacketType
	HelperToAgentPacketTypes []PacketType
}

// SSHRelayV1ExtensionDescriptor returns a fresh copy of the sole locked D2
// extension descriptor. No caller can mutate shared package state.
func SSHRelayV1ExtensionDescriptor() ExtensionDescriptor {
	return ExtensionDescriptor{
		ID:                       ExtensionIDSSHRelayV1,
		Modes:                    []DeliveryMode{DeliveryModeSSHAgent},
		AgentToHelperPacketTypes: nil,
		HelperToAgentPacketTypes: []PacketType{PacketTypeSSHAcceptedFD},
	}
}

// ValidateExtensionDescriptor accepts canonical values only. It never sorts,
// normalizes, defaults, or mutates the descriptor.
func ValidateExtensionDescriptor(descriptor ExtensionDescriptor) error {
	if err := ValidateExtensionID(descriptor.ID); err != nil {
		return err
	}
	if len(descriptor.Modes) == 0 && len(descriptor.AgentToHelperPacketTypes) == 0 && len(descriptor.HelperToAgentPacketTypes) == 0 {
		return ErrEmptyExtensionDescriptor
	}
	if err := validateDeliveryModeClaims(descriptor.Modes); err != nil {
		return err
	}
	if err := validatePacketTypeClaims(descriptor.AgentToHelperPacketTypes); err != nil {
		return err
	}
	if err := validatePacketTypeClaims(descriptor.HelperToAgentPacketTypes); err != nil {
		return err
	}
	for _, mode := range descriptor.Modes {
		if mode != DeliveryModeSSHAgent {
			return ErrExtensionCoreClaim
		}
	}
	for _, packetType := range descriptor.AgentToHelperPacketTypes {
		if packetType.IsCore() {
			return ErrExtensionCoreClaim
		}
	}
	for _, packetType := range descriptor.HelperToAgentPacketTypes {
		if packetType.IsCore() {
			return ErrExtensionCoreClaim
		}
	}
	if len(descriptor.AgentToHelperPacketTypes) != 0 {
		return ErrExtensionPacketDirection
	}
	if descriptor.ID == ExtensionIDSSHRelayV1 && !ExtensionDescriptorEqual(descriptor, SSHRelayV1ExtensionDescriptor()) {
		return ErrLockedExtensionDescriptor
	}
	return nil
}

func validateDeliveryModeClaims(modes []DeliveryMode) error {
	if len(modes) > MaxExtensionCatalogEntries {
		return ErrExtensionCatalogTooLarge
	}
	for index, mode := range modes {
		if err := ValidateDeliveryMode(mode); err != nil {
			return err
		}
		if index == 0 {
			continue
		}
		if modes[index-1] == mode {
			return ErrExtensionCatalogDuplicate
		}
		if modes[index-1] > mode {
			return ErrExtensionCatalogOrder
		}
	}
	return nil
}

func validatePacketTypeClaims(packetTypes []PacketType) error {
	if len(packetTypes) > MaxExtensionCatalogEntries {
		return ErrExtensionCatalogTooLarge
	}
	for index, packetType := range packetTypes {
		if err := ValidatePacketType(packetType); err != nil {
			return err
		}
		if index == 0 {
			continue
		}
		if packetTypes[index-1] == packetType {
			return ErrExtensionCatalogDuplicate
		}
		if packetTypes[index-1] > packetType {
			return ErrExtensionCatalogOrder
		}
	}
	return nil
}

// ExtensionDescriptorEqual compares the descriptor field values. Nil and
// explicit empty claim slices are equivalent because both have canonical wire
// count zero.
func ExtensionDescriptorEqual(left, right ExtensionDescriptor) bool {
	return left.ID == right.ID &&
		deliveryModesEqual(left.Modes, right.Modes) &&
		packetTypesEqual(left.AgentToHelperPacketTypes, right.AgentToHelperPacketTypes) &&
		packetTypesEqual(left.HelperToAgentPacketTypes, right.HelperToAgentPacketTypes)
}

func deliveryModesEqual(left, right []DeliveryMode) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func packetTypesEqual(left, right []PacketType) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// CloneExtensionDescriptor returns a field-for-field deep copy. It preserves
// nil versus explicitly empty slices and does not validate or normalize input.
func CloneExtensionDescriptor(descriptor ExtensionDescriptor) ExtensionDescriptor {
	return ExtensionDescriptor{
		ID:                       descriptor.ID,
		Modes:                    cloneSlice(descriptor.Modes),
		AgentToHelperPacketTypes: cloneSlice(descriptor.AgentToHelperPacketTypes),
		HelperToAgentPacketTypes: cloneSlice(descriptor.HelperToAgentPacketTypes),
	}
}

// CloneExtensionDescriptors returns a deep copy of a descriptor set. It
// preserves nil versus explicitly empty outer and inner slices.
func CloneExtensionDescriptors(descriptors []ExtensionDescriptor) []ExtensionDescriptor {
	if descriptors == nil {
		return nil
	}
	cloned := make([]ExtensionDescriptor, len(descriptors))
	for index, descriptor := range descriptors {
		cloned[index] = CloneExtensionDescriptor(descriptor)
	}
	return cloned
}

func cloneSlice[T ~uint8](values []T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	copy(cloned, values)
	return cloned
}

// ValidateMatchingExtensionSets requires independently canonical helper and
// client sets with identical field values in ascending extension-ID order.
func ValidateMatchingExtensionSets(helper, client []ExtensionDescriptor) error {
	if err := validateExtensionSet(helper); err != nil {
		return err
	}
	if err := validateExtensionSet(client); err != nil {
		return err
	}
	if len(helper) != len(client) {
		return ErrExtensionSetMismatch
	}
	for index := range helper {
		if !ExtensionDescriptorEqual(helper[index], client[index]) {
			return ErrExtensionSetMismatch
		}
	}
	return nil
}

func validateExtensionSet(descriptors []ExtensionDescriptor) error {
	if len(descriptors) > MaxExtensions {
		return ErrExtensionSetTooLarge
	}
	claimedModes := make(map[DeliveryMode]bool)
	claimedPackets := make(map[PacketType]bool)
	for index, descriptor := range descriptors {
		if err := ValidateExtensionDescriptor(descriptor); err != nil {
			return err
		}
		if index > 0 {
			if descriptors[index-1].ID == descriptor.ID {
				return ErrExtensionSetDuplicate
			}
			if descriptors[index-1].ID > descriptor.ID {
				return ErrExtensionSetOrder
			}
		}
		for _, mode := range descriptor.Modes {
			if claimedModes[mode] {
				return ErrExtensionSetDuplicateClaim
			}
			claimedModes[mode] = true
		}
		for _, packetType := range descriptor.AgentToHelperPacketTypes {
			if claimedPackets[packetType] {
				return ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = true
		}
		for _, packetType := range descriptor.HelperToAgentPacketTypes {
			if claimedPackets[packetType] {
				return ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = true
		}
	}
	return nil
}
