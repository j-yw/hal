package credentialprotocol

import (
	"errors"
	"reflect"
	"testing"
)

func TestSSHRelayV1ExtensionDescriptorIsExactAndFresh(t *testing.T) {
	t.Parallel()

	first := SSHRelayV1ExtensionDescriptor()
	want := ExtensionDescriptor{
		ID:                       ExtensionIDSSHRelayV1,
		Modes:                    []DeliveryMode{DeliveryModeSSHAgent},
		AgentToHelperPacketTypes: nil,
		HelperToAgentPacketTypes: []PacketType{PacketTypeSSHAcceptedFD},
	}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("descriptor = %#v, want %#v", first, want)
	}
	if err := ValidateExtensionDescriptor(first); err != nil {
		t.Fatalf("ValidateExtensionDescriptor() error = %v", err)
	}

	first.Modes[0] = DeliveryModeHTTPProxy
	first.HelperToAgentPacketTypes[0] = PacketTypeResponse
	second := SSHRelayV1ExtensionDescriptor()
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("fresh descriptor changed through caller mutation: %#v", second)
	}
}

func TestValidateExtensionDescriptorRejectsNoncanonicalValues(t *testing.T) {
	t.Parallel()

	canonical := SSHRelayV1ExtensionDescriptor()
	repeatedModes := make([]DeliveryMode, MaxExtensionCatalogEntries+1)
	for index := range repeatedModes {
		repeatedModes[index] = DeliveryModeSSHAgent
	}
	repeatedPackets := make([]PacketType, MaxExtensionCatalogEntries+1)
	for index := range repeatedPackets {
		repeatedPackets[index] = PacketTypeSSHAcceptedFD
	}

	tests := []struct {
		name       string
		descriptor ExtensionDescriptor
		want       error
	}{
		{name: "typed zero", descriptor: ExtensionDescriptor{}, want: ErrInvalidExtensionID},
		{name: "unsafe ID", descriptor: replaceDescriptorID(canonical, "ssh/relay"), want: ErrInvalidExtensionID},
		{name: "empty claims", descriptor: ExtensionDescriptor{ID: ExtensionIDSSHRelayV1}, want: ErrEmptyExtensionDescriptor},
		{name: "too many modes", descriptor: replaceDescriptorModes(canonical, repeatedModes), want: ErrExtensionCatalogTooLarge},
		{name: "unknown mode", descriptor: replaceDescriptorModes(canonical, []DeliveryMode{4}), want: ErrUnknownDeliveryMode},
		{name: "duplicate mode", descriptor: replaceDescriptorModes(canonical, []DeliveryMode{DeliveryModeSSHAgent, DeliveryModeSSHAgent}), want: ErrExtensionCatalogDuplicate},
		{name: "unordered modes", descriptor: replaceDescriptorModes(canonical, []DeliveryMode{DeliveryModeSSHAgent, DeliveryModeFileTmpfs}), want: ErrExtensionCatalogOrder},
		{name: "reserved core mode", descriptor: replaceDescriptorModes(canonical, []DeliveryMode{DeliveryModeHTTPProxy}), want: ErrExtensionCoreClaim},
		{name: "known but wrong extension mode", descriptor: replaceDescriptorModes(canonical, []DeliveryMode{DeliveryModeFileTmpfs}), want: ErrExtensionCoreClaim},
		{name: "too many agent packets", descriptor: replaceDescriptorAgentPackets(canonical, repeatedPackets), want: ErrExtensionCatalogTooLarge},
		{name: "unknown agent packet", descriptor: replaceDescriptorAgentPackets(canonical, []PacketType{0x06}), want: ErrUnknownPacketType},
		{name: "duplicate agent packet", descriptor: replaceDescriptorAgentPackets(canonical, []PacketType{PacketTypeSSHAcceptedFD, PacketTypeSSHAcceptedFD}), want: ErrExtensionCatalogDuplicate},
		{name: "unordered agent packets", descriptor: replaceDescriptorAgentPackets(canonical, []PacketType{PacketTypeSSHAcceptedFD, PacketTypeExec}), want: ErrExtensionCatalogOrder},
		{name: "reserved agent core packet", descriptor: replaceDescriptorAgentPackets(canonical, []PacketType{PacketTypeExec}), want: ErrExtensionCoreClaim},
		{name: "wrong direction", descriptor: replaceDescriptorAgentPackets(replaceDescriptorHelperPackets(canonical, nil), []PacketType{PacketTypeSSHAcceptedFD}), want: ErrExtensionPacketDirection},
		{name: "too many helper packets", descriptor: replaceDescriptorHelperPackets(canonical, repeatedPackets), want: ErrExtensionCatalogTooLarge},
		{name: "unknown helper packet", descriptor: replaceDescriptorHelperPackets(canonical, []PacketType{0x22}), want: ErrUnknownPacketType},
		{name: "duplicate helper packet", descriptor: replaceDescriptorHelperPackets(canonical, []PacketType{PacketTypeSSHAcceptedFD, PacketTypeSSHAcceptedFD}), want: ErrExtensionCatalogDuplicate},
		{name: "unordered helper packets", descriptor: replaceDescriptorHelperPackets(canonical, []PacketType{PacketTypeSSHAcceptedFD, PacketTypeExec}), want: ErrExtensionCatalogOrder},
		{name: "reserved helper core packet", descriptor: replaceDescriptorHelperPackets(canonical, []PacketType{PacketTypeResponse}), want: ErrExtensionCoreClaim},
		{name: "missing helper claim", descriptor: replaceDescriptorHelperPackets(canonical, nil), want: ErrLockedExtensionDescriptor},
	}
	staticFuture := replaceDescriptorID(canonical, "future-static-v2")
	if err := ValidateExtensionDescriptor(staticFuture); err != nil {
		t.Fatalf("future static descriptor error = %v", err)
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := CloneExtensionDescriptor(test.descriptor)
			if err := ValidateExtensionDescriptor(test.descriptor); !errors.Is(err, test.want) {
				t.Fatalf("ValidateExtensionDescriptor() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(test.descriptor, before) {
				t.Fatalf("validator mutated descriptor: got %#v, want %#v", test.descriptor, before)
			}
		})
	}
}

func TestCloneExtensionDescriptorDeepCopiesAndPreservesEmptyShape(t *testing.T) {
	t.Parallel()

	original := SSHRelayV1ExtensionDescriptor()
	original.AgentToHelperPacketTypes = []PacketType{}
	clone := CloneExtensionDescriptor(original)
	if clone.AgentToHelperPacketTypes == nil {
		t.Fatal("clone collapsed explicit empty slice to nil")
	}
	clone.Modes[0] = DeliveryModeHTTPProxy
	clone.HelperToAgentPacketTypes[0] = PacketTypeResponse
	clone.AgentToHelperPacketTypes = append(clone.AgentToHelperPacketTypes, PacketTypeExec)
	if original.Modes[0] != DeliveryModeSSHAgent || original.HelperToAgentPacketTypes[0] != PacketTypeSSHAcceptedFD || len(original.AgentToHelperPacketTypes) != 0 {
		t.Fatalf("clone mutation changed original: %#v", original)
	}

	zero := CloneExtensionDescriptor(ExtensionDescriptor{})
	if zero.Modes != nil || zero.AgentToHelperPacketTypes != nil || zero.HelperToAgentPacketTypes != nil {
		t.Fatalf("zero clone did not preserve nil slices: %#v", zero)
	}
}

func TestExtensionDescriptorEqualUsesFieldValuesWithoutMutation(t *testing.T) {
	t.Parallel()

	left := SSHRelayV1ExtensionDescriptor()
	right := CloneExtensionDescriptor(left)
	right.AgentToHelperPacketTypes = []PacketType{}
	leftBefore := CloneExtensionDescriptor(left)
	rightBefore := CloneExtensionDescriptor(right)
	if !ExtensionDescriptorEqual(left, right) {
		t.Fatal("equal descriptors with equivalent empty claims did not compare equal")
	}
	if !reflect.DeepEqual(left, leftBefore) || !reflect.DeepEqual(right, rightBefore) {
		t.Fatal("equality comparison mutated an input")
	}

	mutations := []ExtensionDescriptor{
		replaceDescriptorID(right, "other-v1"),
		replaceDescriptorModes(right, []DeliveryMode{DeliveryModeHTTPProxy}),
		replaceDescriptorAgentPackets(right, []PacketType{PacketTypeSSHAcceptedFD}),
		replaceDescriptorHelperPackets(right, nil),
	}
	for _, candidate := range mutations {
		if ExtensionDescriptorEqual(left, candidate) {
			t.Fatalf("unequal descriptor compared equal: %#v", candidate)
		}
	}
}

func TestCloneExtensionDescriptorsDeepCopiesOuterAndInnerSlices(t *testing.T) {
	t.Parallel()

	original := []ExtensionDescriptor{SSHRelayV1ExtensionDescriptor()}
	clone := CloneExtensionDescriptors(original)
	clone[0].ID = "other-v1"
	clone[0].Modes[0] = DeliveryModeHTTPProxy
	clone = append(clone, ExtensionDescriptor{})
	if len(clone) != 2 {
		t.Fatalf("clone length = %d, want 2 after outer-slice mutation", len(clone))
	}
	if len(original) != 1 || original[0].ID != ExtensionIDSSHRelayV1 || original[0].Modes[0] != DeliveryModeSSHAgent {
		t.Fatalf("clone mutation changed original set: %#v", original)
	}
	if CloneExtensionDescriptors(nil) != nil {
		t.Fatal("nil set clone did not remain nil")
	}
	empty := CloneExtensionDescriptors([]ExtensionDescriptor{})
	if empty == nil || len(empty) != 0 {
		t.Fatalf("explicit empty set clone = %#v, want non-nil empty", empty)
	}
}

func TestValidateMatchingExtensionSetsRequiresCanonicalExactSets(t *testing.T) {
	t.Parallel()

	canonical := SSHRelayV1ExtensionDescriptor()
	modeOnly := ExtensionDescriptor{ID: "alpha-v1", Modes: []DeliveryMode{DeliveryModeSSHAgent}}
	packetOnly := ExtensionDescriptor{ID: "zulu-v1", HelperToAgentPacketTypes: []PacketType{PacketTypeSSHAcceptedFD}}
	if err := ValidateMatchingExtensionSets(nil, []ExtensionDescriptor{}); err != nil {
		t.Fatalf("matching empty sets error = %v", err)
	}
	if err := ValidateMatchingExtensionSets([]ExtensionDescriptor{canonical}, []ExtensionDescriptor{CloneExtensionDescriptor(canonical)}); err != nil {
		t.Fatalf("matching SSH sets error = %v", err)
	}
	if err := ValidateMatchingExtensionSets([]ExtensionDescriptor{modeOnly, packetOnly}, []ExtensionDescriptor{CloneExtensionDescriptor(modeOnly), CloneExtensionDescriptor(packetOnly)}); err != nil {
		t.Fatalf("matching ordered future static sets error = %v", err)
	}

	tests := []struct {
		name   string
		helper []ExtensionDescriptor
		client []ExtensionDescriptor
		want   error
	}{
		{name: "count mismatch", helper: []ExtensionDescriptor{canonical}, client: nil, want: ErrExtensionSetMismatch},
		{name: "field mismatch", helper: []ExtensionDescriptor{modeOnly}, client: []ExtensionDescriptor{replaceDescriptorModes(modeOnly, nil)}, want: ErrEmptyExtensionDescriptor},
		{name: "valid field mismatch", helper: []ExtensionDescriptor{modeOnly}, client: []ExtensionDescriptor{replaceDescriptorHelperPackets(replaceDescriptorModes(modeOnly, nil), []PacketType{PacketTypeSSHAcceptedFD})}, want: ErrExtensionSetMismatch},
		{name: "duplicate helper ID", helper: []ExtensionDescriptor{modeOnly, CloneExtensionDescriptor(modeOnly)}, client: nil, want: ErrExtensionSetDuplicate},
		{name: "duplicate client ID", helper: nil, client: []ExtensionDescriptor{modeOnly, CloneExtensionDescriptor(modeOnly)}, want: ErrExtensionSetDuplicate},
		{name: "unordered helper IDs", helper: []ExtensionDescriptor{packetOnly, modeOnly}, client: nil, want: ErrExtensionSetOrder},
		{name: "duplicate mode claim", helper: []ExtensionDescriptor{modeOnly, replaceDescriptorID(modeOnly, "beta-v1")}, client: nil, want: ErrExtensionSetDuplicateClaim},
		{name: "duplicate packet claim", helper: []ExtensionDescriptor{ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []PacketType{PacketTypeSSHAcceptedFD}}, packetOnly}, client: nil, want: ErrExtensionSetDuplicateClaim},
		{name: "typed zero helper descriptor", helper: []ExtensionDescriptor{{}}, client: []ExtensionDescriptor{{}}, want: ErrInvalidExtensionID},
		{name: "too many helper descriptors", helper: repeatedDescriptors(canonical, MaxExtensions+1), client: nil, want: ErrExtensionSetTooLarge},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			helperBefore := CloneExtensionDescriptors(test.helper)
			clientBefore := CloneExtensionDescriptors(test.client)
			if err := ValidateMatchingExtensionSets(test.helper, test.client); !errors.Is(err, test.want) {
				t.Fatalf("ValidateMatchingExtensionSets() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(test.helper, helperBefore) || !reflect.DeepEqual(test.client, clientBefore) {
				t.Fatal("matching validation mutated an input")
			}
		})
	}
}

func replaceDescriptorID(value ExtensionDescriptor, id ExtensionID) ExtensionDescriptor {
	value = CloneExtensionDescriptor(value)
	value.ID = id
	return value
}

func replaceDescriptorModes(value ExtensionDescriptor, modes []DeliveryMode) ExtensionDescriptor {
	value = CloneExtensionDescriptor(value)
	value.Modes = modes
	return value
}

func replaceDescriptorAgentPackets(value ExtensionDescriptor, packets []PacketType) ExtensionDescriptor {
	value = CloneExtensionDescriptor(value)
	value.AgentToHelperPacketTypes = packets
	return value
}

func replaceDescriptorHelperPackets(value ExtensionDescriptor, packets []PacketType) ExtensionDescriptor {
	value = CloneExtensionDescriptor(value)
	value.HelperToAgentPacketTypes = packets
	return value
}

func repeatedDescriptors(value ExtensionDescriptor, count int) []ExtensionDescriptor {
	result := make([]ExtensionDescriptor, count)
	for index := range result {
		result[index] = CloneExtensionDescriptor(value)
	}
	return result
}
