package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestProcessDescriptorConstantsAndPolicyDigestsAreExact(t *testing.T) {
	t.Parallel()

	if ProcessDescriptorContractVersion != "l8-process-composition-v1" {
		t.Fatalf("ProcessDescriptorContractVersion = %q", ProcessDescriptorContractVersion)
	}
	if ProcessRoleHelper != 1 || ProcessRoleClient != 2 {
		t.Fatalf("roles = (%d, %d), want (1, 2)", ProcessRoleHelper, ProcessRoleClient)
	}
	if MaxProcessDescriptorBytes != 1898 {
		t.Fatalf("MaxProcessDescriptorBytes = %d, want 1898", MaxProcessDescriptorBytes)
	}
	if calculated := processDescriptorHeaderBytes + credentialprotocol.MaxExtensions*(1+credentialprotocol.MaxExtensionIDBytes+3*(1+credentialprotocol.MaxExtensionCatalogEntries)); calculated != MaxProcessDescriptorBytes {
		t.Fatalf("calculated maximum = %d, want %d", calculated, MaxProcessDescriptorBytes)
	}

	helper := expectedPolicyDigest(t, "helper-policy-v1")
	client := expectedPolicyDigest(t, "client-policy-v1")
	if got := hex.EncodeToString(helper[:]); got != "702f1015d6dded7d0991d3275cb3f36d4ddab234d208a9b851369dc6d5fb7df6" {
		t.Fatalf("helper policy digest = %s", got)
	}
	if got := hex.EncodeToString(client[:]); got != "fc2b074212b3573e04be25d71be7dcdd49391a62cb898168bed5d305a68b35f3" {
		t.Fatalf("client policy digest = %s", got)
	}
}

func TestEncodeProcessDescriptorCanonicalVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		descriptor ProcessDescriptor
		wantHex    string
	}{
		{
			name:       "helper empty extension set",
			descriptor: canonicalDescriptor(t, ProcessRoleHelper, nil),
			wantHex:    "484c3844010100000000702f1015d6dded7d0991d3275cb3f36d4ddab234d208a9b851369dc6d5fb7df6",
		},
		{
			name:       "client ssh relay",
			descriptor: canonicalDescriptor(t, ProcessRoleClient, []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}),
			wantHex:    "484c3844010200000001fc2b074212b3573e04be25d71be7dcdd49391a62cb898168bed5d305a68b35f30c7373682d72656c61792d76310103000116",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := cloneProcessDescriptor(test.descriptor)
			encoded, err := EncodeProcessDescriptor(test.descriptor)
			if err != nil {
				t.Fatalf("EncodeProcessDescriptor() error = %v", err)
			}
			if got := hex.EncodeToString(encoded); got != test.wantHex {
				t.Fatalf("encoding = %s, want %s", got, test.wantHex)
			}
			if !reflect.DeepEqual(test.descriptor, before) {
				t.Fatal("encoding mutated its input")
			}

			decoded, err := DecodeProcessDescriptor(encoded)
			if err != nil {
				t.Fatalf("DecodeProcessDescriptor() error = %v", err)
			}
			if !processDescriptorsEqual(decoded, test.descriptor) {
				t.Fatalf("decoded = %#v, want %#v", decoded, test.descriptor)
			}
			reencoded, err := EncodeProcessDescriptor(decoded)
			if err != nil {
				t.Fatalf("re-encode error = %v", err)
			}
			if !bytes.Equal(reencoded, encoded) {
				t.Fatalf("re-encoding differs: %x != %x", reencoded, encoded)
			}
		})
	}
}

func TestProcessDescriptorCodecDefensivelyCopies(t *testing.T) {
	t.Parallel()

	descriptor := canonicalDescriptor(t, ProcessRoleHelper, []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()})
	want, err := EncodeProcessDescriptor(descriptor)
	if err != nil {
		t.Fatalf("EncodeProcessDescriptor() error = %v", err)
	}
	descriptor.Extensions[0].ID = "mutated-v1"
	descriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy

	decoded, err := DecodeProcessDescriptor(want)
	if err != nil {
		t.Fatalf("DecodeProcessDescriptor() error = %v", err)
	}
	wantDecoded := cloneProcessDescriptor(decoded)
	want[10] ^= 0xff
	if !reflect.DeepEqual(decoded, wantDecoded) {
		t.Fatal("decoded descriptor retained the encoded byte slice")
	}
	decoded.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	again, err := DecodeProcessDescriptor(mustDecodeHex(t, "484c3844010100000001702f1015d6dded7d0991d3275cb3f36d4ddab234d208a9b851369dc6d5fb7df60c7373682d72656c61792d76310103000116"))
	if err != nil {
		t.Fatalf("second DecodeProcessDescriptor() error = %v", err)
	}
	if again.Extensions[0].Modes[0] != credentialprotocol.DeliveryModeSSHAgent {
		t.Fatal("decoded descriptors share mutable catalog slices")
	}
}

func TestEncodeProcessDescriptorRejectsEveryNoncanonicalDimension(t *testing.T) {
	t.Parallel()

	canonical := canonicalDescriptor(t, ProcessRoleHelper, nil)
	ssh := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	modeOnly := credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}
	packetOnly := credentialprotocol.ExtensionDescriptor{ID: "zulu-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}

	tests := []struct {
		name       string
		descriptor ProcessDescriptor
		want       error
	}{
		{name: "missing contract", descriptor: replaceContract(canonical, ""), want: ErrProcessDescriptorContract},
		{name: "near contract", descriptor: replaceContract(canonical, ProcessDescriptorContractVersion+" "), want: ErrProcessDescriptorContract},
		{name: "zero role", descriptor: replaceRole(canonical, 0), want: ErrProcessDescriptorRole},
		{name: "unknown role", descriptor: replaceRole(canonical, 3), want: ErrProcessDescriptorRole},
		{name: "too many extensions", descriptor: replaceExtensions(canonical, make([]credentialprotocol.ExtensionDescriptor, credentialprotocol.MaxExtensions+1)), want: ErrProcessDescriptorExtensionCount},
		{name: "invalid extension", descriptor: replaceExtensions(canonical, []credentialprotocol.ExtensionDescriptor{{}}), want: credentialprotocol.ErrInvalidExtensionID},
		{name: "unordered extensions", descriptor: replaceExtensions(canonical, []credentialprotocol.ExtensionDescriptor{packetOnly, modeOnly}), want: credentialprotocol.ErrExtensionSetOrder},
		{name: "duplicate extension ID", descriptor: replaceExtensions(canonical, []credentialprotocol.ExtensionDescriptor{modeOnly, modeOnly}), want: credentialprotocol.ErrExtensionSetDuplicate},
		{name: "duplicate claim", descriptor: replaceExtensions(canonical, []credentialprotocol.ExtensionDescriptor{modeOnly, replaceExtensionID(modeOnly, "beta-v1")}), want: credentialprotocol.ErrExtensionSetDuplicateClaim},
		{name: "locked descriptor mismatch", descriptor: replaceExtensions(canonical, []credentialprotocol.ExtensionDescriptor{replaceExtensionModes(ssh, nil)}), want: credentialprotocol.ErrLockedExtensionDescriptor},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := cloneProcessDescriptor(test.descriptor)
			encoded, err := EncodeProcessDescriptor(test.descriptor)
			if encoded != nil {
				t.Fatalf("encoding = %x, want nil", encoded)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(test.descriptor, before) {
				t.Fatal("failed encoding mutated its input")
			}
		})
	}
}

func TestDecodeProcessDescriptorRejectsMalformedWire(t *testing.T) {
	t.Parallel()

	base, err := EncodeProcessDescriptor(canonicalDescriptor(t, ProcessRoleHelper, nil))
	if err != nil {
		t.Fatalf("EncodeProcessDescriptor() error = %v", err)
	}
	ssh, err := EncodeProcessDescriptor(canonicalDescriptor(t, ProcessRoleHelper, []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}))
	if err != nil {
		t.Fatalf("EncodeProcessDescriptor(ssh) error = %v", err)
	}

	withByte := func(input []byte, offset int, value byte) []byte {
		output := append([]byte(nil), input...)
		output[offset] = value
		return output
	}
	withCount := func(input []byte, offset int, value uint16) []byte {
		output := append([]byte(nil), input...)
		binary.BigEndian.PutUint16(output[offset:offset+2], value)
		return output
	}
	secondClaim := rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{
		{id: "zulu-v1", helperPackets: []byte{byte(credentialprotocol.PacketTypeSSHAcceptedFD)}},
		{id: "alpha-v1", modes: []byte{byte(credentialprotocol.DeliveryModeSSHAgent)}},
	})
	future := "future-v1"

	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{name: "nil", wire: nil, want: ErrProcessDescriptorTruncated},
		{name: "empty", wire: []byte{}, want: ErrProcessDescriptorTruncated},
		{name: "wrong magic", wire: withByte(base, 0, 'X'), want: ErrProcessDescriptorMagic},
		{name: "wrong version", wire: withByte(base, 4, 2), want: ErrProcessDescriptorWireVersion},
		{name: "zero role", wire: withByte(base, 5, 0), want: ErrProcessDescriptorRole},
		{name: "unknown role", wire: withByte(base, 5, 3), want: ErrProcessDescriptorRole},
		{name: "reserved high", wire: withByte(base, 6, 1), want: ErrProcessDescriptorReserved},
		{name: "reserved low", wire: withByte(base, 7, 1), want: ErrProcessDescriptorReserved},
		{name: "extension count overflow", wire: withCount(base, 8, credentialprotocol.MaxExtensions+1), want: ErrProcessDescriptorExtensionCount},
		{name: "missing extension body", wire: withCount(base, 8, 1), want: ErrProcessDescriptorTruncated},
		{name: "trailing byte", wire: append(append([]byte(nil), base...), 0), want: ErrProcessDescriptorTrailingData},
		{name: "ID length zero", wire: withByte(ssh, 42, 0), want: credentialprotocol.ErrInvalidExtensionID},
		{name: "ID length overflow", wire: withByte(ssh, 42, credentialprotocol.MaxExtensionIDBytes+1), want: credentialprotocol.ErrInvalidExtensionID},
		{name: "unsafe ID", wire: withByte(ssh, 43, '/'), want: credentialprotocol.ErrInvalidExtensionID},
		{name: "mode count overflow", wire: withByte(ssh, 55, credentialprotocol.MaxExtensionCatalogEntries+1), want: ErrProcessDescriptorCatalogCount},
		{name: "unknown mode", wire: withByte(ssh, 56, 4), want: credentialprotocol.ErrUnknownDeliveryMode},
		{name: "duplicate modes", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, modes: []byte{3, 3}}}), want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "unordered modes", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, modes: []byte{3, 2}}}), want: credentialprotocol.ErrExtensionCatalogOrder},
		{name: "reserved core mode", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, modes: []byte{1}}}), want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "agent packet count overflow", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: "future-v1", agentPackets: make([]byte, 17)}}), want: ErrProcessDescriptorCatalogCount},
		{name: "helper packet count overflow", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: "future-v1", helperPackets: make([]byte, 17)}}), want: ErrProcessDescriptorCatalogCount},
		{name: "unknown agent packet", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, agentPackets: []byte{0x06}}}), want: credentialprotocol.ErrUnknownPacketType},
		{name: "wrong extension packet direction", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, agentPackets: []byte{0x16}}}), want: credentialprotocol.ErrExtensionPacketDirection},
		{name: "unknown helper packet", wire: withByte(ssh, 59, 0x22), want: credentialprotocol.ErrUnknownPacketType},
		{name: "duplicate helper packets", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, helperPackets: []byte{0x16, 0x16}}}), want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "unordered helper packets", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, helperPackets: []byte{0x16, 0x15}}}), want: credentialprotocol.ErrExtensionCatalogOrder},
		{name: "reserved core packet", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future, helperPackets: []byte{0x20}}}), want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "empty extension claims", wire: rawDescriptorWire(t, ProcessRoleHelper, []rawExtension{{id: future}}), want: credentialprotocol.ErrEmptyExtensionDescriptor},
		{name: "unordered extension IDs", wire: secondClaim, want: credentialprotocol.ErrExtensionSetOrder},
	}

	for cut := 0; cut < len(base); cut++ {
		tests = append(tests, struct {
			name string
			wire []byte
			want error
		}{name: "truncated base " + decimal(cut), wire: append([]byte(nil), base[:cut]...), want: ErrProcessDescriptorTruncated})
	}
	for cut := 42; cut < len(ssh); cut++ {
		tests = append(tests, struct {
			name string
			wire []byte
			want error
		}{name: "truncated extension " + decimal(cut), wire: append([]byte(nil), ssh[:cut]...), want: ErrProcessDescriptorTruncated})
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := append([]byte(nil), test.wire...)
			decoded, err := DecodeProcessDescriptor(test.wire)
			if !reflect.DeepEqual(decoded, ProcessDescriptor{}) {
				t.Fatalf("decoded = %#v, want zero", decoded)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !bytes.Equal(test.wire, before) {
				t.Fatal("decoder mutated input bytes")
			}
		})
	}
}

func TestPolicyDigestMutationsRemainCanonicalButFailComposition(t *testing.T) {
	t.Parallel()

	helper := canonicalDescriptor(t, ProcessRoleHelper, nil)
	client := canonicalDescriptor(t, ProcessRoleClient, nil)
	for index := range helper.PolicySHA256 {
		mutated := cloneProcessDescriptor(helper)
		mutated.PolicySHA256[index] ^= 0x80
		encoded, err := EncodeProcessDescriptor(mutated)
		if err != nil {
			t.Fatalf("byte %d EncodeProcessDescriptor() error = %v", index, err)
		}
		decoded, err := DecodeProcessDescriptor(encoded)
		if err != nil {
			t.Fatalf("byte %d DecodeProcessDescriptor() error = %v", index, err)
		}
		if decoded.PolicySHA256 != mutated.PolicySHA256 {
			t.Fatalf("byte %d policy mutation did not round-trip", index)
		}
		if _, err := ValidateProcessDescriptors(decoded, client); !errors.Is(err, ErrProcessDescriptorPolicy) {
			t.Fatalf("byte %d validation error = %v, want ErrProcessDescriptorPolicy", index, err)
		}
	}
}

func TestDecodeProcessDescriptorRejectsOversizedInputWithoutAllocation(t *testing.T) {
	t.Parallel()

	wire := make([]byte, MaxProcessDescriptorBytes+1)
	copy(wire, "HL8D")
	wire[4] = 1
	wire[5] = byte(ProcessRoleHelper)
	if _, err := DecodeProcessDescriptor(wire); !errors.Is(err, ErrProcessDescriptorTooLarge) {
		t.Fatalf("error = %v, want ErrProcessDescriptorTooLarge", err)
	}
}

func TestValidateProcessDescriptorsCanonicalVector(t *testing.T) {
	t.Parallel()

	helper := canonicalDescriptor(t, ProcessRoleHelper, nil)
	client := canonicalDescriptor(t, ProcessRoleClient, []credentialprotocol.ExtensionDescriptor{})
	helperBefore := cloneProcessDescriptor(helper)
	clientBefore := cloneProcessDescriptor(client)

	composition, err := ValidateProcessDescriptors(helper, client)
	if err != nil {
		t.Fatalf("ValidateProcessDescriptors() error = %v", err)
	}
	if composition.ContractVersion != ProcessDescriptorContractVersion {
		t.Fatalf("contract version = %q", composition.ContractVersion)
	}
	if got := hex.EncodeToString(composition.HelperSHA256[:]); got != "b5a9ad966ddc0cbfd6d319f3347f6e6b0ab87ec22d0807a8bbe7f6e04f523837" {
		t.Fatalf("helper SHA-256 = %s", got)
	}
	if got := hex.EncodeToString(composition.ClientSHA256[:]); got != "3f68b4707bd49af6cb3db46ec577184bc16d34ecf9529e9ced75dca10291326b" {
		t.Fatalf("client SHA-256 = %s", got)
	}
	if got := hex.EncodeToString(composition.CompositionSHA256[:]); got != "cf1597a318a68ae7a35fdfccbac09e957d79856ca9dffcf391563ec97296b910" {
		t.Fatalf("composition SHA-256 = %s", got)
	}
	if !reflect.DeepEqual(helper, helperBefore) || !reflect.DeepEqual(client, clientBefore) {
		t.Fatal("validation mutated a process descriptor")
	}

	ssh := []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}
	if _, err := ValidateProcessDescriptors(
		canonicalDescriptor(t, ProcessRoleHelper, ssh),
		canonicalDescriptor(t, ProcessRoleClient, ssh),
	); err != nil {
		t.Fatalf("matching SSH extension descriptors error = %v", err)
	}
}

func TestValidateProcessDescriptorsRejectsRolePolicyAndExtensionMismatch(t *testing.T) {
	t.Parallel()

	helper := canonicalDescriptor(t, ProcessRoleHelper, nil)
	client := canonicalDescriptor(t, ProcessRoleClient, nil)
	wrongPolicy := helper.PolicySHA256
	wrongPolicy[0] ^= 1
	ssh := []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}

	tests := []struct {
		name   string
		helper ProcessDescriptor
		client ProcessDescriptor
		want   error
	}{
		{name: "arguments reversed", helper: client, client: helper, want: ErrProcessDescriptorRoleOrder},
		{name: "two helpers", helper: helper, client: helper, want: ErrProcessDescriptorRoleOrder},
		{name: "helper policy", helper: replacePolicy(helper, wrongPolicy), client: client, want: ErrProcessDescriptorPolicy},
		{name: "client policy", helper: helper, client: replacePolicy(client, wrongPolicy), want: ErrProcessDescriptorPolicy},
		{name: "helper extensions only", helper: replaceExtensions(helper, ssh), client: client, want: credentialprotocol.ErrExtensionSetMismatch},
		{name: "client extensions only", helper: helper, client: replaceExtensions(client, ssh), want: credentialprotocol.ErrExtensionSetMismatch},
		{name: "invalid helper descriptor", helper: replaceContract(helper, "bad"), client: client, want: ErrProcessDescriptorContract},
		{name: "invalid client descriptor", helper: helper, client: replaceContract(client, "bad"), want: ErrProcessDescriptorContract},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			beforeHelper := cloneProcessDescriptor(test.helper)
			beforeClient := cloneProcessDescriptor(test.client)
			composition, err := ValidateProcessDescriptors(test.helper, test.client)
			if composition != (CompositionDescriptor{}) {
				t.Fatalf("composition = %#v, want zero", composition)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(test.helper, beforeHelper) || !reflect.DeepEqual(test.client, beforeClient) {
				t.Fatal("failed validation mutated an input")
			}
		})
	}
}

func TestProcessDescriptorErrorsAreStableAndRedactionSafe(t *testing.T) {
	t.Parallel()

	seeded := ProcessDescriptor{
		ContractVersion: "token=secret-value /tmp/private.sock https://user:pass@example.test",
		Role:            ProcessRoleHelper,
		Extensions:      []credentialprotocol.ExtensionDescriptor{{ID: "unsafe/path"}},
	}
	_, err := EncodeProcessDescriptor(seeded)
	if !errors.Is(err, ErrProcessDescriptorContract) {
		t.Fatalf("error = %v", err)
	}
	for _, forbidden := range []string{"secret-value", "/tmp/private.sock", "example.test", "unsafe/path"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}

type rawExtension struct {
	id            string
	modes         []byte
	agentPackets  []byte
	helperPackets []byte
}

func rawDescriptorWire(t *testing.T, role ProcessRole, extensions []rawExtension) []byte {
	t.Helper()
	policyID := "helper-policy-v1"
	if role == ProcessRoleClient {
		policyID = "client-policy-v1"
	}
	digest := expectedPolicyDigest(t, policyID)
	wire := make([]byte, 0, MaxProcessDescriptorBytes)
	wire = append(wire, "HL8D"...)
	wire = append(wire, 1, byte(role), 0, 0, byte(len(extensions)>>8), byte(len(extensions)))
	wire = append(wire, digest[:]...)
	for _, extension := range extensions {
		wire = append(wire, byte(len(extension.id)))
		wire = append(wire, extension.id...)
		wire = append(wire, byte(len(extension.modes)))
		wire = append(wire, extension.modes...)
		wire = append(wire, byte(len(extension.agentPackets)))
		wire = append(wire, extension.agentPackets...)
		wire = append(wire, byte(len(extension.helperPackets)))
		wire = append(wire, extension.helperPackets...)
	}
	return wire
}

func canonicalDescriptor(t *testing.T, role ProcessRole, extensions []credentialprotocol.ExtensionDescriptor) ProcessDescriptor {
	t.Helper()
	policyID := "helper-policy-v1"
	if role == ProcessRoleClient {
		policyID = "client-policy-v1"
	}
	return ProcessDescriptor{
		ContractVersion: ProcessDescriptorContractVersion,
		Role:            role,
		Extensions:      credentialprotocol.CloneExtensionDescriptors(extensions),
		PolicySHA256:    expectedPolicyDigest(t, policyID),
	}
}

func expectedPolicyDigest(t *testing.T, policyID string) [32]byte {
	t.Helper()
	return sha256.Sum256(append(opaque16ForTest("hal/l8/process-policy/v1"), opaque16ForTest(policyID)...))
}

func opaque16ForTest(value string) []byte {
	result := make([]byte, 2, len(value)+2)
	binary.BigEndian.PutUint16(result, uint16(len(value)))
	return append(result, value...)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return decoded
}

func cloneProcessDescriptor(value ProcessDescriptor) ProcessDescriptor {
	value.Extensions = credentialprotocol.CloneExtensionDescriptors(value.Extensions)
	return value
}

func processDescriptorsEqual(left, right ProcessDescriptor) bool {
	if left.ContractVersion != right.ContractVersion || left.Role != right.Role || left.PolicySHA256 != right.PolicySHA256 || len(left.Extensions) != len(right.Extensions) {
		return false
	}
	for index := range left.Extensions {
		if !credentialprotocol.ExtensionDescriptorEqual(left.Extensions[index], right.Extensions[index]) {
			return false
		}
	}
	return true
}

func replaceContract(value ProcessDescriptor, contract string) ProcessDescriptor {
	value = cloneProcessDescriptor(value)
	value.ContractVersion = contract
	return value
}

func replaceRole(value ProcessDescriptor, role ProcessRole) ProcessDescriptor {
	value = cloneProcessDescriptor(value)
	value.Role = role
	return value
}

func replaceExtensions(value ProcessDescriptor, extensions []credentialprotocol.ExtensionDescriptor) ProcessDescriptor {
	value = cloneProcessDescriptor(value)
	value.Extensions = credentialprotocol.CloneExtensionDescriptors(extensions)
	return value
}

func replacePolicy(value ProcessDescriptor, digest [32]byte) ProcessDescriptor {
	value = cloneProcessDescriptor(value)
	value.PolicySHA256 = digest
	return value
}

func replaceExtensionID(value credentialprotocol.ExtensionDescriptor, id credentialprotocol.ExtensionID) credentialprotocol.ExtensionDescriptor {
	value = credentialprotocol.CloneExtensionDescriptor(value)
	value.ID = id
	return value
}

func replaceExtensionModes(value credentialprotocol.ExtensionDescriptor, modes []credentialprotocol.DeliveryMode) credentialprotocol.ExtensionDescriptor {
	value = credentialprotocol.CloneExtensionDescriptor(value)
	value.Modes = modes
	return value
}

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	var reversed [20]byte
	position := len(reversed)
	for value > 0 {
		position--
		reversed[position] = byte('0' + value%10)
		value /= 10
	}
	return string(reversed[position:])
}
