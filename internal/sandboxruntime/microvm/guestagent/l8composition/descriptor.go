// Package l8composition is the explicit L8 guest composition junction. This
// file owns only its pure, process-safe descriptor contract; live helper and
// client assembly is added by the later D6 slice.
package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	// ProcessDescriptorContractVersion is the in-memory projection of HL8D
	// wire version 1. The string is intentionally not encoded a second time.
	ProcessDescriptorContractVersion = "l8-process-composition-v1"

	// MaxProcessDescriptorBytes is the exact maximum size of one HL8D record.
	MaxProcessDescriptorBytes = 1898

	processDescriptorWireVersion   byte = 1
	processDescriptorHeaderBytes        = 42
	helperPolicyID                      = "helper-policy-v1"
	clientPolicyID                      = "client-policy-v1"
	processPolicyDigestDomain           = "hal/l8/process-policy/v1"
	processCompositionDigestDomain      = "hal/l8/process-composition/v1"
)

var (
	ErrProcessDescriptorContract       = errors.New("L8 process descriptor contract version is invalid")
	ErrProcessDescriptorMagic          = errors.New("L8 process descriptor magic is invalid")
	ErrProcessDescriptorWireVersion    = errors.New("L8 process descriptor wire version is invalid")
	ErrProcessDescriptorRole           = errors.New("L8 process descriptor role is invalid")
	ErrProcessDescriptorRoleOrder      = errors.New("L8 process descriptors are not helper then client")
	ErrProcessDescriptorReserved       = errors.New("L8 process descriptor reserved field is nonzero")
	ErrProcessDescriptorExtensionCount = errors.New("L8 process descriptor extension count exceeds its bound")
	ErrProcessDescriptorCatalogCount   = errors.New("L8 process descriptor catalog count exceeds its bound")
	ErrProcessDescriptorTooLarge       = errors.New("L8 process descriptor exceeds its size bound")
	ErrProcessDescriptorTruncated      = errors.New("L8 process descriptor is truncated")
	ErrProcessDescriptorTrailingData   = errors.New("L8 process descriptor has trailing data")
	ErrProcessDescriptorPolicy         = errors.New("L8 process descriptor policy digest is invalid")
)

// ProcessRole is the closed process role catalog in an HL8D descriptor.
type ProcessRole uint8

const (
	ProcessRoleHelper ProcessRole = 1
	ProcessRoleClient ProcessRole = 2
)

// ProcessDescriptor attests one process-local policy and immutable extension
// set. It is a non-JSON, data-only value.
type ProcessDescriptor struct {
	ContractVersion string
	Role            ProcessRole
	Extensions      []credentialprotocol.ExtensionDescriptor
	PolicySHA256    [32]byte
}

// CompositionDescriptor binds the canonical helper and client records. It is
// a non-JSON, data-only value.
type CompositionDescriptor struct {
	ContractVersion   string
	HelperSHA256      [32]byte
	ClientSHA256      [32]byte
	CompositionSHA256 [32]byte
}

// EncodeProcessDescriptor returns the sole canonical HL8D wire form. It does
// not normalize, sort, default, or retain caller-owned slices.
func EncodeProcessDescriptor(descriptor ProcessDescriptor) ([]byte, error) {
	if err := validateProcessDescriptor(descriptor); err != nil {
		return nil, err
	}

	size := processDescriptorHeaderBytes
	for _, extension := range descriptor.Extensions {
		size += 1 + len(extension.ID)
		size += 1 + len(extension.Modes)
		size += 1 + len(extension.AgentToHelperPacketTypes)
		size += 1 + len(extension.HelperToAgentPacketTypes)
	}
	if size > MaxProcessDescriptorBytes {
		return nil, ErrProcessDescriptorTooLarge
	}

	encoded := make([]byte, 0, size)
	encoded = append(encoded, 'H', 'L', '8', 'D')
	encoded = append(encoded, processDescriptorWireVersion, byte(descriptor.Role), 0, 0)
	encoded = appendUint16(encoded, uint16(len(descriptor.Extensions)))
	encoded = append(encoded, descriptor.PolicySHA256[:]...)
	for _, extension := range descriptor.Extensions {
		encoded = append(encoded, byte(len(extension.ID)))
		encoded = append(encoded, string(extension.ID)...)
		encoded = appendCatalog(encoded, extension.Modes)
		encoded = appendCatalog(encoded, extension.AgentToHelperPacketTypes)
		encoded = appendCatalog(encoded, extension.HelperToAgentPacketTypes)
	}
	return encoded, nil
}

// DecodeProcessDescriptor accepts only one complete canonical HL8D wire
// record. Returned extension data never aliases the input.
func DecodeProcessDescriptor(encoded []byte) (ProcessDescriptor, error) {
	if len(encoded) > MaxProcessDescriptorBytes {
		return ProcessDescriptor{}, ErrProcessDescriptorTooLarge
	}
	if len(encoded) < processDescriptorHeaderBytes {
		return ProcessDescriptor{}, ErrProcessDescriptorTruncated
	}
	if !bytes.Equal(encoded[:4], []byte("HL8D")) {
		return ProcessDescriptor{}, ErrProcessDescriptorMagic
	}
	if encoded[4] != processDescriptorWireVersion {
		return ProcessDescriptor{}, ErrProcessDescriptorWireVersion
	}
	role := ProcessRole(encoded[5])
	if !validProcessRole(role) {
		return ProcessDescriptor{}, ErrProcessDescriptorRole
	}
	if encoded[6] != 0 || encoded[7] != 0 {
		return ProcessDescriptor{}, ErrProcessDescriptorReserved
	}
	extensionCount := int(binary.BigEndian.Uint16(encoded[8:10]))
	if extensionCount > credentialprotocol.MaxExtensions {
		return ProcessDescriptor{}, ErrProcessDescriptorExtensionCount
	}

	descriptor := ProcessDescriptor{
		ContractVersion: ProcessDescriptorContractVersion,
		Role:            role,
	}
	copy(descriptor.PolicySHA256[:], encoded[10:processDescriptorHeaderBytes])
	if extensionCount > 0 {
		descriptor.Extensions = make([]credentialprotocol.ExtensionDescriptor, extensionCount)
	}
	offset := processDescriptorHeaderBytes
	for index := 0; index < extensionCount; index++ {
		idLength, next, err := decodeBoundedCount(encoded, offset, credentialprotocol.MaxExtensionIDBytes, credentialprotocol.ErrInvalidExtensionID)
		if err != nil {
			return ProcessDescriptor{}, err
		}
		offset = next
		if idLength == 0 {
			return ProcessDescriptor{}, credentialprotocol.ErrInvalidExtensionID
		}
		idBytes, next, err := decodeBytes(encoded, offset, idLength)
		if err != nil {
			return ProcessDescriptor{}, err
		}
		offset = next

		modes, next, err := decodeCatalog[credentialprotocol.DeliveryMode](encoded, offset)
		if err != nil {
			return ProcessDescriptor{}, err
		}
		offset = next
		agentPackets, next, err := decodeCatalog[credentialprotocol.PacketType](encoded, offset)
		if err != nil {
			return ProcessDescriptor{}, err
		}
		offset = next
		helperPackets, next, err := decodeCatalog[credentialprotocol.PacketType](encoded, offset)
		if err != nil {
			return ProcessDescriptor{}, err
		}
		offset = next

		descriptor.Extensions[index] = credentialprotocol.ExtensionDescriptor{
			ID:                       credentialprotocol.ExtensionID(string(idBytes)),
			Modes:                    modes,
			AgentToHelperPacketTypes: agentPackets,
			HelperToAgentPacketTypes: helperPackets,
		}
	}
	if offset != len(encoded) {
		return ProcessDescriptor{}, ErrProcessDescriptorTrailingData
	}
	if err := validateProcessDescriptor(descriptor); err != nil {
		return ProcessDescriptor{}, err
	}
	return cloneDecodedProcessDescriptor(descriptor), nil
}

// ValidateProcessDescriptors validates helper then client, requires their
// process-specific policy digests and matching canonical extension sets, and
// returns the exact composition digest.
func ValidateProcessDescriptors(helper, client ProcessDescriptor) (CompositionDescriptor, error) {
	if helper.Role != ProcessRoleHelper || client.Role != ProcessRoleClient {
		return CompositionDescriptor{}, ErrProcessDescriptorRoleOrder
	}
	helperEncoding, err := EncodeProcessDescriptor(helper)
	if err != nil {
		return CompositionDescriptor{}, err
	}
	clientEncoding, err := EncodeProcessDescriptor(client)
	if err != nil {
		return CompositionDescriptor{}, err
	}
	if helper.PolicySHA256 != processPolicyDigest(helperPolicyID) || client.PolicySHA256 != processPolicyDigest(clientPolicyID) {
		return CompositionDescriptor{}, ErrProcessDescriptorPolicy
	}
	if err := credentialprotocol.ValidateMatchingExtensionSets(helper.Extensions, client.Extensions); err != nil {
		return CompositionDescriptor{}, err
	}

	helperDigest := sha256.Sum256(helperEncoding)
	clientDigest := sha256.Sum256(clientEncoding)
	compositionInput := opaque16(processCompositionDigestDomain)
	compositionInput = append(compositionInput, helperDigest[:]...)
	compositionInput = append(compositionInput, clientDigest[:]...)
	return CompositionDescriptor{
		ContractVersion:   ProcessDescriptorContractVersion,
		HelperSHA256:      helperDigest,
		ClientSHA256:      clientDigest,
		CompositionSHA256: sha256.Sum256(compositionInput),
	}, nil
}

func validateProcessDescriptor(descriptor ProcessDescriptor) error {
	if descriptor.ContractVersion != ProcessDescriptorContractVersion {
		return ErrProcessDescriptorContract
	}
	if !validProcessRole(descriptor.Role) {
		return ErrProcessDescriptorRole
	}
	if len(descriptor.Extensions) > credentialprotocol.MaxExtensions {
		return ErrProcessDescriptorExtensionCount
	}
	return credentialprotocol.ValidateMatchingExtensionSets(descriptor.Extensions, descriptor.Extensions)
}

func validProcessRole(role ProcessRole) bool {
	return role == ProcessRoleHelper || role == ProcessRoleClient
}

func processPolicyDigest(policyID string) [32]byte {
	input := opaque16(processPolicyDigestDomain)
	input = append(input, opaque16(policyID)...)
	return sha256.Sum256(input)
}

func opaque16(value string) []byte {
	encoded := make([]byte, 2, len(value)+2)
	binary.BigEndian.PutUint16(encoded, uint16(len(value)))
	return append(encoded, value...)
}

func appendUint16(output []byte, value uint16) []byte {
	return append(output, byte(value>>8), byte(value))
}

func appendCatalog[T ~uint8](output []byte, values []T) []byte {
	output = append(output, byte(len(values)))
	for _, value := range values {
		output = append(output, byte(value))
	}
	return output
}

func decodeBoundedCount(encoded []byte, offset, maximum int, overflow error) (int, int, error) {
	if offset >= len(encoded) {
		return 0, offset, ErrProcessDescriptorTruncated
	}
	count := int(encoded[offset])
	if count > maximum {
		return 0, offset, overflow
	}
	return count, offset + 1, nil
}

func decodeBytes(encoded []byte, offset, count int) ([]byte, int, error) {
	if count > len(encoded)-offset {
		return nil, offset, ErrProcessDescriptorTruncated
	}
	result := append([]byte(nil), encoded[offset:offset+count]...)
	return result, offset + count, nil
}

func decodeCatalog[T ~uint8](encoded []byte, offset int) ([]T, int, error) {
	count, offset, err := decodeBoundedCount(encoded, offset, credentialprotocol.MaxExtensionCatalogEntries, ErrProcessDescriptorCatalogCount)
	if err != nil {
		return nil, offset, err
	}
	values, offset, err := decodeBytes(encoded, offset, count)
	if err != nil {
		return nil, offset, err
	}
	if count == 0 {
		return nil, offset, nil
	}
	result := make([]T, count)
	for index, value := range values {
		result[index] = T(value)
	}
	return result, offset, nil
}

func cloneDecodedProcessDescriptor(descriptor ProcessDescriptor) ProcessDescriptor {
	descriptor.Extensions = credentialprotocol.CloneExtensionDescriptors(descriptor.Extensions)
	return descriptor
}
