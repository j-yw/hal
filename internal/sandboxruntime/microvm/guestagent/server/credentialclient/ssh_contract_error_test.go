package credentialclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestSSHShapeErrorsUseExactClientContractTaxonomy(t *testing.T) {
	t.Parallel()

	if _, err := NewSSHIOResult(credentialprotocol.SSHAgentMaxFrameBytes+1, false, false); true {
		assertSSHContractError(t, err, ErrSSHIOResult, ClientContractPacket, ClientFieldBody)
	}
	assertSSHContractError(t, ValidateSSHShutdownDirection(0), ErrSSHShutdownDirection, ClientContractPacket, ClientFieldLifecycle)
}

func TestSSHConstructorErrorsUseExactClientContractTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		packetType credentialprotocol.PacketType
		configure  func(*extensionPacketMetadata, *sshTestIssuer)
		absent     bool
		legacy     error
		code       ClientContractErrorCode
		field      ClientContractField
	}{
		{
			name:       "unknown packet type",
			packetType: 0,
			legacy:     credentialprotocol.ErrUnknownPacketType,
			code:       ClientContractPacket,
			field:      ClientFieldPacketType,
		},
		{
			name:       "known non-extension packet type",
			packetType: credentialprotocol.PacketTypeResponse,
			legacy:     ErrExtensionPacketType,
			code:       ClientContractPacket,
			field:      ClientFieldPacketType,
		},
		{
			name:       "missing identity",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.identityDigest = [32]byte{}
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractCorrelation,
			field:  ClientFieldIdentity,
		},
		{
			name:       "missing revision",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.revision = 0
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractCorrelation,
			field:  ClientFieldRevision,
		},
		{
			name:       "binding limit",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.bindingIndex = maxExtensionPacketBindings
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractLimit,
			field:  ClientFieldBody,
		},
		{
			name:       "missing ordinal",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.ordinal = 0
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractLimit,
			field:  ClientFieldBody,
		},
		{
			name:       "ordinal limit",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.ordinal = maxSSHConnectionOrdinal + 1
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractLimit,
			field:  ClientFieldBody,
		},
		{
			name:       "missing expected right digest",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(metadata *extensionPacketMetadata, _ *sshTestIssuer) {
				metadata.capabilitySHA256 = [32]byte{}
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractDescriptor,
			field:  ClientFieldRight,
		},
		{
			name:       "absent right",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			absent:     true,
			legacy:     ErrExtensionRightRequired,
			code:       ClientContractDependency,
			field:      ClientFieldRight,
		},
		{
			name:       "right digest panic",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(_ *extensionPacketMetadata, issuer *sshTestIssuer) {
				issuer.digestPanic = true
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractPanic,
			field:  ClientFieldRight,
		},
		{
			name:       "zero right digest",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(_ *extensionPacketMetadata, issuer *sshTestIssuer) {
				issuer.digest = [32]byte{}
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractDescriptor,
			field:  ClientFieldRight,
		},
		{
			name:       "mismatched right digest",
			packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
			configure: func(_ *extensionPacketMetadata, issuer *sshTestIssuer) {
				issuer.digest = [32]byte{0x62}
			},
			legacy: ErrExtensionPacketMetadata,
			code:   ClientContractDescriptor,
			field:  ClientFieldRight,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest := [32]byte{0x61}
			metadata := sshTestPacketMetadata(digest)
			issuer := &sshTestIssuer{digest: digest}
			if test.configure != nil {
				test.configure(&metadata, issuer)
			}
			capability := SSHConnectionCapability(issuer)
			if test.absent {
				capability = nil
			}
			packet, err := newExtensionPacket(test.packetType, metadata, capability)
			if packet != (ExtensionPacket{}) {
				t.Fatalf("newExtensionPacket() packet = %v, want zero", packet)
			}
			assertSSHContractError(t, err, test.legacy, test.code, test.field)
		})
	}
}

func TestSSHOwnershipFailuresUseExactClientContractTaxonomy(t *testing.T) {
	digest := [32]byte{0x63}
	packet := mustSSHTestPacket(t, digest, &sshTestIssuer{digest: digest})
	accepted, _ := packet.SSHAccepted()
	assertSSHContractError(t, accepted.WaitTransferred(nil), ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
	_, err := accepted.Connection().Read(context.Background(), sshTestSink{capacity: 1})
	assertSSHContractError(t, err, ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
	assertSSHContractError(t, accepted.Connection().Close(context.Background()), ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
	if err := commitExtensionPacketOwnership(packet); err != nil {
		t.Fatal(err)
	}
	assertSSHContractError(t, commitExtensionPacketOwnership(packet), ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
	assertSSHContractError(t, closeOwnedExtensionPacket(context.Background(), packet), ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
	if err := accepted.Connection().Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSSHDependencyFailuresAreSanitizedAsOwnershipContracts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		issuer *sshTestIssuer
		invoke func(SSHConnectionCapability) error
	}{
		{
			name:   "read error",
			issuer: &sshTestIssuer{digest: [32]byte{0x65}, readErr: errors.New("raw-read-error-secret")},
			invoke: func(connection SSHConnectionCapability) error {
				_, err := connection.Read(context.Background(), sshTestSink{capacity: 1})
				return err
			},
		},
		{
			name:   "close error",
			issuer: &sshTestIssuer{digest: [32]byte{0x65}, closeErr: errors.New("raw-close-error-secret")},
			invoke: func(connection SSHConnectionCapability) error {
				return connection.Close(context.Background())
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mustSSHTestPacket(t, [32]byte{0x65}, test.issuer)
			if err := commitExtensionPacketOwnership(packet); err != nil {
				t.Fatal(err)
			}
			accepted, _ := packet.SSHAccepted()
			err := test.invoke(accepted.Connection())
			assertSSHContractError(t, err, ErrExtensionPacketOwnership, ClientContractOwnership, ClientFieldLifecycle)
			for _, secret := range []string{"raw-read-error-secret", "raw-close-error-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("ownership error exposed dependency cause: %v", err)
				}
			}
		})
	}
}

func TestSSHRejectedCapabilityCleanupUsesExactClientContractTaxonomy(t *testing.T) {
	t.Parallel()

	for _, issuer := range []*sshTestIssuer{
		{digest: [32]byte{0x64}, closeErr: errors.New("raw-cleanup-error-secret")},
		{digest: [32]byte{0x64}, closePanic: true},
	} {
		metadata := sshTestPacketMetadata([32]byte{0x64})
		packet, err := newExtensionPacket(0, metadata, issuer)
		if packet != (ExtensionPacket{}) || !errors.Is(err, credentialprotocol.ErrUnknownPacketType) {
			t.Fatalf("newExtensionPacket() = (%v, %v), want primary protocol failure", packet, err)
		}
		if !hasSSHContractError(err, ClientContractPacket, ClientFieldPacketType) {
			t.Fatalf("constructor error lacks packet taxonomy: %v", err)
		}
		if !hasSSHContractError(err, ClientContractCleanup, ClientFieldRight) {
			t.Fatalf("constructor error lacks cleanup taxonomy: %v", err)
		}
		for _, secret := range []string{"raw-cleanup-error-secret", "raw-close-panic-secret"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("constructor error exposed cleanup cause: %v", err)
			}
		}
	}
}

func assertSSHContractError(t *testing.T, err, legacy error, code ClientContractErrorCode, field ClientContractField) {
	t.Helper()
	if !errors.Is(err, legacy) {
		t.Fatalf("error = %v, want errors.Is(%v)", err, legacy)
	}
	var contractError *ClientContractError
	if !errors.As(err, &contractError) {
		t.Fatalf("error = %v, want ClientContractError", err)
	}
	if contractError.Code() != code {
		t.Fatalf("contract code = %v, want %v", contractError.Code(), code)
	}
	gotField, ok := contractError.Field()
	if !ok || gotField != field {
		t.Fatalf("contract field = (%v, %t), want (%v, true)", gotField, ok, field)
	}
}

func hasSSHContractError(err error, code ClientContractErrorCode, field ClientContractField) bool {
	if err == nil {
		return false
	}
	if contractError, ok := err.(*ClientContractError); ok {
		gotField, hasField := contractError.Field()
		return contractError.Code() == code && hasField && gotField == field
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, nested := range joined.Unwrap() {
			if hasSSHContractError(nested, code, field) {
				return true
			}
		}
		return false
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return hasSSHContractError(wrapped.Unwrap(), code, field)
	}
	return false
}
