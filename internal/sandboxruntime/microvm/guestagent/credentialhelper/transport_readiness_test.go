package credentialhelper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestReceivedBootstrapStoresSharedCanonicalDigest(t *testing.T) {
	t.Parallel()

	const (
		agentPID = uint32(42)
		agentUID = uint32(998)
		agentGID = uint32(998)
	)
	bodyBytes := transportBootstrapBody(t, agentPID, agentUID, agentGID, "boot-1", "helper-1")
	header := transportHeader(credentialprotocol.PacketTypeBootstrap, 0, uint32(len(bodyBytes)))
	want, err := credentialprotocol.ComputeCanonicalHelperBootstrapSHA256(header, bodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewReceiveRequest(0, uint32(len(bodyBytes)), 1)
	if err != nil {
		t.Fatal(err)
	}
	body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("pidfd"))}}
	packet, err := NewReceivedBootstrapPacket(context.Background(), request, header, transportCredential(t), 1, body, 1, agentPID, agentUID, agentGID, "boot-1", "helper-1", right)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.Bootstrap()
	if !ok {
		t.Fatal("bootstrap arm absent")
	}
	if arm.bootstrapSHA256 != want || arm.bootstrapSHA256 == ([32]byte{}) {
		t.Fatalf("bootstrap digest = %x, want %x", arm.bootstrapSHA256, want)
	}
	assertBodyDestroyedAndWiped(t, body)
	if err := packet.right.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	badHeader := header
	badHeader.Sequence = 1
	badRequest, err := NewReceiveRequest(1, uint32(len(bodyBytes)), 1)
	if err != nil {
		t.Fatal(err)
	}
	badBody := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	badRight := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("bad-pidfd"))}}
	badPacket, err := NewReceivedBootstrapPacket(context.Background(), badRequest, badHeader, transportCredential(t), 1, badBody, 1, agentPID, agentUID, agentGID, "boot-1", "helper-1", badRight)
	if !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("noncanonical bootstrap sequence error = %v", err)
	}
	if !reflect.DeepEqual(badPacket, ReceivedPacket{}) {
		t.Fatal("invalid bootstrap returned an arm")
	}
	assertBodyDestroyedAndWiped(t, badBody)
	if !badRight.state.closed {
		t.Fatal("invalid bootstrap did not close its right")
	}
}

func TestReceivedExecObservationsMintOnlyAfterCanonicalValidation(t *testing.T) {
	t.Parallel()

	credential := transportCredential(t)
	privatePayload := []byte("private")
	privateDigest := sha256.Sum256(privatePayload)
	privateBytes := make([]byte, 44+len(privatePayload))
	binary.BigEndian.PutUint64(privateBytes[:8], 2)
	binary.BigEndian.PutUint32(privateBytes[8:12], uint32(len(privatePayload)))
	copy(privateBytes[12:44], privateDigest[:])
	copy(privateBytes[44:], privatePayload)
	privateRequest, err := NewReceiveRequest(2, uint32(len(privateBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	privateBody := newTransportTestBody(privateBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	privatePacket, err := NewReceivedExecPrivatePacket(context.Background(), privateRequest, transportJobHeader(credentialprotocol.PacketTypeExecPrivate, 2, uint32(len(privateBytes))), credential, 1, privateBody, 0, 2, uint32(len(privatePayload)), privateDigest)
	if err != nil {
		t.Fatal(err)
	}
	privateArm, ok := privatePacket.ExecPrivate()
	if !ok || reflect.DeepEqual(privateArm.observation, credentialprotocol.HelperExecPrivateObservation{}) {
		t.Fatal("canonical private input did not mint its opaque observation")
	}
	if err := privatePacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}

	streamPayload := []byte("stdin")
	streamDigest := sha256.Sum256(streamPayload)
	streamBytes := transportStreamBody(2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, streamPayload, streamDigest)
	streamRequest, err := NewReceiveRequest(2, uint32(len(streamBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	streamBody := newTransportTestBody(streamBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	streamPacket, err := NewReceivedExecStreamPacket(context.Background(), streamRequest, transportJobHeader(credentialprotocol.PacketTypeExecStream, 2, uint32(len(streamBytes))), credential, 1, streamBody, 0, 2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest)
	if err != nil {
		t.Fatal(err)
	}
	streamArm, ok := streamPacket.ExecStream()
	if !ok || reflect.DeepEqual(streamArm.observation, credentialprotocol.HelperExecStreamObservation{}) {
		t.Fatal("canonical stdin input did not mint its opaque observation")
	}
	if err := streamPacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}

	badPrivateBytes := append([]byte(nil), privateBytes...)
	badPrivateBytes[len(badPrivateBytes)-1] ^= 0xff
	badPrivateRequest, err := NewReceiveRequest(3, uint32(len(badPrivateBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	badPrivateBody := newTransportTestBody(badPrivateBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	badPrivatePacket, err := NewReceivedExecPrivatePacket(context.Background(), badPrivateRequest, transportJobHeader(credentialprotocol.PacketTypeExecPrivate, 3, uint32(len(badPrivateBytes))), credential, 1, badPrivateBody, 0, 2, uint32(len(privatePayload)), privateDigest)
	if !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("noncanonical private input error = %v", err)
	}
	if !reflect.DeepEqual(badPrivatePacket, ReceivedPacket{}) {
		t.Fatal("noncanonical private input returned an observation arm")
	}
	assertBodyDestroyedAndWiped(t, badPrivateBody)

	badStreamBytes := append([]byte(nil), streamBytes...)
	badStreamBytes[len(badStreamBytes)-1] ^= 0xff
	badStreamRequest, err := NewReceiveRequest(3, uint32(len(badStreamBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	badStreamBody := newTransportTestBody(badStreamBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	badStreamPacket, err := NewReceivedExecStreamPacket(context.Background(), badStreamRequest, transportJobHeader(credentialprotocol.PacketTypeExecStream, 3, uint32(len(badStreamBytes))), credential, 1, badStreamBody, 0, 2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest)
	if !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("noncanonical stdin input error = %v", err)
	}
	if !reflect.DeepEqual(badStreamPacket, ReceivedPacket{}) {
		t.Fatal("noncanonical stdin input returned an observation arm")
	}
	assertBodyDestroyedAndWiped(t, badStreamBody)
}
