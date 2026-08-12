package credentialhelper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var _ func(
	ReceiveRequest,
	credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential,
	uint32,
	ReceivedBodyCapability,
	uint32,
	[32]byte,
	credentialprotocol.SafeID,
	credentialprotocol.SafeID,
	[32]byte,
) (ReceivedPacket, error) = NewReceivedAgentHelloPacket

type transportTestView struct{ value []byte }

func (view transportTestView) Len() int { return len(view.value) }
func (transportTestView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}
func (view transportTestView) WriteTo(_ context.Context, sink credentialmemory.CredentialSink) error {
	return sink.WriteCredential(view.value)
}

type transportTestBodyState struct {
	mu        sync.Mutex
	region    []byte
	length    int
	borrows   int
	destroyed bool
}

type transportTestBody struct{ state *transportTestBodyState }

func newTransportTestBody(body []byte, capacity int) transportTestBody {
	region := make([]byte, capacity)
	copy(region, body)
	return transportTestBody{state: &transportTestBodyState{region: region, length: len(body)}}
}

func (body transportTestBody) Len() uint32 {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if body.state.destroyed {
		return 0
	}
	return uint32(body.state.length)
}

func (body transportTestBody) SHA256() [32]byte {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if body.state.destroyed {
		return [32]byte{}
	}
	return sha256.Sum256(body.state.region[:body.state.length])
}

type transportTestLyingBody struct{ transportTestBody }

func (body transportTestLyingBody) SHA256() [32]byte { return sha256.Sum256([]byte("not the body")) }

func (body transportTestBody) Borrow(_ context.Context, callback func(credentialmemory.BorrowedView) error) error {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if body.state.destroyed {
		return ErrContractDestroyed
	}
	body.state.borrows++
	return callback(transportTestView{value: body.state.region[:body.state.length]})
}

func (body transportTestBody) Destroy(context.Context) error {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if body.state.destroyed {
		return ErrContractDestroyed
	}
	clear(body.state.region)
	body.state.length = 0
	body.state.destroyed = true
	return nil
}

type transportTestRightState struct {
	mu     sync.Mutex
	kind   ReceivedCapabilityKind
	digest [32]byte
	closed bool
}

type transportTestRight struct{ state *transportTestRightState }

func (right transportTestRight) Kind() ReceivedCapabilityKind { return right.state.kind }
func (right transportTestRight) SHA256() [32]byte             { return right.state.digest }
func (right transportTestRight) Close(context.Context) error {
	right.state.mu.Lock()
	defer right.state.mu.Unlock()
	if right.state.closed {
		return ErrContractDestroyed
	}
	right.state.closed = true
	return nil
}

func TestReceiveRequestBoundsAndSharedOneShotOwnership(t *testing.T) {
	for _, tc := range []struct {
		sequence uint64
		body     uint32
		rights   uint32
		wantErr  error
	}{
		{sequence: 1, body: 0, rights: 0},
		{sequence: math.MaxUint32, body: credentialprotocol.MaxHelperPacketBodyBytes, rights: 1},
		{sequence: 0, body: 1, rights: 0},
		{sequence: math.MaxUint32 + 1, body: 1, rights: 0, wantErr: ErrContractInvalidArgument},
		{sequence: 1, body: credentialprotocol.MaxHelperPacketBodyBytes + 1, rights: 0, wantErr: ErrContractInvalidArgument},
		{sequence: 1, body: 1, rights: 2, wantErr: ErrContractInvalidArgument},
	} {
		request, err := NewReceiveRequest(tc.sequence, tc.body, tc.rights)
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("NewReceiveRequest(%d,%d,%d) error = %v, want %v", tc.sequence, tc.body, tc.rights, err, tc.wantErr)
		}
		if tc.wantErr == nil && (request.NextSequence() != tc.sequence || request.MaximumBodyBytes() != tc.body || request.ExpectedRights() != tc.rights) {
			t.Fatalf("receive request accessors = %d/%d/%d", request.NextSequence(), request.MaximumBodyBytes(), request.ExpectedRights())
		}
		if tc.wantErr != nil && request != (ReceiveRequest{}) {
			t.Fatal("invalid receive request returned nonzero value")
		}
	}

	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	copyRequest := request
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, uint32(body.Len()))
	packet, err := NewReceivedCloseNotifyPacket(request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil || packet.Type() != credentialprotocol.PacketTypeCloseNotify {
		t.Fatalf("first seal = %#v, %v", packet, err)
	}
	secondBody := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	if _, err := NewReceivedCloseNotifyPacket(copyRequest, header, transportCredential(t), 1, secondBody, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("copied request reuse error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, secondBody)
}

func TestReceivedKernelCredentialBoundsAndOpacity(t *testing.T) {
	for _, pid := range []uint32{1, math.MaxInt32} {
		credential, err := NewReceivedKernelCredential(pid, 0, math.MaxUint32)
		if err != nil {
			t.Fatalf("pid %d: %v", pid, err)
		}
		assertLiveOpaque(t, credential)
	}
	for _, pid := range []uint32{0, math.MaxInt32 + 1, math.MaxUint32} {
		credential, err := NewReceivedKernelCredential(pid, 0, 0)
		if !errors.Is(err, ErrContractInvalidArgument) || credential != (ReceivedKernelCredential{}) {
			t.Fatalf("pid %d = %#v, %v", pid, credential, err)
		}
	}
}

func TestReceivedCloseNotifyCorrelationAndFullCapacityCleanup(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 128)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 8, 1)
	packet, err := NewReceivedCloseNotifyPacket(request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractCorrelation) || packet != (ReceivedPacket{}) {
		t.Fatalf("sequence mismatch = %#v, %v", packet, err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestReceivedPacketRejectsBodyCapabilityDigestDrift(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 128)
	lying := transportTestLyingBody{transportTestBody: body}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 7, 1)
	packet, err := NewReceivedCloseNotifyPacket(request, header, transportCredential(t), 1, lying, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractCorrelation) || packet != (ReceivedPacket{}) {
		t.Fatalf("body digest drift = %#v, %v", packet, err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestMalformedConstructorStillConsumesReceiveOwnership(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 7, 1)
	if _, err := NewReceivedCloseNotifyPacket(request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{}); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("malformed close error = %v", err)
	}
	secondBody := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	if _, err := NewReceivedCloseNotifyPacket(request, header, transportCredential(t), 1, secondBody, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("malformed request reuse error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, secondBody)
}

func TestReceivedPrepareBeginUsesCanonicalCodecAndTypedArm(t *testing.T) {
	digest := sha256.Sum256([]byte("file"))
	decoded := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 99, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "binding-1", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "secret/file", DeclaredFileBytes: 4, FileSHA256: digest}}}
	encoded, err := credentialprotocol.EncodeHelperPrepareBeginBody(decoded)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifestCapability(decoded.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypePrepareBegin, 2, uint32(len(encoded)))
	packet, err := NewReceivedPrepareBeginPacket(request, header, transportCredential(t), 1, body, 0, decoded, manifest)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.PrepareBegin()
	if !ok || arm.Revision() != 1 || arm.ExpiryUnixNano() != 99 || arm.Manifest().SHA256() != manifest.SHA256() {
		t.Fatalf("prepare arm = %#v, %v", arm, ok)
	}
	if _, ok := packet.Exec(); ok {
		t.Fatal("wrong typed arm matched")
	}
	if packet.Header() != header {
		t.Fatal("header accessor changed header")
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestReceivedSensitivePacketRetainsBodyAndRejectsDigestMismatch(t *testing.T) {
	payload := []byte("secret")
	digest := sha256.Sum256(payload)
	bodyBytes := make([]byte, 46+len(payload))
	bodyBytes[7] = 1
	bodyBytes[9] = 1
	bodyBytes[13] = byte(len(payload))
	copy(bodyBytes[14:46], digest[:])
	copy(bodyBytes[46:], payload)
	request, _ := NewReceiveRequest(2, uint32(len(bodyBytes)), 0)
	body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypePrepareFile, 2, uint32(len(bodyBytes)))
	packet, err := NewReceivedPrepareFilePacket(request, header, transportCredential(t), 1, body, 0, 1, 1, uint32(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.PrepareFile()
	if !ok || arm.Revision() != 1 || arm.BindingIndex() != 1 || arm.FileLength() != uint32(len(payload)) || arm.FileSHA256() != digest {
		t.Fatalf("file arm = %#v, %v", arm, ok)
	}
	if body.state.destroyed {
		t.Fatal("sensitive body destroyed before service ownership")
	}
	if packet.body.Len() != uint32(len(payload)) || packet.body.SHA256() != digest {
		t.Fatalf("private retained payload body = %d/%x", packet.body.Len(), packet.body.SHA256())
	}
	body.state.mu.Lock()
	if !reflect.DeepEqual(body.state.region[:body.state.length], bodyBytes) {
		body.state.mu.Unlock()
		t.Fatal("retained transport owner no longer holds the full canonical body")
	}
	payloadAddress := reflect.ValueOf(body.state.region[46 : 46+len(payload)]).Pointer()
	body.state.mu.Unlock()
	borrowCalls := 0
	err = packet.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		borrowCalls++
		if view.Len() != len(payload) {
			t.Fatalf("borrowed payload length = %d, want %d", view.Len(), len(payload))
		}
		sink := &transportSubviewTestSink{maximum: len(payload), want: payload, wantAddress: payloadAddress}
		if writeErr := view.WriteTo(context.Background(), sink); writeErr != nil {
			return writeErr
		}
		if !sink.called || !sink.sameBacking {
			t.Fatal("service payload subview copied or did not synchronously write")
		}
		return nil
	})
	if err != nil || borrowCalls != 1 {
		t.Fatalf("borrow retained payload = %v, calls %d", err, borrowCalls)
	}

	badRequest, _ := NewReceiveRequest(3, uint32(len(bodyBytes)), 0)
	badBody := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	badDigest := sha256.Sum256([]byte("changed"))
	if _, err := NewReceivedPrepareFilePacket(badRequest, transportJobHeader(credentialprotocol.PacketTypePrepareFile, 3, uint32(len(bodyBytes))), transportCredential(t), 1, badBody, 0, 1, 1, uint32(len(payload)), badDigest); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("private digest mismatch = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

func TestReceivedBootstrapRightOwnershipAndTypedNil(t *testing.T) {
	bodyBytes := transportBootstrapBody(t, 42, 998, 998, "boot-1", "helper-1")
	header := transportHeader(credentialprotocol.PacketTypeBootstrap, 1, uint32(len(bodyBytes)))
	request, _ := NewReceiveRequest(1, uint32(len(bodyBytes)), 1)
	body := newTransportTestBody(bodyBytes, 256)
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("pidfd"))}}
	packet, err := NewReceivedBootstrapPacket(request, header, transportCredential(t), 1, body, 1, 42, 998, 998, "boot-1", "helper-1", right)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.Bootstrap()
	if !ok || arm.BootGeneration() != "boot-1" || arm.HelperGeneration() != "helper-1" || arm.AgentIdentitySHA256() == ([32]byte{}) {
		t.Fatalf("bootstrap arm = %#v, %v", arm, ok)
	}
	if right.state.closed {
		t.Fatal("right closed after successful transfer")
	}
	assertBodyDestroyedAndWiped(t, body)

	badRequest, _ := NewReceiveRequest(2, uint32(len(bodyBytes)), 1)
	badBody := newTransportTestBody(bodyBytes, 256)
	var nilRight *transportTestRight
	if _, err := NewReceivedBootstrapPacket(badRequest, transportHeader(credentialprotocol.PacketTypeBootstrap, 2, uint32(len(bodyBytes))), transportCredential(t), 1, badBody, 1, 42, 998, 998, "boot-1", "helper-1", nilRight); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed-nil right = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

type transportTestSink struct {
	maximum int
	value   []byte
	err     error
}

type transportSubviewTestSink struct {
	maximum     int
	want        []byte
	wantAddress uintptr
	called      bool
	sameBacking bool
}

func (sink *transportSubviewTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportSubviewTestSink) WriteCredential(value []byte) error {
	sink.called = true
	sink.sameBacking = len(value) > 0 && reflect.ValueOf(value).Pointer() == sink.wantAddress
	if !reflect.DeepEqual(value, sink.want) {
		return errors.New("unexpected payload subview")
	}
	return nil
}

type transportRetainingTestSink struct {
	maximum int
	alias   []byte
	copy    []byte
	err     error
}

type transportTrackingSendArm struct{ encoded []byte }

func (transportTrackingSendArm) sendPacketArm() {}
func (arm transportTrackingSendArm) encodeCanonical() ([]byte, error) {
	return arm.encoded, nil
}

type transportFailingSendArm struct{ encoded []byte }

func (transportFailingSendArm) sendPacketArm() {}
func (arm transportFailingSendArm) encodeCanonical() ([]byte, error) {
	return arm.encoded, errors.New("encode failed")
}

func (sink *transportRetainingTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportRetainingTestSink) WriteCredential(value []byte) error {
	sink.alias = value
	sink.copy = append(sink.copy[:0], value...)
	return sink.err
}

func (sink *transportTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportTestSink) WriteCredential(value []byte) error {
	if sink.err != nil {
		return sink.err
	}
	sink.value = append(sink.value[:0], value...)
	return nil
}

func TestSendPacketClosedAccessorsAndSynchronousCopy(t *testing.T) {
	body := credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}
	encoded, err := credentialprotocol.EncodeHelperCloseNotifyBody(body)
	if err != nil {
		t.Fatal(err)
	}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, uint32(len(encoded)))
	packet, err := newCloseNotifyPacket(header, body)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Type() != credentialprotocol.PacketTypeCloseNotify || packet.Header() != header || packet.EncodedBodyLength() != 1 || packet.BodySHA256() != sha256.Sum256(encoded) || packet.RightsCount() != 0 || packet.Right() != nil {
		t.Fatalf("send accessors = %#v", packet)
	}
	sink := &transportTestSink{maximum: 1}
	if err := packet.WriteCanonicalBody(sink); err != nil || !reflect.DeepEqual(sink.value, encoded) {
		t.Fatalf("WriteCanonicalBody = %x, %v", sink.value, err)
	}
	encoded[0] = 0xff
	if sink.value[0] != byte(credentialprotocol.CloseReasonNormal) {
		t.Fatal("sink output aliased caller bytes")
	}
	typedNilPacket, err := newCloseNotifyPacket(header, body)
	if err != nil {
		t.Fatal(err)
	}
	var nilSink *transportTestSink
	if err := typedNilPacket.WriteCanonicalBody(nilSink); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed-nil sink error = %v", err)
	}
	if err := typedNilPacket.WriteCanonicalBody(&transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("typed-nil write did not consume packet ownership: %v", err)
	}
}

func TestSendPacketWipesSafeEncodingAfterSynchronousWrite(t *testing.T) {
	body := credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}
	packet, err := newCloseNotifyPacket(transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), body)
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportRetainingTestSink{maximum: 1}
	if err := packet.WriteCanonicalBody(sink); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sink.copy, []byte{byte(credentialprotocol.CloseReasonNormal)}) {
		t.Fatalf("synchronous safe encoding = %x", sink.copy)
	}
	if len(sink.alias) != 1 || !allZeroBytes(sink.alias[:cap(sink.alias)]) {
		t.Fatalf("safe encoding retained after write = %x", sink.alias)
	}
}

func TestSendPacketWipesSafeEncodingAndConsumesOwnershipOnSinkError(t *testing.T) {
	packet, err := newCloseNotifyPacket(transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportRetainingTestSink{maximum: 1, err: errors.New("sink failed")}
	if err := packet.WriteCanonicalBody(sink); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("sink write error = %v", err)
	}
	if len(sink.alias) != 1 || !allZeroBytes(sink.alias[:cap(sink.alias)]) {
		t.Fatalf("failed safe encoding retained after write = %x", sink.alias)
	}
	if err := packet.WriteCanonicalBody(&transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("failed write did not consume packet ownership: %v", err)
	}
}

func TestSendPacketWipesSafeEncodingAfterConstruction(t *testing.T) {
	encoded := make([]byte, 1, 64)
	encoded[0] = byte(credentialprotocol.CloseReasonNormal)
	arm := transportTrackingSendArm{encoded: encoded}
	_, err := newSendPacket(transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), arm, nil)
	if !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("test-only unknown safe arm error = %v", err)
	}
	if !allZeroBytes(encoded[:cap(encoded)]) {
		t.Fatalf("safe encoding retained after construction = %x", encoded)
	}

	failed := make([]byte, 1, 64)
	for index := range failed[:cap(failed)] {
		failed[:cap(failed)][index] = 0xff
	}
	if _, err := newSendPacket(transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), transportFailingSendArm{encoded: failed}, nil); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("failing safe arm error = %v", err)
	}
	if !allZeroBytes(failed[:cap(failed)]) {
		t.Fatal("failed constructor did not wipe scratch through capacity")
	}
}

func TestSendPacketSnapshotsSafeArmBeforeTransportOwnership(t *testing.T) {
	body := credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypePrepareCommit,
		Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision:    1,
		Prepare: &credentialprotocol.HelperPrepareResponseResult{
			ExpiresAtUnixNano: 1,
			ActiveProofID:     "active",
			ExecBindingID:     "exec",
			BindingProofs: []credentialprotocol.HelperBindingProof{{
				BindingID: "binding",
				Mode:      credentialprotocol.DeliveryModeHTTPProxy,
				ProofID:   "proof",
			}},
		},
	}
	canonical, err := credentialprotocol.EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := newResponsePacket(transportJobHeader(credentialprotocol.PacketTypeResponse, 9, uint32(len(canonical))), body)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(canonical)
	body.Prepare.BindingProofs[0].ProofID = "other"
	if got := packet.BodySHA256(); got != wantDigest {
		t.Fatalf("caller alias mutation changed sealed send digest: got %x, want %x", got, wantDigest)
	}
	sink := &transportTestSink{maximum: len(canonical)}
	if err := packet.WriteCanonicalBody(sink); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sink.value, canonical) {
		t.Fatalf("caller alias mutation changed sealed send body: got %x, want %x", sink.value, canonical)
	}
}

func TestSendPacketDeepSnapshotsEveryResponseResultArm(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	tests := []struct {
		name   string
		body   credentialprotocol.HelperResponseBody
		mutate func()
	}{
		{
			name: "prepare",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypePrepareCommit, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Prepare: &credentialprotocol.HelperPrepareResponseResult{
				ExpiresAtUnixNano: 1, ActiveProofID: "active", ExecBindingID: "exec", BindingProofs: []credentialprotocol.HelperBindingProof{{BindingID: "binding", Mode: credentialprotocol.DeliveryModeHTTPProxy, ProofID: "proof"}},
			}},
		},
		{
			name: "renew",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeRenew, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Renew: &credentialprotocol.HelperRenewResponseResult{ExpiresAtUnixNano: 1, ReplacementActiveProofID: "replacement"}},
		},
		{
			name: "revoke",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeRevoke, Disposition: credentialprotocol.ResponseDispositionCleanupComplete, Revision: 1, Revoke: &credentialprotocol.HelperRevokeResponseResult{CleanupProofID: "cleanup", AuthorityAbsent: true, ResourcesAbsent: true}},
		},
		{
			name: "exec",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeExec, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Exec: &credentialprotocol.HelperExecResponseResult{ExitCode: 1, StdinBytes: 1, StdinSHA256: digest, StdoutBytes: 1, StdoutSHA256: digest, StderrBytes: 1, StderrSHA256: digest, ExecTransactionSHA256: digest}},
		},
	}
	for index := range tests {
		test := &tests[index]
		switch test.name {
		case "prepare":
			test.mutate = func() {
				test.body.Prepare.ActiveProofID = "changed"
				test.body.Prepare.BindingProofs[0].ProofID = "changed"
			}
		case "renew":
			test.mutate = func() { test.body.Renew.ReplacementActiveProofID = "changed" }
		case "revoke":
			test.mutate = func() { test.body.Revoke.CleanupProofID = "changed" }
		case "exec":
			test.mutate = func() { test.body.Exec.ExitCode = 2 }
		}
		t.Run(test.name, func(t *testing.T) {
			canonical, err := credentialprotocol.EncodeHelperResponseBody(test.body)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := newResponsePacket(transportJobHeader(credentialprotocol.PacketTypeResponse, 9, uint32(len(canonical))), test.body)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate()
			if packet.BodySHA256() != sha256.Sum256(canonical) {
				t.Fatal("caller mutation changed pinned response digest")
			}
			sink := &transportTestSink{maximum: len(canonical)}
			if err := packet.WriteCanonicalBody(sink); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(sink.value, canonical) {
				t.Fatal("caller mutation changed pinned response encoding")
			}
			if packet.BodySHA256() != sha256.Sum256(canonical) {
				t.Fatal("response digest changed after write")
			}
		})
	}
}

func TestSendPacketWriteIsOneUseAcrossConcurrentAliases(t *testing.T) {
	packet, err := newCloseNotifyPacket(transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := packet.BodySHA256()
	const contenders = 32
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		alias := packet
		go func() {
			defer wait.Done()
			results <- alias.WriteCanonicalBody(&transportTestSink{maximum: 1})
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for writeErr := range results {
		if writeErr == nil {
			successes++
		} else if !errors.Is(writeErr, ErrContractOwnership) {
			t.Fatalf("alias write error = %v", writeErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful alias writes = %d, want 1", successes)
	}
	if packet.BodySHA256() != wantDigest {
		t.Fatal("pinned body digest changed after write")
	}
}

func TestSendPacketSSHRightCardinalityAndOwnership(t *testing.T) {
	digest := sha256.Sum256([]byte("relay"))
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: digest}}
	header := transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 9, 43)
	packet, err := newSSHAcceptedPacket(header, 1, 0, 1, digest, right)
	if err != nil {
		t.Fatal(err)
	}
	if packet.RightsCount() != 1 || packet.Right() != right || right.state.closed {
		t.Fatal("send right ownership changed before Transport")
	}
	bad := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: digest}}
	if _, err := newSSHAcceptedPacket(header, 1, 0, 1, digest, bad); !errors.Is(err, ErrContractCapability) {
		t.Fatalf("wrong outbound right error = %v", err)
	}
	changedDigest := digest
	changedDigest[31] ^= 1
	mismatch := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: changedDigest}}
	mismatchAlias := mismatch
	if _, err := newSSHAcceptedPacket(header, 1, 0, 1, digest, mismatchAlias); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("outbound right/body digest mismatch = %v", err)
	}
	if !mismatch.state.closed {
		t.Fatal("mismatched outbound right alias was not closed")
	}
}

func TestSendExecStreamOwnsLockedBodyUntilExplicitDestroy(t *testing.T) {
	payload := []byte("stdout")
	digest := sha256.Sum256(payload)
	encoded := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, payload, digest)
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 10, uint32(len(encoded)))
	packet, err := newExecStreamPacket(header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, body)
	if err != nil {
		t.Fatal(err)
	}
	pinnedDigest := sha256.Sum256(encoded)
	if body.state.destroyed || packet.BodySHA256() != pinnedDigest || body.state.borrows != 1 {
		t.Fatal("send stream body ownership changed before send")
	}
	sink := &transportTestSink{maximum: len(encoded)}
	if err := packet.WriteCanonicalBody(sink); err != nil || !reflect.DeepEqual(sink.value, encoded) {
		t.Fatalf("send stream copy = %x, %v", sink.value, err)
	}
	if body.state.borrows != 2 {
		t.Fatalf("send stream borrows after construction/write = %d, want 2", body.state.borrows)
	}
	if err := packet.WriteCanonicalBody(sink); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("second send stream write = %v", err)
	}
	if body.state.borrows != 2 {
		t.Fatalf("second stream write borrowed again: %d", body.state.borrows)
	}
	if err := packet.destroyBody(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, body)
	if packet.BodySHA256() != pinnedDigest {
		t.Fatal("pinned stream digest changed after write/destroy")
	}

	badBody := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	badDigest := sha256.Sum256([]byte("different"))
	if _, err := newExecStreamPacket(header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), badDigest, badBody); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("send stream correlation error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

func TestSendExecStreamCanonicalEncoderIsUnavailable(t *testing.T) {
	if encoded, err := (sendExecStreamArm{}).encodeCanonical(); encoded != nil || !errors.Is(err, ErrContractCapability) {
		t.Fatalf("sensitive stream canonical encoder = %x, %v", encoded, err)
	}
	assertPublicMethods(t, reflect.TypeOf((*credentialmemory.CredentialSink)(nil)).Elem(), []string{"MaxCredentialBytes", "WriteCredential"})
}

func TestReceiveRequestConcurrentCopiesHaveOneOwner(t *testing.T) {
	const contenders = 32
	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1)
	credential := transportCredential(t)
	var wait sync.WaitGroup
	wait.Add(contenders)
	results := make(chan error, contenders)
	bodies := make([]transportTestBody, contenders)
	for index := range bodies {
		bodies[index] = newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
		go func(body transportTestBody) {
			defer wait.Done()
			_, constructErr := NewReceivedCloseNotifyPacket(request, header, credential, 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
			results <- constructErr
		}(bodies[index])
	}
	wait.Wait()
	close(results)
	successes := 0
	for constructErr := range results {
		if constructErr == nil {
			successes++
		} else if !errors.Is(constructErr, ErrContractOwnership) {
			t.Fatalf("contender error = %v", constructErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful owners = %d, want 1", successes)
	}
	for _, body := range bodies {
		assertBodyDestroyedAndWiped(t, body)
	}
}

func TestTransportValuePublicMethodSetsAreClosed(t *testing.T) {
	assertPublicMethods(t, reflect.TypeOf(ReceivedKernelCredential{}), []string{"Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "String"})
	assertPublicMethods(t, reflect.TypeOf(ReceiveRequest{}), []string{"ExpectedRights", "Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "MaximumBodyBytes", "NextSequence", "String"})
	assertPublicMethods(t, reflect.TypeOf(ReceivedPacket{}), []string{"AgentHello", "Bootstrap", "CloseNotify", "Exec", "ExecCredit", "ExecPrivate", "ExecStream", "Format", "GoString", "Header", "MarshalBinary", "MarshalJSON", "MarshalText", "PrepareBegin", "PrepareCommit", "PrepareFile", "Renew", "Revoke", "String", "Type"})
	assertPublicMethods(t, reflect.TypeOf(SendPacket{}), []string{"BodySHA256", "EncodedBodyLength", "Format", "GoString", "Header", "MarshalBinary", "MarshalJSON", "MarshalText", "Right", "RightsCount", "String", "Type", "WriteCanonicalBody"})
}

func TestTransportValuesAreOpaqueAsValuesAndPointers(t *testing.T) {
	credential := transportCredential(t)
	request, err := NewReceiveRequest(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		credential, &credential,
		request, &request,
		ReceivedPacket{}, &ReceivedPacket{},
		ReceivedBootstrap{}, &ReceivedBootstrap{},
		ReceivedAgentHello{}, &ReceivedAgentHello{},
		ReceivedPrepareBegin{}, &ReceivedPrepareBegin{},
		ReceivedPrepareFile{}, &ReceivedPrepareFile{},
		ReceivedPrepareCommit{}, &ReceivedPrepareCommit{},
		ReceivedRenew{}, &ReceivedRenew{},
		ReceivedRevoke{}, &ReceivedRevoke{},
		ReceivedExec{}, &ReceivedExec{},
		ReceivedExecPrivate{}, &ReceivedExecPrivate{},
		ReceivedExecStream{}, &ReceivedExecStream{},
		ReceivedExecCredit{}, &ReceivedExecCredit{},
		ReceivedCloseNotify{}, &ReceivedCloseNotify{},
		SendPacket{}, &SendPacket{},
	}
	for _, value := range values {
		assertLiveOpaque(t, value)
	}
}

func TestReceivedAgentHelloParsesOnlyCanonicalDescriptorLength(t *testing.T) {
	credential := transportCredential(t)
	bootstrapDigest := sha256.Sum256([]byte("bootstrap"))
	for _, tc := range []struct {
		name       string
		declared   uint16
		descriptor []byte
		digest     [32]byte
	}{
		{name: "zero length", declared: 0, descriptor: nil, digest: sha256.Sum256(nil)},
		{name: "above maximum", declared: 1899, descriptor: make([]byte, 1899), digest: sha256.Sum256(make([]byte, 1899))},
		{name: "nonexact remainder", declared: 2, descriptor: []byte{1}, digest: sha256.Sum256([]byte{1})},
		{name: "independent digest mismatch", declared: 1, descriptor: []byte{1}, digest: sha256.Sum256([]byte{2})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodyBytes := transportAgentHelloBody(t, bootstrapDigest, "boot-1", "helper-1", tc.declared, tc.descriptor)
			request, err := NewReceiveRequest(1, uint32(len(bodyBytes)), 0)
			if err != nil {
				t.Fatal(err)
			}
			body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
			_, err = NewReceivedAgentHelloPacket(request, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(bodyBytes))), credential, 1, body, 0, bootstrapDigest, "boot-1", "helper-1", tc.digest)
			if !errors.Is(err, ErrContractCorrelation) {
				t.Fatalf("malformed descriptor error = %v", err)
			}
			assertBodyDestroyedAndWiped(t, body)
		})
	}

	descriptor := make([]byte, 1898)
	digest := sha256.Sum256(descriptor)
	bodyBytes := transportAgentHelloBody(t, bootstrapDigest, "boot-1", "helper-1", 1898, descriptor)
	request, err := NewReceiveRequest(1, uint32(len(bodyBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	if _, err := NewReceivedAgentHelloPacket(request, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(bodyBytes))), credential, 1, body, 0, bootstrapDigest, "boot-1", "helper-1", digest); err != nil {
		t.Fatalf("maximum canonical descriptor: %v", err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestAllReceivedTypedArmsRoundTripCanonicalCodecMetadata(t *testing.T) {
	credential := transportCredential(t)
	bootstrapDigest := sha256.Sum256([]byte("bootstrap"))
	descriptor := []byte("canonical-descriptor")
	descriptorDigest := sha256.Sum256(descriptor)
	bootToken, _ := credentialprotocol.EncodeBodyToken("boot-1")
	helperToken, _ := credentialprotocol.EncodeBodyToken("helper-1")
	helloBytes := make([]byte, 32, 32+len(bootToken)+len(helperToken)+2+len(descriptor))
	copy(helloBytes, bootstrapDigest[:])
	helloBytes = append(helloBytes, bootToken...)
	helloBytes = append(helloBytes, helperToken...)
	helloBytes = binary.BigEndian.AppendUint16(helloBytes, uint16(len(descriptor)))
	helloBytes = append(helloBytes, descriptor...)
	helloRequest, _ := NewReceiveRequest(1, uint32(len(helloBytes)), 0)
	helloBody := newTransportTestBody(helloBytes, 256)
	hello, err := NewReceivedAgentHelloPacket(helloRequest, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(helloBytes))), credential, 1, helloBody, 0, bootstrapDigest, "boot-1", "helper-1", descriptorDigest)
	if err != nil {
		t.Fatal(err)
	}
	helloArm, ok := hello.AgentHello()
	if !ok || helloArm.BootstrapSHA256() != bootstrapDigest || helloArm.BootGeneration() != "boot-1" || helloArm.HelperGeneration() != "helper-1" || helloArm.ProcessDescriptorSHA256() != descriptorDigest {
		t.Fatalf("agent hello arm = %#v, %v", helloArm, ok)
	}
	assertBodyDestroyedAndWiped(t, helloBody)

	manifestDigest := sha256.Sum256([]byte("manifest"))
	commitValue := credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest}
	commitBytes, _ := credentialprotocol.EncodeHelperPrepareCommitBody(commitValue)
	commit := receiveCanonicalForTest(t, credentialprotocol.PacketTypePrepareCommit, commitBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedPrepareCommitPacket(request, header, credential, 1, body, 0, commitValue)
	})
	commitArm, ok := commit.PrepareCommit()
	if !ok || commitArm.Revision() != 1 || commitArm.ManifestSHA256() != manifestDigest {
		t.Fatal("prepare commit arm mismatch")
	}

	renewValue := credentialprotocol.HelperRenewBody{Revision: 2, ExpiryUnixNano: 1234, PriorProofID: "proof-1"}
	renewBytes, _ := credentialprotocol.EncodeHelperRenewBody(renewValue)
	renew := receiveCanonicalForTest(t, credentialprotocol.PacketTypeRenew, renewBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedRenewPacket(request, header, credential, 1, body, 0, 2, 1234, "proof-1")
	})
	renewArm, ok := renew.Renew()
	if !ok || renewArm.Revision() != 2 || renewArm.ExpiryUnixNano() != 1234 || renewArm.PriorProofSHA256() == ([32]byte{}) {
		t.Fatal("renew arm mismatch")
	}

	revokeValue := credentialprotocol.HelperRevokeBody{Revision: 2, Reason: credentialprotocol.RevokeReasonRequested}
	revokeBytes, _ := credentialprotocol.EncodeHelperRevokeBody(revokeValue)
	revoke := receiveCanonicalForTest(t, credentialprotocol.PacketTypeRevoke, revokeBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedRevokePacket(request, header, credential, 1, body, 0, revokeValue)
	})
	revokeArm, ok := revoke.Revoke()
	if !ok || revokeArm.Revision() != 2 || revokeArm.Reason() != credentialprotocol.RevokeReasonRequested {
		t.Fatal("revoke arm mismatch")
	}

	planValue := transportExecPlan()
	plan, err := NewExecPlanCapability(planValue)
	if err != nil {
		t.Fatal(err)
	}
	execValue := credentialprotocol.HelperExecBody{Revision: 2, ExecBindingID: "exec-1", Plan: planValue}
	execBytes, err := credentialprotocol.EncodeHelperExecBody(execValue)
	if err != nil {
		t.Fatal(err)
	}
	execPacket := receiveCanonicalForTest(t, credentialprotocol.PacketTypeExec, execBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedExecPacket(request, header, credential, 1, body, 0, 2, "exec-1", 0, [32]byte{}, plan)
	})
	execArm, ok := execPacket.Exec()
	if !ok || execArm.Revision() != 2 || execArm.ExecBindingID() != "exec-1" || execArm.PrivateBindingLength() != 0 || execArm.Plan().SHA256() != plan.SHA256() {
		t.Fatal("exec arm mismatch")
	}
	plan.destroy()

	privatePayload := []byte("private")
	privateDigest := sha256.Sum256(privatePayload)
	privateBytes := make([]byte, 44+len(privatePayload))
	binary.BigEndian.PutUint64(privateBytes[:8], 2)
	binary.BigEndian.PutUint32(privateBytes[8:12], uint32(len(privatePayload)))
	copy(privateBytes[12:44], privateDigest[:])
	copy(privateBytes[44:], privatePayload)
	privateRequest, _ := NewReceiveRequest(2, uint32(len(privateBytes)), 0)
	privateBody := newTransportTestBody(privateBytes, 256)
	privatePacket, err := NewReceivedExecPrivatePacket(privateRequest, transportJobHeader(credentialprotocol.PacketTypeExecPrivate, 2, uint32(len(privateBytes))), credential, 1, privateBody, 0, 2, uint32(len(privatePayload)), privateDigest)
	if err != nil {
		t.Fatal(err)
	}
	privateArm, ok := privatePacket.ExecPrivate()
	if !ok || privateArm.Revision() != 2 || privateArm.PrivateBindingLength() != uint32(len(privatePayload)) || privateArm.PrivateBindingSHA256() != privateDigest {
		t.Fatal("exec private arm mismatch")
	}
	assertRetainedPayloadSubview(t, privatePacket, privateBody, privateBytes, 44, privatePayload, privateDigest)
	if err := privatePacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, privateBody)

	streamPayload := []byte("stdin")
	streamDigest := sha256.Sum256(streamPayload)
	streamBytes := transportStreamBody(2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, streamPayload, streamDigest)
	streamRequest, _ := NewReceiveRequest(2, uint32(len(streamBytes)), 0)
	streamBody := newTransportTestBody(streamBytes, 256)
	streamPacket, err := NewReceivedExecStreamPacket(streamRequest, transportJobHeader(credentialprotocol.PacketTypeExecStream, 2, uint32(len(streamBytes))), credential, 1, streamBody, 0, 2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest)
	if err != nil {
		t.Fatal(err)
	}
	streamArm, ok := streamPacket.ExecStream()
	if !ok || streamArm.Revision() != 2 || streamArm.StreamKind() != credentialprotocol.HelperExecStreamStdin || streamArm.Flags() != credentialprotocol.HelperExecStreamFlagsNone || streamArm.Offset() != 0 || streamArm.PayloadLength() != uint32(len(streamPayload)) || streamArm.PayloadSHA256() != streamDigest {
		t.Fatal("exec stream arm mismatch")
	}
	assertRetainedPayloadSubview(t, streamPacket, streamBody, streamBytes, 56, streamPayload, streamDigest)
	if err := streamPacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, streamBody)

	creditValue := credentialprotocol.HelperExecCreditBody{Revision: 2, StreamKind: credentialprotocol.HelperExecStreamStdout, NextOffset: 10}
	creditBytes, _ := credentialprotocol.EncodeHelperExecCreditBody(creditValue)
	credit := receiveCanonicalForTest(t, credentialprotocol.PacketTypeExecCredit, creditBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedExecCreditPacket(request, header, credential, 1, body, 0, creditValue)
	})
	creditArm, ok := credit.ExecCredit()
	if !ok || creditArm.Revision() != 2 || creditArm.StreamKind() != credentialprotocol.HelperExecStreamStdout || creditArm.NextOffset() != 10 {
		t.Fatal("exec credit arm mismatch")
	}
}

func receiveCanonicalForTest(t *testing.T, packetType credentialprotocol.PacketType, encoded []byte, construct func(ReceiveRequest, credentialprotocol.HelperPacketHeader, transportTestBody) (ReceivedPacket, error)) ReceivedPacket {
	t.Helper()
	request, err := NewReceiveRequest(2, uint32(len(encoded)), 0)
	if err != nil {
		t.Fatal(err)
	}
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	packet, err := construct(request, transportJobHeader(packetType, 2, uint32(len(encoded))), body)
	if err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, body)
	return packet
}

func transportExecPlan() credentialprotocol.HelperExecPlan {
	return credentialprotocol.HelperExecPlan{
		Arguments:      []string{"/bin/true"},
		WorkDirectory:  "/workspace",
		StdinMode:      credentialprotocol.HelperExecStreamModePipe,
		StdoutMode:     credentialprotocol.HelperExecStreamModePipe,
		StderrMode:     credentialprotocol.HelperExecStreamModePipe,
		StdinMaxBytes:  1024,
		StdoutMaxBytes: 1024,
		StderrMaxBytes: 1024,
		Timing:         credentialprotocol.HelperExecTiming{Kind: credentialprotocol.HelperExecTimingTimeoutMillis, Value: 1000},
	}
}

func transportStreamBody(revision uint64, kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payload []byte, digest [32]byte) []byte {
	body := make([]byte, 56+len(payload))
	binary.BigEndian.PutUint64(body[:8], revision)
	body[8] = byte(kind)
	body[9] = byte(flags)
	binary.BigEndian.PutUint64(body[12:20], offset)
	binary.BigEndian.PutUint32(body[20:24], uint32(len(payload)))
	copy(body[24:56], digest[:])
	copy(body[56:], payload)
	return body
}

func transportAgentHelloBody(t *testing.T, bootstrapDigest [32]byte, boot, helper credentialprotocol.SafeID, declared uint16, descriptor []byte) []byte {
	t.Helper()
	bootToken, err := credentialprotocol.EncodeBodyToken(string(boot))
	if err != nil {
		t.Fatal(err)
	}
	helperToken, err := credentialprotocol.EncodeBodyToken(string(helper))
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 32, 32+len(bootToken)+len(helperToken)+2+len(descriptor))
	copy(body, bootstrapDigest[:])
	body = append(body, bootToken...)
	body = append(body, helperToken...)
	body = binary.BigEndian.AppendUint16(body, declared)
	body = append(body, descriptor...)
	return body
}

func assertRetainedPayloadSubview(t *testing.T, packet ReceivedPacket, body transportTestBody, canonical []byte, offset int, payload []byte, digest [32]byte) {
	t.Helper()
	if packet.body.Len() != uint32(len(payload)) || packet.body.SHA256() != digest {
		t.Fatalf("private retained payload body = %d/%x", packet.body.Len(), packet.body.SHA256())
	}
	body.state.mu.Lock()
	if !reflect.DeepEqual(body.state.region[:body.state.length], canonical) {
		body.state.mu.Unlock()
		t.Fatal("retained transport owner no longer holds the full canonical body")
	}
	payloadAddress := reflect.ValueOf(body.state.region[offset : offset+len(payload)]).Pointer()
	body.state.mu.Unlock()
	borrowCalls := 0
	err := packet.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		borrowCalls++
		if view.Len() != len(payload) {
			t.Fatalf("borrowed payload length = %d, want %d", view.Len(), len(payload))
		}
		sink := &transportSubviewTestSink{maximum: len(payload), want: payload, wantAddress: payloadAddress}
		if writeErr := view.WriteTo(context.Background(), sink); writeErr != nil {
			return writeErr
		}
		if !sink.called || !sink.sameBacking {
			t.Fatal("service payload subview copied or did not synchronously write")
		}
		return nil
	})
	if err != nil || borrowCalls != 1 {
		t.Fatalf("borrow retained payload = %v, calls %d", err, borrowCalls)
	}
}

func assertPublicMethods(t *testing.T, value reflect.Type, want []string) {
	t.Helper()
	got := make([]string, value.NumMethod())
	for index := 0; index < value.NumMethod(); index++ {
		got[index] = value.Method(index).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s methods = %v, want %v", value, got, want)
	}
}

func transportHeader(packetType credentialprotocol.PacketType, sequence uint64, bodyLength uint32) credentialprotocol.HelperPacketHeader {
	return credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, BodyLength: bodyLength, BootNonce: sha256.Sum256([]byte("boot nonce"))}
}

func transportJobHeader(packetType credentialprotocol.PacketType, sequence uint64, bodyLength uint32) credentialprotocol.HelperPacketHeader {
	header := transportHeader(packetType, sequence, bodyLength)
	header.RequestID[0] = 1
	header.GuestCredentialIdentityDigest = sha256.Sum256([]byte("identity"))
	return header
}

func transportCredential(t *testing.T) ReceivedKernelCredential {
	t.Helper()
	credential, err := NewReceivedKernelCredential(42, 998, 998)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func transportBootstrapBody(t *testing.T, pid, uid, gid uint32, boot, helper credentialprotocol.SafeID) []byte {
	t.Helper()
	bootWire, err := credentialprotocol.EncodeBodyToken(string(boot))
	if err != nil {
		t.Fatal(err)
	}
	helperWire, err := credentialprotocol.EncodeBodyToken(string(helper))
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 12, 12+len(bootWire)+len(helperWire))
	body[0], body[1], body[2], body[3] = byte(pid>>24), byte(pid>>16), byte(pid>>8), byte(pid)
	body[4], body[5], body[6], body[7] = byte(uid>>24), byte(uid>>16), byte(uid>>8), byte(uid)
	body[8], body[9], body[10], body[11] = byte(gid>>24), byte(gid>>16), byte(gid>>8), byte(gid)
	body = append(body, bootWire...)
	body = append(body, helperWire...)
	return body
}

func assertBodyDestroyedAndWiped(t *testing.T, body transportTestBody) {
	t.Helper()
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if !body.state.destroyed {
		t.Fatal("body was not destroyed")
	}
	for index, value := range body.state.region {
		if value != 0 {
			t.Fatalf("body full-capacity byte %d was not wiped", index)
		}
	}
}

func assertLiveOpaque(t *testing.T, value any) {
	t.Helper()
	for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
		if formatted != "credentialhelper.live[redacted]" {
			t.Fatalf("opaque formatting = %q", formatted)
		}
	}
	if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("JSON marshal = %q, %v", encoded, err)
	}
}

func allZeroBytes(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}
