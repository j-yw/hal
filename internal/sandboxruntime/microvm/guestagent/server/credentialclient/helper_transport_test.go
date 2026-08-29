package credentialclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestL8D7GuestHelperOwnerIsVerifiedPreopened(t *testing.T) {
	owner := reflect.TypeOf((*HelperConnectionOwner)(nil)).Elem()
	if owner.NumMethod() != 2 || owner.Method(0).Name != "AcceptVerified" || owner.Method(1).Name != "Close" {
		t.Fatalf("HelperConnectionOwner methods = %v, want exact AcceptVerified/Close", owner)
	}
	stream := reflect.TypeOf((*VerifiedHelperStream)(nil)).Elem()
	for _, forbidden := range []string{"Bind", "Listen", "Dial", "Accept"} {
		if _, ok := stream.MethodByName(forbidden); ok {
			t.Fatalf("VerifiedHelperStream exposes forbidden %s authority", forbidden)
		}
	}

	sessionID := testDispatchTransportIdentity().sessionID
	digest := [32]byte{9, 8, 7}
	digest[31] = 1
	nonce := [32]byte{1, 2, 3}
	nonce[31] = 4
	expectation, err := newHelperAcceptExpectation(sessionID, digest, "helper-generation-1", nonce)
	if err != nil {
		t.Fatalf("newHelperAcceptExpectation() error = %v", err)
	}
	if expectation.SessionID() != sessionID || expectation.IdentityDigest() != digest ||
		expectation.HelperGeneration() != "helper-generation-1" || expectation.BootNonce() != nonce {
		t.Fatal("helper accept expectation lost correlation")
	}
	assertFailsClosed(t, expectation)
	if _, err := newHelperAcceptExpectation([32]byte{}, digest, "helper-generation-1", nonce); !errors.Is(err, errInvalidHelperAcceptExpectation) {
		t.Fatalf("zero session helper expectation error = %v", err)
	}
}

func TestL8D7GuestHelperPrepareBeginBodyProjectsSafeManifest(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	body, err := helperPrepareBeginBodyFromPrepare(prepare)
	if err != nil {
		t.Fatalf("helperPrepareBeginBodyFromPrepare() error = %v", err)
	}
	if body.Revision != 1 || body.ExpiryUnixNano != prepare.ExpiresAtUnixNano() || len(body.Bindings) != 2 {
		t.Fatalf("prepare-begin body = %#v", body)
	}
	if body.Bindings[0].BindingID != "binding-http" || body.Bindings[0].Mode != credentialprotocol.DeliveryModeHTTPProxy ||
		body.Bindings[0].TargetPath != "" || body.Bindings[0].DeclaredFileBytes != 0 {
		t.Fatalf("http binding = %#v", body.Bindings[0])
	}
	if body.Bindings[1].BindingID != "binding-file" || body.Bindings[1].Mode != credentialprotocol.DeliveryModeFileTmpfs ||
		body.Bindings[1].TargetPath != "credentials/config" || body.Bindings[1].DeclaredFileBytes != 7 {
		t.Fatalf("file binding = %#v", body.Bindings[1])
	}
}

func TestL8D7GuestHelperServeNilOwnerRemainsUnaccepted(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	var helperSends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendHelper = func(context.Context, HelperSendPacket) error {
		helperSends.Add(1)
		return errors.New("nil helper owner must not send")
	}
	err := newDispatchRedClientOpts(t, transport, nil).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want helper dependency unaccepted", err)
	}
	if helperSends.Load() != 0 {
		t.Fatalf("helper sends = %d, want 0", helperSends.Load())
	}
}

func TestL8D7GuestHelperServeSendsPrepareBeginWhenOwnerInjected(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testCredentialPacketSessionIdentity(t, identity.sessionID))
	stream := newFakeHelperStream()
	owner := &fakeHelperOwner{stream: stream}
	var helperSends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendHelper = func(_ context.Context, packet HelperSendPacket) error {
		if packet.packetTypeValue() != credentialprotocol.PacketTypePrepareBegin {
			return errors.New("injected helper send must be prepare-begin")
		}
		header := packet.headerValue()
		if header.Sequence != firstInjectedHelperSendSequence || header.RequestID != prepare.RequestID().Bytes() ||
			header.GuestCredentialIdentityDigest != digest.Bytes() || header.BootNonce != identity.identity.GuestBootNonce {
			return errors.New("prepare-begin header lost session correlation")
		}
		helperSends.Add(1)
		return nil
	}

	err := newDispatchRedClientOpts(t, transport, owner).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want remaining helper payload/proofs unaccepted", err)
	}
	if owner.accepts.Load() != 1 || helperSends.Load() != 1 {
		t.Fatalf("accepts/sends = %d/%d, want 1/1", owner.accepts.Load(), helperSends.Load())
	}
	datagram := stream.bytes()
	header, err := credentialprotocol.ValidateHelperPacketDatagram(datagram)
	if err != nil {
		t.Fatalf("verified helper stream datagram error = %v", err)
	}
	if header.Type != credentialprotocol.PacketTypePrepareBegin || header.Sequence != firstInjectedHelperSendSequence {
		t.Fatalf("stream header = %#v", header)
	}
	decoded, err := credentialprotocol.DecodeHelperPrepareBeginBody(datagram[credentialprotocol.HelperPacketHeaderSize:])
	if err != nil {
		t.Fatalf("DecodeHelperPrepareBeginBody() error = %v", err)
	}
	if decoded.Revision != 1 || len(decoded.Bindings) != 2 || decoded.Bindings[0].BindingID != "binding-http" {
		t.Fatalf("stream prepare-begin body = %#v", decoded)
	}
}

func TestL8D7GuestHelperWriteCanonicalPrepareBeginPacket(t *testing.T) {
	identity := testHelperPacketIdentity()
	nonce := testHelperPacketNonce()
	requestID := testHelperPacketRequestID()
	begin := credentialprotocol.HelperPrepareBeginBody{
		Revision:       1,
		ExpiryUnixNano: 1700000001123456789,
		Bindings: []credentialprotocol.HelperBindingManifestRecord{
			{BindingID: "binding-http", Mode: credentialprotocol.DeliveryModeHTTPProxy},
		},
	}
	packet, err := newHelperPrepareBeginSendPacket(testHelperHeader(0, 1, requestID, identity, nonce, 0), begin)
	if err != nil {
		t.Fatal(err)
	}
	stream := newFakeHelperStream()
	if err := writeHelperSendPacket(context.Background(), stream, packet); err != nil {
		t.Fatalf("writeHelperSendPacket() error = %v", err)
	}
	header, err := credentialprotocol.ValidateHelperPacketDatagram(stream.bytes())
	if err != nil || header.Type != credentialprotocol.PacketTypePrepareBegin || header.RequestID != requestID {
		t.Fatalf("written datagram header = %#v, %v", header, err)
	}
	if helperSendPacketUnconsumed(packet) {
		t.Fatal("writeHelperSendPacket left the send packet unconsumed")
	}
}

func newDispatchRedClientOpts(t *testing.T, transport Transport, helper HelperConnectionOwner) *Client {
	t.Helper()
	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := NewClientPolicy()
	client, err := NewClient(ClientOptions{
		Transport: transport, Policy: policy, Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.Descriptor(), nil),
		Helper:     helper,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type fakeHelperStream struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func newFakeHelperStream() *fakeHelperStream {
	return &fakeHelperStream{}
}

func (stream *fakeHelperStream) Read(p []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.buf.Read(p)
}

func (stream *fakeHelperStream) Write(p []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return 0, io.ErrClosedPipe
	}
	return stream.buf.Write(p)
}

func (stream *fakeHelperStream) SetDeadline(time.Time) error { return nil }

func (stream *fakeHelperStream) Close() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.closed = true
	return nil
}

func (stream *fakeHelperStream) bytes() []byte {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append([]byte(nil), stream.buf.Bytes()...)
}

type fakeHelperOwner struct {
	stream  VerifiedHelperStream
	accepts atomic.Uint32
}

func (owner *fakeHelperOwner) AcceptVerified(_ context.Context, expectation HelperAcceptExpectation) (VerifiedHelperStream, error) {
	if !expectation.valid() || !configuredDependency(owner.stream) {
		return nil, errInvalidHelperAcceptExpectation
	}
	owner.accepts.Add(1)
	return owner.stream, nil
}

func (owner *fakeHelperOwner) Close(context.Context) error {
	if owner.stream == nil {
		return nil
	}
	return owner.stream.Close()
}

var (
	_ VerifiedHelperStream  = (*fakeHelperStream)(nil)
	_ HelperConnectionOwner = (*fakeHelperOwner)(nil)
)
