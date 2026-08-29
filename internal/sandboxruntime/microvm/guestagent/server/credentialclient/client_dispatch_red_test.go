package credentialclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func TestL8D6GuestCredentialClientServeDispatchesCanonicalReadiness(t *testing.T) {
	identity := testDispatchTransportIdentity()
	requestID, err := v2control.NewRequestID([16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(identity.sessionID))
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan struct{})
	sent := make(chan error, 1)
	var receiveCount int
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(ctx context.Context, receive ControllerReceiveRequest) (ControllerPacket, error) {
		receiveCount++
		if receiveCount == 1 {
			expected, set := receive.expectedIdentityValue()
			if receive.nextSequenceValue() != 1 || set || expected != (v2control.IdentityDigest{}) || receive.maximumPlaintextBytesValue() != session.MaxControlPlaintextBytes {
				return ControllerPacket{}, errors.New("readiness admission must use first-prepare-legal unset expected identity")
			}
			return ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmReadiness, readiness: request},
			}, nil
		}
		select {
		case <-closed:
			return ControllerPacket{}, errors.New("closed")
		case <-ctx.Done():
			return ControllerPacket{}, ctx.Err()
		}
	}
	transport.sendController = func(_ context.Context, packet ControllerSendPacket) error {
		response, ok := packet.readinessResponseValue()
		if !ok || response.RequestID() != requestID || response.IdentityDigest() != v2control.NewIdentityDigest(identity.sessionID) || response.HelperGeneration() != string(identity.helperGeneration) {
			err := errors.New("readiness response lost canonical authenticated correlation")
			sent <- err
			return err
		}
		sent <- nil
		return nil
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closed) })
		return nil
	}

	client := newDispatchRedClient(t, transport)
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-serveDone:
		t.Fatalf("Serve returned before canonical readiness dispatch: %v", err)
	case <-time.After(time.Second):
		t.Fatal("canonical readiness dispatch did not occur")
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() after clean Close = %v", err)
	}
}

func TestL8D6GuestCredentialClientCloseWaitsForAdmittedReceiveTermination(t *testing.T) {
	entered := make(chan struct{})
	closeCalled := make(chan struct{})
	allowReceiveReturn := make(chan struct{})
	transport := &dispatchRedTransport{identity: testDispatchTransportIdentity()}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		close(entered)
		<-closeCalled
		<-allowReceiveReturn
		return ControllerPacket{}, errors.New("closed receive")
	}
	transport.close = func(context.Context) error {
		transport.closeOnce.Do(func() { close(closeCalled) })
		return nil
	}
	client := newDispatchRedClient(t, transport)
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(context.Background()) }()
	select {
	case <-entered:
	case err := <-serveDone:
		t.Fatalf("Serve returned before admitting a receive: %v", err)
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not admit a receive")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close(context.Background()) }()
	select {
	case <-closeCalled:
	case <-time.After(time.Second):
		t.Fatal("Close did not close the transport")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the admitted receive terminated: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(allowReceiveReturn)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() after clean synchronous Close = %v", err)
	}
}

func TestL8D6GuestCredentialClientDispatcherContainsDependencyErrorAndPanic(t *testing.T) {
	for _, test := range []struct {
		name string
		call func()
		code ClientContractErrorCode
	}{
		{name: "error", call: func() {}, code: ClientContractPacket},
		{name: "panic", call: func() { panic("raw dispatch panic canary") }, code: ClientContractPanic},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &dispatchRedTransport{identity: testDispatchTransportIdentity()}
			transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
				test.call()
				return ControllerPacket{}, errors.New("raw dispatch error canary")
			}
			client := newDispatchRedClient(t, transport)
			err := client.Serve(context.Background())
			if clientContractCode(err) != test.code || strings.Contains(err.Error(), "canary") {
				t.Fatalf("Serve() error = %v, want sanitized code %d", err, test.code)
			}
		})
	}
}

func TestL8D6GuestCredentialClientServeDestroysRejectedControllerBodies(t *testing.T) {
	identity := testDispatchTransportIdentity()
	payload := []byte("controller-private-payload")
	digest := sha256.Sum256(payload)

	for _, test := range []struct {
		name     string
		packet   func(*testHelperBody) ControllerPacket
		err      error
		body     *testHelperBody
		wantCode ClientContractErrorCode
	}{
		{
			name: "transport-error",
			packet: func(body *testHelperBody) ControllerPacket {
				return ControllerPacket{body: body}
			},
			err:      errors.New("receive failed"),
			wantCode: ClientContractPacket,
		},
		{
			name: "cross-session",
			packet: func(body *testHelperBody) ControllerPacket {
				otherSession := identity.sessionID
				otherSession[0] ^= 0xff
				return ControllerPacket{sequence: 1, sessionID: otherSession, body: body}
			},
			wantCode: ClientContractPacket,
		},
		{
			name: "unsupported-private",
			packet: func(body *testHelperBody) ControllerPacket {
				return ControllerPacket{
					sequence:  1,
					sessionID: identity.sessionID,
					arm:       controllerPacketArm{kind: controllerPacketArmPrivate},
					body:      body,
				}
			},
			wantCode: ClientContractPacket,
		},
		{
			name: "unsupported-stream",
			packet: func(body *testHelperBody) ControllerPacket {
				return ControllerPacket{
					sequence:  1,
					sessionID: identity.sessionID,
					arm:       controllerPacketArm{kind: controllerPacketArmStream},
					body:      body,
				}
			},
			wantCode: ClientContractPacket,
		},
		{
			name: "destroy-error",
			packet: func(body *testHelperBody) ControllerPacket {
				return ControllerPacket{sequence: 1, sessionID: identity.sessionID, body: body}
			},
			body:     &testHelperBody{length: uint32(len(payload)), digest: digest, destroyErr: errors.New("destroy failed")},
			wantCode: ClientContractCleanup,
		},
		{
			name: "destroy-panic",
			packet: func(body *testHelperBody) ControllerPacket {
				return ControllerPacket{sequence: 1, sessionID: identity.sessionID, body: body}
			},
			body:     &testHelperBody{length: uint32(len(payload)), digest: digest, destroyPanic: true},
			wantCode: ClientContractCleanup,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if body == nil {
				body = &testHelperBody{length: uint32(len(payload)), digest: digest}
			}
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
				return test.packet(body), test.err
			}
			if err := newDispatchRedClient(t, transport).Serve(context.Background()); clientContractCode(err) != test.wantCode {
				t.Fatalf("Serve() error = %v, want code %d", err, test.wantCode)
			}
			if !body.destroyed {
				t.Fatal("Serve did not destroy the rejected controller body")
			}
		})
	}

	var typedNilBody *testHelperBody
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{sequence: 1, sessionID: identity.sessionID, body: typedNilBody}, nil
	}
	if err := newDispatchRedClient(t, transport).Serve(context.Background()); clientContractCode(err) != ClientContractPacket {
		t.Fatalf("Serve() typed-nil body error = %v, want code %d", err, ClientContractPacket)
	}
}

func TestL8D6GuestCredentialClientRejectsCrossSessionReadinessPacket(t *testing.T) {
	identity := testDispatchTransportIdentity()
	otherSessionID := identity.sessionID
	otherSessionID[0] ^= 0xff
	requestID, err := v2control.NewRequestID([16]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	request, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(otherSessionID))
	if err != nil {
		t.Fatal(err)
	}

	var sends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: otherSessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmReadiness, readiness: request},
		}, nil
	}
	transport.sendController = func(context.Context, ControllerSendPacket) error {
		sends.Add(1)
		return errors.New("cross-session response must not be sent")
	}
	client := newDispatchRedClient(t, transport)
	if err := client.Serve(context.Background()); clientContractCode(err) != ClientContractPacket {
		t.Fatalf("Serve() error = %v, want packet rejection", err)
	}
	if sends.Load() != 0 {
		t.Fatalf("cross-session readiness sends = %d, want zero", sends.Load())
	}
}

func TestL8D6GuestCredentialClientServeFirstPrepareUsesUnsetSessionBoundIdentity(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	digest := identityDigestForSession(t, testCredentialPacketSessionIdentity(t, identity.sessionID))
	if digest == v2control.NewIdentityDigest(identity.sessionID) {
		t.Fatal("fixture digest collided with raw session bytes")
	}

	var receiveCount atomic.Uint32
	var sends atomic.Uint32
	var helperSends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(_ context.Context, receive ControllerReceiveRequest) (ControllerPacket, error) {
		count := receiveCount.Add(1)
		expected, set := receive.expectedIdentityValue()
		if count != 1 || receive.nextSequenceValue() != 1 || set || expected != (v2control.IdentityDigest{}) ||
			expected == v2control.NewIdentityDigest(identity.sessionID) || receive.maximumPlaintextBytesValue() != session.MaxControlPlaintextBytes {
			return ControllerPacket{}, errors.New("first prepare was not admitted with expectedIdentitySet=false")
		}
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendController = func(context.Context, ControllerSendPacket) error {
		sends.Add(1)
		return errors.New("prepare success must not be sent without helper packets")
	}
	transport.sendHelper = func(context.Context, HelperSendPacket) error {
		helperSends.Add(1)
		return errors.New("helper send constructor is unaccepted")
	}

	err := newDispatchRedClient(t, transport).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want helper packet dependency unaccepted", err)
	}
	if receiveCount.Load() != 1 {
		t.Fatalf("controller receives = %d, want 1; subsequent receive identity pin requires helper packets", receiveCount.Load())
	}
	if sends.Load() != 0 || helperSends.Load() != 0 {
		t.Fatalf("controller/helper sends = %d/%d, want zero without helper constructors", sends.Load(), helperSends.Load())
	}
}

func TestL8D6GuestCredentialClientServeRejectsFirstPrepareIdentityMismatch(t *testing.T) {
	identity := testDispatchTransportIdentity()
	otherSessionID := identity.sessionID
	otherSessionID[31] ^= 0xff
	prepare := testDispatchPrepareRequest(t, transportIdentity{sessionID: otherSessionID})

	var sends atomic.Uint32
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	transport.sendController = func(context.Context, ControllerSendPacket) error {
		sends.Add(1)
		return errors.New("mismatched first prepare must not be answered")
	}
	if err := newDispatchRedClient(t, transport).Serve(context.Background()); clientContractCode(err) != ClientContractPacket {
		t.Fatalf("Serve() error = %v, want identity packet rejection", err)
	}
	if sends.Load() != 0 {
		t.Fatalf("mismatched first prepare sends = %d, want zero", sends.Load())
	}
}

func TestL8D6GuestCredentialClientServeRejectsPrepareBeyondSessionHardExpiry(t *testing.T) {
	identity := testDispatchTransportIdentity()
	identity.hardExpiry = time.Unix(0, 1700000000623456789).UTC()
	prepare := testDispatchPrepareRequest(t, identity)

	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	if err := newDispatchRedClient(t, transport).Serve(context.Background()); clientContractCode(err) != ClientContractPacket {
		t.Fatalf("Serve() error = %v, want expiry packet rejection", err)
	}
}

func TestL8D6GuestCredentialClientServeRenewRevokeExecRequireExpectedIdentitySet(t *testing.T) {
	identity := testDispatchTransportIdentity()
	sessionIdentity := testCredentialPacketSessionIdentity(t, identity.sessionID)
	requestID := testPacketRequestID(t)
	cases := []struct {
		name   string
		packet ControllerPacket
	}{
		{
			name: "renew",
			packet: ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmRenew, renew: testCredentialRenewPacketRequest(t, requestID, sessionIdentity)},
			},
		},
		{
			name: "revoke",
			packet: ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmRevoke, revoke: testCredentialRevokePacketRequest(t, requestID, sessionIdentity)},
			},
		},
		{
			name: "exec",
			packet: ControllerPacket{
				sequence:  1,
				sessionID: identity.sessionID,
				arm:       controllerPacketArm{kind: controllerPacketArmExec, exec: testCredentialExecPacketRequest(t, requestID, sessionIdentity)},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var receiveCount atomic.Uint32
			var sends atomic.Uint32
			transport := &dispatchRedTransport{identity: identity}
			transport.receiveController = func(_ context.Context, receive ControllerReceiveRequest) (ControllerPacket, error) {
				receiveCount.Add(1)
				if _, set := receive.expectedIdentityValue(); set {
					return ControllerPacket{}, errors.New("renew/revoke/exec before prepare must not set expected identity")
				}
				return test.packet, nil
			}
			transport.sendController = func(context.Context, ControllerSendPacket) error {
				sends.Add(1)
				return errors.New("renew/revoke/exec without expectedIdentitySet must not be answered")
			}
			if err := newDispatchRedClient(t, transport).Serve(context.Background()); clientContractCode(err) != ClientContractPacket {
				t.Fatalf("Serve() error = %v, want identity requirement", err)
			}
			if receiveCount.Load() != 1 || sends.Load() != 0 {
				t.Fatalf("receives/sends = %d/%d, want 1/0", receiveCount.Load(), sends.Load())
			}
		})
	}
}

func TestL8D6GuestCredentialClientServeCredentialOperationsRequireHelperPackets(t *testing.T) {
	identity := testDispatchTransportIdentity()
	prepare := testDispatchPrepareRequest(t, identity)
	transport := &dispatchRedTransport{identity: identity}
	transport.receiveController = func(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
		return ControllerPacket{
			sequence:  1,
			sessionID: identity.sessionID,
			arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
		}, nil
	}
	err := newDispatchRedClient(t, transport).Serve(context.Background())
	if !errors.Is(err, ErrClientControlDependencyUnaccepted) {
		t.Fatalf("Serve() error = %v, want named helper packet dependency", err)
	}
}

func testDispatchPrepareRequest(t *testing.T, identity transportIdentity) v2control.CredentialPrepareRequest {
	t.Helper()
	return testCredentialPreparePacketRequest(t, testPacketRequestID(t), testCredentialPacketSessionIdentity(t, identity.sessionID))
}

func newDispatchRedClient(t *testing.T, transport Transport) *Client {
	t.Helper()
	return newDispatchRedClientOpts(t, transport, nil)
}

func testDispatchTransportIdentity() transportIdentity {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	return transportIdentity{
		sessionID: sessionID, identity: identity,
		hardExpiry: time.Unix(0, 1700000001123456789).UTC(), helperGeneration: "helper-generation-1",
	}
}

type dispatchRedTransport struct {
	identity          transportIdentity
	receiveController func(context.Context, ControllerReceiveRequest) (ControllerPacket, error)
	sendController    func(context.Context, ControllerSendPacket) error
	sendHelper        func(context.Context, HelperSendPacket) error
	close             func(context.Context) error
	closeOnce         sync.Once
}

func (transport *dispatchRedTransport) Identity() transportIdentity { return transport.identity }
func (transport *dispatchRedTransport) ReceiveController(ctx context.Context, request ControllerReceiveRequest) (ControllerPacket, error) {
	if transport.receiveController == nil {
		return ControllerPacket{}, errors.New("unexpected controller receive")
	}
	return transport.receiveController(ctx, request)
}
func (transport *dispatchRedTransport) SendController(ctx context.Context, packet ControllerSendPacket) error {
	if transport.sendController == nil {
		return errors.New("unexpected controller send")
	}
	return transport.sendController(ctx, packet)
}
func (*dispatchRedTransport) ReceiveHelper(context.Context, HelperReceiveRequest) (HelperPacket, error) {
	return HelperPacket{}, errors.New("unexpected helper receive")
}
func (transport *dispatchRedTransport) SendHelper(ctx context.Context, packet HelperSendPacket) error {
	if transport.sendHelper == nil {
		return errors.New("unexpected helper send")
	}
	return transport.sendHelper(ctx, packet)
}
func (transport *dispatchRedTransport) Close(ctx context.Context) error {
	if transport.close == nil {
		return nil
	}
	return transport.close(ctx)
}
