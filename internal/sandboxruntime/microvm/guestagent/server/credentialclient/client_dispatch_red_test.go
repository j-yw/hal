package credentialclient

import (
	"context"
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
				return ControllerPacket{}, errors.New("readiness admission was not the exact unbound first receive")
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

func newDispatchRedClient(t *testing.T, transport Transport) *Client {
	t.Helper()
	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := NewClientPolicy()
	client, err := NewClient(ClientOptions{
		Transport: transport, Policy: policy, Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.Descriptor(), nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testDispatchTransportIdentity() transportIdentity {
	identity := testControlSessionIdentity()
	var sessionID [32]byte
	sessionID[0] = 1
	return transportIdentity{
		sessionID: sessionID, identity: identity,
		hardExpiry: time.Unix(1_700_000_000, 0).UTC(), helperGeneration: "helper-generation-1",
	}
}

type dispatchRedTransport struct {
	identity          transportIdentity
	receiveController func(context.Context, ControllerReceiveRequest) (ControllerPacket, error)
	sendController    func(context.Context, ControllerSendPacket) error
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
func (*dispatchRedTransport) SendHelper(context.Context, HelperSendPacket) error {
	return errors.New("unexpected helper send")
}
func (transport *dispatchRedTransport) Close(ctx context.Context) error {
	if transport.close == nil {
		return nil
	}
	return transport.close(ctx)
}
