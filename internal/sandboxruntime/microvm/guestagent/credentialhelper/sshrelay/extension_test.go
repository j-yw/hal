package sshrelay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { panic("typed nil context called") }
func (*typedNilContext) Done() <-chan struct{}       { panic("typed nil context called") }
func (*typedNilContext) Err() error                  { panic("typed nil context called") }
func (*typedNilContext) Value(any) any               { panic("typed nil context called") }

type fakeHost struct {
	creates   int
	publishes int
}

func (host *fakeHost) CreateSSHAgentEndpoint(context.Context, credentialhelper.SSHAgentEndpointRequest) (credentialhelper.SSHAgentEndpoint, error) {
	host.creates++
	return nil, errors.New("unused")
}

func (host *fakeHost) PublishSSHAcceptedConnection(context.Context, credentialhelper.SSHAcceptedPublication, credentialhelper.SSHAgentConnection) error {
	host.publishes++
	return nil
}

type closeRetryEndpoint struct{ calls int }

func (*closeRetryEndpoint) ExecBinding() credentialhelper.ExecBindingCapability { return nil }
func (*closeRetryEndpoint) Accept(context.Context) (credentialhelper.SSHAgentConnection, error) {
	return nil, errors.New("unused")
}
func (endpoint *closeRetryEndpoint) Close(context.Context) (credentialhelper.ExtensionCleanupResult, error) {
	endpoint.calls++
	if endpoint.calls == 1 {
		return credentialhelper.ExtensionCleanupResult{}, errors.New("raw close canary")
	}
	return credentialhelper.NewExtensionCleanupResult(true, credentialhelper.ExtensionCleanupComplete)
}

func TestNewHelperExtensionReturnsExactSideEffectFreeRegistration(t *testing.T) {
	registration, err := NewHelperExtension(HelperOptions{})
	if err != nil {
		t.Fatalf("NewHelperExtension(): %v", err)
	}
	if !credentialprotocol.ExtensionDescriptorEqual(registration.Descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		t.Fatal("NewHelperExtension() returned a noncanonical descriptor")
	}
	if registration.Factory == nil {
		t.Fatal("NewHelperExtension() returned a nil factory")
	}
}

func TestHelperFactoryOpenCreatesNoEndpointAndRejectsUnissuedPrepare(t *testing.T) {
	registration, err := NewHelperExtension(HelperOptions{})
	if err != nil {
		t.Fatalf("NewHelperExtension(): %v", err)
	}
	host := &fakeHost{}
	request, err := credentialhelper.NewExtensionOpenRequest(registration.Descriptor, host)
	if err != nil {
		t.Fatalf("NewExtensionOpenRequest(): %v", err)
	}
	session, err := registration.Factory.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("Factory.Open(): %v", err)
	}
	if host.creates != 0 || host.publishes != 0 {
		t.Fatalf("Open() side effects = creates:%d publishes:%d", host.creates, host.publishes)
	}
	if _, err := session.Prepare(context.Background(), credentialhelper.ExtensionPrepareRequest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Prepare(zero) error = %v, want %v", err, ErrInvalidArgument)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	var typedNil *typedNilContext
	if session, err := registration.Factory.Open(typedNil, request); session != nil || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Factory.Open(typed nil context) = (%v, %v)", session, err)
	}
}

func TestHelperCloseRetainsEndpointAfterFailureForRetry(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	endpoint := &closeRetryEndpoint{}
	session := &helperSession{
		lifetimeCtx: lifetime,
		cancel:      cancel,
		endpoint:    endpoint,
		acceptDone:  closedSignal(),
		prepared:    true,
	}
	if err := session.Close(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first Close() error = %v, want %v", err, ErrCleanupIncomplete)
	}
	if session.endpoint == nil || endpoint.calls != 1 {
		t.Fatalf("failed cleanup ownership = endpoint:%v calls:%d", session.endpoint, endpoint.calls)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("retry Close(): %v", err)
	}
	if session.endpoint != nil || endpoint.calls != 2 {
		t.Fatalf("completed cleanup ownership = endpoint:%v calls:%d", session.endpoint, endpoint.calls)
	}
}
