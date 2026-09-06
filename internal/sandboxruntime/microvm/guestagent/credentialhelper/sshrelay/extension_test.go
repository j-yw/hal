package sshrelay

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type traversalHost struct{ secret string }

func (*traversalHost) CreateSSHAgentEndpoint(context.Context, credentialhelper.SSHAgentEndpointRequest) (credentialhelper.SSHAgentEndpoint, error) {
	return nil, errors.New("unused")
}

func (*traversalHost) PublishSSHAcceptedConnection(context.Context, credentialhelper.SSHAcceptedPublication, credentialhelper.SSHAgentConnection) error {
	return errors.New("unused")
}

type failingHelperConnection struct {
	mu            sync.Mutex
	closeCalls    int
	closeFailures int
}

func (*failingHelperConnection) Read(context.Context, credentialmemory.CredentialSink) (credentialhelper.SSHIOResult, error) {
	return credentialhelper.NewSSHIOResult(0, true, false)
}
func (*failingHelperConnection) Write(context.Context, credentialmemory.BorrowedView) (credentialhelper.SSHIOResult, error) {
	return credentialhelper.NewSSHIOResult(0, false, false)
}
func (*failingHelperConnection) Shutdown(context.Context, credentialhelper.SSHShutdownDirection) error {
	return nil
}
func (connection *failingHelperConnection) Close(context.Context) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.closeCalls++
	if connection.closeFailures > 0 {
		connection.closeFailures--
		return errors.New("raw helper close canary")
	}
	return nil
}

type acceptSequenceEndpoint struct {
	connection credentialhelper.SSHAgentConnection
	firstError error
	accepted   bool
}

func (*acceptSequenceEndpoint) ExecBinding() credentialhelper.ExecBindingCapability { return nil }
func (endpoint *acceptSequenceEndpoint) Accept(context.Context) (credentialhelper.SSHAgentConnection, error) {
	if !endpoint.accepted && endpoint.connection != nil {
		endpoint.accepted = true
		return endpoint.connection, endpoint.firstError
	}
	return nil, errors.New("accept loop canary")
}
func (*acceptSequenceEndpoint) Close(context.Context) (credentialhelper.ExtensionCleanupResult, error) {
	return credentialhelper.NewExtensionCleanupResult(true, credentialhelper.ExtensionCleanupComplete)
}

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

func TestHelperSessionDeniesFormattingAndSerializationTraversal(t *testing.T) {
	const secret = "helper-session-traversal-canary"
	lifetime, cancel := context.WithCancel(context.Background())
	session := &helperSession{
		host:        &traversalHost{secret: secret},
		lifetimeCtx: lifetime,
		cancel:      cancel,
		acceptDone:  closedSignal(),
	}
	rendered := fmt.Sprintf("%v %#v %+v", session, session, session)
	if strings.Contains(rendered, secret) || !strings.Contains(rendered, "sshrelay.live[redacted]") {
		t.Errorf("helper session formatting traversed live state: %q", rendered)
	}
	if encoded, err := json.Marshal(session); encoded != nil || !errors.Is(err, credentialhelper.ErrExtensionSerialization) {
		t.Fatalf("json.Marshal(helper session) = (%q, %v)", encoded, err)
	}
	textMarshaler, textOK := any(session).(encoding.TextMarshaler)
	binaryMarshaler, binaryOK := any(session).(encoding.BinaryMarshaler)
	if !textOK || !binaryOK {
		t.Fatalf("helper session marshal interfaces = text:%v binary:%v", textOK, binaryOK)
	}
	if encoded, err := textMarshaler.MarshalText(); encoded != nil || !errors.Is(err, credentialhelper.ErrExtensionSerialization) {
		t.Fatalf("MarshalText(helper session) = (%q, %v)", encoded, err)
	}
	if encoded, err := binaryMarshaler.MarshalBinary(); encoded != nil || !errors.Is(err, credentialhelper.ErrExtensionSerialization) {
		t.Fatalf("MarshalBinary(helper session) = (%q, %v)", encoded, err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(): %v", err)
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

func TestRejectedEndpointCleanupFailureIsRetainedForSessionClose(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	endpoint := &closeRetryEndpoint{}
	session := &helperSession{
		lifetimeCtx: lifetime,
		cancel:      cancel,
		acceptDone:  closedSignal(),
	}
	if err := session.rejectEndpoint(context.Background(), endpoint); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("rejectEndpoint() error = %v, want %v", err, ErrCleanupIncomplete)
	}
	if len(session.cleanupEndpoints) != 1 || endpoint.calls != 1 {
		t.Fatalf("rejected endpoint ownership = retained:%d calls:%d, want 1/1", len(session.cleanupEndpoints), endpoint.calls)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() retry: %v", err)
	}
	if len(session.cleanupEndpoints) != 0 || endpoint.calls != 2 {
		t.Fatalf("rejected endpoint cleanup = retained:%d calls:%d, want 0/2", len(session.cleanupEndpoints), endpoint.calls)
	}
}

func TestAcceptLoopRetainsFailedConnectionCloseForSessionCleanup(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	connection := &failingHelperConnection{closeFailures: 1}
	endpoint := &acceptSequenceEndpoint{connection: connection}
	session := &helperSession{
		host:        &fakeHost{},
		lifetimeCtx: lifetime,
		cancel:      cancel,
		endpoint:    endpoint,
		identity:    [32]byte{1},
		revision:    1,
		acceptDone:  make(chan struct{}),
		prepared:    true,
	}
	go session.acceptLoop(endpoint)
	<-session.acceptDone
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() retry: %v", err)
	}
	if connection.closeCalls != 2 {
		t.Fatalf("accepted connection close calls = %d, want retained retry count 2", connection.closeCalls)
	}
}

func TestAcceptLoopClosesAndRetainsConnectionReturnedWithError(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	connection := &failingHelperConnection{closeFailures: 2}
	endpoint := &acceptSequenceEndpoint{
		connection: connection,
		firstError: errors.New("raw accept canary"),
	}
	session := &helperSession{
		host:        &fakeHost{},
		lifetimeCtx: lifetime,
		cancel:      cancel,
		endpoint:    endpoint,
		identity:    [32]byte{1},
		revision:    1,
		acceptDone:  make(chan struct{}),
		prepared:    true,
	}
	go session.acceptLoop(endpoint)
	<-session.acceptDone
	if err := session.Close(context.Background()); !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("first Close() error = %v, want sanitized cleanup failure", err)
	}
	if connection.closeCalls != 2 || len(session.cleanupConnections) != 1 {
		t.Fatalf("failed connection cleanup = calls:%d retained:%d, want 2/1", connection.closeCalls, len(session.cleanupConnections))
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() retry: %v", err)
	}
	if connection.closeCalls != 3 || len(session.cleanupConnections) != 0 {
		t.Fatalf("retried connection cleanup = calls:%d retained:%d, want 3/0", connection.closeCalls, len(session.cleanupConnections))
	}
}

func TestRenewAndBindExecFailAfterAcceptLoopFailure(t *testing.T) {
	identity := [32]byte{1}
	lifetime, cancel := context.WithCancel(context.Background())
	endpoint := &acceptSequenceEndpoint{}
	session := &helperSession{
		host:        &fakeHost{},
		lifetimeCtx: lifetime,
		cancel:      cancel,
		endpoint:    endpoint,
		identity:    identity,
		revision:    1,
		acceptDone:  make(chan struct{}),
		prepared:    true,
	}
	go session.acceptLoop(endpoint)
	<-session.acceptDone
	request, err := credentialhelper.NewExtensionRenewRequest(identity, 2, 100)
	if err != nil {
		t.Fatalf("NewExtensionRenewRequest(): %v", err)
	}
	if err := session.Renew(context.Background(), request); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("Renew(after accept failure) error = %v, want %v", err, ErrLifecycle)
	}
	source, err := os.ReadFile("extension.go")
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	bindStart := strings.Index(string(source), "func (session *helperSession) BindExec")
	renewStart := strings.Index(string(source), "func (session *helperSession) Renew")
	if bindStart < 0 || renewStart < bindStart || !strings.Contains(string(source[bindStart:renewStart]), "acceptFailed") {
		t.Fatal("BindExec does not reject the latched accept-loop failure")
	}
	_ = session.Close(context.Background())
}
