package sshrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

func TestClientSSHRelayRegistrationAndFactoryContract(t *testing.T) {
	relay := &testRelay{connections: []RelayConnection{&testRelayConnection{}}}
	registration, err := NewClientExtension(ClientOptions{Relay: relay})
	if err != nil {
		t.Fatalf("NewClientExtension() error = %v", err)
	}
	if !credentialprotocol.ExtensionDescriptorEqual(registration.Descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		t.Fatalf("descriptor = %#v, want SSH relay v1", registration.Descriptor)
	}
	if registration.Factory == nil {
		t.Fatal("registration factory is nil")
	}

	session, err := registration.Factory.Open(context.Background(), credentialclient.ExtensionOpenRequest{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
	})
	if err != nil || session == nil {
		t.Fatalf("Factory.Open() = (%v, %v)", session, err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("session.Close() error = %v", err)
	}

	typedNil := (*testRelay)(nil)
	if _, err := NewClientExtension(ClientOptions{Relay: typedNil}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewClientExtension(typed nil) error = %v", err)
	}
	wrong := credentialprotocol.ExtensionDescriptor{ID: "wrong-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}
	if got, err := registration.Factory.Open(context.Background(), credentialclient.ExtensionOpenRequest{Descriptor: wrong}); got != nil || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Factory.Open(wrong descriptor) = (%v, %v)", got, err)
	}
}

func TestClientSSHRelayPassesOnlyAuthenticatedSafeOpenMetadata(t *testing.T) {
	relay := &testRelay{connections: []RelayConnection{&testRelayConnection{}}}
	session := newTestSession(t, relay)
	accepted := &testAcceptedPacket{
		revision: 17, binding: 3, ordinal: 9, digest: [32]byte{0x7a},
		connection: &testClientConnection{digest: [32]byte{0x7a}}, transferred: make(chan struct{}),
	}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	relay.mu.Lock()
	requests := append([]RelayOpenRequest(nil), relay.requests...)
	relay.mu.Unlock()
	if len(requests) != 1 || requests[0].Revision() != 17 || requests[0].BindingIndex() != 3 ||
		requests[0].Ordinal() != 9 || requests[0].CapabilitySHA256() != ([32]byte{0x7a}) {
		t.Fatalf("relay open requests = %#v", requests)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClientSSHRelayWaitsForCommittedTransferAndSerializesRoundTrips(t *testing.T) {
	request := []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
	response := credentialprotocol.EncodeSSHAgentFailure()
	connection := &testClientConnection{reads: []testRead{{payload: request}, {eof: true}}, writeDone: make(chan struct{})}
	relayConnection := &testRelayConnection{
		response: append([]byte(nil), response...),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	session := newTestSession(t, &testRelay{connections: []RelayConnection{relayConnection}})
	transferred := make(chan struct{})
	accepted := &testAcceptedPacket{
		revision:    1,
		ordinal:     1,
		digest:      [32]byte{1},
		connection:  connection,
		transferred: transferred,
	}

	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := connection.readCalls.Load(); got != 0 {
		t.Fatalf("Read before transfer = %d", got)
	}
	close(transferred)
	select {
	case <-relayConnection.entered:
	case <-time.After(time.Second):
		t.Fatal("relay round trip did not start")
	}
	if got := connection.readCalls.Load(); got != 1 {
		t.Fatalf("Read while response outstanding = %d, want 1", got)
	}
	if got := relayConnection.maxInflight.Load(); got != 1 {
		t.Fatalf("maximum outstanding relay requests = %d, want 1", got)
	}
	if got := relayConnection.lastRequest(); string(got) != string(request) {
		t.Fatalf("relay request = %v, want %v", got, request)
	}
	close(relayConnection.release)
	select {
	case <-connection.writeDone:
	case <-time.After(time.Second):
		t.Fatal("guest response was not written")
	}

	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := connection.written(); string(got) != string(response) {
		t.Fatalf("guest response = %v, want %v", got, response)
	}
	if connection.shutdownCalls.Load() != 1 || connection.closeCalls.Load() != 1 || relayConnection.closeCalls.Load() != 1 {
		t.Fatalf("cleanup calls = shutdown:%d guest-close:%d relay-close:%d, want 1 each",
			connection.shutdownCalls.Load(), connection.closeCalls.Load(), relayConnection.closeCalls.Load())
	}
}

func TestClientSSHRelayCloseCancelsUncommittedTransferAndRetriesAbsence(t *testing.T) {
	connection := &testClientConnection{}
	relayConnection := &testRelayConnection{closeFailures: 2}
	session := newTestSession(t, &testRelay{connections: []RelayConnection{relayConnection}})
	accepted := &testAcceptedPacket{
		revision:    1,
		ordinal:     1,
		digest:      [32]byte{1},
		connection:  connection,
		transferred: make(chan struct{}),
	}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	if err := session.Close(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first Close() error = %v, want cleanup incomplete", err)
	}
	if got := connection.closeCalls.Load(); got != 0 {
		t.Fatalf("uncommitted guest connection close calls = %d, want 0", got)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if got := relayConnection.closeCalls.Load(); got != 3 {
		t.Fatalf("relay cleanup attempts = %d, want 3", got)
	}
}

func TestClientSSHRelayDrainCancelsTransferredPumpAndClosesBothSides(t *testing.T) {
	connection := &testClientConnection{readEntered: make(chan struct{}), blockRead: true}
	relayConnection := &testRelayConnection{}
	session := newTestSession(t, &testRelay{connections: []RelayConnection{relayConnection}})
	transferred := make(chan struct{})
	close(transferred)
	accepted := &testAcceptedPacket{
		revision: 1, ordinal: 1, digest: [32]byte{1}, connection: connection, transferred: transferred,
	}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	select {
	case <-connection.readEntered:
	case <-time.After(time.Second):
		t.Fatal("transferred pump did not begin reading")
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if connection.closeCalls.Load() != 1 || relayConnection.closeCalls.Load() != 1 {
		t.Fatalf("drain cleanup calls = guest:%d relay:%d, want 1 each", connection.closeCalls.Load(), relayConnection.closeCalls.Load())
	}
}

func TestClientSSHRelayMalformedFrameTerminatesWithoutRelayRequest(t *testing.T) {
	connection := &testClientConnection{
		reads:      []testRead{{payload: []byte{0, 0, 0, 2, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}}},
		closedDone: make(chan struct{}),
	}
	relayConnection := &testRelayConnection{}
	session := newTestSession(t, &testRelay{connections: []RelayConnection{relayConnection}})
	transferred := make(chan struct{})
	close(transferred)
	accepted := &testAcceptedPacket{revision: 1, ordinal: 1, digest: [32]byte{1}, connection: connection, transferred: transferred}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	select {
	case <-connection.closedDone:
	case <-time.After(time.Second):
		t.Fatal("malformed-frame pump did not converge")
	}
	if relayConnection.roundTripCalls.Load() != 0 {
		t.Fatalf("relay requests = %d, want 0", relayConnection.roundTripCalls.Load())
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClientSSHRelayGuestCleanupFailureKeepsAbsenceIncomplete(t *testing.T) {
	connection := &testClientConnection{reads: []testRead{{eof: true}}, closeError: true, closedDone: make(chan struct{})}
	session := newTestSession(t, &testRelay{connections: []RelayConnection{&testRelayConnection{}}})
	transferred := make(chan struct{})
	close(transferred)
	accepted := &testAcceptedPacket{revision: 1, ordinal: 1, digest: [32]byte{1}, connection: connection, transferred: transferred}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	select {
	case <-connection.closedDone:
	case <-time.After(time.Second):
		t.Fatal("pump cleanup did not attempt guest close")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := session.Close(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("Close(%d) error = %v, want cleanup incomplete", attempt, err)
		}
	}
}

func TestClientSSHRelayCancelledCloseStartsDrainAndCanBeRetried(t *testing.T) {
	session := newTestSession(t, &testRelay{connections: []RelayConnection{&testRelayConnection{}}})
	accepted := &testAcceptedPacket{
		revision: 1, ordinal: 1, digest: [32]byte{1}, connection: &testClientConnection{}, transferred: make(chan struct{}),
	}
	if err := session.handleAccepted(context.Background(), accepted); err != nil {
		t.Fatalf("handleAccepted() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Close(ctx); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Close(cancelled) error = %v, want cleanup incomplete", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(retry) error = %v", err)
	}
}

func TestClientSSHRelayRejectsMalformedAndPanicDependenciesWithoutLeaks(t *testing.T) {
	openErrorConnection := &testRelayConnection{}
	tests := []struct {
		name  string
		relay Relay
	}{
		{name: "typed nil connection", relay: &testRelay{typedNil: true}},
		{name: "open panic", relay: &testRelay{openPanic: true}},
		{name: "connection with error", relay: &testRelay{connections: []RelayConnection{openErrorConnection}, openError: errors.New("raw-open-canary")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newTestSession(t, test.relay)
			accepted := &testAcceptedPacket{revision: 1, ordinal: 1, digest: [32]byte{1}, connection: &testClientConnection{}, transferred: make(chan struct{})}
			err := session.handleAccepted(context.Background(), accepted)
			if !errors.Is(err, ErrDependency) || strings.Contains(fmt.Sprint(err), "raw-open-canary") {
				t.Fatalf("handleAccepted() error = %v, want sanitized dependency error", err)
			}
			_ = session.Close(context.Background())
		})
	}
	if got := openErrorConnection.closeCalls.Load(); got != 1 {
		t.Fatalf("connection returned with error close calls = %d, want 1", got)
	}
}

func TestClientSSHRelayRejectsUntrustedAcceptedMetadataBeforeOpen(t *testing.T) {
	tests := []struct {
		name     string
		accepted *testAcceptedPacket
	}{
		{name: "zero revision", accepted: &testAcceptedPacket{ordinal: 1, digest: [32]byte{1}, connection: &testClientConnection{}}},
		{name: "binding out of range", accepted: &testAcceptedPacket{revision: 1, binding: credentialprotocol.MaxHelperBindings, ordinal: 1, digest: [32]byte{1}, connection: &testClientConnection{}}},
		{name: "ordinal out of range", accepted: &testAcceptedPacket{revision: 1, ordinal: credentialprotocol.SSHAgentRelayMaxLifetimeConnections + 1, digest: [32]byte{1}, connection: &testClientConnection{}}},
		{name: "zero digest", accepted: &testAcceptedPacket{revision: 1, ordinal: 1, connection: &testClientConnection{}}},
		{name: "digest mismatch", accepted: &testAcceptedPacket{revision: 1, ordinal: 1, digest: [32]byte{2}, connection: &testClientConnection{}}},
		{name: "typed nil connection", accepted: &testAcceptedPacket{revision: 1, ordinal: 1, digest: [32]byte{1}, connection: (*testClientConnection)(nil)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relay := &testRelay{connections: []RelayConnection{&testRelayConnection{}}}
			session := newTestSession(t, relay)
			if err := session.handleAccepted(context.Background(), test.accepted); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("handleAccepted() error = %v", err)
			}
			relay.mu.Lock()
			openCalls := len(relay.requests)
			relay.mu.Unlock()
			if openCalls != 0 {
				t.Fatalf("relay open calls = %d, want 0", openCalls)
			}
			if err := session.Close(context.Background()); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestClientSSHRelayContainsPanickingContexts(t *testing.T) {
	registration, err := NewClientExtension(ClientOptions{Relay: &testRelay{}})
	if err != nil {
		t.Fatal(err)
	}
	if session, err := registration.Factory.Open(panickingContext{}, credentialclient.ExtensionOpenRequest{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor()}); session != nil || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Factory.Open(panic context) = (%v, %v)", session, err)
	}
	session := newTestSession(t, &testRelay{})
	if err := session.Close(panickingContext{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Close(panic context) error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClientSSHRelayLiveValuesAreRedactedAndSerializationDenied(t *testing.T) {
	values := []any{
		ClientOptions{Relay: &testRelay{}},
		RelayOpenRequest{},
		&clientSession{},
	}
	for _, value := range values {
		if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrSerialization) {
			t.Errorf("json.Marshal(%T) = (%q, %v)", value, encoded, err)
		}
		formatted := fmt.Sprintf("%v %#v %s", value, value, value)
		if strings.Contains(formatted, "raw") || !strings.Contains(formatted, "redacted") {
			t.Errorf("format(%T) = %q", value, formatted)
		}
	}
}

func newTestSession(t *testing.T, relay Relay) *clientSession {
	t.Helper()
	registration, err := NewClientExtension(ClientOptions{Relay: relay})
	if err != nil {
		t.Fatalf("NewClientExtension() error = %v", err)
	}
	opened, err := registration.Factory.Open(context.Background(), credentialclient.ExtensionOpenRequest{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor()})
	if err != nil {
		t.Fatalf("Factory.Open() error = %v", err)
	}
	session, ok := opened.(*clientSession)
	if !ok {
		t.Fatalf("Factory.Open() session = %T", opened)
	}
	return session
}

type testAcceptedPacket struct {
	revision    uint64
	binding     uint16
	ordinal     uint8
	digest      [32]byte
	connection  credentialclient.SSHConnectionCapability
	transferred <-chan struct{}
}

func (packet *testAcceptedPacket) Revision() uint64           { return packet.revision }
func (packet *testAcceptedPacket) BindingIndex() uint16       { return packet.binding }
func (packet *testAcceptedPacket) Ordinal() uint8             { return packet.ordinal }
func (packet *testAcceptedPacket) CapabilitySHA256() [32]byte { return packet.digest }
func (packet *testAcceptedPacket) Connection() credentialclient.SSHConnectionCapability {
	return packet.connection
}
func (packet *testAcceptedPacket) WaitTransferred(ctx context.Context) error {
	select {
	case <-packet.transferred:
		return nil
	case <-ctx.Done():
		return errors.New("raw-transfer-canary")
	}
}

type testRelay struct {
	mu          sync.Mutex
	connections []RelayConnection
	requests    []RelayOpenRequest
	typedNil    bool
	openPanic   bool
	openError   error
}

func (relay *testRelay) Open(_ context.Context, request RelayOpenRequest) (RelayConnection, error) {
	if relay.openPanic {
		panic("raw-open-panic-canary")
	}
	if relay.typedNil {
		return (*testRelayConnection)(nil), nil
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.requests = append(relay.requests, request)
	if len(relay.connections) == 0 {
		return nil, relay.openError
	}
	connection := relay.connections[0]
	relay.connections = relay.connections[1:]
	return connection, relay.openError
}

type testRelayConnection struct {
	mu             sync.Mutex
	response       []byte
	requests       [][]byte
	entered        chan struct{}
	release        chan struct{}
	closeFailures  int
	closeCalls     atomic.Int32
	inflight       atomic.Int32
	maxInflight    atomic.Int32
	roundTripCalls atomic.Int32
}

func (connection *testRelayConnection) RoundTrip(ctx context.Context, request credentialmemory.BorrowedView, response credentialmemory.CredentialSink) error {
	connection.roundTripCalls.Add(1)
	current := connection.inflight.Add(1)
	defer connection.inflight.Add(-1)
	for {
		maximum := connection.maxInflight.Load()
		if current <= maximum || connection.maxInflight.CompareAndSwap(maximum, current) {
			break
		}
	}
	if request == nil || request.Len() == 0 {
		return errors.New("empty request")
	}
	requestSink := &testCaptureSink{maximum: credentialprotocol.SSHAgentMaxFrameBytes}
	if err := request.WriteTo(ctx, requestSink); err != nil {
		return err
	}
	connection.mu.Lock()
	connection.requests = append(connection.requests, append([]byte(nil), requestSink.value...))
	connection.mu.Unlock()
	if connection.entered != nil {
		select {
		case <-connection.entered:
		default:
			close(connection.entered)
		}
	}
	if connection.release != nil {
		select {
		case <-connection.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return response.WriteCredential(connection.response)
}

func (connection *testRelayConnection) Close(context.Context) error {
	call := int(connection.closeCalls.Add(1))
	if call <= connection.closeFailures {
		return errors.New("raw-relay-close-canary")
	}
	return nil
}

func (connection *testRelayConnection) lastRequest() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if len(connection.requests) == 0 {
		return nil
	}
	return append([]byte(nil), connection.requests[len(connection.requests)-1]...)
}

type testRead struct {
	payload []byte
	eof     bool
}

type testClientConnection struct {
	mu            sync.Mutex
	digest        [32]byte
	reads         []testRead
	writes        []byte
	readEntered   chan struct{}
	writeDone     chan struct{}
	closedDone    chan struct{}
	blockRead     bool
	closeError    bool
	readCalls     atomic.Int32
	shutdownCalls atomic.Int32
	closeCalls    atomic.Int32
}

func (connection *testClientConnection) SHA256() [32]byte {
	if connection.digest == ([32]byte{}) {
		return [32]byte{1}
	}
	return connection.digest
}

func (connection *testClientConnection) Read(ctx context.Context, sink credentialmemory.CredentialSink) (credentialclient.SSHIOResult, error) {
	connection.readCalls.Add(1)
	if connection.readEntered != nil {
		select {
		case <-connection.readEntered:
		default:
			close(connection.readEntered)
		}
	}
	if connection.blockRead {
		<-ctx.Done()
		return credentialclient.SSHIOResult{}, ctx.Err()
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if len(connection.reads) == 0 {
		return credentialclient.NewSSHIOResult(0, true, false)
	}
	read := connection.reads[0]
	connection.reads = connection.reads[1:]
	if read.eof {
		return credentialclient.NewSSHIOResult(0, true, false)
	}
	if err := sink.WriteCredential(read.payload); err != nil {
		return credentialclient.SSHIOResult{}, err
	}
	return credentialclient.NewSSHIOResult(uint64(len(read.payload)), false, false)
}

func (connection *testClientConnection) Write(ctx context.Context, source credentialmemory.BorrowedView) (credentialclient.SSHIOResult, error) {
	sink := &testCaptureSink{maximum: credentialprotocol.SSHAgentMaxFrameBytes}
	if err := source.WriteTo(ctx, sink); err != nil {
		return credentialclient.SSHIOResult{}, err
	}
	connection.mu.Lock()
	connection.writes = append(connection.writes, sink.value...)
	connection.mu.Unlock()
	if connection.writeDone != nil {
		select {
		case <-connection.writeDone:
		default:
			close(connection.writeDone)
		}
	}
	return credentialclient.NewSSHIOResult(uint64(len(sink.value)), false, false)
}

func (connection *testClientConnection) Shutdown(context.Context, credentialclient.SSHShutdownDirection) error {
	connection.shutdownCalls.Add(1)
	return nil
}

func (connection *testClientConnection) Close(context.Context) error {
	connection.closeCalls.Add(1)
	if connection.closedDone != nil {
		select {
		case <-connection.closedDone:
		default:
			close(connection.closedDone)
		}
	}
	if connection.closeError {
		return errors.New("raw-guest-close-canary")
	}
	return nil
}

func (connection *testClientConnection) written() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return append([]byte(nil), connection.writes...)
}

type testCaptureSink struct {
	maximum int
	value   []byte
}

type panickingContext struct{}

func (panickingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panickingContext) Done() <-chan struct{}       { panic("raw-context-canary") }
func (panickingContext) Err() error                  { return nil }
func (panickingContext) Value(any) any               { return nil }

func (sink *testCaptureSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *testCaptureSink) WriteCredential(value []byte) error {
	if len(value) > sink.maximum-len(sink.value) {
		return errors.New("overflow")
	}
	sink.value = append(sink.value, value...)
	return nil
}
