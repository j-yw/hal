package credentialclient

import (
	"context"
	"crypto/sha256"
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
)

func TestL8CredentialClientPinsDescriptorAndUsesSingleServeLifecycle(t *testing.T) {
	t.Parallel()

	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	descriptor := newLifecycleDescriptor(policy.descriptor, nil)
	transport := &lifecycleTransport{}
	client, err := NewClient(ClientOptions{
		Transport:  transport,
		Policy:     policy,
		Extensions: registry,
		Descriptor: descriptor,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if descriptor.projections.Load() != 12 || descriptor.writes.Load() != 1 {
		t.Fatalf("descriptor calls = projections %d writes %d, want 12/1", descriptor.projections.Load(), descriptor.writes.Load())
	}

	serveResult := make(chan error, 1)
	go func() { serveResult <- client.Serve(context.Background()) }()
	deadline := time.After(2 * time.Second)
	for {
		client.state.mu.Lock()
		serveCalled := client.state.serveCalled
		client.state.mu.Unlock()
		if serveCalled {
			break
		}
		select {
		case <-deadline:
			t.Fatal("first Serve did not establish the single-Serve latch")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := client.Serve(context.Background()); clientContractCode(err) != ClientContractServeState {
		t.Fatalf("second Serve error = %v, want serve-state", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	const closers = 16
	var wait sync.WaitGroup
	closeErrors := make(chan error, closers)
	for index := 0; index < closers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			closeErrors <- client.Close(canceled)
		}()
	}
	wait.Wait()
	close(closeErrors)
	for closeErr := range closeErrors {
		if closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}
	if err := <-serveResult; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if got := transport.closes.Load(); got != 1 {
		t.Fatalf("Transport.Close calls = %d, want 1", got)
	}
	if !transport.closeHadDeadline.Load() || transport.closeWasCanceled.Load() {
		t.Fatal("Transport.Close did not receive the live internal cleanup context")
	}
}

func TestL8CredentialClientOpensAndClosesExtensionsInCanonicalReverseOrder(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var events []string
	registrations := []ExtensionRegistration{
		{
			Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}},
			Factory:    &lifecycleFactory{id: "alpha", mu: &mu, events: &events},
		},
		{
			Descriptor: credentialprotocol.ExtensionDescriptor{ID: "beta-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}},
			Factory:    &lifecycleFactory{id: "beta", mu: &mu, events: &events},
		},
	}
	registry, err := NewExtensionRegistry(registrations...)
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	client, err := NewClient(ClientOptions{
		Transport:  &lifecycleTransport{},
		Policy:     policy,
		Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.descriptor, registry.Descriptors()),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"open:alpha", "open:beta", "close:beta", "close:alpha"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

func TestL8CredentialClientRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()

	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	descriptor := newLifecycleDescriptor(policy.descriptor, nil)
	var typedNilTransport *lifecycleTransport
	client, err := NewClient(ClientOptions{Transport: typedNilTransport, Policy: policy, Extensions: registry, Descriptor: descriptor})
	if client != nil || clientContractCode(err) != ClientContractDependency {
		t.Fatalf("NewClient(typed nil transport) = (%v, %v), want nil/dependency", client, err)
	}
}

func TestL8CredentialClientConstructorRollbackIsReverseAndSanitized(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name          string
		firstCloseErr error
		wantCode      ClientContractErrorCode
	}{
		{name: "ordinary open failure", wantCode: ClientContractExtension},
		{name: "rollback failure", firstCloseErr: errors.New("raw close canary"), wantCode: ClientContractCleanup},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			var events []string
			first := &scriptedLifecycleFactory{id: "alpha", mu: &mu, events: &events, closeErr: test.firstCloseErr}
			second := &scriptedLifecycleFactory{id: "beta", mu: &mu, events: &events, openErr: errors.New("raw open canary")}
			registry, err := NewExtensionRegistry(
				ExtensionRegistration{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}, Factory: first},
				ExtensionRegistration{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "beta-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}, Factory: second},
			)
			if err != nil {
				t.Fatalf("NewExtensionRegistry() error = %v", err)
			}
			policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
			transport := &lifecycleTransport{}
			client, err := NewClient(ClientOptions{
				Transport:  transport,
				Policy:     policy,
				Extensions: registry,
				Descriptor: newLifecycleDescriptor(policy.descriptor, registry.Descriptors()),
			})
			if client != nil || clientContractCode(err) != test.wantCode {
				t.Fatalf("NewClient() = (%v, %v), want nil/code %v", client, err, test.wantCode)
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatalf("NewClient() exposed dependency error: %v", err)
			}
			if got := transport.closes.Load(); got != 0 {
				t.Fatalf("constructor failure closed caller-owned transport %d times", got)
			}
			mu.Lock()
			defer mu.Unlock()
			want := []string{"open:alpha", "open:beta", "close:alpha"}
			if fmt.Sprint(events) != fmt.Sprint(want) {
				t.Fatalf("events = %v, want %v", events, want)
			}
		})
	}
}

func TestL8CredentialClientLiveValuesDoNotTraverseDependencies(t *testing.T) {
	t.Parallel()

	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	options := ClientOptions{
		Transport:  &leakingLifecycleTransport{secret: "transport-secret-canary"},
		Policy:     policy,
		Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.descriptor, nil),
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		formatted := fmt.Sprintf(format, options)
		if strings.Contains(formatted, "transport-secret-canary") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("ClientOptions format %q = %q", format, formatted)
		}
	}
	if encoded, err := json.Marshal(options); clientContractCode(err) != ClientContractSerialization || len(encoded) != 0 {
		t.Fatalf("json.Marshal(ClientOptions) = (%q, %v), want serialization denial", encoded, err)
	}
}

func TestL8CredentialClientDescriptorSinkExpiresBeforeConstructorReturns(t *testing.T) {
	t.Parallel()

	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	descriptor := newLifecycleDescriptor(policy.descriptor, nil)
	descriptor.retainSink = true
	client, err := NewClient(ClientOptions{
		Transport:  &lifecycleTransport{},
		Policy:     policy,
		Extensions: registry,
		Descriptor: descriptor,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer func() { _ = client.Close(context.Background()) }()
	if descriptor.retained == nil {
		t.Fatal("descriptor did not retain the test sink")
	}
	if got := descriptor.retained.MaxCredentialBytes(); got != 0 {
		t.Fatalf("expired sink MaxCredentialBytes() = %d, want 0", got)
	}
	if err := descriptor.retained.WriteCredential([]byte("after-return")); !errors.Is(err, errClientDescriptorWrite) {
		t.Fatalf("expired sink WriteCredential() error = %v, want static rejection", err)
	}
}

func TestL8CredentialClientDrainLatchesCleanupAndStillClosesTransport(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var events []string
	registry, err := NewExtensionRegistry(ExtensionRegistration{
		Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}},
		Factory: &scriptedLifecycleFactory{
			id: "alpha", mu: &mu, events: &events, closeErr: errors.New("raw drain canary"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := &lifecyclePolicy{descriptor: newClientPolicyDescriptor()}
	transport := &lifecycleTransport{}
	client, err := NewClient(ClientOptions{
		Transport:  transport,
		Policy:     policy,
		Extensions: registry,
		Descriptor: newLifecycleDescriptor(policy.descriptor, registry.Descriptors()),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	first := client.Close(context.Background())
	second := client.Close(context.Background())
	if clientContractCode(first) != ClientContractCleanup || clientContractCode(second) != ClientContractCleanup {
		t.Fatalf("Close errors = (%v, %v), want latched cleanup", first, second)
	}
	if strings.Contains(first.Error(), "canary") || strings.Contains(second.Error(), "canary") {
		t.Fatal("Close exposed raw cleanup failure")
	}
	if got := transport.closes.Load(); got != 1 {
		t.Fatalf("Transport.Close calls = %d, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(events) != fmt.Sprint([]string{"open:alpha", "close:alpha"}) {
		t.Fatalf("events = %v", events)
	}
}

type lifecyclePolicy struct{ descriptor PolicyDescriptor }

func (*lifecyclePolicy) Authorize(ClientPolicyRequest) (ClientPolicyDecision, error) {
	return newClientPolicyAllowDecision(), nil
}
func (policy *lifecyclePolicy) Descriptor() PolicyDescriptor { return policy.descriptor }

type lifecycleDescriptor struct {
	policy      PolicyDescriptor
	extensions  []credentialprotocol.ExtensionDescriptor
	encoded     []byte
	digest      [32]byte
	projections atomic.Uint32
	writes      atomic.Uint32
	retainSink  bool
	retained    credentialmemory.CredentialSink
}

func newLifecycleDescriptor(policy PolicyDescriptor, extensions []credentialprotocol.ExtensionDescriptor) *lifecycleDescriptor {
	encoded := []byte("canonical-client-descriptor")
	return &lifecycleDescriptor{
		policy:     policy,
		extensions: credentialprotocol.CloneExtensionDescriptors(extensions),
		encoded:    encoded,
		digest:     sha256.Sum256(encoded),
	}
}

func (descriptor *lifecycleDescriptor) ContractVersion() uint8 {
	descriptor.projections.Add(1)
	return 1
}
func (descriptor *lifecycleDescriptor) Role() uint8 {
	descriptor.projections.Add(1)
	return 2
}
func (descriptor *lifecycleDescriptor) PolicySHA256() [32]byte {
	descriptor.projections.Add(1)
	return descriptor.policy.SHA256()
}
func (descriptor *lifecycleDescriptor) Extensions() []credentialprotocol.ExtensionDescriptor {
	descriptor.projections.Add(1)
	return credentialprotocol.CloneExtensionDescriptors(descriptor.extensions)
}
func (descriptor *lifecycleDescriptor) EncodedLength() uint16 {
	descriptor.projections.Add(1)
	return uint16(len(descriptor.encoded))
}
func (descriptor *lifecycleDescriptor) SHA256() [32]byte {
	descriptor.projections.Add(1)
	return descriptor.digest
}
func (descriptor *lifecycleDescriptor) WriteCanonical(sink credentialmemory.CredentialSink) error {
	descriptor.writes.Add(1)
	if descriptor.retainSink {
		descriptor.retained = sink
	}
	return sink.WriteCredential(descriptor.encoded)
}

type lifecycleTransport struct {
	closes           atomic.Uint32
	closeHadDeadline atomic.Bool
	closeWasCanceled atomic.Bool
}

func (*lifecycleTransport) ReceiveController(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
	return ControllerPacket{}, errors.New("unexpected receive")
}
func (*lifecycleTransport) SendController(context.Context, ControllerSendPacket) error {
	return errors.New("unexpected send")
}
func (*lifecycleTransport) ReceiveHelper(context.Context, HelperReceiveRequest) (HelperPacket, error) {
	return HelperPacket{}, errors.New("unexpected receive")
}
func (*lifecycleTransport) SendHelper(context.Context, HelperSendPacket) error {
	return errors.New("unexpected send")
}
func (transport *lifecycleTransport) Close(ctx context.Context) error {
	transport.closes.Add(1)
	_, hasDeadline := ctx.Deadline()
	transport.closeHadDeadline.Store(hasDeadline)
	transport.closeWasCanceled.Store(ctx.Err() != nil)
	return nil
}

type lifecycleFactory struct {
	id     string
	mu     *sync.Mutex
	events *[]string
}

type scriptedLifecycleFactory struct {
	id       string
	mu       *sync.Mutex
	events   *[]string
	openErr  error
	closeErr error
}

func (factory *scriptedLifecycleFactory) Open(_ context.Context, _ ExtensionOpenRequest) (ExtensionSession, error) {
	factory.mu.Lock()
	*factory.events = append(*factory.events, "open:"+factory.id)
	factory.mu.Unlock()
	if factory.openErr != nil {
		return nil, factory.openErr
	}
	return &scriptedLifecycleSession{id: factory.id, mu: factory.mu, events: factory.events, closeErr: factory.closeErr}, nil
}

type scriptedLifecycleSession struct {
	id       string
	mu       *sync.Mutex
	events   *[]string
	closeErr error
}

func (*scriptedLifecycleSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (session *scriptedLifecycleSession) Close(context.Context) error {
	session.mu.Lock()
	*session.events = append(*session.events, "close:"+session.id)
	session.mu.Unlock()
	return session.closeErr
}

func (factory *lifecycleFactory) Open(_ context.Context, _ ExtensionOpenRequest) (ExtensionSession, error) {
	factory.mu.Lock()
	*factory.events = append(*factory.events, "open:"+factory.id)
	factory.mu.Unlock()
	return &lifecycleSession{id: factory.id, mu: factory.mu, events: factory.events}, nil
}

type lifecycleSession struct {
	id     string
	mu     *sync.Mutex
	events *[]string
}

func (*lifecycleSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (session *lifecycleSession) Close(context.Context) error {
	session.mu.Lock()
	*session.events = append(*session.events, "close:"+session.id)
	session.mu.Unlock()
	return nil
}

func clientContractCode(err error) ClientContractErrorCode {
	var contractError *ClientContractError
	if !errors.As(err, &contractError) {
		return 0
	}
	return contractError.Code()
}

type leakingLifecycleTransport struct{ secret string }

func (*leakingLifecycleTransport) ReceiveController(context.Context, ControllerReceiveRequest) (ControllerPacket, error) {
	return ControllerPacket{}, errors.New("unused")
}
func (*leakingLifecycleTransport) SendController(context.Context, ControllerSendPacket) error {
	return errors.New("unused")
}
func (*leakingLifecycleTransport) ReceiveHelper(context.Context, HelperReceiveRequest) (HelperPacket, error) {
	return HelperPacket{}, errors.New("unused")
}
func (*leakingLifecycleTransport) SendHelper(context.Context, HelperSendPacket) error {
	return errors.New("unused")
}
func (*leakingLifecycleTransport) Close(context.Context) error { return nil }
func (transport *leakingLifecycleTransport) String() string    { return transport.secret }
