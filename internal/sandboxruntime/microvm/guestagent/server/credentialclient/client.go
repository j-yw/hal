package credentialclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	clientProcessContractVersion uint8 = 1
	clientProcessRole            uint8 = 2
	maxClientDescriptorBytes           = 1898
	clientCleanupTimeout               = 30 * time.Second
)

var errClientDescriptorWrite = errors.New("credential client descriptor write rejected")

// ClientOptions contains the complete construction-time dependency set.
// Helper is optional and default-off; a nil owner keeps helper send unaccepted.
type ClientOptions struct {
	Transport  Transport
	Policy     Policy
	Extensions *ExtensionRegistry
	Descriptor ClientProcessDescriptor
	Helper     HelperConnectionOwner
}

func (ClientOptions) MarshalJSON() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldDependency)
}
func (ClientOptions) MarshalText() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldDependency)
}
func (ClientOptions) MarshalBinary() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldDependency)
}
func (*ClientOptions) UnmarshalJSON([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldDependency)
}
func (*ClientOptions) UnmarshalText([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldDependency)
}
func (*ClientOptions) UnmarshalBinary([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldDependency)
}
func (ClientOptions) String() string   { return "credentialclient.live[redacted]" }
func (ClientOptions) GoString() string { return "credentialclient.live[redacted]" }
func (ClientOptions) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

// ClientProcessDescriptor is the narrow immutable D6-issued descriptor view.
// Implementations write their canonical form only into a bounded credential
// sink; the client retains only the independently verified digest.
type ClientProcessDescriptor interface {
	ContractVersion() uint8
	Role() uint8
	PolicySHA256() [32]byte
	Extensions() []credentialprotocol.ExtensionDescriptor
	EncodedLength() uint16
	SHA256() [32]byte
	WriteCanonical(credentialmemory.CredentialSink) error
}

// Client owns one unprivileged credential transport lifetime.
type Client struct {
	liveValue
	transport        Transport
	policy           Policy
	policyDescriptor PolicyDescriptor
	extensions       []credentialprotocol.ExtensionDescriptor
	descriptorSHA256 [32]byte
	helper           HelperConnectionOwner
	state            *clientState
}

func (Client) MarshalJSON() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (Client) MarshalText() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (Client) MarshalBinary() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (*Client) UnmarshalJSON([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (*Client) UnmarshalText([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (*Client) UnmarshalBinary([]byte) error {
	return clientError(ClientContractSerialization, ClientFieldLifecycle)
}
func (Client) String() string   { return "credentialclient.live[redacted]" }
func (Client) GoString() string { return "credentialclient.live[redacted]" }
func (Client) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

type clientPhase uint8

const (
	clientPhaseNew clientPhase = iota + 1
	clientPhaseServing
	clientPhaseDraining
	clientPhaseClosed
	clientPhaseTerminal
)

type openedClientExtension struct {
	descriptor credentialprotocol.ExtensionDescriptor
	session    ExtensionSession
}

type clientState struct {
	mu                 sync.Mutex
	phase              clientPhase
	serveCalled        bool
	closeStarted       bool
	transportClosed    bool
	opened             []openedClientExtension
	terminalError      error
	completion         chan struct{}
	admittedOperations sync.WaitGroup
}

type clientDescriptorSnapshot struct {
	contractVersion uint8
	role            uint8
	policySHA256    [32]byte
	extensions      []credentialprotocol.ExtensionDescriptor
	encodedLength   uint16
	sha256          [32]byte
}

// NewClient validates and snapshots every dependency before taking extension
// session ownership. No descriptor source or canonical descriptor bytes are
// retained after this function returns.
func NewClient(options ClientOptions) (*Client, error) {
	if !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Descriptor) || options.Extensions == nil {
		return nil, clientError(ClientContractDependency, ClientFieldDependency)
	}
	if options.Helper != nil && !configuredDependency(options.Helper) {
		return nil, clientError(ClientContractDependency, ClientFieldDependency)
	}
	var helper HelperConnectionOwner
	if configuredDependency(options.Helper) {
		helper = options.Helper
	}

	firstPolicy, panicked := readPolicyDescriptor(options.Policy)
	if panicked {
		return nil, clientError(ClientContractPanic, ClientFieldPolicy)
	}
	secondPolicy, panicked := readPolicyDescriptor(options.Policy)
	if panicked {
		return nil, clientError(ClientContractPanic, ClientFieldPolicy)
	}
	expectedPolicy := newClientPolicyDescriptor()
	if firstPolicy.ID() != secondPolicy.ID() || firstPolicy.SHA256() != secondPolicy.SHA256() || firstPolicy.ID() != expectedPolicy.ID() || firstPolicy.SHA256() != expectedPolicy.SHA256() {
		return nil, clientError(ClientContractPolicy, ClientFieldPolicy)
	}

	firstExtensions := options.Extensions.Descriptors()
	secondExtensions := options.Extensions.Descriptors()
	if !clientDescriptorSetsEqual(firstExtensions, secondExtensions) || !validClientDescriptorSet(firstExtensions) {
		return nil, clientError(ClientContractDescriptor, ClientFieldExtension)
	}
	stableExtensions := credentialprotocol.CloneExtensionDescriptors(firstExtensions)

	firstDescriptor, panicked := readClientDescriptor(options.Descriptor)
	if panicked {
		return nil, clientError(ClientContractPanic, ClientFieldDescriptor)
	}
	secondDescriptor, panicked := readClientDescriptor(options.Descriptor)
	if panicked {
		return nil, clientError(ClientContractPanic, ClientFieldDescriptor)
	}
	if !clientDescriptorSnapshotsEqual(firstDescriptor, secondDescriptor) ||
		firstDescriptor.contractVersion != clientProcessContractVersion ||
		firstDescriptor.role != clientProcessRole ||
		firstDescriptor.policySHA256 != firstPolicy.SHA256() ||
		!clientDescriptorSetsEqual(firstDescriptor.extensions, stableExtensions) ||
		firstDescriptor.encodedLength == 0 || firstDescriptor.encodedLength > maxClientDescriptorBytes ||
		firstDescriptor.sha256 == ([32]byte{}) {
		return nil, clientError(ClientContractDescriptor, ClientFieldDescriptor)
	}

	descriptorDigest, descriptorFailure := pinClientDescriptor(options.Descriptor, int(firstDescriptor.encodedLength))
	if descriptorFailure != nil {
		return nil, descriptorFailure
	}
	if descriptorDigest != firstDescriptor.sha256 {
		return nil, clientError(ClientContractDescriptor, ClientFieldDescriptor)
	}

	opened, openFailure := openClientExtensions(options.Extensions)
	if openFailure != nil {
		return nil, openFailure
	}

	return &Client{
		transport:        options.Transport,
		policy:           options.Policy,
		policyDescriptor: firstPolicy,
		extensions:       credentialprotocol.CloneExtensionDescriptors(stableExtensions),
		descriptorSHA256: descriptorDigest,
		helper:           helper,
		state: &clientState{
			phase:      clientPhaseNew,
			opened:     opened,
			completion: make(chan struct{}),
		},
	}, nil
}

// Serve establishes the sole service lifetime and waits for its shared drain.
// Operational packet dispatch is layered onto this lifecycle owner without a
// second Serve or cleanup path.
func (client *Client) Serve(ctx context.Context) error {
	if ctx == nil || client == nil || client.state == nil {
		return clientError(ClientContractDependency, ClientFieldLifecycle)
	}
	state := client.state
	state.mu.Lock()
	if state.serveCalled || state.phase != clientPhaseNew {
		state.mu.Unlock()
		return clientError(ClientContractServeState, ClientFieldLifecycle)
	}
	state.serveCalled = true
	state.phase = clientPhaseServing
	completion := state.completion
	state.mu.Unlock()
	if _, operational := client.transport.(authenticatedTransport); operational {
		dispatchErr := client.serveCredentialLifecycle(ctx)
		client.startDrain()
		<-completion
		if cleanupErr := client.latchedError(); cleanupErr != nil {
			return cleanupErr
		}
		return dispatchErr
	}

	select {
	case <-completion:
		return client.latchedError()
	case <-ctx.Done():
		client.startDrain()
		<-completion
		return client.latchedError()
	}
}

// ServeStarted reports whether the sole Serve entrypoint has accepted lifecycle
// ownership. It exists only so the process-local root server can serialize an
// immediate shutdown behind that ownership handoff.
func (client *Client) ServeStarted() bool {
	if client == nil || client.state == nil {
		return false
	}
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	return client.state.serveCalled
}

// Close starts or joins the sole internally bounded drain. Caller cancellation
// never shortens or abandons cleanup.
func (client *Client) Close(ctx context.Context) error {
	if ctx == nil || client == nil || client.state == nil {
		return clientError(ClientContractDependency, ClientFieldLifecycle)
	}
	client.startDrain()
	<-client.state.completion
	return client.latchedError()
}

func (client *Client) startDrain() {
	state := client.state
	state.mu.Lock()
	if state.closeStarted {
		state.mu.Unlock()
		return
	}
	state.closeStarted = true
	state.phase = clientPhaseDraining
	state.mu.Unlock()

	cleanupCtx, cancel := context.WithTimeout(context.Background(), clientCleanupTimeout)
	cleanupFailed := false
	for index := len(state.opened) - 1; index >= 0; index-- {
		if closeClientExtension(cleanupCtx, state.opened[index].session) {
			cleanupFailed = true
		}
	}
	if closeClientHelper(cleanupCtx, client.helper) {
		cleanupFailed = true
	}

	state.mu.Lock()
	state.transportClosed = true
	state.mu.Unlock()
	if closeClientTransport(cleanupCtx, client.transport) {
		cleanupFailed = true
	}
	client.state.admittedOperations.Wait()
	if cleanupCtx.Err() != nil {
		cleanupFailed = true
	}
	cancel()

	state.mu.Lock()
	if cleanupFailed {
		state.phase = clientPhaseTerminal
		state.terminalError = clientError(ClientContractCleanup, ClientFieldLifecycle)
	} else {
		state.phase = clientPhaseClosed
	}
	close(state.completion)
	state.mu.Unlock()
}

func (client *Client) latchedError() error {
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	return client.state.terminalError
}

func readPolicyDescriptor(policy Policy) (descriptor PolicyDescriptor, panicked bool) {
	defer func() {
		if recover() != nil {
			descriptor = PolicyDescriptor{}
			panicked = true
		}
	}()
	return policy.Descriptor(), false
}

func readClientDescriptor(source ClientProcessDescriptor) (snapshot clientDescriptorSnapshot, panicked bool) {
	defer func() {
		if recover() != nil {
			snapshot = clientDescriptorSnapshot{}
			panicked = true
		}
	}()
	snapshot = clientDescriptorSnapshot{
		contractVersion: source.ContractVersion(),
		role:            source.Role(),
		policySHA256:    source.PolicySHA256(),
		extensions:      credentialprotocol.CloneExtensionDescriptors(source.Extensions()),
		encodedLength:   source.EncodedLength(),
		sha256:          source.SHA256(),
	}
	return snapshot, false
}

func clientDescriptorSnapshotsEqual(first, second clientDescriptorSnapshot) bool {
	return first.contractVersion == second.contractVersion &&
		first.role == second.role &&
		first.policySHA256 == second.policySHA256 &&
		first.encodedLength == second.encodedLength &&
		first.sha256 == second.sha256 &&
		clientDescriptorSetsEqual(first.extensions, second.extensions)
}

func clientDescriptorSetsEqual(first, second []credentialprotocol.ExtensionDescriptor) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if !credentialprotocol.ExtensionDescriptorEqual(first[index], second[index]) {
			return false
		}
	}
	return true
}

func validClientDescriptorSet(descriptors []credentialprotocol.ExtensionDescriptor) bool {
	if len(descriptors) > credentialprotocol.MaxExtensions {
		return false
	}
	for index, descriptor := range descriptors {
		if credentialprotocol.ValidateExtensionDescriptor(descriptor) != nil {
			return false
		}
		if index > 0 && descriptors[index-1].ID >= descriptor.ID {
			return false
		}
	}
	return true
}

type exactClientDescriptorSink struct {
	mu     sync.Mutex
	target []byte
	offset int
	hash   hash.Hash
	active bool
	failed bool
}

func (sink *exactClientDescriptorSink) MaxCredentialBytes() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.active {
		return 0
	}
	return len(sink.target)
}

func (sink *exactClientDescriptorSink) WriteCredential(source []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.active || sink.failed || len(source) > len(sink.target)-sink.offset {
		sink.failed = true
		return errClientDescriptorWrite
	}
	copy(sink.target[sink.offset:], source)
	_, _ = sink.hash.Write(source)
	sink.offset += len(source)
	return nil
}

func (sink *exactClientDescriptorSink) seal() (int, [32]byte, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var digest [32]byte
	if sink.hash != nil {
		copy(digest[:], sink.hash.Sum(nil))
	}
	offset := sink.offset
	failed := sink.failed
	sink.active = false
	sink.target = nil
	sink.hash = nil
	return offset, digest, failed
}

func pinClientDescriptor(source ClientProcessDescriptor, length int) ([32]byte, *ClientContractError) {
	mapping, err := credentialmemory.NewLockedMapping(length)
	if err != nil {
		return [32]byte{}, clientError(ClientContractDescriptor, ClientFieldDescriptor)
	}
	var digest [32]byte
	var writeFailed bool
	var panicked bool
	loadErr := mapping.Load(context.Background(), func(region []byte) (written int, result error) {
		sink := &exactClientDescriptorSink{target: region, hash: sha256.New(), active: true}
		sealed := false
		defer func() {
			if recover() != nil {
				panicked = true
				result = errClientDescriptorWrite
				written = 0
			}
			if !sealed {
				sink.seal()
			}
		}()
		if err := source.WriteCanonical(sink); err != nil {
			writeFailed = true
			return 0, errClientDescriptorWrite
		}
		offset, sealedDigest, failed := sink.seal()
		sealed = true
		if failed || offset != len(region) {
			writeFailed = true
			return 0, errClientDescriptorWrite
		}
		digest = sealedDigest
		return offset, nil
	})
	destroyErr := mapping.Destroy()
	if destroyErr != nil {
		return [32]byte{}, clientError(ClientContractCleanup, ClientFieldDescriptor)
	}
	if panicked {
		return [32]byte{}, clientError(ClientContractPanic, ClientFieldDescriptor)
	}
	if loadErr != nil || writeFailed {
		return [32]byte{}, clientError(ClientContractDescriptor, ClientFieldDescriptor)
	}
	return digest, nil
}

func openClientExtensions(registry *ExtensionRegistry) ([]openedClientExtension, *ClientContractError) {
	opened := make([]openedClientExtension, 0, len(registry.registrations))
	for _, registration := range registry.registrations {
		request := ExtensionOpenRequest{Descriptor: credentialprotocol.CloneExtensionDescriptor(registration.descriptor)}
		operationCtx, operationCancel := context.WithTimeout(context.Background(), clientCleanupTimeout)
		session, openErr, contractFailure, panicked := callClientExtensionFactory(operationCtx, registration.factory, request)
		operationExpired := operationCtx.Err() != nil
		operationCancel()
		if panicked || openErr != nil || contractFailure || operationExpired {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), clientCleanupTimeout)
			cleanupFailed := false
			if (openErr != nil || operationExpired) && session != nil && closeClientExtension(cleanupCtx, session) {
				cleanupFailed = true
			}
			for index := len(opened) - 1; index >= 0; index-- {
				if closeClientExtension(cleanupCtx, opened[index].session) {
					cleanupFailed = true
				}
			}
			if cleanupCtx.Err() != nil {
				cleanupFailed = true
			}
			cleanupCancel()
			if cleanupFailed {
				return nil, clientError(ClientContractCleanup, ClientFieldExtension)
			}
			if panicked {
				return nil, clientError(ClientContractPanic, ClientFieldExtension)
			}
			return nil, clientError(ClientContractExtension, ClientFieldExtension)
		}
		opened = append(opened, openedClientExtension{
			descriptor: credentialprotocol.CloneExtensionDescriptor(registration.descriptor),
			session:    session,
		})
	}
	return opened, nil
}

func callClientExtensionFactory(ctx context.Context, factory ExtensionFactory, request ExtensionOpenRequest) (session ExtensionSession, openErr error, contractFailure bool, panicked bool) {
	defer func() {
		if recover() != nil {
			session = nil
			openErr = nil
			contractFailure = false
			panicked = true
		}
	}()
	session, openErr = factory.Open(ctx, request)
	if openErr == nil {
		if !configuredDependency(session) {
			return session, nil, true, false
		}
		return session, nil, false, false
	}
	return session, openErr, session != nil, false
}

func closeClientExtension(ctx context.Context, session ExtensionSession) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return session.Close(ctx) != nil
}

func closeClientHelper(ctx context.Context, helper HelperConnectionOwner) (failed bool) {
	if !configuredDependency(helper) {
		return false
	}
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return helper.Close(ctx) != nil
}

func closeClientTransport(ctx context.Context, transport Transport) (failed bool) {
	defer func() {
		if recover() != nil {
			failed = true
		}
	}()
	return transport.Close(ctx) != nil
}
