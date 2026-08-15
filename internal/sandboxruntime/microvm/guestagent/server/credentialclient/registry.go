package credentialclient

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrExtensionFactoryRequired = errors.New("credential client extension factory is required")
	ErrExtensionFactoryContract = errors.New("credential client extension factory return contract is invalid")
)

// ExtensionRegistration is one immutable-registry construction input.
type ExtensionRegistration struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Factory    ExtensionFactory
}

func (ExtensionRegistration) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionRegistration) MarshalText() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionRegistration) String() string   { return "credentialclient.live[redacted]" }
func (ExtensionRegistration) GoString() string { return "credentialclient.live[redacted]" }
func (ExtensionRegistration) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

// ExtensionFactory opens service-lifetime state for one configured extension.
type ExtensionFactory interface {
	Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error)
}

// ExtensionOpenRequest is the descriptor snapshot for one configured
// extension. The client seam deliberately exposes no helper-style host.
type ExtensionOpenRequest struct {
	Descriptor credentialprotocol.ExtensionDescriptor
}

func (ExtensionOpenRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionOpenRequest) MarshalText() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionOpenRequest) String() string   { return "credentialclient.live[redacted]" }
func (ExtensionOpenRequest) GoString() string { return "credentialclient.live[redacted]" }
func (ExtensionOpenRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

// ExtensionSession handles only packets claimed by its frozen descriptor.
type ExtensionSession interface {
	Handle(context.Context, ExtensionPacket) error
	Close(context.Context) error
}

type extensionRegistration struct {
	descriptor credentialprotocol.ExtensionDescriptor
	factory    ExtensionFactory
}

// ExtensionRegistry is an immutable, construction-time extension set.
type ExtensionRegistry struct {
	registrations []extensionRegistration
}

func (ExtensionRegistry) MarshalJSON() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionRegistry) MarshalText() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}

func (ExtensionRegistry) String() string   { return "credentialclient.live[redacted]" }
func (ExtensionRegistry) GoString() string { return "credentialclient.live[redacted]" }
func (ExtensionRegistry) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

// NewExtensionRegistry validates, snapshots, and freezes a complete canonical
// registration set. Input order must already be ascending by extension ID.
func NewExtensionRegistry(registrations ...ExtensionRegistration) (*ExtensionRegistry, error) {
	if len(registrations) > credentialprotocol.MaxExtensions {
		return nil, credentialprotocol.ErrExtensionSetTooLarge
	}

	result := &ExtensionRegistry{
		registrations: make([]extensionRegistration, len(registrations)),
	}
	claimedModes := make(map[credentialprotocol.DeliveryMode]struct{}, len(registrations))
	claimedPackets := make(map[credentialprotocol.PacketType]struct{}, len(registrations))
	for index, registration := range registrations {
		if err := credentialprotocol.ValidateExtensionDescriptor(registration.Descriptor); err != nil {
			return nil, err
		}
		if !configuredDependency(registration.Factory) {
			return nil, ErrExtensionFactoryRequired
		}
		if index > 0 {
			previousID := registrations[index-1].Descriptor.ID
			if previousID == registration.Descriptor.ID {
				return nil, credentialprotocol.ErrExtensionSetDuplicate
			}
			if previousID > registration.Descriptor.ID {
				return nil, credentialprotocol.ErrExtensionSetOrder
			}
		}
		for _, mode := range registration.Descriptor.Modes {
			if _, exists := claimedModes[mode]; exists {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedModes[mode] = struct{}{}
		}
		for _, packetType := range registration.Descriptor.AgentToHelperPacketTypes {
			if _, exists := claimedPackets[packetType]; exists {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = struct{}{}
		}
		for _, packetType := range registration.Descriptor.HelperToAgentPacketTypes {
			if _, exists := claimedPackets[packetType]; exists {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = struct{}{}
		}
		result.registrations[index] = extensionRegistration{
			descriptor: credentialprotocol.CloneExtensionDescriptor(registration.Descriptor),
			factory:    registration.Factory,
		}
	}
	return result, nil
}

// Descriptors returns a fresh deep copy in canonical extension-ID order.
func (registry *ExtensionRegistry) Descriptors() []credentialprotocol.ExtensionDescriptor {
	if registry == nil {
		return nil
	}
	descriptors := make([]credentialprotocol.ExtensionDescriptor, len(registry.registrations))
	for index, registration := range registry.registrations {
		descriptors[index] = credentialprotocol.CloneExtensionDescriptor(registration.descriptor)
	}
	return descriptors
}

// openExtension applies the frozen factory return matrix. The supplied
// context is also the already-bounded cleanup context for a malformed return;
// this helper never detaches or creates an unbounded replacement context.
func openExtension(ctx context.Context, factory ExtensionFactory, request ExtensionOpenRequest) (ExtensionSession, error) {
	if !configuredDependency(factory) {
		return nil, ErrExtensionFactoryRequired
	}
	if err := credentialprotocol.ValidateExtensionDescriptor(request.Descriptor); err != nil {
		return nil, err
	}
	request.Descriptor = credentialprotocol.CloneExtensionDescriptor(request.Descriptor)
	session, err := factory.Open(ctx, request)
	if err == nil {
		if !configuredDependency(session) {
			return nil, ErrExtensionFactoryContract
		}
		return session, nil
	}
	if session == nil {
		return nil, err
	}
	closeInvalidExtensionSession(ctx, session)
	return nil, ErrExtensionFactoryContract
}

func closeInvalidExtensionSession(ctx context.Context, session ExtensionSession) {
	defer func() {
		_ = recover()
	}()
	_ = session.Close(ctx)
}

// configuredDependency rejects nil-capable dynamic nils without invoking a
// method on the candidate. Interface values are recursively unwrapped.
func configuredDependency(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && reflected.Kind() == reflect.Interface {
		if reflected.IsNil() {
			return false
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() {
		return false
	}
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return !reflected.IsNil()
	default:
		return true
	}
}
