package credentialhelper

import (
	"context"
	"errors"
	"reflect"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var ErrExtensionFactoryRequired = errors.New("credential helper extension factory is required")

var ErrExtensionFactoryContract = errors.New("credential helper extension factory contract violation")

// ExtensionRegistration binds one canonical descriptor to its process-local
// factory. Registration has no side effects.
type ExtensionRegistration struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Factory    ExtensionFactory
}

// ExtensionRegistry is an immutable process-local extension set.
type ExtensionRegistry struct {
	entries []extensionEntry
}

type extensionEntry struct {
	descriptor credentialprotocol.ExtensionDescriptor
	factory    ExtensionFactory
}

// NewExtensionRegistry validates and freezes the complete registration set.
// Input must already be in strictly increasing extension-ID order.
func NewExtensionRegistry(registrations ...ExtensionRegistration) (*ExtensionRegistry, error) {
	if len(registrations) > credentialprotocol.MaxExtensions {
		return nil, credentialprotocol.ErrExtensionSetTooLarge
	}

	entries := make([]extensionEntry, 0, len(registrations))
	claimedModes := make(map[credentialprotocol.DeliveryMode]struct{}, len(registrations))
	claimedPackets := make(map[credentialprotocol.PacketType]struct{}, len(registrations))
	var previousID credentialprotocol.ExtensionID
	for index, registration := range registrations {
		if !configuredDependency(registration.Factory) {
			return nil, ErrExtensionFactoryRequired
		}
		if err := credentialprotocol.ValidateExtensionDescriptor(registration.Descriptor); err != nil {
			return nil, err
		}
		if index > 0 {
			if previousID == registration.Descriptor.ID {
				return nil, credentialprotocol.ErrExtensionSetDuplicate
			}
			if previousID > registration.Descriptor.ID {
				return nil, credentialprotocol.ErrExtensionSetOrder
			}
		}
		for _, mode := range registration.Descriptor.Modes {
			if _, duplicate := claimedModes[mode]; duplicate {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedModes[mode] = struct{}{}
		}
		for _, packetType := range registration.Descriptor.AgentToHelperPacketTypes {
			if _, duplicate := claimedPackets[packetType]; duplicate {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = struct{}{}
		}
		for _, packetType := range registration.Descriptor.HelperToAgentPacketTypes {
			if _, duplicate := claimedPackets[packetType]; duplicate {
				return nil, credentialprotocol.ErrExtensionSetDuplicateClaim
			}
			claimedPackets[packetType] = struct{}{}
		}

		entries = append(entries, extensionEntry{
			descriptor: credentialprotocol.CloneExtensionDescriptor(registration.Descriptor),
			factory:    registration.Factory,
		})
		previousID = registration.Descriptor.ID
	}

	return &ExtensionRegistry{entries: entries}, nil
}

// Descriptors returns a fresh deep snapshot in canonical extension-ID order.
func (registry *ExtensionRegistry) Descriptors() []credentialprotocol.ExtensionDescriptor {
	if registry == nil || len(registry.entries) == 0 {
		return nil
	}
	descriptors := make([]credentialprotocol.ExtensionDescriptor, len(registry.entries))
	for index, entry := range registry.entries {
		descriptors[index] = credentialprotocol.CloneExtensionDescriptor(entry.descriptor)
	}
	return descriptors
}

// configuredDependency rejects nil interfaces and nil values of every
// nil-capable dynamic kind without calling a method on the candidate.
func configuredDependency(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

// resolveExtensionOpenResult applies the frozen factory return matrix. It is
// kept private until the service lifecycle is implemented by its owning slice.
func resolveExtensionOpenResult(cleanupCtx context.Context, session ExtensionSession, openErr error) (ExtensionSession, error) {
	configured := configuredDependency(session)
	if openErr == nil {
		if !configured {
			return nil, ErrExtensionFactoryContract
		}
		return session, nil
	}
	if session == nil {
		return nil, openErr
	}
	if !configured {
		return nil, ErrExtensionFactoryContract
	}
	_ = session.Close(cleanupCtx)
	return nil, ErrExtensionFactoryContract
}
