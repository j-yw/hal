package credentialhelper

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type factoryFunc func(context.Context, ExtensionOpenRequest) (ExtensionSession, error)

func (factory factoryFunc) Open(ctx context.Context, request ExtensionOpenRequest) (ExtensionSession, error) {
	return factory(ctx, request)
}

type pointerFactory struct{}

func (*pointerFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return nil, nil
}

type mapFactory map[string]string

func (mapFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return nil, nil
}

type sliceFactory []string

func (sliceFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return nil, nil
}

type channelFactory chan struct{}

func (channelFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return nil, nil
}

type fakeSession struct {
	closeCalls int
	closeCtx   context.Context
}

func (*fakeSession) Prepare(context.Context, ExtensionPrepareRequest) (ExtensionPrepareResult, error) {
	return ExtensionPrepareResult{}, nil
}
func (*fakeSession) BindExec(context.Context, ExtensionExecRequest) (ExtensionExecResult, error) {
	return ExtensionExecResult{}, nil
}
func (*fakeSession) Renew(context.Context, ExtensionRenewRequest) error { return nil }
func (*fakeSession) Revoke(context.Context, ExtensionRevokeRequest) (ExtensionCleanupResult, error) {
	return ExtensionCleanupResult{}, nil
}
func (session *fakeSession) Close(ctx context.Context) error {
	session.closeCalls++
	session.closeCtx = ctx
	return nil
}

func validFactory() ExtensionFactory {
	return factoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) { return nil, nil })
}

func registration(descriptor credentialprotocol.ExtensionDescriptor) ExtensionRegistration {
	return ExtensionRegistration{Descriptor: descriptor, Factory: validFactory()}
}

func TestNewExtensionRegistryRejectsNilAndTypedNilFactories(t *testing.T) {
	var pointer *pointerFactory
	var mapValue mapFactory
	var sliceValue sliceFactory
	var functionValue factoryFunc
	var channelValue channelFactory

	tests := []struct {
		name    string
		factory ExtensionFactory
	}{
		{name: "nil interface", factory: nil},
		{name: "typed nil pointer", factory: pointer},
		{name: "typed nil map", factory: mapValue},
		{name: "typed nil slice", factory: sliceValue},
		{name: "typed nil function", factory: functionValue},
		{name: "typed nil channel", factory: channelValue},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewExtensionRegistry(ExtensionRegistration{
				Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
				Factory:    test.factory,
			})
			if !errors.Is(err, ErrExtensionFactoryRequired) {
				t.Fatalf("error = %v, want %v", err, ErrExtensionFactoryRequired)
			}
		})
	}
}

func TestNewExtensionRegistryRejectsInvalidDescriptorsAndClaims(t *testing.T) {
	ssh := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	modeOnly := credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}
	packetOnly := credentialprotocol.ExtensionDescriptor{ID: "zulu-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}

	tests := []struct {
		name          string
		registrations []ExtensionRegistration
		want          error
	}{
		{name: "empty ID", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{})}, want: credentialprotocol.ErrInvalidExtensionID},
		{name: "noncanonical ID", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: " alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}})}, want: credentialprotocol.ErrInvalidExtensionID},
		{name: "empty claims", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1"})}, want: credentialprotocol.ErrEmptyExtensionDescriptor},
		{name: "unknown mode", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{99}})}, want: credentialprotocol.ErrUnknownDeliveryMode},
		{name: "unknown packet", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{99}})}, want: credentialprotocol.ErrUnknownPacketType},
		{name: "reserved core mode", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeFileTmpfs}})}, want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "reserved core packet", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeResponse}})}, want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "noncanonical descriptor catalog", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent, credentialprotocol.DeliveryModeSSHAgent}})}, want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "noncanonical packet catalog", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD, credentialprotocol.PacketTypeSSHAcceptedFD}})}, want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "wrong packet direction", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", AgentToHelperPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}})}, want: credentialprotocol.ErrExtensionPacketDirection},
		{name: "locked descriptor mismatch", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: credentialprotocol.ExtensionIDSSHRelayV1, Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}})}, want: credentialprotocol.ErrLockedExtensionDescriptor},
		{name: "duplicate ID", registrations: []ExtensionRegistration{registration(modeOnly), registration(modeOnly)}, want: credentialprotocol.ErrExtensionSetDuplicate},
		{name: "duplicate mode", registrations: []ExtensionRegistration{registration(modeOnly), registration(credentialprotocol.ExtensionDescriptor{ID: "beta-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}})}, want: credentialprotocol.ErrExtensionSetDuplicateClaim},
		{name: "duplicate packet claim", registrations: []ExtensionRegistration{registration(credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}), registration(packetOnly)}, want: credentialprotocol.ErrExtensionSetDuplicateClaim},
		{name: "descending IDs", registrations: []ExtensionRegistration{registration(packetOnly), registration(modeOnly)}, want: credentialprotocol.ErrExtensionSetOrder},
		{name: "byte duplicate registrations", registrations: []ExtensionRegistration{registration(ssh), registration(credentialprotocol.CloneExtensionDescriptor(ssh))}, want: credentialprotocol.ErrExtensionSetDuplicate},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewExtensionRegistry(test.registrations...)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewExtensionRegistryDoesNotInvokeFactory(t *testing.T) {
	factory := factoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
		panic("registry construction invoked extension factory")
	})
	registry, err := NewExtensionRegistry(ExtensionRegistration{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		Factory:    factory,
	})
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	if len(registry.Descriptors()) != 1 {
		t.Fatalf("Descriptors() = %#v", registry.Descriptors())
	}
}

func TestExtensionRegistrySnapshotsAreImmutableAndCanonical(t *testing.T) {
	firstDescriptor := credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}
	secondDescriptor := credentialprotocol.ExtensionDescriptor{ID: "zulu-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}
	registrations := []ExtensionRegistration{registration(firstDescriptor), registration(secondDescriptor)}
	want := credentialprotocol.CloneExtensionDescriptors([]credentialprotocol.ExtensionDescriptor{firstDescriptor, secondDescriptor})

	registry, err := NewExtensionRegistry(registrations...)
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	registrations[0].Descriptor.ID = "mutated-v1"
	registrations[0].Descriptor.Modes[0] = 99
	registrations[1].Descriptor.HelperToAgentPacketTypes[0] = 99

	first := registry.Descriptors()
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Descriptors() = %#v, want %#v", first, want)
	}
	first[0].ID = "mutated-again-v1"
	first[0].Modes[0] = 99
	first[1].HelperToAgentPacketTypes[0] = 99
	if second := registry.Descriptors(); !reflect.DeepEqual(second, want) {
		t.Fatalf("second Descriptors() = %#v, want %#v", second, want)
	}

	const readers = 32
	var wait sync.WaitGroup
	wait.Add(readers)
	for index := 0; index < readers; index++ {
		go func() {
			defer wait.Done()
			for read := 0; read < 100; read++ {
				got := registry.Descriptors()
				if !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent Descriptors() = %#v", got)
					return
				}
				got[0].Modes[0] = 99
			}
		}()
	}
	wait.Wait()
}

func TestEmptyAndNilExtensionRegistriesDescribeNoExtensions(t *testing.T) {
	registry, err := NewExtensionRegistry()
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	if descriptors := registry.Descriptors(); len(descriptors) != 0 {
		t.Fatalf("Descriptors() = %#v, want empty", descriptors)
	}
	var nilRegistry *ExtensionRegistry
	if descriptors := nilRegistry.Descriptors(); len(descriptors) != 0 {
		t.Fatalf("nil Descriptors() = %#v, want empty", descriptors)
	}
}

func TestExtensionRegistryExposesOnlyDescriptors(t *testing.T) {
	typeOf := reflect.TypeOf((*ExtensionRegistry)(nil))
	method, ok := typeOf.MethodByName("Descriptors")
	if !ok || method.Type.NumIn() != 1 || method.Type.NumOut() != 1 || method.Type.Out(0) != reflect.TypeOf([]credentialprotocol.ExtensionDescriptor{}) {
		t.Fatalf("Descriptors method = %#v", method)
	}
	for _, forbidden := range []string{"Register", "MustRegister", "Lookup", "Factory", "CloneWithAdditions"} {
		if _, exists := typeOf.MethodByName(forbidden); exists {
			t.Errorf("ExtensionRegistry exposes forbidden method %s", forbidden)
		}
	}
}

func TestExtensionFactoryReturnMatrix(t *testing.T) {
	ordinaryFailure := errors.New("safe extension open failure")

	t.Run("non-nil value and nil error succeeds", func(t *testing.T) {
		session := &fakeSession{}
		got, err := resolveExtensionOpenResult(context.Background(), session, nil)
		if err != nil || got != session || session.closeCalls != 0 {
			t.Fatalf("result = %v, %v, close calls %d", got, err, session.closeCalls)
		}
	})

	t.Run("nil value and nil error violates contract", func(t *testing.T) {
		got, err := resolveExtensionOpenResult(context.Background(), nil, nil)
		if got != nil || !errors.Is(err, ErrExtensionFactoryContract) {
			t.Fatalf("result = %v, %v", got, err)
		}
	})

	t.Run("typed nil value and nil error violates contract", func(t *testing.T) {
		var session *fakeSession
		got, err := resolveExtensionOpenResult(context.Background(), session, nil)
		if got != nil || !errors.Is(err, ErrExtensionFactoryContract) {
			t.Fatalf("result = %v, %v", got, err)
		}
	})

	t.Run("nil value and non-nil error is ordinary failure", func(t *testing.T) {
		got, err := resolveExtensionOpenResult(context.Background(), nil, ordinaryFailure)
		if got != nil || !errors.Is(err, ordinaryFailure) || errors.Is(err, ErrExtensionFactoryContract) {
			t.Fatalf("result = %v, %v", got, err)
		}
	})

	t.Run("non-nil value and non-nil error violates contract and closes", func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		cleanupCtx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		session := &fakeSession{}
		got, err := resolveExtensionOpenResult(cleanupCtx, session, ordinaryFailure)
		if got != nil || !errors.Is(err, ErrExtensionFactoryContract) || errors.Is(err, ordinaryFailure) {
			t.Fatalf("result = %v, %v", got, err)
		}
		gotDeadline, hasDeadline := session.closeCtx.Deadline()
		if session.closeCalls != 1 || session.closeCtx != cleanupCtx || !hasDeadline || !gotDeadline.Equal(deadline) {
			t.Fatalf("close calls = %d, context identity = %v, deadline = %v/%v", session.closeCalls, session.closeCtx == cleanupCtx, gotDeadline, hasDeadline)
		}
	})

	t.Run("typed nil value and non-nil error violates contract without call", func(t *testing.T) {
		var session *fakeSession
		got, err := resolveExtensionOpenResult(context.Background(), session, ordinaryFailure)
		if got != nil || !errors.Is(err, ErrExtensionFactoryContract) || errors.Is(err, ordinaryFailure) {
			t.Fatalf("result = %v, %v", got, err)
		}
	})
}

func TestExtensionRegistryRejectsTooManyRegistrationsBeforeRetention(t *testing.T) {
	registrations := make([]ExtensionRegistration, credentialprotocol.MaxExtensions+1)
	for index := range registrations {
		registrations[index] = registration(credentialprotocol.SSHRelayV1ExtensionDescriptor())
	}
	if _, err := NewExtensionRegistry(registrations...); !errors.Is(err, credentialprotocol.ErrExtensionSetTooLarge) {
		t.Fatalf("error = %v, want %v", err, credentialprotocol.ErrExtensionSetTooLarge)
	}
}
