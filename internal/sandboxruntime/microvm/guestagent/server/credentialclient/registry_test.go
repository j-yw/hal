package credentialclient

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestExtensionContractMethodAndFieldSetsAreExact(t *testing.T) {
	t.Parallel()

	assertInterfaceMethods(t, reflect.TypeOf((*ExtensionFactory)(nil)).Elem(), map[string]string{
		"Open": "func(context.Context, credentialclient.ExtensionOpenRequest) (credentialclient.ExtensionSession, error)",
	})
	assertInterfaceMethods(t, reflect.TypeOf((*ExtensionSession)(nil)).Elem(), map[string]string{
		"Close":  "func(context.Context) error",
		"Handle": "func(context.Context, credentialclient.ExtensionPacket) error",
	})
	assertStructFields(t, reflect.TypeOf(ExtensionRegistration{}), []fieldContract{
		{name: "Descriptor", typeName: "credentialprotocol.ExtensionDescriptor", exported: true},
		{name: "Factory", typeName: "credentialclient.ExtensionFactory", exported: true},
	})
	assertStructFields(t, reflect.TypeOf(ExtensionOpenRequest{}), []fieldContract{
		{name: "Descriptor", typeName: "credentialprotocol.ExtensionDescriptor", exported: true},
	})
	registryType := reflect.TypeOf((*ExtensionRegistry)(nil))
	descriptorsMethod, ok := registryType.MethodByName("Descriptors")
	if !ok || descriptorsMethod.Type.String() != "func(*credentialclient.ExtensionRegistry) []credentialprotocol.ExtensionDescriptor" {
		t.Fatalf("ExtensionRegistry.Descriptors method = %v/%t", descriptorsMethod, ok)
	}
	if _, ok := registryType.MethodByName("Register"); ok {
		t.Fatal("ExtensionRegistry exposes forbidden Register method")
	}
}

func TestNewExtensionRegistryAcceptsCanonicalInputAndReturnsDeepSnapshots(t *testing.T) {
	t.Parallel()

	firstDescriptor := credentialprotocol.ExtensionDescriptor{
		ID:    "alpha-v1",
		Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent},
	}
	secondDescriptor := credentialprotocol.ExtensionDescriptor{
		ID:                       "beta-v1",
		HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD},
	}
	registrations := []ExtensionRegistration{
		{Descriptor: credentialprotocol.CloneExtensionDescriptor(firstDescriptor), Factory: staticFactory{}},
		{Descriptor: credentialprotocol.CloneExtensionDescriptor(secondDescriptor), Factory: staticFactory{}},
	}
	want := credentialprotocol.CloneExtensionDescriptors([]credentialprotocol.ExtensionDescriptor{firstDescriptor, secondDescriptor})

	registry, err := NewExtensionRegistry(registrations...)
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	registrations[0].Descriptor.ID = "mutated-v1"
	registrations[0].Descriptor.Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	registrations[1].Descriptor.HelperToAgentPacketTypes[0] = credentialprotocol.PacketTypeExec

	first := registry.Descriptors()
	assertDescriptorsEqual(t, first, want)
	first[0].ID = "changed-v1"
	first[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	first[1].HelperToAgentPacketTypes[0] = credentialprotocol.PacketTypeExec
	first = append(first, credentialprotocol.ExtensionDescriptor{})
	if len(first) != 3 {
		t.Fatal("test mutation did not extend the caller snapshot")
	}

	second := registry.Descriptors()
	assertDescriptorsEqual(t, second, want)
	if &second[0] == &registry.Descriptors()[0] {
		t.Fatal("Descriptors() reused an outer backing array")
	}
}

func TestNewExtensionRegistryRejectsEveryInvalidRegistrationClass(t *testing.T) {
	t.Parallel()

	sshMode := credentialprotocol.ExtensionDescriptor{
		ID:    "alpha-v1",
		Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent},
	}
	sshPacket := credentialprotocol.ExtensionDescriptor{
		ID:                       "beta-v1",
		HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD},
	}
	tests := []struct {
		name          string
		registrations []ExtensionRegistration
		want          error
	}{
		{name: "empty ID", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrInvalidExtensionID},
		{name: "invalid ID", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "not canonical", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrInvalidExtensionID},
		{name: "empty claims", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1"}, Factory: staticFactory{}}}, want: credentialprotocol.ErrEmptyExtensionDescriptor},
		{name: "reserved core mode", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeHTTPProxy}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "reserved core packet", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeResponse}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionCoreClaim},
		{name: "unknown mode", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{99}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrUnknownDeliveryMode},
		{name: "unknown packet", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{0x22}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrUnknownPacketType},
		{name: "duplicate descriptor mode", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent, credentialprotocol.DeliveryModeSSHAgent}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "duplicate descriptor packet", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD, credentialprotocol.PacketTypeSSHAcceptedFD}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionCatalogDuplicate},
		{name: "packet in wrong direction", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", AgentToHelperPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionPacketDirection},
		{name: "noncanonical descriptor order", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent, credentialprotocol.DeliveryModeFileTmpfs}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionCatalogOrder},
		{name: "locked SSH mismatch", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: credentialprotocol.ExtensionIDSSHRelayV1, Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrLockedExtensionDescriptor},
		{name: "duplicate ID", registrations: []ExtensionRegistration{{Descriptor: sshMode, Factory: staticFactory{}}, {Descriptor: sshMode, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionSetDuplicate},
		{name: "byte duplicate registration", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: staticFactory{}}, {Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionSetDuplicate},
		{name: "duplicate mode claim", registrations: []ExtensionRegistration{{Descriptor: sshMode, Factory: staticFactory{}}, {Descriptor: credentialprotocol.ExtensionDescriptor{ID: "beta-v1", Modes: []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}}, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionSetDuplicateClaim},
		{name: "duplicate packet claim", registrations: []ExtensionRegistration{{Descriptor: credentialprotocol.ExtensionDescriptor{ID: "alpha-v1", HelperToAgentPacketTypes: []credentialprotocol.PacketType{credentialprotocol.PacketTypeSSHAcceptedFD}}, Factory: staticFactory{}}, {Descriptor: sshPacket, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionSetDuplicateClaim},
		{name: "noncanonical registration order", registrations: []ExtensionRegistration{{Descriptor: sshPacket, Factory: staticFactory{}}, {Descriptor: sshMode, Factory: staticFactory{}}}, want: credentialprotocol.ErrExtensionSetOrder},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if registry, err := NewExtensionRegistry(test.registrations...); !errors.Is(err, test.want) || registry != nil {
				t.Fatalf("NewExtensionRegistry() = (%v, %v), want (nil, %v)", registry, err, test.want)
			}
		})
	}
	tooMany := make([]ExtensionRegistration, credentialprotocol.MaxExtensions+1)
	for index := range tooMany {
		tooMany[index] = ExtensionRegistration{Descriptor: sshMode, Factory: staticFactory{}}
	}
	if registry, err := NewExtensionRegistry(tooMany...); !errors.Is(err, credentialprotocol.ErrExtensionSetTooLarge) || registry != nil {
		t.Fatalf("NewExtensionRegistry(too many) = (%v, %v), want ErrExtensionSetTooLarge", registry, err)
	}
}

func TestNewExtensionRegistryRejectsNilAndEveryConstructibleTypedNilFactory(t *testing.T) {
	t.Parallel()

	var pointer *pointerFactory
	var mapping mapFactory
	var slice sliceFactory
	var function functionFactory
	var channel channelFactory
	var nested ExtensionFactory
	tests := []struct {
		name    string
		factory ExtensionFactory
	}{
		{name: "nil interface", factory: nil},
		{name: "typed nil pointer", factory: pointer},
		{name: "typed nil map", factory: mapping},
		{name: "typed nil slice", factory: slice},
		{name: "typed nil function", factory: function},
		{name: "typed nil channel", factory: channel},
		{name: "nested nil interface", factory: nested},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registration := ExtensionRegistration{
				Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
				Factory:    test.factory,
			}
			if registry, err := NewExtensionRegistry(registration); !errors.Is(err, ErrExtensionFactoryRequired) || registry != nil {
				t.Fatalf("NewExtensionRegistry() = (%v, %v), want (nil, ErrExtensionFactoryRequired)", registry, err)
			}
		})
	}
}

func TestExtensionRegistrySupportsConcurrentDefensiveReads(t *testing.T) {
	t.Parallel()

	descriptor := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	registry, err := NewExtensionRegistry(ExtensionRegistration{Descriptor: descriptor, Factory: staticFactory{}})
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}

	const readers = 64
	const readsPerReader = 100
	var wait sync.WaitGroup
	errorsFound := make(chan string, readers)
	for reader := 0; reader < readers; reader++ {
		wait.Add(1)
		go func(reader int) {
			defer wait.Done()
			for read := 0; read < readsPerReader; read++ {
				snapshot := registry.Descriptors()
				if len(snapshot) != 1 || !credentialprotocol.ExtensionDescriptorEqual(snapshot[0], descriptor) {
					errorsFound <- "snapshot changed"
					return
				}
				snapshot[0].ID = credentialprotocol.ExtensionID("mutated-v1")
				snapshot[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
			}
		}(reader)
	}
	wait.Wait()
	close(errorsFound)
	for message := range errorsFound {
		t.Error(message)
	}
}

func TestExtensionFactoryOpenReturnMatrix(t *testing.T) {
	descriptor := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	request := ExtensionOpenRequest{Descriptor: descriptor}
	cleanupContext := context.WithValue(context.Background(), cleanupContextKey{}, "bounded-cleanup")

	valid := &trackingSession{}
	session, err := openExtension(cleanupContext, extensionFactoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
		return valid, nil
	}), request)
	if err != nil || session != valid || valid.closes.Load() != 0 {
		t.Fatalf("valid return = (%v, %v), closes=%d", session, err, valid.closes.Load())
	}

	ordinaryFailure := errors.New("safe extension open failure")
	session, err = openExtension(cleanupContext, extensionFactoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
		return nil, ordinaryFailure
	}), request)
	if session != nil || !errors.Is(err, ordinaryFailure) {
		t.Fatalf("ordinary failure = (%v, %v), want nil/original error", session, err)
	}

	for _, test := range []struct {
		name    string
		session ExtensionSession
	}{
		{name: "nil interface", session: nil},
		{name: "typed nil pointer", session: (*nilPointerSession)(nil)},
		{name: "typed nil map", session: nilMapSession(nil)},
		{name: "typed nil slice", session: nilSliceSession(nil)},
		{name: "typed nil function", session: nilFunctionSession(nil)},
		{name: "typed nil channel", session: nilChannelSession(nil)},
	} {
		t.Run(test.name+" with nil error", func(t *testing.T) {
			opened, openErr := openExtension(cleanupContext, extensionFactoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
				return test.session, nil
			}), request)
			if opened != nil || !errors.Is(openErr, ErrExtensionFactoryContract) {
				t.Fatalf("openExtension() = (%v, %v), want nil/ErrExtensionFactoryContract", opened, openErr)
			}
		})
	}

	invalidValue := &trackingSession{}
	opened, openErr := openExtension(cleanupContext, extensionFactoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
		return invalidValue, ordinaryFailure
	}), request)
	if opened != nil || !errors.Is(openErr, ErrExtensionFactoryContract) || errors.Is(openErr, ordinaryFailure) {
		t.Fatalf("value plus error = (%v, %v), want sanitized contract violation", opened, openErr)
	}
	if invalidValue.closes.Load() != 1 || invalidValue.closeContext != cleanupContext {
		t.Fatalf("invalid value cleanup = calls %d context match %t", invalidValue.closes.Load(), invalidValue.closeContext == cleanupContext)
	}

	typedNilSessionCloseCalls.Store(0)
	opened, openErr = openExtension(cleanupContext, extensionFactoryFunc(func(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
		return (*nilPointerSession)(nil), ordinaryFailure
	}), request)
	if opened != nil || !errors.Is(openErr, ErrExtensionFactoryContract) || typedNilSessionCloseCalls.Load() != 1 {
		t.Fatalf("typed nil plus error = (%v, %v), closes=%d", opened, openErr, typedNilSessionCloseCalls.Load())
	}
}

func TestExtensionFactoryOpenReceivesDescriptorSnapshot(t *testing.T) {
	t.Parallel()

	descriptor := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	original := credentialprotocol.CloneExtensionDescriptor(descriptor)
	opened, err := openExtension(context.Background(), extensionFactoryFunc(func(_ context.Context, request ExtensionOpenRequest) (ExtensionSession, error) {
		request.Descriptor.ID = "mutated-v1"
		request.Descriptor.Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
		request.Descriptor.HelperToAgentPacketTypes[0] = credentialprotocol.PacketTypeExec
		return staticSession{}, nil
	}), ExtensionOpenRequest{Descriptor: descriptor})
	if err != nil || opened == nil {
		t.Fatalf("openExtension() = (%v, %v), want success", opened, err)
	}
	if !credentialprotocol.ExtensionDescriptorEqual(descriptor, original) {
		t.Fatal("factory mutation escaped the open-request snapshot")
	}
}

type staticFactory struct{}

func (staticFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type staticSession struct{}

func (staticSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (staticSession) Close(context.Context) error                   { return nil }

type extensionFactoryFunc func(context.Context, ExtensionOpenRequest) (ExtensionSession, error)

func (function extensionFactoryFunc) Open(ctx context.Context, request ExtensionOpenRequest) (ExtensionSession, error) {
	return function(ctx, request)
}

type trackingSession struct {
	closes       atomic.Uint32
	closeContext context.Context
}

func (*trackingSession) Handle(context.Context, ExtensionPacket) error { return nil }

func (session *trackingSession) Close(ctx context.Context) error {
	session.closeContext = ctx
	session.closes.Add(1)
	return nil
}

var typedNilSessionCloseCalls atomic.Uint32

type nilPointerSession struct{}

func (*nilPointerSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (session *nilPointerSession) Close(context.Context) error {
	if session == nil {
		typedNilSessionCloseCalls.Add(1)
	}
	return nil
}

type nilMapSession map[string]struct{}

func (nilMapSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (nilMapSession) Close(context.Context) error                   { return nil }

type nilSliceSession []struct{}

func (nilSliceSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (nilSliceSession) Close(context.Context) error                   { return nil }

type nilFunctionSession func()

func (nilFunctionSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (nilFunctionSession) Close(context.Context) error                   { return nil }

type nilChannelSession chan struct{}

func (nilChannelSession) Handle(context.Context, ExtensionPacket) error { return nil }
func (nilChannelSession) Close(context.Context) error                   { return nil }

type cleanupContextKey struct{}

type pointerFactory struct{}

func (*pointerFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type mapFactory map[string]struct{}

func (mapFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type sliceFactory []struct{}

func (sliceFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type functionFactory func()

func (functionFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type channelFactory chan struct{}

func (channelFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

type fieldContract struct {
	name     string
	typeName string
	exported bool
}

func assertInterfaceMethods(t *testing.T, interfaceType reflect.Type, want map[string]string) {
	t.Helper()
	if interfaceType.NumMethod() != len(want) {
		t.Fatalf("%s method count = %d, want %d", interfaceType, interfaceType.NumMethod(), len(want))
	}
	for index := 0; index < interfaceType.NumMethod(); index++ {
		method := interfaceType.Method(index)
		wantType, ok := want[method.Name]
		if !ok {
			t.Errorf("%s has unexpected method %s", interfaceType, method.Name)
			continue
		}
		if got := method.Type.String(); got != wantType {
			t.Errorf("%s.%s type = %q, want %q", interfaceType, method.Name, got, wantType)
		}
	}
}

func assertStructFields(t *testing.T, structure reflect.Type, want []fieldContract) {
	t.Helper()
	if structure.NumField() != len(want) {
		t.Fatalf("%s field count = %d, want %d", structure, structure.NumField(), len(want))
	}
	for index, fieldWant := range want {
		field := structure.Field(index)
		if field.Name != fieldWant.name || field.Type.String() != fieldWant.typeName || field.IsExported() != fieldWant.exported || field.Tag != "" {
			t.Errorf("%s field %d = %s %s exported=%t tag=%q, want %s %s exported=%t no tag", structure, index, field.Name, field.Type, field.IsExported(), field.Tag, fieldWant.name, fieldWant.typeName, fieldWant.exported)
		}
	}
}

func assertDescriptorsEqual(t *testing.T, got, want []credentialprotocol.ExtensionDescriptor) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("descriptor count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if !credentialprotocol.ExtensionDescriptorEqual(got[index], want[index]) {
			t.Errorf("descriptor %d differs", index)
		}
	}
}
