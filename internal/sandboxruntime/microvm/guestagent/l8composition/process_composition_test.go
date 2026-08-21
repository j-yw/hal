package l8composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

func TestL8D6CompositionOptionShapesAreExact(t *testing.T) {
	t.Parallel()

	assertCompositionStruct(t, reflect.TypeOf(HelperOptions{}), []compositionField{
		{name: "Core", typeName: "credentialhelper.Core"},
		{name: "Transport", typeName: "credentialhelper.Transport"},
		{name: "Policy", typeName: "credentialhelper.Policy"},
		{name: "Host", typeName: "credentialhelper.ExtensionHost"},
		{name: "Runtime", typeName: "credentialhelper.ServiceRuntime"},
		{name: "SSH", typeName: "credentialhelper.ExtensionRegistration"},
	})
	assertCompositionStruct(t, reflect.TypeOf(ClientOptions{}), []compositionField{
		{name: "Transport", typeName: "credentialclient.Transport"},
		{name: "Policy", typeName: "credentialclient.Policy"},
		{name: "SSH", typeName: "credentialclient.ExtensionRegistration"},
	})
}

func TestL8D6NewHelperBuildsExactLocalRegistryAndDescriptor(t *testing.T) {
	t.Parallel()

	core := &compositionHelperCore{}
	transport := &compositionHelperTransport{}
	policy := &compositionHelperPolicy{underlying: credentialhelper.NewHelperPolicy()}
	host := &compositionHelperHost{}
	runtime := &compositionHelperRuntime{}
	factory := &compositionHelperFactory{}
	registration := credentialhelper.ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: factory}
	service, descriptor, err := NewHelper(HelperOptions{Core: core, Transport: transport, Policy: policy, Host: host, Runtime: runtime, SSH: registration})
	if err != nil {
		t.Fatalf("NewHelper() error = %v", err)
	}
	if service == nil {
		t.Fatal("NewHelper() returned nil service")
	}
	if calls := policy.descriptorCalls.Load(); calls != 2 {
		t.Fatalf("Policy.Descriptor calls = %d, want 2", calls)
	}
	if calls := factory.opens.Load(); calls != 0 {
		t.Fatalf("helper extension factory opened during composition: %d", calls)
	}
	assertProcessDescriptor(t, descriptor, ProcessRoleHelper, processPolicyDigest(helperPolicyID))
	assertServiceDependencyIdentity(t, service, "core", core)
	assertServiceDependencyIdentity(t, service, "transport", transport)
	assertServiceDependencyIdentity(t, service, "policy", policy)
	assertServiceDependencyIdentity(t, service, "host", host)
	assertServiceDependencyIdentity(t, service, "runtime", runtime)

	registration.Descriptor.Modes[0] = credentialprotocol.DeliveryModeFileTmpfs
	descriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	_, fresh, err := NewHelper(HelperOptions{Core: core, Transport: transport, Policy: credentialhelper.NewHelperPolicy(), Host: host, Runtime: runtime, SSH: credentialhelper.ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: factory}})
	if err != nil {
		t.Fatalf("second NewHelper() error = %v", err)
	}
	if fresh.Extensions[0].Modes[0] != credentialprotocol.DeliveryModeSSHAgent {
		t.Fatal("helper composition retained caller or returned descriptor slice")
	}
}

func TestL8D6NewHelperRejectsDependenciesRegistrationAndPolicyBeforeAssembly(t *testing.T) {
	t.Parallel()

	valid := validHelperOptions()
	var nilCore *compositionHelperCore
	var nilTransport *compositionHelperTransport
	var nilPolicy *compositionHelperPolicy
	var nilHost *compositionHelperHost
	var nilRuntime *compositionHelperRuntime
	var nilFactory *compositionHelperFactory
	tests := []struct {
		name   string
		mutate func(*HelperOptions)
		want   error
	}{
		{name: "nil core", mutate: func(options *HelperOptions) { options.Core = nil }, want: ErrCompositionDependency},
		{name: "typed nil core", mutate: func(options *HelperOptions) { options.Core = nilCore }, want: ErrCompositionDependency},
		{name: "nil transport", mutate: func(options *HelperOptions) { options.Transport = nil }, want: ErrCompositionDependency},
		{name: "typed nil transport", mutate: func(options *HelperOptions) { options.Transport = nilTransport }, want: ErrCompositionDependency},
		{name: "nil policy", mutate: func(options *HelperOptions) { options.Policy = nil }, want: ErrCompositionDependency},
		{name: "typed nil policy", mutate: func(options *HelperOptions) { options.Policy = nilPolicy }, want: ErrCompositionDependency},
		{name: "nil host", mutate: func(options *HelperOptions) { options.Host = nil }, want: ErrCompositionDependency},
		{name: "typed nil host", mutate: func(options *HelperOptions) { options.Host = nilHost }, want: ErrCompositionDependency},
		{name: "nil runtime", mutate: func(options *HelperOptions) { options.Runtime = nil }, want: ErrCompositionDependency},
		{name: "typed nil runtime", mutate: func(options *HelperOptions) { options.Runtime = nilRuntime }, want: ErrCompositionDependency},
		{name: "nil factory", mutate: func(options *HelperOptions) { options.SSH.Factory = nil }, want: ErrCompositionRegistration},
		{name: "typed nil factory", mutate: func(options *HelperOptions) { options.SSH.Factory = nilFactory }, want: ErrCompositionRegistration},
		{name: "wrong descriptor", mutate: func(options *HelperOptions) { options.SSH.Descriptor.ID = "other-v1" }, want: ErrCompositionRegistration},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := valid
			test.mutate(&options)
			service, descriptor, err := NewHelper(options)
			if service != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, test.want) {
				t.Fatalf("NewHelper() = (%v, %#v, %v), want nil/zero/%v", service, descriptor, err, test.want)
			}
			if strings.Contains(fmt.Sprint(err), "secret-canary") {
				t.Fatal("NewHelper error exposed dependency content")
			}
		})
	}

	panicPolicy := &compositionHelperPolicy{underlying: credentialhelper.NewHelperPolicy(), panicAt: 1}
	options := valid
	options.Policy = panicPolicy
	if service, descriptor, err := NewHelper(options); service != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionPanic) || strings.Contains(fmt.Sprint(err), "secret-canary") {
		t.Fatalf("NewHelper(panic) = (%v, %#v, %v), want sanitized panic rejection", service, descriptor, err)
	}
	changingPolicy := &compositionHelperPolicy{underlying: credentialhelper.NewHelperPolicy(), zeroAt: 2}
	options.Policy = changingPolicy
	if service, descriptor, err := NewHelper(options); service != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionPolicy) {
		t.Fatalf("NewHelper(changing policy) = (%v, %#v, %v), want policy rejection", service, descriptor, err)
	}
}

func TestL8D6NewClientPinsCanonicalDescriptorAndOwnsFactoryErrors(t *testing.T) {
	t.Parallel()

	transport := &compositionClientTransport{}
	policy := &compositionClientPolicy{underlying: credentialclient.NewClientPolicy()}
	session := &compositionClientSession{}
	factory := &compositionClientFactory{session: session}
	client, descriptor, err := NewClient(ClientOptions{
		Transport: transport,
		Policy:    policy,
		SSH:       credentialclient.ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: factory},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
	if calls := policy.descriptorCalls.Load(); calls != 4 {
		t.Fatalf("Policy.Descriptor calls = %d, want 4 D6+client validations", calls)
	}
	if calls := factory.opens.Load(); calls != 1 {
		t.Fatalf("client extension factory opens = %d, want 1", calls)
	}
	if !credentialprotocol.ExtensionDescriptorEqual(factory.openedDescriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		t.Fatalf("factory descriptor = %#v, want exact SSH registration", factory.openedDescriptor)
	}
	assertProcessDescriptor(t, descriptor, ProcessRoleClient, processPolicyDigest(clientPolicyID))
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Client.Close() error = %v", err)
	}
	if calls := session.closes.Load(); calls != 1 {
		t.Fatalf("client extension closes = %d, want 1", calls)
	}

	badSession := &compositionClientSession{}
	badFactory := &compositionClientFactory{session: badSession, err: errors.New("secret-canary")}
	failed, failedDescriptor, err := NewClient(ClientOptions{
		Transport: &compositionClientTransport{},
		Policy:    credentialclient.NewClientPolicy(),
		SSH:       credentialclient.ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: badFactory},
	})
	if failed != nil || failedDescriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionClient) || strings.Contains(fmt.Sprint(err), "secret-canary") {
		t.Fatalf("NewClient(factory error) = (%v, %#v, %v), want sanitized client failure", failed, failedDescriptor, err)
	}
	if badSession.closes.Load() != 1 {
		t.Fatalf("non-nil/error session closes = %d, want 1", badSession.closes.Load())
	}
}

func TestL8D6NewClientRejectsTypedNilPanicAndRegistrationFailures(t *testing.T) {
	t.Parallel()

	valid := validClientOptions()
	var nilTransport *compositionClientTransport
	var nilPolicy *compositionClientPolicy
	var nilFactory *compositionClientFactory
	tests := []struct {
		name   string
		mutate func(*ClientOptions)
		want   error
	}{
		{name: "nil transport", mutate: func(options *ClientOptions) { options.Transport = nil }, want: ErrCompositionDependency},
		{name: "typed nil transport", mutate: func(options *ClientOptions) { options.Transport = nilTransport }, want: ErrCompositionDependency},
		{name: "nil policy", mutate: func(options *ClientOptions) { options.Policy = nil }, want: ErrCompositionDependency},
		{name: "typed nil policy", mutate: func(options *ClientOptions) { options.Policy = nilPolicy }, want: ErrCompositionDependency},
		{name: "nil factory", mutate: func(options *ClientOptions) { options.SSH.Factory = nil }, want: ErrCompositionRegistration},
		{name: "typed nil factory", mutate: func(options *ClientOptions) { options.SSH.Factory = nilFactory }, want: ErrCompositionRegistration},
		{name: "wrong descriptor", mutate: func(options *ClientOptions) { options.SSH.Descriptor.HelperToAgentPacketTypes = nil }, want: ErrCompositionRegistration},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := valid
			test.mutate(&options)
			client, descriptor, err := NewClient(options)
			if client != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, test.want) {
				t.Fatalf("NewClient() = (%v, %#v, %v), want nil/zero/%v", client, descriptor, err, test.want)
			}
		})
	}

	options := valid
	options.Policy = &compositionClientPolicy{underlying: credentialclient.NewClientPolicy(), panicAt: 1}
	if client, descriptor, err := NewClient(options); client != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionPanic) || strings.Contains(fmt.Sprint(err), "secret-canary") {
		t.Fatalf("NewClient(panic) = (%v, %#v, %v), want sanitized panic rejection", client, descriptor, err)
	}
	options.Policy = &compositionClientPolicy{underlying: credentialclient.NewClientPolicy(), zeroAt: 2}
	if client, descriptor, err := NewClient(options); client != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionPolicy) {
		t.Fatalf("NewClient(changing policy) = (%v, %#v, %v), want policy rejection", client, descriptor, err)
	}
	options.Policy = &compositionClientPolicy{underlying: credentialclient.NewClientPolicy(), zeroAt: 3}
	if client, descriptor, err := NewClient(options); client != nil || descriptor != (ProcessDescriptor{}) || !errors.Is(err, ErrCompositionClient) {
		t.Fatalf("NewClient(downstream policy drift) = (%v, %#v, %v), want client rejection", client, descriptor, err)
	}
}

func TestL8D6ClientDescriptorViewIsCanonicalImmutableAndBodyFree(t *testing.T) {
	t.Parallel()

	descriptor := ProcessDescriptor{
		ContractVersion: ProcessDescriptorContractVersion,
		Role:            ProcessRoleClient,
		Extensions:      []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()},
		PolicySHA256:    processPolicyDigest(clientPolicyID),
	}
	want, err := EncodeProcessDescriptor(descriptor)
	if err != nil {
		t.Fatalf("EncodeProcessDescriptor() error = %v", err)
	}
	view, err := newClientProcessDescriptor(descriptor)
	if err != nil {
		t.Fatalf("newClientProcessDescriptor() error = %v", err)
	}
	descriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeFileTmpfs
	if view.ContractVersion() != 1 || view.Role() != uint8(ProcessRoleClient) || view.PolicySHA256() != processPolicyDigest(clientPolicyID) || view.EncodedLength() != uint16(len(want)) || view.SHA256() == ([32]byte{}) {
		t.Fatal("client descriptor view projections are not exact")
	}
	extensions := view.Extensions()
	extensions[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	if view.Extensions()[0].Modes[0] != credentialprotocol.DeliveryModeSSHAgent {
		t.Fatal("client descriptor view returned an aliased extension set")
	}
	sink := &compositionDescriptorSink{maximum: len(want)}
	if err := view.WriteCanonical(sink); err != nil || !reflect.DeepEqual(sink.bytes, want) {
		t.Fatalf("WriteCanonical() = (%x, %v), want %x", sink.bytes, err, want)
	}
	viewType := reflect.TypeOf(view)
	for index := 0; index < viewType.NumField(); index++ {
		if viewType.Field(index).Type == reflect.TypeOf([]byte(nil)) {
			t.Fatalf("client descriptor view retains canonical body field %s", viewType.Field(index).Name)
		}
	}
	assertCompositionSerializationDenied(t, view)
}

func TestL8D6CompositionValuesDenyGenericSerializationAndFormatting(t *testing.T) {
	t.Parallel()

	values := []any{
		validHelperOptions(),
		validClientOptions(),
		ProcessDescriptor{ContractVersion: "secret-canary", Extensions: []credentialprotocol.ExtensionDescriptor{{ID: "secret-canary"}}},
		CompositionDescriptor{ContractVersion: "secret-canary"},
	}
	for _, value := range values {
		assertCompositionSerializationDenied(t, value)
	}
}

type compositionField struct {
	name     string
	typeName string
}

func assertCompositionStruct(t *testing.T, structure reflect.Type, want []compositionField) {
	t.Helper()
	if structure.NumField() != len(want) {
		t.Fatalf("%s fields = %d, want %d", structure.Name(), structure.NumField(), len(want))
	}
	for index, expected := range want {
		field := structure.Field(index)
		if field.Name != expected.name || field.Type.String() != expected.typeName || field.Tag != "" {
			t.Errorf("%s field %d = %s %s %q, want %s %s without tag", structure.Name(), index, field.Name, field.Type, field.Tag, expected.name, expected.typeName)
		}
	}
}

func assertProcessDescriptor(t *testing.T, descriptor ProcessDescriptor, role ProcessRole, policyDigest [32]byte) {
	t.Helper()
	if descriptor.ContractVersion != ProcessDescriptorContractVersion || descriptor.Role != role || descriptor.PolicySHA256 != policyDigest || len(descriptor.Extensions) != 1 || !credentialprotocol.ExtensionDescriptorEqual(descriptor.Extensions[0], credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		t.Fatalf("descriptor = %#v, want exact role/policy/SSH composition", descriptor)
	}
	if _, err := EncodeProcessDescriptor(descriptor); err != nil {
		t.Fatalf("returned descriptor is not canonical: %v", err)
	}
}

func assertServiceDependencyIdentity(t *testing.T, service *credentialhelper.Service, field string, want any) {
	t.Helper()
	got := reflect.ValueOf(service).Elem().FieldByName(field)
	if !got.IsValid() || got.Kind() != reflect.Interface || got.IsNil() || got.Elem().Kind() != reflect.Pointer || got.Elem().Pointer() != reflect.ValueOf(want).Pointer() {
		t.Fatalf("Service.%s does not retain the exact explicit dependency", field)
	}
}

func assertCompositionSerializationDenied(t *testing.T, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if !errors.Is(err, ErrCompositionSerialization) || strings.Contains(string(encoded), "secret-canary") {
		t.Errorf("json.Marshal(%T) = (%q, %v), want fail-closed", value, encoded, err)
	}
	textMarshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
	if !ok {
		t.Errorf("%T lacks MarshalText denial", value)
	} else if encoded, err := textMarshaler.MarshalText(); !errors.Is(err, ErrCompositionSerialization) || len(encoded) != 0 {
		t.Errorf("MarshalText(%T) = (%q, %v), want empty denial", value, encoded, err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		formatted := fmt.Sprintf(format, value)
		if strings.Contains(formatted, "secret-canary") || !strings.Contains(formatted, "redacted") {
			t.Errorf("format %s for %T = %q, want redacted", format, value, formatted)
		}
	}
}

func validHelperOptions() HelperOptions {
	return HelperOptions{
		Core:      &compositionHelperCore{},
		Transport: &compositionHelperTransport{},
		Policy:    credentialhelper.NewHelperPolicy(),
		Host:      &compositionHelperHost{},
		Runtime:   &compositionHelperRuntime{},
		SSH: credentialhelper.ExtensionRegistration{
			Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
			Factory:    &compositionHelperFactory{},
		},
	}
}

func validClientOptions() ClientOptions {
	return ClientOptions{
		Transport: &compositionClientTransport{},
		Policy:    credentialclient.NewClientPolicy(),
		SSH: credentialclient.ExtensionRegistration{
			Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
			Factory:    &compositionClientFactory{session: &compositionClientSession{}},
		},
	}
}

type compositionHelperCore struct{}

func (*compositionHelperCore) BeginPrepare(context.Context, credentialhelper.CorePrepareRequest) (credentialhelper.CorePreparation, error) {
	return nil, nil
}
func (*compositionHelperCore) BeginExec(context.Context, credentialhelper.CoreExecRequest, credentialmemory.BorrowedView) (credentialhelper.CoreExecution, error) {
	return nil, nil
}
func (*compositionHelperCore) Renew(context.Context, credentialhelper.CoreRenewRequest) error {
	return nil
}
func (*compositionHelperCore) Revoke(context.Context, credentialhelper.CoreRevokeRequest) (credentialhelper.CoreCleanupResult, error) {
	return credentialhelper.CoreCleanupResult{}, nil
}
func (*compositionHelperCore) Inspect(context.Context, credentialhelper.CoreInspectRequest) (credentialhelper.CoreInspection, error) {
	return credentialhelper.CoreInspection{}, nil
}
func (*compositionHelperCore) Close(context.Context) error { return nil }

type compositionHelperTransport struct{}

func (*compositionHelperTransport) Receive(context.Context, credentialhelper.ReceiveRequest) (credentialhelper.ReceivedPacket, error) {
	return credentialhelper.ReceivedPacket{}, nil
}
func (*compositionHelperTransport) Send(context.Context, credentialhelper.SendPacket) error {
	return nil
}
func (*compositionHelperTransport) Close(context.Context) error { return nil }

type compositionHelperHost struct{}

func (*compositionHelperHost) CreateSSHAgentEndpoint(context.Context, credentialhelper.SSHAgentEndpointRequest) (credentialhelper.SSHAgentEndpoint, error) {
	return nil, nil
}
func (*compositionHelperHost) PublishSSHAcceptedConnection(context.Context, credentialhelper.SSHAcceptedPublication, credentialhelper.SSHAgentConnection) error {
	return nil
}

type compositionHelperRuntime struct{}

func (*compositionHelperRuntime) Bootstrap(context.Context) (credentialhelper.ServiceBootstrap, error) {
	return credentialhelper.ServiceBootstrap{}, nil
}
func (*compositionHelperRuntime) BindAgent(context.Context, credentialhelper.ServiceAgentBindingRequest, credentialhelper.ReceivedCapability) error {
	return nil
}
func (*compositionHelperRuntime) ObserveJob(context.Context, credentialhelper.ServiceJobObservationRequest) (credentialhelper.ServiceJobObservation, error) {
	return credentialhelper.ServiceJobObservation{}, nil
}
func (*compositionHelperRuntime) Loss() <-chan credentialhelper.ServiceLoss { return nil }
func (*compositionHelperRuntime) BeginCleanup() (credentialhelper.ServiceCleanupBudget, error) {
	return nil, nil
}
func (*compositionHelperRuntime) Close(context.Context) error { return nil }

type compositionHelperPolicy struct {
	underlying      credentialhelper.Policy
	descriptorCalls atomic.Uint32
	panicAt         uint32
	zeroAt          uint32
}

func (policy *compositionHelperPolicy) Authorize(request credentialhelper.PolicyRequest) (credentialhelper.PolicyDecision, error) {
	return policy.underlying.Authorize(request)
}
func (policy *compositionHelperPolicy) Descriptor() credentialhelper.PolicyDescriptor {
	call := policy.descriptorCalls.Add(1)
	if call == policy.panicAt {
		panic("secret-canary")
	}
	if call == policy.zeroAt {
		return credentialhelper.PolicyDescriptor{}
	}
	return policy.underlying.Descriptor()
}

type compositionHelperFactory struct{ opens atomic.Uint32 }

func (factory *compositionHelperFactory) Open(context.Context, credentialhelper.ExtensionOpenRequest) (credentialhelper.ExtensionSession, error) {
	factory.opens.Add(1)
	return &compositionHelperSession{}, nil
}

type compositionHelperSession struct{}

func (*compositionHelperSession) Prepare(context.Context, credentialhelper.ExtensionPrepareRequest) (credentialhelper.ExtensionPrepareResult, error) {
	return credentialhelper.ExtensionPrepareResult{}, nil
}
func (*compositionHelperSession) BindExec(context.Context, credentialhelper.ExtensionExecRequest) (credentialhelper.ExtensionExecResult, error) {
	return credentialhelper.ExtensionExecResult{}, nil
}
func (*compositionHelperSession) Renew(context.Context, credentialhelper.ExtensionRenewRequest) error {
	return nil
}
func (*compositionHelperSession) Revoke(context.Context, credentialhelper.ExtensionRevokeRequest) (credentialhelper.ExtensionCleanupResult, error) {
	return credentialhelper.ExtensionCleanupResult{}, nil
}
func (*compositionHelperSession) Close(context.Context) error { return nil }

type compositionClientTransport struct{ closes atomic.Uint32 }

func (*compositionClientTransport) ReceiveController(context.Context, credentialclient.ControllerReceiveRequest) (credentialclient.ControllerPacket, error) {
	return credentialclient.ControllerPacket{}, nil
}
func (*compositionClientTransport) SendController(context.Context, credentialclient.ControllerSendPacket) error {
	return nil
}
func (*compositionClientTransport) ReceiveHelper(context.Context, credentialclient.HelperReceiveRequest) (credentialclient.HelperPacket, error) {
	return credentialclient.HelperPacket{}, nil
}
func (*compositionClientTransport) SendHelper(context.Context, credentialclient.HelperSendPacket) error {
	return nil
}
func (transport *compositionClientTransport) Close(context.Context) error {
	transport.closes.Add(1)
	return nil
}

type compositionClientPolicy struct {
	underlying      credentialclient.Policy
	descriptorCalls atomic.Uint32
	panicAt         uint32
	zeroAt          uint32
}

func (policy *compositionClientPolicy) Authorize(request credentialclient.ClientPolicyRequest) (credentialclient.ClientPolicyDecision, error) {
	return policy.underlying.Authorize(request)
}
func (policy *compositionClientPolicy) Descriptor() credentialclient.PolicyDescriptor {
	call := policy.descriptorCalls.Add(1)
	if call == policy.panicAt {
		panic("secret-canary")
	}
	if call == policy.zeroAt {
		return credentialclient.PolicyDescriptor{}
	}
	return policy.underlying.Descriptor()
}

type compositionClientFactory struct {
	session          credentialclient.ExtensionSession
	err              error
	panicOnOpen      bool
	opens            atomic.Uint32
	openedDescriptor credentialprotocol.ExtensionDescriptor
}

func (factory *compositionClientFactory) Open(_ context.Context, request credentialclient.ExtensionOpenRequest) (credentialclient.ExtensionSession, error) {
	factory.opens.Add(1)
	if factory.panicOnOpen {
		panic("secret-canary")
	}
	factory.openedDescriptor = credentialprotocol.CloneExtensionDescriptor(request.Descriptor)
	return factory.session, factory.err
}

type compositionClientSession struct{ closes atomic.Uint32 }

func (*compositionClientSession) Handle(context.Context, credentialclient.ExtensionPacket) error {
	return nil
}
func (session *compositionClientSession) Close(context.Context) error {
	session.closes.Add(1)
	return nil
}

type compositionDescriptorSink struct {
	maximum int
	bytes   []byte
}

func (sink *compositionDescriptorSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *compositionDescriptorSink) WriteCredential(value []byte) error {
	if len(value) > sink.maximum-len(sink.bytes) {
		return errors.New("too large")
	}
	sink.bytes = append(sink.bytes, value...)
	return nil
}
