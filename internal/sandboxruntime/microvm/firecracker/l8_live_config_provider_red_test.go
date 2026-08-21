package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestL8LiveBootConfigContractFieldsAreExactAndAdjacent(t *testing.T) {
	assertAdjacentL8Fields(t, reflect.TypeFor[BackendConfig](), "VerifiedL7Assets", []fieldContract{
		{name: "VerifiedL8Profile", typeName: "*localresolver.VerifiedL8Profile", tag: `json:"-"`},
		{name: "VerifiedL8Assets", typeName: "*localresolver.VerifiedL8AssetLease", tag: `json:"-"`},
	})
	assertAdjacentL8Fields(t, reflect.TypeFor[BackendOptions](), "L7LiveConfigProvider", []fieldContract{
		{name: "L8LiveConfigProvider", typeName: "firecracker.L8LiveBootConfigProvider"},
	})
	assertAdjacentL8Fields(t, reflect.TypeFor[Backend](), "l7LiveConfigProvider", []fieldContract{
		{name: "l8LiveConfigProvider", typeName: "firecracker.L8LiveBootConfigProvider"},
	})

	requestType := reflect.TypeFor[L8LiveBootConfigRequest]()
	assertExactL8StructFields(t, requestType, []fieldContract{
		{name: "RuntimeGenerationID", typeName: "string", tag: `json:"runtimeGenerationId"`},
	})
	overlayType := reflect.TypeFor[L8LiveBootConfigOverlay]()
	assertExactL8StructFields(t, overlayType, []fieldContract{
		{name: "RuntimeGenerationID", typeName: "string", tag: `json:"runtimeGenerationId"`},
		{name: "LaunchDescriptor", typeName: "*assets.LaunchDescriptor", tag: `json:"-"`},
		{name: "VerifiedL8Profile", typeName: "*localresolver.VerifiedL8Profile", tag: `json:"-"`},
		{name: "VerifiedL8Assets", typeName: "*localresolver.VerifiedL8AssetLease", tag: `json:"-"`},
		{name: "NetworkMode", typeName: "microvm.NetworkMode", tag: `json:"networkMode"`},
		{name: "NetworkInterfaces", typeName: "[]firecracker.NetworkInterfaceConfig", tag: `json:"-"`},
		{name: "StaticNetwork", typeName: "*firecracker.StaticNetworkBootConfig", tag: `json:"-"`},
		{name: "AssetChildFDStart", typeName: "int", tag: `json:"-"`},
	})
}

func TestL8LiveBootConfigProviderIsInertOnPlanningOnlyDefault(t *testing.T) {
	provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	adapter := &fakeProcessAdapter{}
	controller := firecrackerController{
		baseStateDir:         firecrackerPathTestBase("l8-provider-inert"),
		processAdapter:       adapter,
		l8LiveConfigProvider: provider,
	}
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    l7LiveConfigTestTarget("runtime-l8-default-inert"),
	}); err != nil {
		t.Fatal(err)
	}
	if adapter.prepareCalls != 1 || adapter.startCalls != 0 || provider.calls != 0 {
		t.Fatalf("planning-only calls = provider %d, prepare %d, start %d", provider.calls, adapter.prepareCalls, adapter.startCalls)
	}
}

func TestL8LiveBootConfigTypedNilProviderFailsBeforePlanning(t *testing.T) {
	var provider *recordingL8LiveConfigProvider
	adapter := &fakeProcessAdapter{}
	controller := l8LiveConfigTestController(adapter, provider)
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    l7LiveConfigTestTarget("runtime-l8-typed-nil"),
	}); err == nil {
		t.Fatal("Start() error = nil, want typed-nil L8 provider rejection")
	}
	if adapter.prepareCalls != 0 || adapter.startCalls != 0 {
		t.Fatalf("typed-nil L8 provider crossed process boundary: %#v", adapter)
	}
}

func TestL8LiveBootConfigEmptyRuntimeFailsBeforeProviderCall(t *testing.T) {
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = ""
	base.ProductionVsock = true
	provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	if _, owned, err := prepareL8LiveBootConfig(context.Background(), provider, base); err == nil || owned != nil {
		t.Fatalf("prepareL8LiveBootConfig(empty runtime) = owned %#v, err %v", owned, err)
	}
	if provider.calls != 0 {
		t.Fatalf("empty runtime called provider %d times", provider.calls)
	}
}

func TestL8AndL7LiveConfigProvidersAreMutuallyExclusiveBeforeEitherCall(t *testing.T) {
	l7Provider := &panickingL7LiveConfigProvider{}
	l8Provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	adapter := &fakeProcessAdapter{}
	controller := l8LiveConfigTestController(adapter, l8Provider)
	controller.l7LiveConfigProvider = l7Provider
	_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    l7LiveConfigTestTarget("runtime-l8-mutual-exclusion"),
	})
	var operationErr *microvm.OperationError
	if err == nil || !errors.As(err, &operationErr) || operationErr.Field != "liveConfigProvider" ||
		!errors.Is(err, microvm.ErrInvalidConfig) {
		t.Fatalf("Start() error = %v, want sanitized provider mutual-exclusion error", err)
	}
	if l7Provider.calls != 0 || l8Provider.calls != 0 || adapter.prepareCalls != 0 || adapter.startCalls != 0 {
		t.Fatalf("mutually exclusive providers crossed a boundary: l7=%d l8=%d adapter=%#v", l7Provider.calls, l8Provider.calls, adapter)
	}
}

func TestL8LiveBootConfigProviderPanicIsContainedBeforePlanning(t *testing.T) {
	provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	adapter := &fakeProcessAdapter{}
	controller := l8LiveConfigTestController(adapter, provider)
	_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    l7LiveConfigTestTarget("runtime-l8-provider-panic"),
	})
	if err == nil {
		t.Fatal("Start() error = nil, want contained L8 provider panic")
	}
	if strings.Contains(err.Error(), "private provider panic") {
		t.Fatalf("provider panic leaked through public error: %v", err)
	}
	if provider.calls != 1 || adapter.prepareCalls != 0 || adapter.startCalls != 0 {
		t.Fatalf("provider panic crossed process boundary: calls=%d adapter=%#v", provider.calls, adapter)
	}
}

func TestL8LiveBootConfigRejectsZeroAndForgedAuthority(t *testing.T) {
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = "runtime-l8-forged"
	base.ProductionVsock = true
	descriptor := l8ShapeLaunchDescriptor(base.LaunchDescriptor)
	forgedProfile := &localresolver.VerifiedL8Profile{}
	forgedLease := &localresolver.VerifiedL8AssetLease{}
	provider := &recordingL8LiveConfigProvider{overlay: L8LiveBootConfigOverlay{
		RuntimeGenerationID: base.RuntimeID,
		LaunchDescriptor:    descriptor,
		VerifiedL8Profile:   forgedProfile,
		VerifiedL8Assets:    forgedLease,
		NetworkMode:         microvm.NetworkModeL7PolicyProxy,
		NetworkInterfaces:   append([]NetworkInterfaceConfig(nil), validL7NetworkBackendConfig(t).NetworkInterfaces...),
		StaticNetwork:       validL7NetworkBackendConfig(t).StaticNetwork,
		AssetChildFDStart:   l7NamespaceKernelChildFD,
	}}
	if _, owned, err := prepareL8LiveBootConfig(context.Background(), provider, base); err == nil || owned != nil {
		t.Fatalf("prepareL8LiveBootConfig(forged) = owned %#v, err %v", owned, err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
}

func TestL8LiveBootConfigProviderErrorRetainsReturnedLeaseOwnership(t *testing.T) {
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = "runtime-l8-provider-error"
	base.ProductionVsock = true
	privateErr := errors.New("private L8 provider /host/path token=ghp_secret")
	forgedLease := &localresolver.VerifiedL8AssetLease{}
	provider := &recordingL8LiveConfigProvider{
		overlay: L8LiveBootConfigOverlay{RuntimeGenerationID: "nonzero", VerifiedL8Assets: forgedLease},
		err:     privateErr,
	}
	_, owned, err := prepareL8LiveBootConfig(context.Background(), provider, base)
	if err == nil || owned != nil {
		t.Fatalf("prepareL8LiveBootConfig(provider error) = owned %#v, err %v", owned, err)
	}
	if strings.Contains(err.Error(), privateErr.Error()) {
		t.Fatalf("private provider error leaked: %v", err)
	}
	// A provider-error result never transfers ownership. The exact returned
	// pointer therefore remains safe for the provider to close itself.
	if closeErr := forgedLease.Close(); closeErr != nil {
		t.Fatalf("provider-owned lease close error = %v", closeErr)
	}
}

func TestL8LiveBootConfigRejectsBaseL7AuthorityBeforeProviderCall(t *testing.T) {
	base := validL7NetworkBackendConfig(t)
	base.RuntimeID = "runtime-l8-base-l7"
	provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	if _, owned, err := prepareL8LiveBootConfig(context.Background(), provider, base); err == nil || owned != nil {
		t.Fatalf("prepareL8LiveBootConfig(L7 base) = owned %#v, err %v", owned, err)
	}
	if provider.calls != 0 {
		t.Fatalf("L7/L8 config mutual exclusion called provider %d times", provider.calls)
	}
	if err := base.VerifiedL7Assets.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloneL8LaunchDescriptorDeepCopiesAndPreservesSliceShape(t *testing.T) {
	source := assets.LaunchDescriptor{
		ID:     "l8-production-credentials-image",
		Labels: []assets.SafeLabel{},
		Assets: []assets.LaunchAsset{{
			ID:     "kernel",
			Role:   assets.AssetRoleKernel,
			Kind:   assets.AssetKindKernelImage,
			Labels: []assets.SafeLabel{"image"},
			Source: assets.AssetSource{
				Type:     assets.SourceTypeLocalFile,
				HostPath: &assets.HostPathMetadata{Path: "/private/kernel", Role: assets.HostPathRoleResolvedLocalAsset},
			},
			InitConfig:  &assets.InitConfigMetadata{Labels: []assets.SafeLabel{}},
			AgentConfig: &assets.AgentConfigMetadata{Features: []assets.SafeLabel{"credential_delivery_v2"}},
			Resources: []assets.ResourceMetadata{{
				ID: "resource", Labels: []assets.SafeLabel{"locked"},
			}},
		}},
	}
	cloned := cloneL8LaunchDescriptor(source)
	if cloned.Labels == nil || cloned.Assets[0].InitConfig.Labels == nil {
		t.Fatal("deep clone collapsed explicit empty slices to nil")
	}
	cloned.Assets[0].Labels[0] = "changed"
	cloned.Assets[0].Source.HostPath.Path = "/changed"
	cloned.Assets[0].AgentConfig.Features[0] = "changed"
	cloned.Assets[0].Resources[0].Labels[0] = "changed"
	if source.Assets[0].Labels[0] != "image" || source.Assets[0].Source.HostPath.Path != "/private/kernel" ||
		source.Assets[0].AgentConfig.Features[0] != "credential_delivery_v2" ||
		source.Assets[0].Resources[0].Labels[0] != "locked" {
		t.Fatal("deep clone aliases caller-owned nested metadata")
	}
	if cloneL8LaunchDescriptor(assets.LaunchDescriptor{}).Labels != nil ||
		cloneL8LaunchDescriptor(assets.LaunchDescriptor{}).Assets != nil {
		t.Fatal("deep clone changed nil slice shape")
	}
}

func TestBackendConfigJSONNeverProjectsL8Authority(t *testing.T) {
	config := validFirecrackerOperationConfig(t)
	config.VerifiedL8Profile = &localresolver.VerifiedL8Profile{}
	config.VerifiedL8Assets = &localresolver.VerifiedL8AssetLease{}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"VerifiedL8", "verifiedL8", "l8Profile", "l8Assets"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("BackendConfig JSON projected L8 authority marker %q: %s", forbidden, encoded)
		}
	}
}

func TestL8LiveConfigProviderDoesNotProjectTargetMetadata(t *testing.T) {
	provider := &recordingL8LiveConfigProvider{panicOnCall: true}
	backend := NewBackend(BackendOptions{L8LiveConfigProvider: provider})
	target, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Name:      "l8-metadata-inert",
		Config:    validMicroVMConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"VerifiedL8", "verifiedL8", "l8Profile", "l8Assets", "production-credentials-profile"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("Target metadata projected L8 authority marker %q: %s", forbidden, encoded)
		}
	}
	if provider.calls != 0 {
		t.Fatalf("Create called default-off L8 provider %d times", provider.calls)
	}
}

type fieldContract struct {
	name     string
	typeName string
	tag      string
}

func assertAdjacentL8Fields(t *testing.T, typ reflect.Type, after string, expected []fieldContract) {
	t.Helper()
	field, ok := typ.FieldByName(after)
	if !ok {
		t.Fatalf("%s omits anchor field %s", typ, after)
	}
	assertL8FieldsAt(t, typ, field.Index[0]+1, expected)
}

func assertExactL8StructFields(t *testing.T, typ reflect.Type, expected []fieldContract) {
	t.Helper()
	if typ.NumField() != len(expected) {
		t.Fatalf("%s field count = %d, want %d", typ, typ.NumField(), len(expected))
	}
	assertL8FieldsAt(t, typ, 0, expected)
}

func assertL8FieldsAt(t *testing.T, typ reflect.Type, start int, expected []fieldContract) {
	t.Helper()
	for index, want := range expected {
		actual := typ.Field(start + index)
		if actual.Name != want.name || actual.Type.String() != want.typeName || string(actual.Tag) != want.tag {
			t.Fatalf("%s field %d = %s %s %q, want %s %s %q", typ, start+index, actual.Name, actual.Type, actual.Tag, want.name, want.typeName, want.tag)
		}
	}
}

type recordingL8LiveConfigProvider struct {
	overlay     L8LiveBootConfigOverlay
	err         error
	calls       int
	panicOnCall bool
}

func (provider *recordingL8LiveConfigProvider) ProvideL8LiveBootConfig(context.Context, L8LiveBootConfigRequest) (L8LiveBootConfigOverlay, error) {
	provider.calls++
	if provider.panicOnCall {
		panic("private provider panic /host/path token=ghp_secret")
	}
	return provider.overlay, provider.err
}

type panickingL7LiveConfigProvider struct{ calls int }

func (provider *panickingL7LiveConfigProvider) ProvideL7LiveBootConfig(context.Context, L7LiveBootConfigRequest) (L7LiveBootConfigOverlay, error) {
	provider.calls++
	panic("L7 provider must not be called")
}

func l8LiveConfigTestController(adapter ProcessAdapter, provider L8LiveBootConfigProvider) firecrackerController {
	return firecrackerController{
		baseStateDir:         firecrackerPathTestBase("l8-live-provider"),
		processAdapter:       adapter,
		bootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		liveProcessManager:   fakeLiveBootSafetyHooks{},
		liveStart:            true,
		productionVsock:      true,
		productionBridge:     l5ConcurrentStartBridge{},
		l8LiveConfigProvider: provider,
	}
}

func l8ShapeLaunchDescriptor(input *assets.LaunchDescriptor) *assets.LaunchDescriptor {
	if input == nil {
		return nil
	}
	descriptor := *input
	descriptor.ID = "l8-production-credentials-image"
	descriptor.Labels = []assets.SafeLabel{"firecracker", "reproducible", "network-profile", "production-credentials-profile"}
	return &descriptor
}
