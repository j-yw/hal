package firecracker

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestL7LiveBootConfigOverlayMapsOnlyPrivateLiveFields(t *testing.T) {
	verified := validL7NetworkBackendConfig(t)
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = "runtime-overlay-a"
	base.ProductionVsock = true
	overlay := l7LiveOverlayFromConfig(base.RuntimeID, verified)

	got, owned, err := prepareL7LiveBootConfig(context.Background(), &recordingL7LiveConfigProvider{
		overlays: map[string]L7LiveBootConfigOverlay{base.RuntimeID: overlay},
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	if owned != verified.VerifiedL7Assets {
		t.Fatal("prepareL7LiveBootConfig() did not return exact owned asset lease")
	}
	if got.BackendID != base.BackendID || got.ExecutablePath != base.ExecutablePath || got.JailerPath != base.JailerPath ||
		got.CPUCount != base.CPUCount || got.MemoryMiB != base.MemoryMiB || got.RuntimeID != base.RuntimeID ||
		!reflect.DeepEqual(got.Paths, base.Paths) || !reflect.DeepEqual(got.GuestWorkDir, base.GuestWorkDir) || !got.ProductionVsock {
		t.Fatalf("L7 overlay changed immutable base config: base=%#v got=%#v", base, got)
	}
	if got.LaunchDescriptor != verified.LaunchDescriptor || got.VerifiedL7Profile != verified.VerifiedL7Profile ||
		got.VerifiedL7Assets != verified.VerifiedL7Assets || got.NetworkMode != verified.NetworkMode ||
		!reflect.DeepEqual(got.NetworkInterfaces, verified.NetworkInterfaces) ||
		!reflect.DeepEqual(got.StaticNetwork, verified.StaticNetwork) || got.AssetChildFDStart != 5 {
		t.Fatalf("L7 overlay mapping = %#v, want exact verified private fields", got)
	}
	overlay.NetworkInterfaces[0].HostDeviceName = "substituted"
	overlay.StaticNetwork.ProxyURL = "http://198.51.100.9:9"
	if got.NetworkInterfaces[0].HostDeviceName == "substituted" || got.StaticNetwork.ProxyURL == "http://198.51.100.9:9" {
		t.Fatal("L7 overlay result aliases mutable provider values")
	}
}

func TestL7LiveBootConfigProviderFailureRetainsProviderLeaseOwnership(t *testing.T) {
	verified := validL7NetworkBackendConfig(t)
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = "runtime-provider-error"
	base.ProductionVsock = true
	providerErr := errors.New("private provider failure /host/path token=ghp_secret")
	provider := &recordingL7LiveConfigProvider{
		overlays: map[string]L7LiveBootConfigOverlay{base.RuntimeID: l7LiveOverlayFromConfig(base.RuntimeID, verified)},
		err:      providerErr,
	}
	if _, owned, err := prepareL7LiveBootConfig(context.Background(), provider, base); err == nil || owned != nil {
		t.Fatalf("prepareL7LiveBootConfig(provider error) = owned %#v, err %v", owned, err)
	}
	if err := verified.VerifiedL7Assets.ConfirmCurrent(verified.LaunchDescriptor); err != nil {
		t.Fatalf("provider-owned lease was closed on provider error: %v", err)
	}
}

func TestL7LiveBootConfigValidationFailureClosesReturnedLease(t *testing.T) {
	verified := validL7NetworkBackendConfig(t)
	base := validFirecrackerOperationConfig(t)
	base.RuntimeID = "runtime-validation-a"
	base.ProductionVsock = true
	overlay := l7LiveOverlayFromConfig("runtime-substituted", verified)
	if _, owned, err := prepareL7LiveBootConfig(context.Background(), &recordingL7LiveConfigProvider{
		overlays: map[string]L7LiveBootConfigOverlay{base.RuntimeID: overlay},
	}, base); err == nil || owned != nil {
		t.Fatalf("prepareL7LiveBootConfig(mismatch) = owned %#v, err %v", owned, err)
	}
	if err := verified.VerifiedL7Assets.ConfirmCurrent(verified.LaunchDescriptor); !errors.Is(err, localresolver.ErrFileUnavailable) {
		t.Fatalf("validation-failed lease remained open: %v", err)
	}
}

func TestL7LiveBootConfigPlanFailureClosesBackendOwnedLease(t *testing.T) {
	verified := validL7NetworkBackendConfig(t)
	provider := &recordingL7LiveConfigProvider{overlays: map[string]L7LiveBootConfigOverlay{}}
	adapter := &fakeProcessAdapter{prepare: func(context.Context, ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
		return ProcessCommandDescriptor{}, errors.New("private plan adapter failure /host/path")
	}}
	controller := firecrackerController{
		baseStateDir:         t.TempDir(),
		processAdapter:       adapter,
		bootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		liveProcessManager:   fakeLiveBootSafetyHooks{},
		liveStart:            true,
		productionVsock:      true,
		productionBridge:     l5ConcurrentStartBridge{},
		l7LiveConfigProvider: provider,
	}
	target := l7LiveConfigTestTarget("runtime-plan-failure")
	provider.overlays[target.Runtime.RuntimeID] = l7LiveOverlayFromConfig(target.Runtime.RuntimeID, verified)
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target,
	}); err == nil {
		t.Fatal("Start() error = nil, want process planning failure")
	}
	if adapter.prepareCalls != 1 || adapter.startCalls != 0 {
		t.Fatalf("process calls = prepare %d, start %d", adapter.prepareCalls, adapter.startCalls)
	}
	if err := verified.VerifiedL7Assets.ConfirmCurrent(verified.LaunchDescriptor); !errors.Is(err, localresolver.ErrFileUnavailable) {
		t.Fatalf("plan-failed backend lease remained open: %v", err)
	}
}

func TestL7LiveBootConfigTypedNilProviderFailsBeforePlanning(t *testing.T) {
	var provider *recordingL7LiveConfigProvider
	adapter := &fakeProcessAdapter{}
	controller := firecrackerController{
		baseStateDir:         t.TempDir(),
		processAdapter:       adapter,
		bootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		liveProcessManager:   fakeLiveBootSafetyHooks{},
		liveStart:            true,
		productionVsock:      true,
		productionBridge:     l5ConcurrentStartBridge{},
		l7LiveConfigProvider: provider,
	}
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: l7LiveConfigTestTarget("runtime-typed-nil"),
	}); err == nil {
		t.Fatal("Start() error = nil, want typed-nil provider rejection")
	}
	if adapter.prepareCalls != 0 || adapter.startCalls != 0 {
		t.Fatalf("typed-nil provider crossed process boundary: %#v", adapter)
	}
}

func TestL7LiveBootConfigProviderIsInertOnPlanningOnlyDefault(t *testing.T) {
	provider := &recordingL7LiveConfigProvider{panicOnCall: true}
	adapter := &fakeProcessAdapter{}
	controller := firecrackerController{baseStateDir: t.TempDir(), processAdapter: adapter, l7LiveConfigProvider: provider}
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: l7LiveConfigTestTarget("runtime-default-inert"),
	}); err != nil {
		t.Fatal(err)
	}
	if adapter.prepareCalls != 1 || adapter.startCalls != 0 || provider.callCount() != 0 {
		t.Fatalf("planning-only calls = provider %d, prepare %d, start %d", provider.callCount(), adapter.prepareCalls, adapter.startCalls)
	}
}

func TestL7LiveBootConfigConcurrentRuntimesKeepExactIdentityAndAssets(t *testing.T) {
	firstVerified := validL7NetworkBackendConfig(t)
	secondVerified := validL7NetworkBackendConfig(t)
	first := validFirecrackerOperationConfig(t)
	first.RuntimeID, first.ProductionVsock = "runtime-parallel-a", true
	second := validFirecrackerOperationConfig(t)
	second.RuntimeID, second.ProductionVsock = "runtime-parallel-b", true
	provider := &recordingL7LiveConfigProvider{overlays: map[string]L7LiveBootConfigOverlay{
		first.RuntimeID:  l7LiveOverlayFromConfig(first.RuntimeID, firstVerified),
		second.RuntimeID: l7LiveOverlayFromConfig(second.RuntimeID, secondVerified),
	}}

	type result struct {
		config BackendConfig
		lease  *localresolver.VerifiedL7AssetLease
		err    error
	}
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, config := range []BackendConfig{first, second} {
		config := config
		go func() {
			ready.Done()
			ready.Wait()
			prepared, lease, err := prepareL7LiveBootConfig(context.Background(), provider, config)
			results <- result{config: prepared, lease: lease, err: err}
		}()
	}
	seen := map[string]result{}
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		seen[got.config.RuntimeID] = got
	}
	if seen[first.RuntimeID].lease != firstVerified.VerifiedL7Assets || seen[first.RuntimeID].config.LaunchDescriptor != firstVerified.LaunchDescriptor ||
		seen[second.RuntimeID].lease != secondVerified.VerifiedL7Assets || seen[second.RuntimeID].config.LaunchDescriptor != secondVerified.LaunchDescriptor {
		t.Fatalf("parallel overlay identity/assets were swapped: %#v", seen)
	}
	if provider.callCount() != 2 {
		t.Fatalf("parallel provider calls = %d, want 2", provider.callCount())
	}
}

type recordingL7LiveConfigProvider struct {
	mu          sync.Mutex
	overlays    map[string]L7LiveBootConfigOverlay
	err         error
	calls       []string
	panicOnCall bool
}

func (p *recordingL7LiveConfigProvider) ProvideL7LiveBootConfig(_ context.Context, request L7LiveBootConfigRequest) (L7LiveBootConfigOverlay, error) {
	if p.panicOnCall {
		panic("L7 live config provider called on inert path")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, request.RuntimeGenerationID)
	return p.overlays[request.RuntimeGenerationID], p.err
}

func (p *recordingL7LiveConfigProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func l7LiveOverlayFromConfig(runtimeID string, config BackendConfig) L7LiveBootConfigOverlay {
	return L7LiveBootConfigOverlay{
		RuntimeGenerationID: runtimeID,
		LaunchDescriptor:    config.LaunchDescriptor,
		VerifiedL7Profile:   config.VerifiedL7Profile,
		VerifiedL7Assets:    config.VerifiedL7Assets,
		NetworkMode:         config.NetworkMode,
		NetworkInterfaces:   append([]NetworkInterfaceConfig(nil), config.NetworkInterfaces...),
		StaticNetwork:       config.StaticNetwork,
		AssetChildFDStart:   5,
	}
}

func l7LiveConfigTestTarget(runtimeID string) sandboxruntime.Target {
	return sandboxruntime.Target{ID: runtimeID, Name: runtimeID, Provider: BackendID,
		Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM, RuntimeID: runtimeID}}
}
