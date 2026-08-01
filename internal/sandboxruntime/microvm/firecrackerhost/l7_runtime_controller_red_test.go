package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestL7RuntimeControllerParallelRuntimesKeepExactTopologyOwnership(t *testing.T) {
	firstID := l7RuntimeControllerIdentity("a")
	secondID := l7RuntimeControllerIdentity("b")
	sequence := &l7RuntimeCallSequence{}
	firstSession := newL7RuntimeFakeTopologySession(firstID, sequence)
	secondSession := newL7RuntimeFakeTopologySession(secondID, sequence)
	intents := &l7RuntimeFakeIntentProvider{requests: map[string]l7network.PrepareRequest{
		firstID.RuntimeGenerationID:  {Identity: firstID, Plan: l7RuntimeControllerPlan(firstID)},
		secondID.RuntimeGenerationID: {Identity: secondID, Plan: l7RuntimeControllerPlan(secondID)},
	}}
	topologies := &l7RuntimeFakeTopologyFactory{sessions: map[string]*l7RuntimeFakeTopologySession{
		firstID.RuntimeGenerationID: firstSession, secondID.RuntimeGenerationID: secondSession,
	}}
	assetProvider := &l7RuntimeFakeAssetProvider{assets: map[string]l7RuntimeAssets{
		firstID.RuntimeGenerationID:  l7RuntimeControllerAssets(firstID.RuntimeGenerationID),
		secondID.RuntimeGenerationID: l7RuntimeControllerAssets(secondID.RuntimeGenerationID),
	}}
	runtimes := &l7RuntimeFakeFirecrackerFactory{sequence: sequence, runtimes: map[string]*l7RuntimeFakeFirecrackerRuntime{}}
	registry, err := newL7RuntimeControllerRegistry(l7RuntimeControllerDependencies{
		Intent: intents, Topology: topologies, Assets: assetProvider, Firecracker: runtimes,
	})
	if err != nil {
		t.Fatal(err)
	}

	firstController, err := registry.Controller(firstID.RuntimeGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	secondController, err := registry.Controller(secondID.RuntimeGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if firstController == secondController {
		t.Fatal("parallel runtime generations shared one outer controller")
	}
	again, err := registry.Controller(firstID.RuntimeGenerationID)
	if err != nil || again != firstController {
		t.Fatalf("same runtime controller lookup = %#v, %v, want stable controller", again, err)
	}

	type startResult struct {
		target *sandboxruntime.Target
		err    error
	}
	results := make(chan startResult, 2)
	ready := make(chan struct{})
	var callers sync.WaitGroup
	callers.Add(2)
	for _, input := range []struct {
		controller microvm.Controller
		identity   l7network.Identity
	}{{firstController, firstID}, {secondController, secondID}} {
		input := input
		go func() {
			callers.Done()
			<-ready
			target, startErr := input.controller.Start(context.Background(), l7RuntimeControllerLifecycleRequest(microvm.OperationStart, input.identity.RuntimeGenerationID))
			results <- startResult{target: target, err: startErr}
		}()
	}
	callers.Wait()
	close(ready)

	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.target == nil || result.target.Status != string(l7network.StatusActive) {
			t.Fatalf("started target = %#v, want outer active publication", result.target)
		}
		sequence.add(result.target.Runtime.RuntimeID, "active")
	}

	for _, identity := range []l7network.Identity{firstID, secondID} {
		runtime := runtimes.runtime(identity.RuntimeGenerationID)
		session := topologies.session(identity.RuntimeGenerationID)
		provided := assetProvider.asset(identity.RuntimeGenerationID)
		if runtime == nil || session == nil {
			t.Fatalf("runtime/session %q was not constructed", identity.RuntimeGenerationID)
		}
		if runtime.request.Identity != identity || runtime.request.Namespace != session.launch.Namespace ||
			runtime.request.TopologyGenerationID != identity.TopologyGenerationID {
			t.Fatalf("runtime handoff %q = %#v, want exact topology ownership", identity.RuntimeGenerationID, runtime.request)
		}
		if runtime.overlay.RuntimeGenerationID != identity.RuntimeGenerationID ||
			runtime.overlay.LaunchDescriptor != provided.LaunchDescriptor ||
			runtime.overlay.VerifiedL7Profile != provided.VerifiedL7Profile ||
			runtime.overlay.VerifiedL7Assets != provided.VerifiedL7Assets ||
			runtime.overlay.NetworkInterfaces[0].HostDeviceName != session.launch.HostDeviceName ||
			runtime.overlay.StaticNetwork.ProxyURL != session.launch.ProxyURL {
			t.Fatalf("runtime overlay %q crossed ownership: %#v", identity.RuntimeGenerationID, runtime.overlay)
		}
		if session.inspectCalls != 1 || runtime.startCalls != 1 {
			t.Fatalf("runtime %q calls = start %d inspect %d, want 1/1", identity.RuntimeGenerationID, runtime.startCalls, session.inspectCalls)
		}
		sequence.requireOrdered(t, identity.RuntimeGenerationID, "prepare", "build", "start", "inspect", "active")
	}
}

func TestL7RuntimeControllerProxyLossAndStopRaceCleansExactRuntimeOnce(t *testing.T) {
	identity := l7RuntimeControllerIdentity("race")
	sequence := &l7RuntimeCallSequence{}
	session := newL7RuntimeFakeTopologySession(identity, sequence)
	topologies := &l7RuntimeFakeTopologyFactory{sessions: map[string]*l7RuntimeFakeTopologySession{identity.RuntimeGenerationID: session}}
	runtimes := &l7RuntimeFakeFirecrackerFactory{sequence: sequence, runtimes: map[string]*l7RuntimeFakeFirecrackerRuntime{}}
	registry, err := newL7RuntimeControllerRegistry(l7RuntimeControllerDependencies{
		Intent: &l7RuntimeFakeIntentProvider{requests: map[string]l7network.PrepareRequest{
			identity.RuntimeGenerationID: {Identity: identity, Plan: l7RuntimeControllerPlan(identity)},
		}},
		Topology: topologies,
		Assets: &l7RuntimeFakeAssetProvider{assets: map[string]l7RuntimeAssets{
			identity.RuntimeGenerationID: l7RuntimeControllerAssets(identity.RuntimeGenerationID),
		}},
		Firecracker: runtimes,
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := registry.Controller(identity.RuntimeGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	started, err := controller.Start(context.Background(), l7RuntimeControllerLifecycleRequest(microvm.OperationStart, identity.RuntimeGenerationID))
	if err != nil {
		t.Fatal(err)
	}
	sequence.add(identity.RuntimeGenerationID, "active")

	stopResult := make(chan error, 1)
	go func() {
		_, stopErr := controller.Stop(context.Background(), l7RuntimeControllerLifecycleRequest(microvm.OperationStop, identity.RuntimeGenerationID))
		stopResult <- stopErr
	}()
	session.publishLoss(l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusQuarantined}})
	if err := <-stopResult; err != nil {
		t.Fatal(err)
	}
	sequence.add(identity.RuntimeGenerationID, "stopped")
	select {
	case <-session.cleaned:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy-loss/stop race cleanup did not finish")
	}

	runtime := runtimes.runtime(identity.RuntimeGenerationID)
	if runtime == nil {
		t.Fatal("Firecracker runtime was not constructed")
	}
	if runtime.stopCalls != 1 || runtime.terminationCalls != 1 || session.quarantineCalls != 1 || session.cleanupCalls != 1 {
		t.Fatalf("race calls = stop %d termination %d quarantine %d cleanup %d, want exactly 1 each",
			runtime.stopCalls, runtime.terminationCalls, session.quarantineCalls, session.cleanupCalls)
	}
	if runtime.lastStopTarget.Runtime.RuntimeID != started.Runtime.RuntimeID || session.cleanedBinding != runtime.terminatedBinding {
		t.Fatal("proxy-loss/stop race cleaned a substituted runtime generation")
	}
	sequence.requireOrdered(t, identity.RuntimeGenerationID, "prepare", "build", "start", "inspect", "active", "quarantine", "stop", "termination", "cleanup", "stopped")
}

type l7RuntimeFakeIntentProvider struct {
	mu       sync.Mutex
	requests map[string]l7network.PrepareRequest
}

func (provider *l7RuntimeFakeIntentProvider) ResolveL7RuntimeIntent(_ context.Context, runtimeID string) (l7network.PrepareRequest, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	request, ok := provider.requests[runtimeID]
	if !ok {
		return l7network.PrepareRequest{}, errors.New("missing runtime intent")
	}
	return request, nil
}

type l7RuntimeFakeTopologyFactory struct {
	mu       sync.Mutex
	sessions map[string]*l7RuntimeFakeTopologySession
}

func (factory *l7RuntimeFakeTopologyFactory) PrepareL7RuntimeTopology(_ context.Context, request l7network.PrepareRequest) (l7RuntimeTopologySession, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	session := factory.sessions[request.Identity.RuntimeGenerationID]
	if session == nil || session.identity != request.Identity {
		return nil, errors.New("missing exact runtime topology")
	}
	session.sequence.add(request.Identity.RuntimeGenerationID, "prepare")
	return session, nil
}

func (factory *l7RuntimeFakeTopologyFactory) session(runtimeID string) *l7RuntimeFakeTopologySession {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.sessions[runtimeID]
}

type l7RuntimeFakeAssetProvider struct {
	mu     sync.Mutex
	assets map[string]l7RuntimeAssets
}

func (provider *l7RuntimeFakeAssetProvider) AcquireL7RuntimeAssets(_ context.Context, identity l7network.Identity) (l7RuntimeAssets, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	value, ok := provider.assets[identity.RuntimeGenerationID]
	if !ok {
		return l7RuntimeAssets{}, errors.New("missing runtime assets")
	}
	return value, nil
}

func (provider *l7RuntimeFakeAssetProvider) asset(runtimeID string) l7RuntimeAssets {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.assets[runtimeID]
}

type l7RuntimeFakeTopologySession struct {
	mu              sync.Mutex
	identity        l7network.Identity
	launch          l7RuntimeLaunch
	loss            chan l7RuntimeProxyLoss
	cleaned         chan struct{}
	sequence        *l7RuntimeCallSequence
	inspectCalls    int
	quarantineCalls int
	cleanupCalls    int
	cleanedBinding  l7network.TerminatedVMBinding
}

func newL7RuntimeFakeTopologySession(identity l7network.Identity, sequence *l7RuntimeCallSequence) *l7RuntimeFakeTopologySession {
	return &l7RuntimeFakeTopologySession{
		identity: identity,
		launch: l7RuntimeLaunch{
			InterfaceID: "net1", HostDeviceName: "tap-" + identity.RuntimeGenerationID,
			GuestMAC: "02:00:00:00:00:02", GuestInterfaceName: "eth0",
			IPv4Address: "192.0.2.2/30", IPv4Gateway: "192.0.2.1",
			IPv6Address: "fd00:7::2/126", IPv6Gateway: "fd00:7::1",
			ProxyURL: "http://192.0.2.1:18080", TopologyGenerationID: identity.TopologyGenerationID,
			RuntimeGenerationID: identity.RuntimeGenerationID, Namespace: &l7RuntimeFakeNamespace{runtimeID: identity.RuntimeGenerationID},
		},
		loss: make(chan l7RuntimeProxyLoss, 1), cleaned: make(chan struct{}), sequence: sequence,
	}
}

func (session *l7RuntimeFakeTopologySession) L7RuntimeLaunch(identity l7network.Identity) (l7RuntimeLaunch, error) {
	if session == nil || identity != session.identity {
		return l7RuntimeLaunch{}, l7network.ErrIdentityMismatch
	}
	return session.launch, nil
}

func (session *l7RuntimeFakeTopologySession) InspectAfterGuestReady(_ context.Context, identity l7network.Identity, binding l7network.RunningGuestBinding) (l7network.Metadata, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if identity != session.identity || binding == nil || binding.GuestCorrelation() != l7RuntimeControllerCorrelation(identity) || binding.GuestReadinessProofID() != identity.TopologyGenerationID {
		return l7network.Metadata{}, l7network.ErrIdentityMismatch
	}
	session.inspectCalls++
	session.sequence.add(identity.RuntimeGenerationID, "inspect")
	return l7network.Metadata{Identity: identity, Status: l7network.StatusInspected, RawPacketIsolationVerified: true}, nil
}

func (session *l7RuntimeFakeTopologySession) Quarantine(_ context.Context, identity l7network.Identity) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if identity != session.identity {
		return l7network.ErrIdentityMismatch
	}
	if session.quarantineCalls == 0 {
		session.quarantineCalls++
		session.sequence.add(identity.RuntimeGenerationID, "quarantine")
	}
	return nil
}

func (session *l7RuntimeFakeTopologySession) CleanupAfterVMQuiesced(_ context.Context, identity l7network.Identity, binding l7network.TerminatedVMBinding) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if identity != session.identity || binding == nil || binding.VMCorrelation() != l7RuntimeControllerCorrelation(identity) {
		return l7network.ErrIdentityMismatch
	}
	session.cleanupCalls++
	session.cleanedBinding = binding
	session.sequence.add(identity.RuntimeGenerationID, "cleanup")
	if session.cleanupCalls == 1 {
		close(session.cleaned)
	}
	return nil
}

func (session *l7RuntimeFakeTopologySession) L7RuntimeProxyLoss() <-chan l7RuntimeProxyLoss {
	return session.loss
}

func (session *l7RuntimeFakeTopologySession) publishLoss(result l7RuntimeProxyLoss) {
	session.loss <- result
	close(session.loss)
}

type l7RuntimeFakeNamespace struct{ runtimeID string }

func (*l7RuntimeFakeNamespace) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	return nil, nil, errors.New("fake namespace duplicate is not a live launch")
}

type l7RuntimeFakeFirecrackerFactory struct {
	mu       sync.Mutex
	sequence *l7RuntimeCallSequence
	runtimes map[string]*l7RuntimeFakeFirecrackerRuntime
}

func (factory *l7RuntimeFakeFirecrackerFactory) NewL7FirecrackerRuntime(_ context.Context, request l7FirecrackerRuntimeRequest) (l7FirecrackerRuntime, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.runtimes[request.Identity.RuntimeGenerationID] != nil {
		return nil, errors.New("duplicate Firecracker runtime construction")
	}
	runtime := &l7RuntimeFakeFirecrackerRuntime{request: request, sequence: factory.sequence,
		terminatedBinding: &l7RuntimeFakeTerminatedBinding{correlation: l7RuntimeControllerCorrelation(request.Identity), proofID: "terminated-" + request.Identity.RuntimeGenerationID}}
	factory.runtimes[request.Identity.RuntimeGenerationID] = runtime
	factory.sequence.add(request.Identity.RuntimeGenerationID, "build")
	return runtime, nil
}

func (factory *l7RuntimeFakeFirecrackerFactory) runtime(runtimeID string) *l7RuntimeFakeFirecrackerRuntime {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.runtimes[runtimeID]
}

type l7RuntimeFakeFirecrackerRuntime struct {
	mu                sync.Mutex
	request           l7FirecrackerRuntimeRequest
	sequence          *l7RuntimeCallSequence
	overlay           firecracker.L7LiveBootConfigOverlay
	startCalls        int
	stopCalls         int
	terminationCalls  int
	lastStopTarget    sandboxruntime.Target
	terminatedBinding *l7RuntimeFakeTerminatedBinding
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) Start(ctx context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	overlay, err := runtime.request.LiveConfigProvider.ProvideL7LiveBootConfig(ctx, firecracker.L7LiveBootConfigRequest{RuntimeGenerationID: runtime.request.Identity.RuntimeGenerationID})
	if err != nil {
		return nil, err
	}
	runtime.overlay = overlay
	runtime.startCalls++
	runtime.sequence.add(runtime.request.Identity.RuntimeGenerationID, "start")
	target := request.Target
	target.Status = string(l7network.StatusInspected)
	return &target, nil
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) Stop(_ context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stopCalls++
	runtime.lastStopTarget = request.Target
	runtime.sequence.add(runtime.request.Identity.RuntimeGenerationID, "stop")
	target := request.Target
	target.Status = string(l7network.StatusStopped)
	return &target, nil
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) Delete(context.Context, microvm.ControllerLifecycleRequest) error {
	return nil
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) Inspect(_ context.Context, request microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	target := request.Target
	return &target, nil
}

func (*l7RuntimeFakeFirecrackerRuntime) Exec(context.Context, microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	return nil, errors.New("unused")
}

func (*l7RuntimeFakeFirecrackerRuntime) CopyIn(context.Context, microvm.ControllerCopyRequest) error {
	return errors.New("unused")
}

func (*l7RuntimeFakeFirecrackerRuntime) CopyOut(context.Context, microvm.ControllerCopyRequest) error {
	return errors.New("unused")
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) RunningGuestBinding(identity l7network.Identity) (l7network.RunningGuestBinding, error) {
	if identity != runtime.request.Identity {
		return nil, l7network.ErrIdentityMismatch
	}
	return &l7RuntimeFakeRunningGuestBinding{correlation: l7RuntimeControllerCorrelation(identity), proofID: identity.TopologyGenerationID}, nil
}

func (runtime *l7RuntimeFakeFirecrackerRuntime) TerminatedVMBinding(identity l7network.Identity, _ sandboxruntime.Target) (l7network.TerminatedVMBinding, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if identity != runtime.request.Identity || runtime.stopCalls != 1 {
		return nil, l7network.ErrIdentityMismatch
	}
	runtime.terminationCalls++
	runtime.sequence.add(identity.RuntimeGenerationID, "termination")
	return runtime.terminatedBinding, nil
}

type l7RuntimeFakeRunningGuestBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
}

func (binding *l7RuntimeFakeRunningGuestBinding) GuestCorrelation() networkenforcement.EnforcementCorrelation {
	return binding.correlation
}

func (binding *l7RuntimeFakeRunningGuestBinding) GuestReadinessProofID() string {
	return binding.proofID
}

type l7RuntimeFakeTerminatedBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
}

func (binding *l7RuntimeFakeTerminatedBinding) VMCorrelation() networkenforcement.EnforcementCorrelation {
	return binding.correlation
}

func (binding *l7RuntimeFakeTerminatedBinding) VMTerminationProofID() string { return binding.proofID }

type l7RuntimeCallSequence struct {
	mu     sync.Mutex
	events map[string][]string
}

func (sequence *l7RuntimeCallSequence) add(runtimeID, event string) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.events == nil {
		sequence.events = make(map[string][]string)
	}
	sequence.events[runtimeID] = append(sequence.events[runtimeID], event)
}

func (sequence *l7RuntimeCallSequence) requireOrdered(t *testing.T, runtimeID string, want ...string) {
	t.Helper()
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	got := sequence.events[runtimeID]
	if len(got) != len(want) {
		t.Fatalf("sequence %q = %#v, want %#v", runtimeID, got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("sequence %q = %#v, want %#v", runtimeID, got, want)
		}
	}
}

func l7RuntimeControllerIdentity(suffix string) l7network.Identity {
	return l7network.Identity{
		SandboxID: "sandbox-" + suffix, ExecutionID: "execution-" + suffix, WorkerID: "worker-" + suffix,
		RuntimeGenerationID: "runtime-" + suffix, PlanID: "plan-" + suffix, PolicySnapshotID: "policy-" + suffix,
		ProxySessionID: "proxy-session-" + suffix, ProxyGenerationID: "proxy-generation-" + suffix,
		TopologyGenerationID: "topology-generation-" + suffix, RuleGenerationID: "rule-generation-" + suffix,
	}
}

func l7RuntimeControllerCorrelation(identity l7network.Identity) networkenforcement.EnforcementCorrelation {
	return networkenforcement.EnforcementCorrelation{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
}

func l7RuntimeControllerPlan(identity l7network.Identity) networkenforcement.Plan {
	return networkenforcement.Plan{
		ID: identity.PlanID, Source: networkenforcement.PlanSourceRuntime, Operation: "run",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{ID: identity.PolicySnapshotID, Preset: networkenforcement.PolicyPresetDenyByDefault},
		DefaultPosture: networkenforcement.DefaultPostureDenyByDefault,
		Proxy: &networkenforcement.ProxyRoutingIntent{ProxySessionID: identity.ProxySessionID, Mechanism: networkenforcement.EnforcementMechanismProxy,
			HTTP: networkenforcement.ProxyRoutingModeRouteViaProxy, HTTPS: networkenforcement.ProxyRoutingModeRouteViaProxy},
		Firewall: &networkenforcement.FirewallIntent{Mode: networkenforcement.FirewallIntentModeApply, Mechanism: networkenforcement.EnforcementMechanismFirewall},
	}
}

func l7RuntimeControllerAssets(runtimeID string) l7RuntimeAssets {
	descriptor := &assets.LaunchDescriptor{ID: assets.SafeID("descriptor-" + runtimeID)}
	profile := &localresolver.VerifiedL7Profile{}
	return l7RuntimeAssets{LaunchDescriptor: descriptor, VerifiedL7Profile: profile, VerifiedL7Assets: &localresolver.VerifiedL7AssetLease{}}
}

func l7RuntimeControllerLifecycleRequest(operation, runtimeID string) microvm.ControllerLifecycleRequest {
	return microvm.ControllerLifecycleRequest{
		Operation: operation,
		Target: sandboxruntime.Target{ID: runtimeID, Name: runtimeID, Provider: firecracker.BackendID,
			Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM, RuntimeID: runtimeID}},
	}
}
