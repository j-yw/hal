package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

var ErrL7LiveCompositionInvalid = errors.New("Firecracker L7 live composition is invalid")

// L7LiveDriverOptions is the distinct opt-in production construction surface
// for the L7 Firecracker topology. Generic NewLiveDriver and all default
// command/worker paths remain unchanged and cannot select this composition.
type L7LiveDriverOptions struct {
	Live             LiveDriverOptions
	Intent           L7RuntimeIntentResolver
	Assets           L7RuntimeAssetResolver
	Topology         l7network.Options
	NamespaceStarter NamespaceProcessStarter
	NSenterPath      string
}

// NewL7LiveDriver constructs a driver whose per-target controller prepares a
// concrete l7network session before it creates any Firecracker live runtime.
func NewL7LiveDriver(options L7LiveDriverOptions) (*microvm.Driver, error) {
	config, backend, err := newL7LiveBackend(options)
	if err != nil {
		return nil, err
	}
	return microvm.NewDriver(microvm.DriverOptions{
		Config: config, CapabilityDetector: options.Live.CapabilityDetector, Backend: backend,
	}), nil
}

func newL7LiveBackend(options L7LiveDriverOptions) (microvm.Config, microvm.Backend, error) {
	if runtime.GOOS != "linux" || interfaceValueIsNil(options.Intent) || interfaceValueIsNil(options.Assets) ||
		interfaceValueIsNil(options.NamespaceStarter) || !validL7NSenterPath(options.NSenterPath) ||
		options.Live.HostProcessRunner != nil || options.Live.GuestReadinessProbe != nil || options.Live.GuestTransport != nil {
		return microvm.Config{}, nil, ErrL7LiveCompositionInvalid
	}
	config, err := validatedLiveDriverConfig(options.Live.Config)
	if err != nil {
		return microvm.Config{}, nil, ErrL7LiveCompositionInvalid
	}
	baseStateDir, err := validatedLiveDriverBaseStateDir(options.Live.BaseStateDir)
	if err != nil || options.Live.BootAcceptancePoller == nil {
		return microvm.Config{}, nil, ErrL7LiveCompositionInvalid
	}

	topologyOptions := options.Topology
	topologyOptions.Enabled = true
	topologyOptions.GuestIsolation = productionL7GuestIsolationVerifier{}
	topologyOptions.VMTermination = productionL7VMTerminationVerifier{}
	coordinator, err := l7network.New(topologyOptions)
	if err != nil {
		return microvm.Config{}, nil, ErrL7LiveCompositionInvalid
	}
	factory := &productionL7FirecrackerFactory{
		live: options.Live, baseStateDir: baseStateDir,
		namespaceStarter: options.NamespaceStarter, nsenterPath: filepath.Clean(options.NSenterPath),
	}
	registry, err := newL7RuntimeControllerRegistry(l7RuntimeControllerDependencies{
		Intent: options.Intent,
		Topology: productionL7TopologyFactory{
			coordinator: coordinator,
		},
		Assets: options.Assets, Firecracker: factory,
	})
	if err != nil {
		return microvm.Config{}, nil, ErrL7LiveCompositionInvalid
	}
	createBackend := firecracker.NewBackend(firecracker.BackendOptions{BaseStateDir: baseStateDir})
	return config, &l7LiveBackend{create: createBackend, registry: registry}, nil
}

func validL7NSenterPath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !hasOSExecProcessControl(value)
}

type l7LiveBackend struct {
	create   *firecracker.Backend
	registry *l7RuntimeControllerRegistry
}

func (backend *l7LiveBackend) Create(ctx context.Context, request microvm.BackendCreateRequest) (*sandboxruntime.Target, error) {
	if backend == nil || backend.create == nil {
		return nil, ErrL7LiveCompositionInvalid
	}
	return backend.create.Create(nonNilContext(ctx), request)
}

func (backend *l7LiveBackend) Controller(_ context.Context, request microvm.ControllerRequest) (microvm.Controller, error) {
	if backend == nil || backend.registry == nil || !validL7ControllerTarget(request.Target) {
		return nil, errL7RuntimeController
	}
	return backend.registry.Controller(request.Target.Runtime.RuntimeID)
}

func validL7ControllerTarget(target sandboxruntime.Target) bool {
	runtimeID := strings.TrimSpace(target.Runtime.RuntimeID)
	return l7RuntimeSafeID(runtimeID) && strings.TrimSpace(target.ID) == runtimeID &&
		target.Provider == firecracker.BackendID && target.Runtime.Driver == sandboxruntime.DriverMicroVM
}

type productionL7TopologyFactory struct{ coordinator *l7network.Coordinator }

func (factory productionL7TopologyFactory) PrepareL7RuntimeTopology(
	ctx context.Context,
	request l7network.PrepareRequest,
) (l7RuntimeTopologySession, error) {
	if factory.coordinator == nil {
		return nil, errL7RuntimeController
	}
	session, err := factory.coordinator.Prepare(nonNilContext(ctx), request)
	if session == nil {
		return nil, err
	}
	return &productionL7TopologySession{session: session}, err
}

type productionL7TopologySession struct {
	session  *l7network.Session
	lossOnce sync.Once
	loss     chan l7RuntimeProxyLoss
}

func (session *productionL7TopologySession) L7RuntimeLaunch(identity l7network.Identity) (l7RuntimeLaunch, error) {
	if session == nil || session.session == nil {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	descriptor, err := session.session.LaunchDescriptor(identity)
	if err != nil {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	interfaceID, hostDevice, guestMAC, ok := descriptor.NetworkInterface()
	if !ok {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	guestInterface, ipv4, ipv4Gateway, ipv6, ipv6Gateway, proxyURL, ok := descriptor.StaticNetwork()
	if !ok {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	topologyGeneration, runtimeGeneration, ok := descriptor.ProofGenerations()
	if !ok {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	namespace, err := session.session.ProcessNamespace(identity)
	if err != nil {
		return l7RuntimeLaunch{}, errL7RuntimeController
	}
	return l7RuntimeLaunch{
		InterfaceID: interfaceID, HostDeviceName: hostDevice, GuestMAC: guestMAC,
		GuestInterfaceName: guestInterface, IPv4Address: ipv4, IPv4Gateway: ipv4Gateway,
		IPv6Address: ipv6, IPv6Gateway: ipv6Gateway, ProxyURL: proxyURL,
		TopologyGenerationID: topologyGeneration, RuntimeGenerationID: runtimeGeneration, Namespace: namespace,
	}, nil
}

func (session *productionL7TopologySession) InspectAfterGuestReady(
	ctx context.Context,
	identity l7network.Identity,
	binding l7network.RunningGuestBinding,
) (l7network.Metadata, error) {
	if session == nil || session.session == nil {
		return l7network.Metadata{}, errL7RuntimeController
	}
	return session.session.InspectAfterGuestReady(nonNilContext(ctx), identity, binding)
}

func (session *productionL7TopologySession) Inspect(ctx context.Context, identity l7network.Identity) (l7network.Metadata, error) {
	if session == nil || session.session == nil {
		return l7network.Metadata{}, errL7RuntimeController
	}
	return session.session.Inspect(nonNilContext(ctx), identity)
}

func (session *productionL7TopologySession) AbortBeforeVM(ctx context.Context, identity l7network.Identity) error {
	if session == nil || session.session == nil {
		return errL7RuntimeController
	}
	return session.session.AbortBeforeVM(nonNilContext(ctx), identity)
}

func (session *productionL7TopologySession) Quarantine(ctx context.Context, identity l7network.Identity) error {
	if session == nil || session.session == nil {
		return errL7RuntimeController
	}
	return session.session.Quarantine(nonNilContext(ctx), identity)
}

func (session *productionL7TopologySession) CleanupAfterVMQuiesced(
	ctx context.Context,
	identity l7network.Identity,
	binding l7network.TerminatedVMBinding,
) error {
	if session == nil || session.session == nil {
		return errL7RuntimeController
	}
	return session.session.CleanupAfterVMQuiesced(nonNilContext(ctx), identity, binding)
}

func (session *productionL7TopologySession) L7RuntimeProxyLoss() <-chan l7RuntimeProxyLoss {
	if session == nil || session.session == nil {
		return nil
	}
	session.lossOnce.Do(func() {
		session.loss = make(chan l7RuntimeProxyLoss, 1)
		source := session.session.Loss()
		if source == nil {
			close(session.loss)
			return
		}
		go func() {
			result, ok := <-source
			if ok {
				session.loss <- l7RuntimeProxyLoss{Metadata: result.Metadata(), Err: result.Err()}
			}
			close(session.loss)
		}()
	})
	return session.loss
}

type productionL7FirecrackerFactory struct {
	live             LiveDriverOptions
	baseStateDir     string
	namespaceStarter NamespaceProcessStarter
	nsenterPath      string
}

func (factory *productionL7FirecrackerFactory) NewL7FirecrackerRuntime(
	ctx context.Context,
	request l7FirecrackerRuntimeRequest,
) (l7FirecrackerRuntime, error) {
	if factory == nil || interfaceValueIsNil(request.Namespace) || interfaceValueIsNil(request.LiveConfigProvider) ||
		!l7RuntimeSafeID(request.TopologyGenerationID) || request.TopologyGenerationID != request.Identity.TopologyGenerationID {
		return nil, errL7RuntimeController
	}
	namespaceRunner, err := NewNamespaceProcessRunner(NamespaceProcessRunnerOptions{
		Namespace: request.Namespace, Starter: factory.namespaceStarter, NSenterPath: factory.nsenterPath,
	})
	if err != nil {
		return nil, errL7RuntimeController
	}
	lifecycleOptions := liveDriverLifecycleOptions(factory.live)
	lifecycleOptions = append(lifecycleOptions, withProcessLifecycleProductionVsock())
	lifecycle := NewProcessLifecycleManager(namespaceRunner, lifecycleOptions...)
	tracker := &l7ProcessTracker{lifecycle: lifecycle}
	adapter := NewAdapter(liveDriverAdapterOptions(factory.live, lifecycle)...)
	adapter.processRunner = tracker
	bridge := NewProductionVsockBridge(ProductionVsockBridgeOptions{
		Lifecycle: lifecycle, Timeout: factory.live.GuestTimeout, PollInterval: factory.live.GuestPollInterval,
		RequireIsolationProof: true, RequireNetworkProof: true, IsolationProofGeneration: request.TopologyGenerationID,
	})
	backend := firecracker.NewBackend(firecracker.BackendOptions{
		BaseStateDir:   factory.baseStateDir,
		ProcessAdapter: firecracker.ProcessLaunchAdapter{Starter: adapter}, BootAcceptanceWaiter: adapter,
		LiveProcessManager: adapter, LiveStart: true, ProductionVsock: true, ProductionBridge: bridge,
		L7LiveConfigProvider: request.LiveConfigProvider,
	})
	controller, err := backend.Controller(nonNilContext(ctx), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Target: sandboxruntime.Target{ID: request.Identity.RuntimeGenerationID, Provider: firecracker.BackendID,
			Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM, RuntimeID: request.Identity.RuntimeGenerationID}},
	})
	if err != nil || controller == nil {
		return nil, errL7RuntimeController
	}
	return &productionL7FirecrackerRuntime{
		controller: controller, identity: request.Identity, bridge: bridge, lifecycle: lifecycle, tracker: tracker,
	}, nil
}

type l7ProcessTracker struct {
	lifecycle *ProcessLifecycleManager
	mu        sync.Mutex
	handle    firecracker.ProcessHandleMetadata
	attempted bool
	uncertain bool
}

type l7RetainedProcessCleaner interface {
	RetryRetainedProcessCleanup(context.Context) error
}

func (tracker *l7ProcessTracker) StartProcess(
	ctx context.Context,
	request firecracker.ProcessRunnerStartRequest,
) (firecracker.ProcessHandleMetadata, error) {
	if tracker == nil || tracker.lifecycle == nil {
		return firecracker.ProcessHandleMetadata{}, errL7RuntimeController
	}
	handle, err := tracker.lifecycle.StartProcess(nonNilContext(ctx), request)
	tracker.mu.Lock()
	tracker.attempted = true
	// NamespaceProcessRunner returns cleanup_incomplete whenever a returned
	// process cannot be proven terminated and reaped. Other start failures
	// occur before launch or only after that runner has contained the exact
	// returned process, so they are valid no-process evidence.
	tracker.uncertain = err != nil && errors.Is(err, ErrNamespaceProcessCleanupIncomplete)
	if err == nil && strings.TrimSpace(handle.ID) != "" && strings.TrimSpace(handle.Source) != "" {
		tracker.handle = handle
	}
	tracker.mu.Unlock()
	return handle, err
}

func (tracker *l7ProcessTracker) snapshot() (firecracker.ProcessHandleMetadata, bool) {
	if tracker == nil {
		return firecracker.ProcessHandleMetadata{}, false
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	handle := tracker.handle
	return handle, strings.TrimSpace(handle.ID) != "" && strings.TrimSpace(handle.Source) != ""
}

func (tracker *l7ProcessTracker) absenceConfirmed() bool {
	if tracker == nil {
		return false
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.attempted && strings.TrimSpace(tracker.handle.ID) == "" &&
		strings.TrimSpace(tracker.handle.Source) == "" && !tracker.uncertain
}

func (tracker *l7ProcessTracker) retryUncertainProcessCleanup(ctx context.Context) error {
	if tracker == nil || tracker.lifecycle == nil {
		return errL7RuntimeController
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if !tracker.uncertain {
		return nil
	}
	cleaner, ok := tracker.lifecycle.runner.(l7RetainedProcessCleaner)
	if !ok || interfaceValueIsNil(cleaner) || strings.TrimSpace(tracker.handle.ID) != "" ||
		strings.TrimSpace(tracker.handle.Source) != "" {
		return errL7RuntimeController
	}
	if err := cleaner.RetryRetainedProcessCleanup(nonNilContext(ctx)); err != nil {
		return errL7RuntimeController
	}
	tracker.uncertain = false
	return nil
}

type productionL7FirecrackerRuntime struct {
	controller microvm.Controller
	identity   l7network.Identity
	bridge     *ProductionVsockBridge
	lifecycle  *ProcessLifecycleManager
	tracker    *l7ProcessTracker
	mu         sync.Mutex
	started    *sandboxruntime.Target
}

func (runtime *productionL7FirecrackerRuntime) Start(ctx context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if runtime == nil || runtime.controller == nil {
		return nil, errL7RuntimeController
	}
	started, err := runtime.controller.Start(nonNilContext(ctx), request)
	if started != nil {
		copy := cloneL7RuntimeTarget(*started)
		runtime.mu.Lock()
		runtime.started = &copy
		runtime.mu.Unlock()
	}
	return started, err
}

func (runtime *productionL7FirecrackerRuntime) Stop(ctx context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if runtime == nil || runtime.controller == nil {
		return nil, errL7RuntimeController
	}
	return runtime.controller.Stop(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) Delete(ctx context.Context, request microvm.ControllerLifecycleRequest) error {
	if runtime == nil || runtime.controller == nil {
		return errL7RuntimeController
	}
	return runtime.controller.Delete(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) Inspect(ctx context.Context, request microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	if runtime == nil || runtime.controller == nil {
		return nil, errL7RuntimeController
	}
	return runtime.controller.Inspect(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) Exec(ctx context.Context, request microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	if runtime == nil || runtime.controller == nil {
		return nil, errL7RuntimeController
	}
	return runtime.controller.Exec(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) CopyIn(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if runtime == nil || runtime.controller == nil {
		return errL7RuntimeController
	}
	return runtime.controller.CopyIn(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) CopyOut(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if runtime == nil || runtime.controller == nil {
		return errL7RuntimeController
	}
	return runtime.controller.CopyOut(nonNilContext(ctx), request)
}

func (runtime *productionL7FirecrackerRuntime) RunningGuestBinding(identity l7network.Identity) (l7network.RunningGuestBinding, error) {
	if runtime == nil || runtime.bridge == nil || identity != runtime.identity {
		return nil, errL7RuntimeController
	}
	runtime.mu.Lock()
	if runtime.started == nil {
		runtime.mu.Unlock()
		return nil, errL7RuntimeController
	}
	target := cloneL7RuntimeTarget(*runtime.started)
	runtime.mu.Unlock()
	proof, err := runtime.bridge.refreshL7Proof(context.Background(), target, identity.TopologyGenerationID)
	if err != nil || proof.runtimeID != identity.RuntimeGenerationID {
		return nil, errL7RuntimeController
	}
	return &productionL7RunningGuestBinding{
		correlation: l7EnforcementCorrelation(identity), readinessProofID: proof.bridgeGeneration,
		topologyGenerationID: identity.TopologyGenerationID, target: target, bridge: runtime.bridge, proof: proof,
	}, nil
}

func (runtime *productionL7FirecrackerRuntime) TerminatedVMBinding(
	identity l7network.Identity,
	_ sandboxruntime.Target,
) (l7network.TerminatedVMBinding, error) {
	if runtime == nil || runtime.lifecycle == nil || runtime.tracker == nil || identity != runtime.identity {
		return nil, errL7RuntimeController
	}
	if err := runtime.tracker.retryUncertainProcessCleanup(context.Background()); err != nil {
		return nil, errL7RuntimeController
	}
	handle, ok := runtime.tracker.snapshot()
	noProcess := false
	if !ok {
		if !runtime.tracker.absenceConfirmed() {
			return nil, errL7RuntimeController
		}
		noProcess = true
	} else if !runtime.lifecycle.LiveProcessTerminated(firecracker.LiveProcessRequest{Handle: handle}) {
		return nil, errL7RuntimeController
	}
	generation := handle.ID
	if noProcess {
		generation = "no-process"
	}
	return &productionL7TerminatedVMBinding{
		correlation: l7EnforcementCorrelation(identity), proofID: l7ProofID("terminated", identity, generation),
		lifecycle: runtime.lifecycle, tracker: runtime.tracker, handle: handle, noProcess: noProcess,
	}, nil
}

type productionL7RunningGuestBinding struct {
	correlation          networkenforcement.EnforcementCorrelation
	readinessProofID     string
	topologyGenerationID string
	target               sandboxruntime.Target
	bridge               *ProductionVsockBridge
	proof                productionVsockL7Proof
}

func (binding *productionL7RunningGuestBinding) GuestCorrelation() networkenforcement.EnforcementCorrelation {
	if binding == nil {
		return networkenforcement.EnforcementCorrelation{}
	}
	return binding.correlation
}

func (binding *productionL7RunningGuestBinding) GuestReadinessProofID() string {
	if binding == nil {
		return ""
	}
	return binding.readinessProofID
}

type productionL7GuestIsolationVerifier struct{}

func (productionL7GuestIsolationVerifier) VerifyRunningGuestRawPacketIsolation(
	ctx context.Context,
	request l7network.RunningGuestRawPacketIsolationRequest,
) (l7network.RunningGuestRawPacketIsolationProof, error) {
	binding, ok := request.Binding.(*productionL7RunningGuestBinding)
	if !ok || binding == nil || binding.bridge == nil || request.ReadinessProofID != binding.readinessProofID ||
		!networkenforcement.EnforcementCorrelationsEqual(request.Correlation, binding.correlation) {
		return l7network.RunningGuestRawPacketIsolationProof{}, errL7RuntimeController
	}
	fresh, err := binding.bridge.refreshL7Proof(nonNilContext(ctx), binding.target, binding.topologyGenerationID)
	if err != nil || fresh != binding.proof {
		return l7network.RunningGuestRawPacketIsolationProof{}, errL7RuntimeController
	}
	verifiedAt := time.Now().UnixMilli()
	if verifiedAt <= 0 {
		return l7network.RunningGuestRawPacketIsolationProof{}, errL7RuntimeController
	}
	correlation := binding.correlation
	return l7network.RunningGuestRawPacketIsolationProof{
		ReadinessProofID: binding.readinessProofID,
		RawPacketProof: networkenforcement.RawPacketIsolationProof{
			ID:     l7ProofID("raw", l7IdentityFromCorrelation(correlation), fresh.bridgeGeneration),
			Status: networkenforcement.RawPacketIsolationStatusVerified, VerifiedAtUnixMilli: verifiedAt,
			Correlation: &correlation, ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified,
		},
	}, nil
}

type productionL7TerminatedVMBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
	lifecycle   *ProcessLifecycleManager
	tracker     *l7ProcessTracker
	handle      firecracker.ProcessHandleMetadata
	noProcess   bool
}

func (binding *productionL7TerminatedVMBinding) VMCorrelation() networkenforcement.EnforcementCorrelation {
	if binding == nil {
		return networkenforcement.EnforcementCorrelation{}
	}
	return binding.correlation
}

func (binding *productionL7TerminatedVMBinding) VMTerminationProofID() string {
	if binding == nil {
		return ""
	}
	return binding.proofID
}

type productionL7VMTerminationVerifier struct{}

func (productionL7VMTerminationVerifier) VerifyVMTermination(
	_ context.Context,
	request l7network.VMTerminationRequest,
) (l7network.VMTerminationProof, error) {
	binding, ok := request.Binding.(*productionL7TerminatedVMBinding)
	if !ok || binding == nil || binding.lifecycle == nil || request.TerminationProofID != binding.proofID ||
		!networkenforcement.EnforcementCorrelationsEqual(request.Correlation, binding.correlation) || !binding.terminal() {
		return l7network.VMTerminationProof{}, errL7RuntimeController
	}
	return l7network.VMTerminationProof{
		ID:                 l7ProofID("vm", l7IdentityFromCorrelation(binding.correlation), binding.proofID),
		TerminationProofID: binding.proofID, Correlation: binding.correlation, Stopped: true, Reaped: true,
	}, nil
}

func (binding *productionL7TerminatedVMBinding) terminal() bool {
	if binding == nil || binding.lifecycle == nil {
		return false
	}
	if binding.noProcess {
		return binding.tracker != nil && binding.tracker.absenceConfirmed()
	}
	return binding.lifecycle.LiveProcessTerminated(firecracker.LiveProcessRequest{Handle: binding.handle})
}

func l7EnforcementCorrelation(identity l7network.Identity) networkenforcement.EnforcementCorrelation {
	return networkenforcement.EnforcementCorrelation{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
}

func l7IdentityFromCorrelation(value networkenforcement.EnforcementCorrelation) l7network.Identity {
	return l7network.Identity{
		SandboxID: value.SandboxID, ExecutionID: value.ExecutionID, WorkerID: value.WorkerID,
		RuntimeGenerationID: value.RuntimeID, PlanID: value.PlanID, PolicySnapshotID: value.PolicySnapshotID,
		ProxySessionID: value.ProxySessionID, ProxyGenerationID: value.ProxyGenerationID,
		TopologyGenerationID: value.TopologyGenerationID, RuleGenerationID: value.RuleGenerationID,
	}
}

func l7ProofID(kind string, identity l7network.Identity, generation string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		kind, identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeGenerationID,
		identity.PlanID, identity.PolicySnapshotID, identity.ProxySessionID, identity.ProxyGenerationID,
		identity.TopologyGenerationID, identity.RuleGenerationID, generation,
	}, "\x00")))
	return kind + "-" + hex.EncodeToString(digest[:16])
}
