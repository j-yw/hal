package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

var errL7RuntimeController = errors.New("Firecracker L7 runtime controller failed")

type l7RuntimeIntentProvider interface {
	ResolveL7RuntimeIntent(context.Context, string) (l7network.PrepareRequest, error)
}

type l7RuntimeTopologyFactory interface {
	PrepareL7RuntimeTopology(context.Context, l7network.PrepareRequest) (l7RuntimeTopologySession, error)
}

type l7RuntimeTopologySession interface {
	L7RuntimeLaunch(l7network.Identity) (l7RuntimeLaunch, error)
	InspectAfterGuestReady(context.Context, l7network.Identity, l7network.RunningGuestBinding) (l7network.Metadata, error)
	Quarantine(context.Context, l7network.Identity) error
	CleanupAfterVMQuiesced(context.Context, l7network.Identity, l7network.TerminatedVMBinding) error
	L7RuntimeProxyLoss() <-chan l7RuntimeProxyLoss
}

type l7RuntimeAssetProvider interface {
	AcquireL7RuntimeAssets(context.Context, l7network.Identity) (l7RuntimeAssets, error)
}

type l7FirecrackerRuntimeFactory interface {
	NewL7FirecrackerRuntime(context.Context, l7FirecrackerRuntimeRequest) (l7FirecrackerRuntime, error)
}

type l7FirecrackerRuntime interface {
	microvm.Controller
	RunningGuestBinding(l7network.Identity) (l7network.RunningGuestBinding, error)
	TerminatedVMBinding(l7network.Identity, sandboxruntime.Target) (l7network.TerminatedVMBinding, error)
}

type l7RuntimeControllerDependencies struct {
	Intent      l7RuntimeIntentProvider
	Topology    l7RuntimeTopologyFactory
	Assets      l7RuntimeAssetProvider
	Firecracker l7FirecrackerRuntimeFactory
}

type l7RuntimeAssets struct {
	LaunchDescriptor  *assets.LaunchDescriptor
	VerifiedL7Profile *localresolver.VerifiedL7Profile
	VerifiedL7Assets  *localresolver.VerifiedL7AssetLease
}

func (l7RuntimeAssets) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type l7RuntimeLaunch struct {
	InterfaceID          string
	HostDeviceName       string
	GuestMAC             string
	GuestInterfaceName   string
	IPv4Address          string
	IPv4Gateway          string
	IPv6Address          string
	IPv6Gateway          string
	ProxyURL             string
	TopologyGenerationID string
	RuntimeGenerationID  string
	Namespace            NamespaceProcessFileProvider
}

func (l7RuntimeLaunch) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type l7RuntimeProxyLoss struct {
	Metadata l7network.Metadata
	Err      error
}

type l7FirecrackerRuntimeRequest struct {
	Identity             l7network.Identity
	TopologyGenerationID string
	LiveConfigProvider   firecracker.L7LiveBootConfigProvider
	Namespace            NamespaceProcessFileProvider
}

func (l7FirecrackerRuntimeRequest) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type l7RuntimeControllerRegistry struct {
	mu           sync.Mutex
	dependencies l7RuntimeControllerDependencies
	controllers  map[string]*l7RuntimeController
}

func newL7RuntimeControllerRegistry(dependencies l7RuntimeControllerDependencies) (*l7RuntimeControllerRegistry, error) {
	if interfaceValueIsNil(dependencies.Intent) || interfaceValueIsNil(dependencies.Topology) ||
		interfaceValueIsNil(dependencies.Assets) || interfaceValueIsNil(dependencies.Firecracker) {
		return nil, errL7RuntimeController
	}
	return &l7RuntimeControllerRegistry{
		dependencies: dependencies,
		controllers:  make(map[string]*l7RuntimeController),
	}, nil
}

func (registry *l7RuntimeControllerRegistry) Controller(runtimeGenerationID string) (microvm.Controller, error) {
	if registry == nil {
		return nil, errL7RuntimeController
	}
	runtimeGenerationID = strings.TrimSpace(runtimeGenerationID)
	if !l7RuntimeSafeID(runtimeGenerationID) {
		return nil, errL7RuntimeController
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if controller := registry.controllers[runtimeGenerationID]; controller != nil {
		return controller, nil
	}
	controller := &l7RuntimeController{
		runtimeGenerationID: runtimeGenerationID,
		dependencies:        registry.dependencies,
		state:               l7RuntimeStateIdle,
	}
	registry.controllers[runtimeGenerationID] = controller
	return controller, nil
}

type l7RuntimeState uint8

const (
	l7RuntimeStateIdle l7RuntimeState = iota
	l7RuntimeStateStarting
	l7RuntimeStateActive
	l7RuntimeStateStopping
	l7RuntimeStateStopped
	l7RuntimeStateFailed
	l7RuntimeStateDeleted
)

type l7RuntimeController struct {
	opMu                sync.Mutex
	runtimeGenerationID string
	dependencies        l7RuntimeControllerDependencies
	state               l7RuntimeState
	identity            l7network.Identity
	session             l7RuntimeTopologySession
	runtime             l7FirecrackerRuntime
	target              *sandboxruntime.Target
	lossDone            chan struct{}
}

func (controller *l7RuntimeController) Start(ctx context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if controller == nil {
		return nil, errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if controller.state != l7RuntimeStateIdle || !controller.requestMatchesRuntime(request.Target) {
		return nil, errL7RuntimeController
	}
	controller.state = l7RuntimeStateStarting
	prepared, err := controller.prepareRuntimeLocked(nonNilContext(ctx), request)
	if err != nil {
		controller.state = l7RuntimeStateFailed
		return nil, errL7RuntimeController
	}
	started, err := prepared.runtime.Start(nonNilContext(ctx), request)
	if err != nil || started == nil || !prepared.slot.claimedByRuntime() {
		cleanupErr := prepared.slot.closeIfUnclaimed()
		controller.state = l7RuntimeStateFailed
		controller.quarantinePreparedSession()
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr)
	}
	controller.runtime = prepared.runtime
	binding, err := controller.runtime.RunningGuestBinding(controller.identity)
	if err != nil || interfaceValueIsNil(binding) {
		_, cleanupErr := controller.stopAndCleanupStartedRuntimeLocked(*started)
		controller.state = l7RuntimeStateFailed
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr)
	}
	metadata, err := controller.session.InspectAfterGuestReady(nonNilContext(ctx), controller.identity, binding)
	if err != nil || metadata.Identity != controller.identity || metadata.Status != l7network.StatusInspected || !metadata.RawPacketIsolationVerified {
		_, cleanupErr := controller.stopAndCleanupStartedRuntimeLocked(*started)
		controller.state = l7RuntimeStateFailed
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr)
	}
	active := cloneL7RuntimeTarget(*started)
	active.Status = string(l7network.StatusActive)
	controller.target = &active
	controller.state = l7RuntimeStateActive
	controller.startLossWatcherLocked()
	result := cloneL7RuntimeTarget(active)
	return &result, nil
}

type l7PreparedRuntime struct {
	runtime l7FirecrackerRuntime
	slot    *l7LiveConfigSlot
}

func (controller *l7RuntimeController) prepareRuntimeLocked(ctx context.Context, request microvm.ControllerLifecycleRequest) (l7PreparedRuntime, error) {
	intent, err := controller.dependencies.Intent.ResolveL7RuntimeIntent(ctx, controller.runtimeGenerationID)
	if err != nil || intent.Identity.RuntimeGenerationID != controller.runtimeGenerationID {
		return l7PreparedRuntime{}, errL7RuntimeController
	}
	session, err := controller.dependencies.Topology.PrepareL7RuntimeTopology(ctx, intent)
	if err != nil || interfaceValueIsNil(session) {
		if !interfaceValueIsNil(session) {
			controller.identity, controller.session = intent.Identity, session
		}
		return l7PreparedRuntime{}, errL7RuntimeController
	}
	controller.identity, controller.session = intent.Identity, session
	launch, err := session.L7RuntimeLaunch(intent.Identity)
	if err != nil || !validL7RuntimeLaunch(launch, intent.Identity) {
		controller.quarantinePreparedSession()
		return l7PreparedRuntime{}, errL7RuntimeController
	}
	resolvedAssets, err := controller.dependencies.Assets.AcquireL7RuntimeAssets(ctx, intent.Identity)
	if err != nil || !validL7RuntimeAssets(resolvedAssets) {
		closeErr := closeL7RuntimeAssets(resolvedAssets)
		controller.quarantinePreparedSession()
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, closeErr)
	}
	overlay := firecracker.L7LiveBootConfigOverlay{
		RuntimeGenerationID: intent.Identity.RuntimeGenerationID,
		LaunchDescriptor:    resolvedAssets.LaunchDescriptor,
		VerifiedL7Profile:   resolvedAssets.VerifiedL7Profile,
		VerifiedL7Assets:    resolvedAssets.VerifiedL7Assets,
		NetworkMode:         microvm.NetworkModeL7PolicyProxy,
		NetworkInterfaces: []firecracker.NetworkInterfaceConfig{{
			InterfaceID: launch.InterfaceID, HostDeviceName: launch.HostDeviceName, GuestMAC: launch.GuestMAC,
		}},
		StaticNetwork: &firecracker.StaticNetworkBootConfig{
			GuestInterfaceName: launch.GuestInterfaceName,
			IPv4Address:        launch.IPv4Address, IPv4Gateway: launch.IPv4Gateway,
			IPv6Address: launch.IPv6Address, IPv6Gateway: launch.IPv6Gateway,
			ProxyURL: launch.ProxyURL,
		},
		AssetChildFDStart: 5,
	}
	slot := &l7LiveConfigSlot{runtimeGenerationID: controller.runtimeGenerationID, overlay: overlay}
	runtime, err := controller.dependencies.Firecracker.NewL7FirecrackerRuntime(ctx, l7FirecrackerRuntimeRequest{
		Identity: intent.Identity, TopologyGenerationID: launch.TopologyGenerationID,
		LiveConfigProvider: slot, Namespace: launch.Namespace,
	})
	if err != nil || interfaceValueIsNil(runtime) {
		closeErr := slot.closeIfUnclaimed()
		controller.quarantinePreparedSession()
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, closeErr)
	}
	return l7PreparedRuntime{runtime: runtime, slot: slot}, nil
}

func (controller *l7RuntimeController) Stop(_ context.Context, request microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if controller == nil {
		return nil, errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if !controller.requestMatchesRuntime(request.Target) {
		return nil, errL7RuntimeController
	}
	if controller.state == l7RuntimeStateStopped && controller.target != nil {
		result := cloneL7RuntimeTarget(*controller.target)
		return &result, nil
	}
	if controller.state != l7RuntimeStateActive || controller.target == nil {
		return nil, errL7RuntimeController
	}
	stopped, err := controller.stopAndCleanupStartedRuntimeLocked(*controller.target)
	if err != nil {
		controller.state = l7RuntimeStateFailed
		return nil, errL7RuntimeController
	}
	return stopped, nil
}

func (controller *l7RuntimeController) stopAndCleanupStartedRuntimeLocked(target sandboxruntime.Target) (*sandboxruntime.Target, error) {
	controller.state = l7RuntimeStateStopping
	cleanupCtx := context.Background()
	quarantineErr := controller.session.Quarantine(cleanupCtx, controller.identity)
	stopped, stopErr := controller.runtime.Stop(cleanupCtx, microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Target:    cloneL7RuntimeTarget(target),
	})
	if stopErr != nil || stopped == nil {
		return nil, sanitizeL7RuntimeControllerErrors(quarantineErr, stopErr)
	}
	binding, bindingErr := controller.runtime.TerminatedVMBinding(controller.identity, *stopped)
	var topologyCleanupErr error
	if bindingErr == nil && !interfaceValueIsNil(binding) {
		topologyCleanupErr = controller.session.CleanupAfterVMQuiesced(cleanupCtx, controller.identity, binding)
	} else if bindingErr == nil {
		bindingErr = errL7RuntimeController
	}
	if err := sanitizeL7RuntimeControllerErrors(quarantineErr, bindingErr, topologyCleanupErr); err != nil {
		return nil, err
	}
	result := cloneL7RuntimeTarget(*stopped)
	result.Status = string(l7network.StatusStopped)
	controller.target = &result
	controller.state = l7RuntimeStateStopped
	returned := cloneL7RuntimeTarget(result)
	return &returned, nil
}

func (controller *l7RuntimeController) Delete(ctx context.Context, request microvm.ControllerLifecycleRequest) error {
	if controller == nil {
		return errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if !controller.requestMatchesRuntime(request.Target) || controller.runtime == nil {
		return errL7RuntimeController
	}
	if controller.state == l7RuntimeStateActive && controller.target != nil {
		if _, err := controller.stopAndCleanupStartedRuntimeLocked(*controller.target); err != nil {
			controller.state = l7RuntimeStateFailed
			return errL7RuntimeController
		}
	}
	if controller.state != l7RuntimeStateStopped || controller.target == nil {
		return errL7RuntimeController
	}
	deleteRequest := request
	deleteRequest.Target = cloneL7RuntimeTarget(*controller.target)
	if err := controller.runtime.Delete(nonNilContext(ctx), deleteRequest); err != nil {
		return errL7RuntimeController
	}
	controller.state = l7RuntimeStateDeleted
	return nil
}

func (controller *l7RuntimeController) Inspect(ctx context.Context, request microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	if controller == nil {
		return nil, errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if !controller.requestMatchesRuntime(request.Target) || controller.runtime == nil || controller.target == nil {
		return nil, errL7RuntimeController
	}
	request.Target = cloneL7RuntimeTarget(*controller.target)
	result, err := controller.runtime.Inspect(nonNilContext(ctx), request)
	if err != nil || result == nil {
		return nil, errL7RuntimeController
	}
	cloned := cloneL7RuntimeTarget(*result)
	cloned.Status = controller.target.Status
	return &cloned, nil
}

func (controller *l7RuntimeController) Exec(ctx context.Context, request microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	if controller == nil {
		return nil, errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		return nil, errL7RuntimeController
	}
	request.Target = cloneL7RuntimeTarget(*controller.target)
	return controller.runtime.Exec(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) CopyIn(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if controller == nil {
		return errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		return errL7RuntimeController
	}
	request.Target = cloneL7RuntimeTarget(*controller.target)
	return controller.runtime.CopyIn(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) CopyOut(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if controller == nil {
		return errL7RuntimeController
	}
	controller.opMu.Lock()
	defer controller.opMu.Unlock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		return errL7RuntimeController
	}
	request.Target = cloneL7RuntimeTarget(*controller.target)
	return controller.runtime.CopyOut(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) startLossWatcherLocked() {
	if controller.lossDone != nil || controller.session == nil {
		return
	}
	loss := controller.session.L7RuntimeProxyLoss()
	if loss == nil {
		return
	}
	controller.lossDone = make(chan struct{})
	go func() {
		defer close(controller.lossDone)
		result, ok := <-loss
		if !ok {
			return
		}
		controller.opMu.Lock()
		defer controller.opMu.Unlock()
		if controller.state != l7RuntimeStateActive || controller.target == nil {
			return
		}
		if result.Metadata.Status == l7network.StatusStopped {
			return
		}
		_, _ = controller.stopAndCleanupStartedRuntimeLocked(*controller.target)
	}()
}

func (controller *l7RuntimeController) quarantinePreparedSession() {
	if controller == nil || interfaceValueIsNil(controller.session) {
		return
	}
	_ = controller.session.Quarantine(context.Background(), controller.identity)
}

func (controller *l7RuntimeController) requestMatchesRuntime(target sandboxruntime.Target) bool {
	if controller == nil {
		return false
	}
	runtimeID := strings.TrimSpace(target.Runtime.RuntimeID)
	if runtimeID == "" {
		runtimeID = strings.TrimSpace(target.ID)
	}
	return runtimeID == controller.runtimeGenerationID
}

type l7LiveConfigSlot struct {
	mu                  sync.Mutex
	runtimeGenerationID string
	overlay             firecracker.L7LiveBootConfigOverlay
	claimed             bool
	closed              bool
}

func (slot *l7LiveConfigSlot) ProvideL7LiveBootConfig(ctx context.Context, request firecracker.L7LiveBootConfigRequest) (firecracker.L7LiveBootConfigOverlay, error) {
	if slot == nil {
		return firecracker.L7LiveBootConfigOverlay{}, errL7RuntimeController
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return firecracker.L7LiveBootConfigOverlay{}, err
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.claimed || slot.closed || strings.TrimSpace(request.RuntimeGenerationID) != slot.runtimeGenerationID ||
		slot.overlay.RuntimeGenerationID != slot.runtimeGenerationID {
		return firecracker.L7LiveBootConfigOverlay{}, errL7RuntimeController
	}
	slot.claimed = true
	return slot.overlay, nil
}

func (slot *l7LiveConfigSlot) claimedByRuntime() bool {
	if slot == nil {
		return false
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	return slot.claimed && !slot.closed
}

func (slot *l7LiveConfigSlot) closeIfUnclaimed() error {
	if slot == nil {
		return nil
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.claimed || slot.closed {
		return nil
	}
	slot.closed = true
	return closeL7RuntimeAssets(l7RuntimeAssets{VerifiedL7Assets: slot.overlay.VerifiedL7Assets})
}

func validL7RuntimeLaunch(launch l7RuntimeLaunch, identity l7network.Identity) bool {
	return launch.RuntimeGenerationID == identity.RuntimeGenerationID &&
		launch.TopologyGenerationID == identity.TopologyGenerationID &&
		strings.TrimSpace(launch.InterfaceID) != "" && strings.TrimSpace(launch.HostDeviceName) != "" &&
		strings.TrimSpace(launch.GuestMAC) != "" && strings.TrimSpace(launch.GuestInterfaceName) != "" &&
		strings.TrimSpace(launch.IPv4Address) != "" && strings.TrimSpace(launch.IPv4Gateway) != "" &&
		strings.TrimSpace(launch.IPv6Address) != "" && strings.TrimSpace(launch.IPv6Gateway) != "" &&
		strings.TrimSpace(launch.ProxyURL) != "" && !interfaceValueIsNil(launch.Namespace)
}

func validL7RuntimeAssets(value l7RuntimeAssets) bool {
	return value.LaunchDescriptor != nil && value.VerifiedL7Profile != nil && value.VerifiedL7Assets != nil
}

func closeL7RuntimeAssets(value l7RuntimeAssets) error {
	if value.VerifiedL7Assets == nil {
		return nil
	}
	return value.VerifiedL7Assets.Close()
}

func sanitizeL7RuntimeControllerErrors(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return errL7RuntimeController
		}
	}
	return nil
}

func l7RuntimeSafeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (index > 0 && (r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func cloneL7RuntimeTarget(target sandboxruntime.Target) sandboxruntime.Target {
	cloned := target
	if target.Runtime.Metadata == nil {
		return cloned
	}
	metadata := *target.Runtime.Metadata
	metadata.CapabilityLabels = append([]string(nil), target.Runtime.Metadata.CapabilityLabels...)
	metadata.PathRoles = append([]string(nil), target.Runtime.Metadata.PathRoles...)
	if target.Runtime.Metadata.ProcessLaunch != nil {
		process := *target.Runtime.Metadata.ProcessLaunch
		process.Labels = append([]string(nil), target.Runtime.Metadata.ProcessLaunch.Labels...)
		metadata.ProcessLaunch = &process
	}
	if target.Runtime.Metadata.GuestReadiness != nil {
		readiness := *target.Runtime.Metadata.GuestReadiness
		readiness.Labels = append([]string(nil), target.Runtime.Metadata.GuestReadiness.Labels...)
		metadata.GuestReadiness = &readiness
	}
	cloned.Runtime.Metadata = &metadata
	return cloned
}
