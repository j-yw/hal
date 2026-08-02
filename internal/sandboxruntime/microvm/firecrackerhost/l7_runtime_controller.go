package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

var errL7RuntimeController = errors.New("Firecracker L7 runtime controller failed")

const l7RuntimeControllerCleanupTimeout = 5 * time.Second

// L7RuntimeIntentResolver supplies one immutable, runtime-bound topology
// request to the explicit L7 live composition. Implementations must not
// persist live endpoint data in the request.
type L7RuntimeIntentResolver interface {
	ResolveL7RuntimeIntent(context.Context, string) (l7network.PrepareRequest, error)
}

type l7RuntimeIntentProvider = L7RuntimeIntentResolver

type l7RuntimeTopologyFactory interface {
	PrepareL7RuntimeTopology(context.Context, l7network.PrepareRequest) (l7RuntimeTopologySession, error)
}

type l7RuntimeTopologySession interface {
	L7RuntimeLaunch(l7network.Identity) (l7RuntimeLaunch, error)
	InspectAfterGuestReady(context.Context, l7network.Identity, l7network.RunningGuestBinding) (l7network.Metadata, error)
	Inspect(context.Context, l7network.Identity) (l7network.Metadata, error)
	AbortBeforeVM(context.Context, l7network.Identity) error
	Quarantine(context.Context, l7network.Identity) error
	CleanupAfterVMQuiesced(context.Context, l7network.Identity, l7network.TerminatedVMBinding) error
	L7RuntimeProxyLoss() <-chan l7RuntimeProxyLoss
}

// L7RuntimeAssetResolver acquires one verified descriptor/profile/lease set
// for the exact runtime generation. Ownership transfers only through the
// successful live-config handoff.
type L7RuntimeAssetResolver interface {
	AcquireL7RuntimeAssets(context.Context, l7network.Identity) (L7RuntimeAssets, error)
}

type l7RuntimeAssetProvider = L7RuntimeAssetResolver

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

// L7RuntimeAssets is the live-only verified launch material accepted by the
// explicit L7 controller. JSON deliberately exposes none of its contents.
type L7RuntimeAssets struct {
	LaunchDescriptor  *assets.LaunchDescriptor
	VerifiedL7Profile *localresolver.VerifiedL7Profile
	VerifiedL7Assets  *localresolver.VerifiedL7AssetLease
}

func (L7RuntimeAssets) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type l7RuntimeAssets = L7RuntimeAssets

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
	preVMCleanup        *l7RuntimePreVMCleanup
	vmCleanup           *l7RuntimeVMCleanup
}

type l7RuntimePreVMCleanup struct {
	session        l7RuntimeTopologySession
	assets         *l7LiveConfigSlot
	sessionPending bool
	assetsPending  bool
}

type l7RuntimeVMCleanup struct {
	target              sandboxruntime.Target
	assets              *l7LiveConfigSlot
	assetsPending       bool
	quarantineConfirmed bool
	stopConfirmed       bool
	stoppedTarget       *sandboxruntime.Target
	terminatedBinding   l7network.TerminatedVMBinding
	topologyCleanupDone bool
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
		if controller.preVMCleanup != nil {
			controller.state = l7RuntimeStateFailed
		} else {
			controller.state = l7RuntimeStateIdle
			controller.identity = l7network.Identity{}
			controller.session = nil
			controller.runtime = nil
			controller.target = nil
			controller.vmCleanup = nil
		}
		return nil, errL7RuntimeController
	}
	// Ownership becomes VM-possible before invoking Start. Every return from
	// that handoff, including nil/error combinations, must therefore cross the
	// exact stop/reap and topology-cleanup boundary.
	controller.runtime = prepared.runtime
	controller.vmCleanup = &l7RuntimeVMCleanup{
		target:        cloneL7RuntimeTarget(request.Target),
		assets:        prepared.slot,
		assetsPending: true,
	}
	started, err := prepared.runtime.Start(nonNilContext(ctx), request)
	claimed := prepared.slot.claimedByRuntime()
	validStarted := controller.requestMatchesRuntimePointer(started)
	if validStarted {
		controller.vmCleanup.target = cloneL7RuntimeTarget(*started)
	}
	if err != nil || !validStarted || !claimed {
		_, cleanupErr := controller.containVMOwnedRuntimeLocked()
		if cleanupErr != nil {
			controller.state = l7RuntimeStateFailed
		}
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr, invalidL7RuntimeStartResult(validStarted, claimed))
	}
	binding, err := controller.runtime.RunningGuestBinding(controller.identity)
	if err != nil || interfaceValueIsNil(binding) {
		_, cleanupErr := controller.containVMOwnedRuntimeLocked()
		if cleanupErr != nil {
			controller.state = l7RuntimeStateFailed
		}
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr, nilL7RuntimeRunningBinding(binding))
	}
	metadata, err := controller.session.InspectAfterGuestReady(nonNilContext(ctx), controller.identity, binding)
	if err != nil || !validL7RuntimeInspectedMetadata(metadata, controller.identity) {
		_, cleanupErr := controller.containVMOwnedRuntimeLocked()
		if cleanupErr != nil {
			controller.state = l7RuntimeStateFailed
		}
		return nil, sanitizeL7RuntimeControllerErrors(err, cleanupErr, invalidL7RuntimeInspectedMetadata(metadata, controller.identity))
	}
	loss := controller.session.L7RuntimeProxyLoss()
	if loss == nil {
		_, cleanupErr := controller.containVMOwnedRuntimeLocked()
		if cleanupErr != nil {
			controller.state = l7RuntimeStateFailed
		}
		return nil, sanitizeL7RuntimeControllerErrors(errL7RuntimeController, cleanupErr)
	}
	active := cloneL7RuntimeTarget(*started)
	active.Status = string(l7network.StatusActive)
	controller.target = &active
	controller.state = l7RuntimeStateActive
	controller.startLossWatcherLocked(loss)
	result := cloneL7RuntimeTarget(active)
	return &result, nil
}

func invalidL7RuntimeStartResult(validStarted, claimed bool) error {
	if !validStarted || !claimed {
		return errL7RuntimeController
	}
	return nil
}

func nilL7RuntimeRunningBinding(binding l7network.RunningGuestBinding) error {
	if interfaceValueIsNil(binding) {
		return errL7RuntimeController
	}
	return nil
}

func invalidL7RuntimeInspectedMetadata(metadata l7network.Metadata, identity l7network.Identity) error {
	if !validL7RuntimeInspectedMetadata(metadata, identity) {
		return errL7RuntimeController
	}
	return nil
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
	if !interfaceValueIsNil(session) {
		controller.identity, controller.session = intent.Identity, session
	}
	if err != nil || interfaceValueIsNil(session) {
		var cleanupErr error
		if !interfaceValueIsNil(session) {
			cleanupErr = controller.beginPreVMCleanupLocked(session, nil)
		}
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, cleanupErr, nilL7RuntimeTopologySession(session))
	}
	launch, err := session.L7RuntimeLaunch(intent.Identity)
	if err != nil || !validL7RuntimeLaunch(launch, intent.Identity) {
		cleanupErr := controller.beginPreVMCleanupLocked(session, nil)
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, cleanupErr, invalidL7RuntimeLaunchError(launch, intent.Identity))
	}
	resolvedAssets, err := controller.dependencies.Assets.AcquireL7RuntimeAssets(ctx, intent.Identity)
	assetSlot := l7RuntimeAssetCleanupSlot(controller.runtimeGenerationID, resolvedAssets)
	if err != nil || !validL7RuntimeAssets(resolvedAssets) {
		cleanupErr := controller.beginPreVMCleanupLocked(session, assetSlot)
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, cleanupErr, invalidL7RuntimeAssetsError(resolvedAssets))
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
		cleanupErr := controller.beginPreVMCleanupLocked(session, slot)
		return l7PreparedRuntime{}, sanitizeL7RuntimeControllerErrors(err, cleanupErr, nilL7RuntimeFirecracker(runtime))
	}
	return l7PreparedRuntime{runtime: runtime, slot: slot}, nil
}

func nilL7RuntimeTopologySession(session l7RuntimeTopologySession) error {
	if interfaceValueIsNil(session) {
		return errL7RuntimeController
	}
	return nil
}

func invalidL7RuntimeLaunchError(launch l7RuntimeLaunch, identity l7network.Identity) error {
	if !validL7RuntimeLaunch(launch, identity) {
		return errL7RuntimeController
	}
	return nil
}

func invalidL7RuntimeAssetsError(value l7RuntimeAssets) error {
	if !validL7RuntimeAssets(value) {
		return errL7RuntimeController
	}
	return nil
}

func nilL7RuntimeFirecracker(runtime l7FirecrackerRuntime) error {
	if interfaceValueIsNil(runtime) {
		return errL7RuntimeController
	}
	return nil
}

func l7RuntimeAssetCleanupSlot(runtimeGenerationID string, value l7RuntimeAssets) *l7LiveConfigSlot {
	if value.VerifiedL7Assets == nil {
		return nil
	}
	return &l7LiveConfigSlot{
		runtimeGenerationID: runtimeGenerationID,
		overlay:             firecracker.L7LiveBootConfigOverlay{VerifiedL7Assets: value.VerifiedL7Assets},
	}
}

func (controller *l7RuntimeController) beginPreVMCleanupLocked(session l7RuntimeTopologySession, assets *l7LiveConfigSlot) error {
	cleanup := &l7RuntimePreVMCleanup{
		session:        session,
		assets:         assets,
		sessionPending: !interfaceValueIsNil(session),
		assetsPending:  assets != nil,
	}
	controller.preVMCleanup = cleanup
	return controller.retryPreVMCleanupLocked()
}

func (controller *l7RuntimeController) retryPreVMCleanupLocked() error {
	if controller == nil || controller.preVMCleanup == nil {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), l7RuntimeControllerCleanupTimeout)
	defer cancel()
	cleanup := controller.preVMCleanup
	var failures []error
	// Assets were acquired after topology preparation, so release them first
	// while still attempting topology rollback even if release is uncertain.
	if cleanup.assetsPending {
		if err := cleanup.assets.closeIfUnclaimed(); err != nil {
			failures = append(failures, err)
		} else {
			cleanup.assetsPending = false
		}
	}
	if cleanup.sessionPending {
		if err := cleanup.session.AbortBeforeVM(cleanupCtx, controller.identity); err != nil {
			failures = append(failures, err)
		} else {
			cleanup.sessionPending = false
		}
	}
	if cleanup.assetsPending || cleanup.sessionPending {
		return sanitizeL7RuntimeControllerErrors(append(failures, errL7RuntimeController)...)
	}
	controller.preVMCleanup = nil
	controller.session = nil
	return nil
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
	if controller.preVMCleanup != nil {
		if err := controller.retryPreVMCleanupLocked(); err != nil {
			controller.state = l7RuntimeStateFailed
			return nil, errL7RuntimeController
		}
		result := cloneL7RuntimeTarget(request.Target)
		result.Status = string(l7network.StatusStopped)
		controller.target = &result
		controller.state = l7RuntimeStateStopped
		returned := cloneL7RuntimeTarget(result)
		return &returned, nil
	}
	if controller.vmCleanup == nil || controller.runtime == nil || controller.session == nil {
		return nil, errL7RuntimeController
	}
	stopped, err := controller.containVMOwnedRuntimeLocked()
	if err != nil {
		controller.state = l7RuntimeStateFailed
		return nil, errL7RuntimeController
	}
	return stopped, nil
}

func (controller *l7RuntimeController) containVMOwnedRuntimeLocked() (*sandboxruntime.Target, error) {
	if controller == nil || controller.vmCleanup == nil || interfaceValueIsNil(controller.runtime) || interfaceValueIsNil(controller.session) {
		return nil, errL7RuntimeController
	}
	controller.state = l7RuntimeStateStopping
	cleanupCtx, cancel := context.WithTimeout(context.Background(), l7RuntimeControllerCleanupTimeout)
	defer cancel()
	cleanup := controller.vmCleanup
	var failures []error

	if cleanup.assetsPending {
		if err := cleanup.assets.closeIfUnclaimed(); err != nil {
			failures = append(failures, err)
		} else {
			cleanup.assetsPending = false
		}
	}
	if !cleanup.quarantineConfirmed {
		if err := controller.session.Quarantine(cleanupCtx, controller.identity); err != nil {
			failures = append(failures, err)
		} else {
			cleanup.quarantineConfirmed = true
		}
	}
	if !cleanup.stopConfirmed {
		stopped, stopErr := controller.runtime.Stop(cleanupCtx, microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Target:    cloneL7RuntimeTarget(cleanup.target),
		})
		if stopped != nil && controller.requestMatchesRuntime(*stopped) && stopErr == nil {
			value := cloneL7RuntimeTarget(*stopped)
			cleanup.stoppedTarget = &value
			cleanup.stopConfirmed = true
		}
		if stopErr != nil || stopped == nil || !controller.requestMatchesRuntimePointer(stopped) {
			failures = append(failures, sanitizeL7RuntimeControllerErrors(stopErr, invalidL7RuntimeStoppedTarget(stopped, controller)))
		}
	}
	if interfaceValueIsNil(cleanup.terminatedBinding) {
		terminationTarget := cleanup.target
		if cleanup.stoppedTarget != nil {
			terminationTarget = *cleanup.stoppedTarget
		}
		binding, bindingErr := controller.runtime.TerminatedVMBinding(controller.identity, cloneL7RuntimeTarget(terminationTarget))
		if bindingErr == nil && !interfaceValueIsNil(binding) {
			cleanup.terminatedBinding = binding
		} else {
			failures = append(failures, sanitizeL7RuntimeControllerErrors(bindingErr, nilL7RuntimeTerminatedBinding(binding)))
		}
	}
	if cleanup.quarantineConfirmed && !interfaceValueIsNil(cleanup.terminatedBinding) && !cleanup.topologyCleanupDone {
		if err := controller.session.CleanupAfterVMQuiesced(cleanupCtx, controller.identity, cleanup.terminatedBinding); err != nil {
			failures = append(failures, err)
		} else {
			cleanup.topologyCleanupDone = true
		}
	}
	if cleanup.assetsPending || !cleanup.quarantineConfirmed || interfaceValueIsNil(cleanup.terminatedBinding) || !cleanup.topologyCleanupDone {
		controller.state = l7RuntimeStateFailed
		return nil, sanitizeL7RuntimeControllerErrors(append(failures, errL7RuntimeController)...)
	}
	result := cloneL7RuntimeTarget(cleanup.target)
	if cleanup.stoppedTarget != nil {
		result = cloneL7RuntimeTarget(*cleanup.stoppedTarget)
	}
	result.Status = string(l7network.StatusStopped)
	controller.target = &result
	controller.state = l7RuntimeStateStopped
	controller.vmCleanup = nil
	returned := cloneL7RuntimeTarget(result)
	return &returned, nil
}

func invalidL7RuntimeStoppedTarget(target *sandboxruntime.Target, controller *l7RuntimeController) error {
	if target == nil || controller == nil || !controller.requestMatchesRuntime(*target) {
		return errL7RuntimeController
	}
	return nil
}

func nilL7RuntimeTerminatedBinding(binding l7network.TerminatedVMBinding) error {
	if interfaceValueIsNil(binding) {
		return errL7RuntimeController
	}
	return nil
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
	if controller.state == l7RuntimeStateActive || (controller.vmCleanup != nil && controller.state != l7RuntimeStateStopped) {
		if _, err := controller.containVMOwnedRuntimeLocked(); err != nil {
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
	if controller.state == l7RuntimeStateStopped {
		if err != nil || !controller.requestMatchesRuntimePointer(result) {
			return nil, errL7RuntimeController
		}
		cloned := cloneL7RuntimeTarget(*result)
		cloned.Status = string(l7network.StatusStopped)
		return &cloned, nil
	}
	if controller.state != l7RuntimeStateActive || err != nil || !controller.requestMatchesRuntimePointer(result) {
		if controller.vmCleanup != nil {
			_, _ = controller.containVMOwnedRuntimeLocked()
		}
		return nil, errL7RuntimeController
	}
	metadata, topologyErr := controller.session.Inspect(nonNilContext(ctx), controller.identity)
	if topologyErr != nil || !validL7RuntimeInspectedMetadata(metadata, controller.identity) {
		_, _ = controller.containVMOwnedRuntimeLocked()
		return nil, errL7RuntimeController
	}
	cloned := cloneL7RuntimeTarget(*result)
	cloned.Status = string(l7network.StatusActive)
	return &cloned, nil
}

func (controller *l7RuntimeController) Exec(ctx context.Context, request microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	if controller == nil {
		return nil, errL7RuntimeController
	}
	controller.opMu.Lock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		controller.opMu.Unlock()
		return nil, errL7RuntimeController
	}
	runtime := controller.runtime
	request.Target = cloneL7RuntimeTarget(*controller.target)
	controller.opMu.Unlock()
	return runtime.Exec(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) CopyIn(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if controller == nil {
		return errL7RuntimeController
	}
	controller.opMu.Lock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		controller.opMu.Unlock()
		return errL7RuntimeController
	}
	runtime := controller.runtime
	request.Target = cloneL7RuntimeTarget(*controller.target)
	controller.opMu.Unlock()
	return runtime.CopyIn(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) CopyOut(ctx context.Context, request microvm.ControllerCopyRequest) error {
	if controller == nil {
		return errL7RuntimeController
	}
	controller.opMu.Lock()
	if controller.state != l7RuntimeStateActive || controller.runtime == nil || controller.target == nil || !controller.requestMatchesRuntime(request.Target) {
		controller.opMu.Unlock()
		return errL7RuntimeController
	}
	runtime := controller.runtime
	request.Target = cloneL7RuntimeTarget(*controller.target)
	controller.opMu.Unlock()
	return runtime.CopyOut(nonNilContext(ctx), request)
}

func (controller *l7RuntimeController) startLossWatcherLocked(loss <-chan l7RuntimeProxyLoss) {
	if controller.lossDone != nil || controller.session == nil || loss == nil {
		return
	}
	controller.lossDone = make(chan struct{})
	go func() {
		defer close(controller.lossDone)
		result, ok := <-loss
		controller.opMu.Lock()
		defer controller.opMu.Unlock()
		if controller.state != l7RuntimeStateActive || controller.target == nil {
			return
		}
		// A valid result says the session has already attempted quarantine; an
		// invalid/closed result is even less trustworthy. Either way, an active
		// controller must revoke work and complete exact VM containment.
		if !ok || !validL7RuntimeProxyLossResult(result, controller.identity) {
			_, _ = controller.containVMOwnedRuntimeLocked()
			return
		}
		_, _ = controller.containVMOwnedRuntimeLocked()
	}()
}

func validL7RuntimeProxyLossResult(result l7RuntimeProxyLoss, identity l7network.Identity) bool {
	if result.Metadata.Identity != identity {
		return false
	}
	switch result.Metadata.Status {
	case l7network.StatusQuarantined:
		return result.Err == nil
	case l7network.StatusCleanupIncomplete:
		return errors.Is(result.Err, l7network.ErrCleanupIncomplete) || errors.Is(result.Err, l7network.ErrQuarantineFailed)
	default:
		return false
	}
}

func (controller *l7RuntimeController) requestMatchesRuntime(target sandboxruntime.Target) bool {
	if controller == nil {
		return false
	}
	return target.ID == controller.runtimeGenerationID &&
		target.Runtime.RuntimeID == controller.runtimeGenerationID &&
		target.Provider == firecracker.BackendID &&
		target.Runtime.Driver == sandboxruntime.DriverMicroVM
}

func (controller *l7RuntimeController) requestMatchesRuntimePointer(target *sandboxruntime.Target) bool {
	return target != nil && controller.requestMatchesRuntime(*target)
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
	if err := closeL7RuntimeAssets(l7RuntimeAssets{VerifiedL7Assets: slot.overlay.VerifiedL7Assets}); err != nil {
		return err
	}
	slot.closed = true
	return nil
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

func validL7RuntimeInspectedMetadata(metadata l7network.Metadata, identity l7network.Identity) bool {
	return metadata.Identity == identity && metadata.Status == l7network.StatusInspected &&
		metadata.StructuralInspected && metadata.TAPInspected && metadata.RulesInspected &&
		metadata.RawPacketIsolationVerified && strings.TrimSpace(metadata.RuleDigest) != ""
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
