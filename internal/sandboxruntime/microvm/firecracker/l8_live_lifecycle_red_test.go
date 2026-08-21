//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestL8RenderUsesExclusiveAuthorityBranch(t *testing.T) {
	config := l8LifecycleConfig(t, "runtime-l8-render")
	probe := &l8AuthorityLifecycleProbe{}
	files, effective, err := renderLiveBootFilesForStartWithL8Authority(config, probe.operations())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || probe.prepareCalls != 1 || probe.confirmCalls != 3 {
		t.Fatalf("L8 render = files %d prepare %d confirm %d, want 2/1/3", len(files), probe.prepareCalls, probe.confirmCalls)
	}
	if effective.VerifiedL7Profile != nil || effective.VerifiedL7Assets != nil ||
		effective.VerifiedL8Profile == nil || effective.VerifiedL8Assets != config.VerifiedL8Assets {
		t.Fatalf("effective L8 render authority = %#v", effective)
	}
	if err := closeProcessInheritedFiles(files); err != nil {
		t.Fatal(err)
	}
	if err := closeBackendOwnedL8LeaseWithAuthority(config.VerifiedL8Assets, probe.operations()); err != nil {
		t.Fatal(err)
	}
	if probe.closeCalls != 1 || probe.material == nil {
		t.Fatalf("L8 render cleanup = close %d material nil %t", probe.closeCalls, probe.material == nil)
	}
}

func TestL8RenderRejectsMixedL7AndL8AuthorityBeforeEitherPrepare(t *testing.T) {
	config := l8LifecycleConfig(t, "runtime-l8-mixed")
	l7 := validL7NetworkBackendConfig(t)
	config.VerifiedL7Profile = l7.VerifiedL7Profile
	config.VerifiedL7Assets = l7.VerifiedL7Assets
	probe := &l8AuthorityLifecycleProbe{}
	if _, _, err := renderLiveBootFilesForStartWithL8Authority(config, probe.operations()); err == nil {
		t.Fatal("mixed L7/L8 render error = nil")
	}
	if probe.prepareCalls != 0 || probe.confirmCalls != 0 || probe.closeCalls != 0 {
		t.Fatalf("mixed authority crossed L8 boundary: %#v", probe)
	}
	if err := l7.VerifiedL7Assets.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestL8StartTransfersLeaseUntilProvedStop(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
	controller, provider, target := l8LifecycleController(t, probe, manager, "runtime-l8-success")
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || probe.prepareCalls != 1 || probe.confirmCalls != 7 || probe.closeCalls != 0 {
		t.Fatalf("successful L8 start calls = provider %d prepare %d confirm %d close %d", provider.calls, probe.prepareCalls, probe.confirmCalls, probe.closeCalls)
	}
	if !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
		t.Fatal("successful L8 start did not transfer lease into process ownership")
	}
	stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Target:    *started,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != sandbox.StatusStopped || manager.stopCalls != 1 || probe.closeCalls != 1 {
		t.Fatalf("proved L8 stop = status %q stop %d close %d", stopped.Status, manager.stopCalls, probe.closeCalls)
	}
	if controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
		t.Fatal("proved stop retained L8 lease ownership")
	}
}

func TestL8ProvedStopRetainsOwnershipWhenLeaseCloseIsUncertain(t *testing.T) {
	for _, test := range []struct {
		name       string
		closeError error
		closePanic bool
	}{
		{name: "error", closeError: errors.New("private stop close error /host/path token=secret")},
		{name: "panic", closePanic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{closeError: test.closeError, closePanic: test.closePanic}
			manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
			controller, _, target := l8LifecycleController(t, probe, manager, "runtime-l8-stop-close-"+test.name)
			started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
				Operation: microvm.OperationStart,
				Config:    validMicroVMConfig(),
				Target:    target,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
				Operation: microvm.OperationStop,
				Target:    *started,
			})
			if err == nil {
				t.Fatalf("uncertain lease close %s error = nil", test.name)
			}
			if strings.Contains(err.Error(), "/host/path") || strings.Contains(err.Error(), "token=secret") {
				t.Fatalf("uncertain lease close %s leaked private failure: %v", test.name, err)
			}
			if manager.stopCalls != 1 || probe.closeCalls != 1 ||
				!controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
				t.Fatalf("uncertain lease close %s = stop %d close %d owned %t", test.name, manager.stopCalls, probe.closeCalls, controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid"))
			}
			if _, tracked := controller.liveSessions.Process(target.Runtime.RuntimeID, "fake-pid"); !tracked {
				t.Fatalf("uncertain lease close %s discarded process-keyed ownership", test.name)
			}
		})
	}
}

func TestL8PostStartDriftStopsBeforeLeaseClose(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{confirmErrorAt: 7}
	manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
	controller, _, target := l8LifecycleController(t, probe, manager, "runtime-l8-post-start-drift")
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	}); err == nil {
		t.Fatal("post-start drift error = nil")
	}
	if manager.cleanupCalls != 1 || probe.closeCalls != 1 || manager.cleanupOrder >= probe.closeOrder {
		t.Fatalf("post-start drift ordering = cleanup %d@%d close %d@%d", manager.cleanupCalls, manager.cleanupOrder, probe.closeCalls, probe.closeOrder)
	}
	if controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
		t.Fatal("proved post-start cleanup retained L8 lease")
	}
}

func TestL8PostStartCleanupUncertaintyRetainsLease(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{confirmErrorAt: 7}
	manager := &l8LifecycleProcessManager{cleanupProvesAbsence: false}
	controller, _, target := l8LifecycleController(t, probe, manager, "runtime-l8-post-start-uncertain")
	_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err == nil || !strings.Contains(err.Error(), "terminal state was not verified") {
		t.Fatalf("uncertain post-start cleanup error = %v", err)
	}
	if manager.cleanupCalls != 1 || probe.closeCalls != 0 {
		t.Fatalf("uncertain cleanup = cleanup %d close %d", manager.cleanupCalls, probe.closeCalls)
	}
	if !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
		t.Fatal("uncertain post-start cleanup released L8 lease")
	}
}

func TestL8ProvisionallyOwnedLeaseCleanupErrorsAndPanicsAreObserved(t *testing.T) {
	for _, test := range []struct {
		name       string
		closeError error
		closePanic bool
	}{
		{name: "error", closeError: errors.New("private close error /host/path token=secret")},
		{name: "panic", closePanic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtimeID := "runtime-l8-close-" + test.name
			overlayConfig := l8LifecycleConfig(t, runtimeID)
			config := validFirecrackerOperationConfig(t)
			config.RuntimeID = runtimeID
			config.ProductionVsock = true
			probe := &l8AuthorityLifecycleProbe{closeError: test.closeError, closePanic: test.closePanic}
			provider := &recordingL8LiveConfigProvider{overlay: l8LifecycleOverlay(overlayConfig)}
			provider.overlay.RuntimeGenerationID = "runtime-mismatch"
			_, owned, err := prepareL8LiveBootConfigWithAuthority(context.Background(), provider, config, probe.operations())
			if err == nil || owned != nil || probe.closeCalls != 1 {
				t.Fatalf("cleanup %s = owned %#v err %v close %d", test.name, owned, err, probe.closeCalls)
			}
			if strings.Contains(err.Error(), "/host/path") || strings.Contains(err.Error(), "token=secret") {
				t.Fatalf("cleanup %s leaked private failure: %v", test.name, err)
			}
		})
	}
}

type l8AuthorityLifecycleProbe struct {
	confirmCalls   int
	confirmErrorAt int
	prepareCalls   int
	closeCalls     int
	closeError     error
	closePanic     bool
	closeOrder     int
	material       l8LaunchMaterialWriterForTest
	sequence       *l8LifecycleSequence
}

func (probe *l8AuthorityLifecycleProbe) operations() l8AuthorityOperations {
	return l8AuthorityOperations{
		profileMatches:      func(*localresolver.VerifiedL8Profile, *assets.LaunchDescriptor) bool { return true },
		profileMatchesLease: func(*localresolver.VerifiedL8Profile, *localresolver.VerifiedL8AssetLease) bool { return true },
		confirmCurrent: func(*localresolver.VerifiedL8AssetLease, *assets.LaunchDescriptor) error {
			probe.confirmCalls++
			if probe.confirmErrorAt == probe.confirmCalls {
				return errors.New("private currentness drift /host/path")
			}
			return nil
		},
		prepareLaunch: func(_ *localresolver.VerifiedL8AssetLease, descriptor *assets.LaunchDescriptor, writer localresolver.L8LaunchMaterialWriter) (assets.LaunchDescriptor, localresolver.VerifiedL8Profile, error) {
			probe.prepareCalls++
			probe.material = writer
			prepared := cloneL8LaunchDescriptor(*descriptor)
			for index := range prepared.Assets {
				path, err := writer.WriteAsset(prepared.Assets[index].Role, bytes.NewReader([]byte("l8-"+string(prepared.Assets[index].Role))))
				if err != nil {
					return assets.LaunchDescriptor{}, localresolver.VerifiedL8Profile{}, err
				}
				prepared.Assets[index].Source.HostPath.Path = path
			}
			if err := writer.Validate(); err != nil {
				return assets.LaunchDescriptor{}, localresolver.VerifiedL8Profile{}, err
			}
			return prepared, localresolver.VerifiedL8Profile{}, nil
		},
		closeLease: func(*localresolver.VerifiedL8AssetLease) error {
			probe.closeCalls++
			if probe.sequence != nil {
				probe.closeOrder = probe.sequence.Next()
			}
			if probe.closePanic {
				panic("private close panic /host/path")
			}
			if probe.material != nil {
				if err := probe.material.Close(); err != nil {
					return err
				}
			}
			return probe.closeError
		},
	}
}

type l8LaunchMaterialWriterForTest interface {
	WriteAsset(assets.AssetRole, io.Reader) (string, error)
	Validate() error
	Close() error
}

type l8LifecycleProcessManager struct {
	cleanupProvesAbsence bool
	terminated           bool
	cleanupCalls         int
	stopCalls            int
	cleanupOrder         int
	sequence             *l8LifecycleSequence
}

func (manager *l8LifecycleProcessManager) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	manager.cleanupCalls++
	manager.cleanupOrder = manager.sequence.Next()
	manager.terminated = manager.cleanupProvesAbsence
	return nil
}

func (manager *l8LifecycleProcessManager) StopLiveProcess(context.Context, LiveProcessRequest) error {
	manager.stopCalls++
	manager.terminated = true
	return nil
}

func (*l8LifecycleProcessManager) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
}

func (manager *l8LifecycleProcessManager) LiveProcessTerminated(LiveProcessRequest) bool {
	return manager.terminated
}

type l8LifecycleSequence struct {
	mu    sync.Mutex
	value int
}

func (sequence *l8LifecycleSequence) Next() int {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.value++
	return sequence.value
}

func l8LifecycleController(
	t *testing.T,
	probe *l8AuthorityLifecycleProbe,
	manager *l8LifecycleProcessManager,
	runtimeID string,
) (firecrackerController, *recordingL8LiveConfigProvider, sandboxruntime.Target) {
	t.Helper()
	config := l8LifecycleConfig(t, runtimeID)
	provider := &recordingL8LiveConfigProvider{overlay: l8LifecycleOverlay(config)}
	adapter := &fakeProcessAdapter{}
	sequence := &l8LifecycleSequence{}
	probe.sequence = sequence
	manager.sequence = sequence
	operations := probe.operations()
	controller := firecrackerController{
		baseStateDir:         config.Paths.StateDir,
		processAdapter:       adapter,
		bootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		liveProcessManager:   manager,
		liveStart:            true,
		productionVsock:      true,
		productionBridge:     l5ConcurrentStartBridge{},
		l8LiveConfigProvider: provider,
		liveSessions:         newLiveSessionRegistry(),
		l8Authority:          &operations,
	}
	target := l7LiveConfigTestTarget(runtimeID)
	return controller, provider, target
}

func l8LifecycleConfig(t *testing.T, runtimeID string) BackendConfig {
	t.Helper()
	l7 := validL7NetworkBackendConfig(t)
	descriptor := l8ShapeLaunchDescriptor(l7.LaunchDescriptor)
	interfaces := append([]NetworkInterfaceConfig(nil), l7.NetworkInterfaces...)
	staticNetwork := *l7.StaticNetwork
	if err := l7.VerifiedL7Assets.Close(); err != nil {
		t.Fatal(err)
	}
	config := validFirecrackerOperationConfig(t)
	config.RuntimeID = runtimeID
	baseDir, err := os.MkdirTemp("", "hal-l8-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(baseDir) })
	config.Paths.StateDir = filepath.Join(baseDir, "state")
	config.Paths.APISocketPath = filepath.Join(config.Paths.StateDir, "api.sock")
	config.Paths.ConfigPath = filepath.Join(config.Paths.StateDir, "config.json")
	config.Paths.LogPath = filepath.Join(config.Paths.StateDir, "firecracker.log")
	config.Paths.MetricsPath = filepath.Join(config.Paths.StateDir, "firecracker.metrics")
	config.Paths.VsockSocketPath = filepath.Join(config.Paths.StateDir, "guest.vsock")
	config.ProductionVsock = true
	config.LaunchDescriptor = descriptor
	config.VerifiedL8Profile = &localresolver.VerifiedL8Profile{}
	config.VerifiedL8Assets = &localresolver.VerifiedL8AssetLease{}
	config.NetworkMode = microvm.NetworkModeL7PolicyProxy
	config.NetworkInterfaces = interfaces
	config.StaticNetwork = &staticNetwork
	config.AssetChildFDStart = l7NamespaceKernelChildFD
	return config
}

func l8LifecycleOverlay(config BackendConfig) L8LiveBootConfigOverlay {
	return L8LiveBootConfigOverlay{
		RuntimeGenerationID: config.RuntimeID,
		LaunchDescriptor:    config.LaunchDescriptor,
		VerifiedL8Profile:   config.VerifiedL8Profile,
		VerifiedL8Assets:    config.VerifiedL8Assets,
		NetworkMode:         config.NetworkMode,
		NetworkInterfaces:   config.NetworkInterfaces,
		StaticNetwork:       config.StaticNetwork,
		AssetChildFDStart:   config.AssetChildFDStart,
	}
}
