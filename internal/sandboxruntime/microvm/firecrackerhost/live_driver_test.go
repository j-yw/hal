package firecrackerhost

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestNewLiveBackendOptionsComposesExplicitFirecrackerLiveDependencies(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	runner := &fakeHostProcessRunner{}
	poller := &fakeBootAcceptancePoller{}
	clock := fakeClock{now: time.Unix(123, 0)}
	sleeper := &fakeSleeper{}
	cleanupFS := newFakeCleanupFilesystem()

	options, err := NewLiveBackendOptions(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		Clock:                clock,
		Sleeper:              sleeper,
		BootTimeout:          5 * time.Second,
		BootPollInterval:     25 * time.Millisecond,
		CleanupFilesystem:    cleanupFS,
		CapabilityDetector:   liveDriverAvailableDetector{},
	})
	if err != nil {
		t.Fatalf("NewLiveBackendOptions() error = %v, want nil", err)
	}

	if options.BaseStateDir != baseStateDir {
		t.Fatalf("BaseStateDir = %q, want %q", options.BaseStateDir, baseStateDir)
	}
	if !options.LiveStart {
		t.Fatal("LiveStart = false, want true")
	}

	processAdapter, ok := options.ProcessAdapter.(firecracker.ProcessLaunchAdapter)
	if !ok {
		t.Fatalf("ProcessAdapter = %T, want firecracker.ProcessLaunchAdapter", options.ProcessAdapter)
	}
	hostAdapter, ok := processAdapter.Starter.(*Adapter)
	if !ok {
		t.Fatalf("ProcessLaunchAdapter.Starter = %T, want *Adapter", processAdapter.Starter)
	}
	if options.BootAcceptanceWaiter != hostAdapter {
		t.Fatalf("BootAcceptanceWaiter = %T, want same host adapter used by ProcessLaunchAdapter", options.BootAcceptanceWaiter)
	}
	if options.LiveProcessManager != hostAdapter {
		t.Fatalf("LiveProcessManager = %T, want same host adapter used by ProcessLaunchAdapter", options.LiveProcessManager)
	}

	lifecycle, ok := hostAdapter.processRunner.(*ProcessLifecycleManager)
	if !ok {
		t.Fatalf("adapter process runner = %T, want *ProcessLifecycleManager", hostAdapter.processRunner)
	}
	if lifecycle.runner != runner {
		t.Fatal("process lifecycle manager did not receive injected host process runner")
	}
	if lifecycle.cleanupFS != cleanupFS {
		t.Fatal("process lifecycle manager did not receive injected cleanup filesystem")
	}
	if hostAdapter.cleanup != lifecycle {
		t.Fatal("adapter live cleanup does not use the same process lifecycle manager as process start")
	}
	if hostAdapter.poller != poller {
		t.Fatal("adapter did not receive injected boot acceptance poller")
	}
	if got := hostAdapter.clock.Now(); !got.Equal(clock.now) {
		t.Fatalf("adapter clock Now() = %s, want %s", got, clock.now)
	}
	if hostAdapter.sleeper != sleeper {
		t.Fatal("adapter did not receive injected sleeper")
	}
	if hostAdapter.bootTimeout != 5*time.Second {
		t.Fatalf("adapter boot timeout = %s, want 5s", hostAdapter.bootTimeout)
	}
	if hostAdapter.bootInterval != 25*time.Millisecond {
		t.Fatalf("adapter boot interval = %s, want 25ms", hostAdapter.bootInterval)
	}
}

func TestNewLiveDriverUsesExplicitBackendAndCapabilityOverride(t *testing.T) {
	detector := &recordingLiveDriverCapabilityDetector{report: liveDriverAvailableCapabilityReport()}
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:             liveDriverValidConfig(),
		BaseStateDir:       filepath.Join(t.TempDir(), "firecracker-state"),
		CapabilityDetector: detector,
		HostProcessRunner:  &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		}},
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	if detector.calls != 1 {
		t.Fatalf("capability detector calls = %d, want 1", detector.calls)
	}
	if !reflect.DeepEqual(detector.request.Config, microvm.ApplyDefaults(liveDriverValidConfig())) {
		t.Fatalf("capability detector config = %#v, want defaulted live config", detector.request.Config)
	}

	metadata := driver.Metadata()
	if !metadata.BackendConfigured {
		t.Fatal("driver metadata BackendConfigured = false, want true")
	}
	if metadata.Availability != microvm.CapabilityAvailabilityAvailable {
		t.Fatalf("driver metadata Availability = %q, want %q", metadata.Availability, microvm.CapabilityAvailabilityAvailable)
	}
	if metadata.ReasonCode != microvm.DriverReasonAvailable {
		t.Fatalf("driver metadata ReasonCode = %q, want %q", metadata.ReasonCode, microvm.DriverReasonAvailable)
	}

	target, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-dev"})
	if err != nil {
		t.Fatalf("driver Create() error = %v, want nil", err)
	}
	if target == nil || target.Runtime.Metadata == nil {
		t.Fatalf("driver Create() target = %#v, want Firecracker metadata", target)
	}
	if target.Runtime.Metadata.Backend != firecracker.BackendID {
		t.Fatalf("target backend = %q, want %q", target.Runtime.Metadata.Backend, firecracker.BackendID)
	}
}

func TestNewLiveBackendOptionsRejectsInvalidExplicitInputs(t *testing.T) {
	tests := []struct {
		name    string
		options LiveDriverOptions
		field   string
	}{
		{
			name: "missing firecracker executable path",
			options: LiveDriverOptions{
				Config:               liveDriverConfigWithoutHypervisorPath(),
				BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
				BootAcceptancePoller: &fakeBootAcceptancePoller{},
			},
			field: "executablePath",
		},
		{
			name: "missing base state dir",
			options: LiveDriverOptions{
				Config:               liveDriverValidConfig(),
				BootAcceptancePoller: &fakeBootAcceptancePoller{},
			},
			field: "baseStateDir",
		},
		{
			name: "missing boot poller",
			options: LiveDriverOptions{
				Config:       liveDriverValidConfig(),
				BaseStateDir: filepath.Join(t.TempDir(), "firecracker-state"),
			},
			field: "bootAcceptancePoller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLiveBackendOptions(tt.options)
			if err == nil {
				t.Fatal("NewLiveBackendOptions() error = nil, want validation error")
			}
			var operationErr *microvm.OperationError
			if !errors.As(err, &operationErr) {
				t.Fatalf("error = %T %v, want *microvm.OperationError", err, err)
			}
			if operationErr.Field != tt.field {
				t.Fatalf("OperationError.Field = %q, want %q", operationErr.Field, tt.field)
			}
		})
	}
}

func liveDriverValidConfig() microvm.Config {
	return microvm.Config{
		HypervisorPath:  "/usr/bin/firecracker",
		KernelImagePath: "/opt/hal/images/vmlinux",
		RootfsPath:      "/opt/hal/images/rootfs.ext4",
		CPUCount:        1,
		MemoryMiB:       256,
		DiskSizeMiB:     1024,
		GuestWorkDir:    "/workspace",
		NetworkMode:     microvm.NetworkModeNoLiveNetworking,
	}
}

func liveDriverConfigWithoutHypervisorPath() microvm.Config {
	config := liveDriverValidConfig()
	config.HypervisorPath = ""
	return config
}

type liveDriverAvailableDetector struct{}

func (liveDriverAvailableDetector) DetectMicroVMCapability(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
	return liveDriverAvailableCapabilityReport()
}

type recordingLiveDriverCapabilityDetector struct {
	calls   int
	request microvm.CapabilityDetectionRequest
	report  microvm.CapabilityReport
}

func (detector *recordingLiveDriverCapabilityDetector) DetectMicroVMCapability(request microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
	detector.calls++
	detector.request = request
	return detector.report
}

func liveDriverAvailableCapabilityReport() microvm.CapabilityReport {
	kvmReadable := true
	hypervisorAvailable := true
	return microvm.CapabilityReport{
		OS:                             "linux",
		Architecture:                   "amd64",
		KVMDevicePresent:               true,
		KVMReadable:                    &kvmReadable,
		HypervisorExecutableConfigured: true,
		HypervisorExecutableAvailable:  &hypervisorAvailable,
		Availability:                   microvm.CapabilityAvailabilityAvailable,
		ReasonCode:                     microvm.CapabilityReasonAvailable,
	}
}
