package microvm

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestDriverSatisfiesSandboxruntimeDriver(t *testing.T) {
	var _ sandboxruntime.Driver = (*Driver)(nil)
}

func TestDriverIDReturnsMicroVMRuntimeID(t *testing.T) {
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})

	if got := driver.ID(); got != sandboxruntime.DriverMicroVM {
		t.Fatalf("ID() = %q, want %q", got, sandboxruntime.DriverMicroVM)
	}
}

func TestDriverMetadataIdentifiesMicroVMRuntimeBoundary(t *testing.T) {
	report := availableCapabilityReport()
	driver := NewDriver(DriverOptions{CapabilityDetector: fixedCapabilityDetector(report)})

	metadata := driver.Metadata()
	if metadata.DriverID != sandboxruntime.DriverMicroVM {
		t.Fatalf("DriverID = %q, want %q", metadata.DriverID, sandboxruntime.DriverMicroVM)
	}
	if metadata.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("IsolationLevel = %q, want %q", metadata.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
	if metadata.UsesHostDockerSocket {
		t.Fatal("UsesHostDockerSocket = true, want false for microVM driver")
	}
	if metadata.RuntimeFamily != RuntimeFamilyMicroVM {
		t.Fatalf("RuntimeFamily = %q, want %q", metadata.RuntimeFamily, RuntimeFamilyMicroVM)
	}
}

func TestDriverMetadataReflectsCapabilityDetectionState(t *testing.T) {
	report := CapabilityReport{
		OS:                            "linux",
		Architecture:                  "arm64",
		KVMDevicePresent:              true,
		KVMReadable:                   capabilityBool(false),
		Availability:                  CapabilityAvailabilityUnavailable,
		ReasonCode:                    CapabilityReasonKVMDeviceUnreadable,
		Error:                         NewUnavailableCapabilityError("detect_capability", errors.New("kvm device is not readable")),
		HypervisorExecutableAvailable: capabilityBool(true),
	}
	driver := NewDriver(DriverOptions{CapabilityDetector: fixedCapabilityDetector(report)})

	metadata := driver.Metadata()
	if !reflect.DeepEqual(metadata.Capability, report) {
		t.Fatalf("Metadata().Capability = %#v, want %#v", metadata.Capability, report)
	}
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", metadata.Availability, CapabilityAvailabilityUnavailable)
	}
	if metadata.Capability.ReasonCode != CapabilityReasonKVMDeviceUnreadable {
		t.Fatalf("Capability.ReasonCode = %q, want %q", metadata.Capability.ReasonCode, CapabilityReasonKVMDeviceUnreadable)
	}
	if metadata.ReasonCode != DriverReasonCapabilityUnavailable {
		t.Fatalf("ReasonCode = %q, want %q", metadata.ReasonCode, DriverReasonCapabilityUnavailable)
	}
}

func TestDefaultDriverConstructionIsUnavailableWithoutBackendPrerequisites(t *testing.T) {
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})

	metadata := driver.Metadata()
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q without backend prerequisites", metadata.Availability, CapabilityAvailabilityUnavailable)
	}
	if metadata.ReasonCode != DriverReasonBackendNotConfigured {
		t.Fatalf("ReasonCode = %q, want %q", metadata.ReasonCode, DriverReasonBackendNotConfigured)
	}
	if metadata.BackendConfigured {
		t.Fatal("BackendConfigured = true, want false by default")
	}

	_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-dev"})
	assertOperationError(t, err, ErrorCodeBackendNotConfigured, "create")
}

func TestDefaultProductionDriverDetectsCapabilityAndStartsUnavailable(t *testing.T) {
	driver := New()
	metadata := driver.Metadata()

	if metadata.DriverID != sandboxruntime.DriverMicroVM {
		t.Fatalf("DriverID = %q, want %q", metadata.DriverID, sandboxruntime.DriverMicroVM)
	}
	if metadata.Capability.Availability == "" {
		t.Fatalf("Capability.Availability is empty in default production metadata: %#v", metadata.Capability)
	}
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want unavailable without backend prerequisites", metadata.Availability)
	}
	if metadata.BackendConfigured {
		t.Fatal("BackendConfigured = true, want false for default production construction")
	}
}

func availableCapabilityReport() CapabilityReport {
	return CapabilityReport{
		OS:                             "linux",
		Architecture:                   "amd64",
		KVMDevicePresent:               true,
		KVMReadable:                    capabilityBool(true),
		HypervisorExecutableConfigured: false,
		Availability:                   CapabilityAvailabilityAvailable,
		ReasonCode:                     CapabilityReasonAvailable,
	}
}

func fixedCapabilityDetector(report CapabilityReport) CapabilityDetector {
	return CapabilityDetectorFunc(func(CapabilityDetectionRequest) CapabilityReport {
		return report
	})
}

func assertOperationError(t *testing.T, err error, code ErrorCode, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error = nil, want %s", operation, code)
	}
	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("%s error type = %T, want *OperationError", operation, err)
	}
	if opErr.Code != code {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, code)
	}
	if opErr.Operation != operation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, operation)
	}
}
