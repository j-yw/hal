package microvm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const kvmDevicePath = "/dev/kvm"

const (
	CapabilityAvailabilityAvailable   CapabilityAvailability = "available"
	CapabilityAvailabilityUnavailable CapabilityAvailability = "unavailable"
)

const (
	CapabilityReasonAvailable                   CapabilityReasonCode = "available"
	CapabilityReasonUnsupportedOS               CapabilityReasonCode = "unsupported_os"
	CapabilityReasonKVMDeviceMissing            CapabilityReasonCode = "kvm_device_missing"
	CapabilityReasonKVMDeviceCheckFailed        CapabilityReasonCode = "kvm_device_check_failed"
	CapabilityReasonKVMDeviceUnreadable         CapabilityReasonCode = "kvm_device_unreadable"
	CapabilityReasonHypervisorExecutableMissing CapabilityReasonCode = "hypervisor_executable_missing"
)

// CapabilityAvailability is the final host capability state reported by the
// detector.
type CapabilityAvailability string

// CapabilityReasonCode is a stable redaction-safe explanation for the final
// capability state.
type CapabilityReasonCode string

// CapabilityReport is the public, redaction-safe result of host capability
// detection. It intentionally records booleans and reason codes rather than
// raw host paths or environment data.
type CapabilityReport struct {
	OS                             string                 `json:"os"`
	Architecture                   string                 `json:"architecture"`
	KVMDevicePresent               bool                   `json:"kvmDevicePresent"`
	KVMReadable                    *bool                  `json:"kvmReadable,omitempty"`
	HypervisorExecutableConfigured bool                   `json:"hypervisorExecutableConfigured"`
	HypervisorExecutableAvailable  *bool                  `json:"hypervisorExecutableAvailable,omitempty"`
	Availability                   CapabilityAvailability `json:"availability"`
	ReasonCode                     CapabilityReasonCode   `json:"reasonCode,omitempty"`
	Error                          *OperationError        `json:"error,omitempty"`
}

// CapabilityDetectionRequest carries backend-neutral inputs for capability
// detection.
type CapabilityDetectionRequest struct {
	Config Config
}

// CapabilityDetector is the injectable boundary used by runtime resolution
// code that needs microVM host capability information.
type CapabilityDetector interface {
	DetectMicroVMCapability(CapabilityDetectionRequest) CapabilityReport
}

// CapabilityDetectorFunc adapts a function into a fakeable capability
// detector.
type CapabilityDetectorFunc func(CapabilityDetectionRequest) CapabilityReport

func (fn CapabilityDetectorFunc) DetectMicroVMCapability(request CapabilityDetectionRequest) CapabilityReport {
	if fn == nil {
		return HostCapabilityDetector{}.DetectMicroVMCapability(request)
	}
	return fn(request)
}

// CapabilityProbe is the narrow host-inspection boundary used by the default
// detector. Tests can fake it without relying on the current machine.
type CapabilityProbe interface {
	RuntimeOS() string
	RuntimeArch() string
	Stat(path string) error
	OpenReadOnly(path string) error
	LookPath(file string) (string, error)
}

// HostCapabilityDetector detects host microVM support without mutating host
// state.
type HostCapabilityDetector struct {
	Probe CapabilityProbe
}

// DetectHostCapability runs the default host detector.
func DetectHostCapability(request CapabilityDetectionRequest) CapabilityReport {
	return HostCapabilityDetector{}.DetectMicroVMCapability(request)
}

func (detector HostCapabilityDetector) DetectMicroVMCapability(request CapabilityDetectionRequest) CapabilityReport {
	probe := detector.Probe
	if probe == nil {
		probe = hostCapabilityProbe{}
	}

	report := CapabilityReport{
		OS:                             safeCapabilityToken(probe.RuntimeOS()),
		Architecture:                   safeCapabilityToken(probe.RuntimeArch()),
		HypervisorExecutableConfigured: strings.TrimSpace(request.Config.HypervisorPath) != "",
		Availability:                   CapabilityAvailabilityUnavailable,
	}

	if report.OS != "linux" {
		return unavailableCapabilityReport(report, CapabilityReasonUnsupportedOS,
			fmt.Errorf("microvm requires linux host capability, got %s/%s", report.OS, report.Architecture))
	}

	if err := probe.Stat(kvmDevicePath); err != nil {
		if capabilityIsNotExist(err) {
			return unavailableCapabilityReport(report, CapabilityReasonKVMDeviceMissing,
				errors.New("kvm device is not present"))
		}
		return unavailableCapabilityReport(report, CapabilityReasonKVMDeviceCheckFailed,
			fmt.Errorf("kvm device presence check failed: %w", err))
	}
	report.KVMDevicePresent = true

	if err := probe.OpenReadOnly(kvmDevicePath); err != nil {
		report.KVMReadable = capabilityBool(false)
		return unavailableCapabilityReport(report, CapabilityReasonKVMDeviceUnreadable,
			fmt.Errorf("kvm device is not readable: %w", err))
	}
	report.KVMReadable = capabilityBool(true)

	if hypervisorPath := strings.TrimSpace(request.Config.HypervisorPath); hypervisorPath != "" {
		if _, err := probe.LookPath(hypervisorPath); err != nil {
			report.HypervisorExecutableAvailable = capabilityBool(false)
			return unavailableCapabilityReport(report, CapabilityReasonHypervisorExecutableMissing,
				fmt.Errorf("configured hypervisor executable unavailable: %w", err))
		}
		report.HypervisorExecutableAvailable = capabilityBool(true)
	}

	report.Availability = CapabilityAvailabilityAvailable
	report.ReasonCode = CapabilityReasonAvailable
	report.Error = nil
	return report
}

type hostCapabilityProbe struct{}

func (hostCapabilityProbe) RuntimeOS() string {
	return runtime.GOOS
}

func (hostCapabilityProbe) RuntimeArch() string {
	return runtime.GOARCH
}

func (hostCapabilityProbe) Stat(path string) error {
	_, err := os.Stat(path)
	return err
}

func (hostCapabilityProbe) OpenReadOnly(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func (hostCapabilityProbe) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func unavailableCapabilityReport(report CapabilityReport, reason CapabilityReasonCode, err error) CapabilityReport {
	report.Availability = CapabilityAvailabilityUnavailable
	report.ReasonCode = reason
	report.Error = NewUnavailableCapabilityError("detect_capability", err)
	return report
}

func capabilityBool(value bool) *bool {
	return &value
}

func capabilityIsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

func safeCapabilityToken(value string) string {
	if safe := sanitizeIdentifier(value); safe != "" {
		return safe
	}
	return "unknown"
}
