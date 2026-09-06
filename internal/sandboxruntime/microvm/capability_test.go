package microvm

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func TestCapabilityReportContractFieldsAndJSONNames(t *testing.T) {
	reportType := reflect.TypeOf(CapabilityReport{})

	assertConfigField(t, reportType, "OS", reflect.TypeOf(""), `json:"os"`)
	assertConfigField(t, reportType, "Architecture", reflect.TypeOf(""), `json:"architecture"`)
	assertConfigField(t, reportType, "KVMDevicePresent", reflect.TypeOf(false), `json:"kvmDevicePresent"`)
	assertConfigField(t, reportType, "KVMReadable", reflect.TypeOf((*bool)(nil)), `json:"kvmReadable,omitempty"`)
	assertConfigField(t, reportType, "HypervisorExecutableConfigured", reflect.TypeOf(false), `json:"hypervisorExecutableConfigured"`)
	assertConfigField(t, reportType, "HypervisorExecutableAvailable", reflect.TypeOf((*bool)(nil)), `json:"hypervisorExecutableAvailable,omitempty"`)
	assertConfigField(t, reportType, "Availability", reflect.TypeOf(CapabilityAvailability("")), `json:"availability"`)
	assertConfigField(t, reportType, "ReasonCode", reflect.TypeOf(CapabilityReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, reportType, "Error", reflect.TypeOf((*OperationError)(nil)), `json:"error,omitempty"`)
}

func TestDetectCapabilityReportsNonLinuxUnavailableWithoutKVMProbe(t *testing.T) {
	probe := &fakeCapabilityProbe{goos: "darwin", goarch: "arm64"}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{})

	if report.OS != "darwin" || report.Architecture != "arm64" {
		t.Fatalf("report host = %s/%s, want darwin/arm64", report.OS, report.Architecture)
	}
	if report.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", report.Availability, CapabilityAvailabilityUnavailable)
	}
	if report.ReasonCode != CapabilityReasonUnsupportedOS {
		t.Fatalf("ReasonCode = %q, want %q", report.ReasonCode, CapabilityReasonUnsupportedOS)
	}
	if report.KVMDevicePresent {
		t.Fatal("KVMDevicePresent = true on non-Linux host, want false")
	}
	if report.KVMReadable != nil {
		t.Fatalf("KVMReadable = %v, want omitted on non-Linux host", *report.KVMReadable)
	}
	if len(probe.statPaths) != 0 || len(probe.openPaths) != 0 {
		t.Fatalf("non-Linux detection touched KVM paths: stat=%v open=%v", probe.statPaths, probe.openPaths)
	}
}

func TestDetectCapabilityReportsLinuxWithoutKVMUnavailable(t *testing.T) {
	probe := &fakeCapabilityProbe{
		goos:    "linux",
		goarch:  "amd64",
		statErr: fs.ErrNotExist,
	}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{})

	if report.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", report.Availability, CapabilityAvailabilityUnavailable)
	}
	if report.ReasonCode != CapabilityReasonKVMDeviceMissing {
		t.Fatalf("ReasonCode = %q, want %q", report.ReasonCode, CapabilityReasonKVMDeviceMissing)
	}
	if report.KVMDevicePresent {
		t.Fatal("KVMDevicePresent = true, want false")
	}
	if report.KVMReadable != nil {
		t.Fatalf("KVMReadable = %v, want omitted when /dev/kvm is missing", *report.KVMReadable)
	}
	if got, want := probe.statPaths, []string{"/dev/kvm"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stat paths = %v, want %v", got, want)
	}
	if len(probe.openPaths) != 0 {
		t.Fatalf("open paths = %v, want no open when /dev/kvm is missing", probe.openPaths)
	}
}

func TestDetectCapabilityAllowsFakeKVMAvailableWithoutHostKVM(t *testing.T) {
	probe := &fakeCapabilityProbe{goos: "linux", goarch: "arm64"}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{})

	if report.Availability != CapabilityAvailabilityAvailable {
		t.Fatalf("Availability = %q, want %q", report.Availability, CapabilityAvailabilityAvailable)
	}
	if report.ReasonCode != CapabilityReasonAvailable {
		t.Fatalf("ReasonCode = %q, want %q", report.ReasonCode, CapabilityReasonAvailable)
	}
	if !report.KVMDevicePresent {
		t.Fatal("KVMDevicePresent = false, want true")
	}
	if report.KVMReadable == nil || !*report.KVMReadable {
		t.Fatalf("KVMReadable = %v, want true", report.KVMReadable)
	}
	if got, want := probe.openPaths, []string{"/dev/kvm"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("open paths = %v, want %v", got, want)
	}
}

func TestCapabilityDetectorFuncCanReportFakeAvailableKVM(t *testing.T) {
	readable := true
	var detector CapabilityDetector = CapabilityDetectorFunc(func(CapabilityDetectionRequest) CapabilityReport {
		return CapabilityReport{
			OS:                            "linux",
			Architecture:                  "amd64",
			KVMDevicePresent:              true,
			KVMReadable:                   &readable,
			Availability:                  CapabilityAvailabilityAvailable,
			ReasonCode:                    CapabilityReasonAvailable,
			HypervisorExecutableAvailable: nil,
		}
	})

	report := detector.DetectMicroVMCapability(CapabilityDetectionRequest{})
	if report.Availability != CapabilityAvailabilityAvailable || !report.KVMDevicePresent || report.KVMReadable == nil || !*report.KVMReadable {
		t.Fatalf("fake detector report = %#v, want available KVM", report)
	}
}

func TestDetectCapabilityReportsMissingConfiguredHypervisorExecutableUnavailable(t *testing.T) {
	probe := &fakeCapabilityProbe{
		goos:        "linux",
		goarch:      "amd64",
		lookPathErr: errors.New("stat /Users/alice/private/firecracker: no such file or directory token=raw-secret endpoint=https://deploy.example.test:8443/api"),
	}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{
		Config: Config{HypervisorPath: "/Users/alice/private/firecracker"},
	})

	if report.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", report.Availability, CapabilityAvailabilityUnavailable)
	}
	if report.ReasonCode != CapabilityReasonHypervisorExecutableMissing {
		t.Fatalf("ReasonCode = %q, want %q", report.ReasonCode, CapabilityReasonHypervisorExecutableMissing)
	}
	if !report.HypervisorExecutableConfigured {
		t.Fatal("HypervisorExecutableConfigured = false, want true")
	}
	if report.HypervisorExecutableAvailable == nil || *report.HypervisorExecutableAvailable {
		t.Fatalf("HypervisorExecutableAvailable = %v, want false", report.HypervisorExecutableAvailable)
	}
	if report.Error == nil {
		t.Fatal("Error = nil, want sanitized unavailable capability error")
	}
	if got, want := probe.lookPathNames, []string{"/Users/alice/private/firecracker"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lookPath names = %v, want %v", got, want)
	}
}

func TestCapabilityErrorStringsAreSanitized(t *testing.T) {
	probe := &fakeCapabilityProbe{
		goos:        "linux",
		goarch:      "amd64",
		lookPathErr: errors.New("stat /Users/alice/private/firecracker: no such file or directory token=raw-secret endpoint=https://deploy.example.test:8443/api"),
	}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{
		Config: Config{HypervisorPath: "/Users/alice/private/firecracker"},
	})
	if report.Error == nil {
		t.Fatal("Error = nil, want sanitized error")
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal(CapabilityReport) error: %v", err)
	}
	publicText := report.Error.Error() + " " + string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private/firecracker",
		"raw-secret",
		"deploy.example.test",
		"8443",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public capability text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
	for _, want := range []string{
		"unavailable_capability",
		"detect_capability",
		"[redacted-path]",
		"token=[redacted]",
		"[redacted-endpoint]",
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("public capability text %q missing sanitized marker %q", publicText, want)
		}
	}
}

type fakeCapabilityProbe struct {
	goos        string
	goarch      string
	statErr     error
	openErr     error
	lookPathErr error

	statPaths     []string
	openPaths     []string
	lookPathNames []string
}

func (probe *fakeCapabilityProbe) RuntimeOS() string {
	return probe.goos
}

func (probe *fakeCapabilityProbe) RuntimeArch() string {
	return probe.goarch
}

func (probe *fakeCapabilityProbe) Stat(path string) error {
	probe.statPaths = append(probe.statPaths, path)
	return probe.statErr
}

func (probe *fakeCapabilityProbe) OpenReadOnly(path string) error {
	probe.openPaths = append(probe.openPaths, path)
	return probe.openErr
}

func (probe *fakeCapabilityProbe) LookPath(file string) (string, error) {
	probe.lookPathNames = append(probe.lookPathNames, file)
	if probe.lookPathErr != nil {
		return "", probe.lookPathErr
	}
	return "/fake/bin/" + file, nil
}
