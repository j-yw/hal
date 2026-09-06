package microvm

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func TestLiveE2EFirecrackerPreflightRequiresExplicitMarkersBeforeHostInspection(t *testing.T) {
	t.Run("missing live marker skips without host probes", func(t *testing.T) {
		probe := &fakeLiveE2EPreflightProbe{}
		detector := &fakeLiveE2ECapabilityDetector{report: availableLiveE2ECapabilityReport()}

		result := PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
			FirecrackerLiveMarker:   false,
			FirecrackerBinaryMarker: "/Users/alice/private/firecracker",
			KernelMarker:            "/Users/alice/private/vmlinux",
			RootfsMarker:            "/Users/alice/private/rootfs.ext4",
			Probe:                   probe,
			CapabilityDetector:      detector,
		})

		assertLiveE2EPreflightSkip(t, result, LiveE2EPrerequisiteFirecrackerLiveMarker, LiveE2EReasonFirecrackerMarkerMissing)
		if len(probe.calls) != 0 {
			t.Fatalf("probe calls = %v, want none before live marker", probe.calls)
		}
		if detector.calls != 0 {
			t.Fatalf("detector calls = %d, want none before live marker", detector.calls)
		}
		assertLiveE2EPreflightNoUnsafeFragments(t, result)
	})

	t.Run("missing launch asset markers skip without host probes", func(t *testing.T) {
		probe := &fakeLiveE2EPreflightProbe{}
		detector := &fakeLiveE2ECapabilityDetector{report: availableLiveE2ECapabilityReport()}

		result := PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
			FirecrackerLiveMarker: true,
			Probe:                 probe,
			CapabilityDetector:    detector,
		})

		if !result.ShouldSkipLiveAction() {
			t.Fatal("preflight allowed live action with missing launch asset markers")
		}
		if result.ReasonCode != LiveE2EReasonFirecrackerBinaryMissing {
			t.Fatalf("reason = %q, want %q", result.ReasonCode, LiveE2EReasonFirecrackerBinaryMissing)
		}
		for _, prerequisite := range []LiveE2EPrerequisiteName{
			LiveE2EPrerequisiteFirecrackerBinary,
			LiveE2EPrerequisiteFirecrackerKernel,
			LiveE2EPrerequisiteFirecrackerRootfs,
		} {
			requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, prerequisite)
		}
		if len(probe.calls) != 0 {
			t.Fatalf("probe calls = %v, want none before launch asset markers", probe.calls)
		}
		if detector.calls != 0 {
			t.Fatalf("detector calls = %d, want none before launch asset markers", detector.calls)
		}
		assertLiveE2EPreflightNoUnsafeFragments(t, result)
	})
}

func TestLiveE2EFirecrackerPreflightValidatesAssetsBeforeCapabilityDetection(t *testing.T) {
	probe := &fakeLiveE2EPreflightProbe{
		lookPathErrs: map[string]error{
			"/Users/alice/private/firecracker": errors.New("stat /Users/alice/private/firecracker token=ghp_secret host=builder.internal"),
		},
	}
	detector := &fakeLiveE2ECapabilityDetector{report: availableLiveE2ECapabilityReport()}

	result := PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   true,
		FirecrackerBinaryMarker: "/Users/alice/private/firecracker",
		KernelMarker:            "/Users/alice/private/vmlinux",
		RootfsMarker:            "/Users/alice/private/rootfs.ext4",
		Probe:                   probe,
		CapabilityDetector:      detector,
	})

	assertLiveE2EPreflightSkip(t, result, LiveE2EPrerequisiteFirecrackerBinary, LiveE2EReasonFirecrackerUnavailable)
	if detector.calls != 0 {
		t.Fatalf("detector calls = %d, want none after failed asset preflight", detector.calls)
	}
	if got, want := probe.calls, []string{
		"lookPath:/Users/alice/private/firecracker",
		"stat:/Users/alice/private/vmlinux",
		"open:/Users/alice/private/vmlinux",
		"stat:/Users/alice/private/rootfs.ext4",
		"open:/Users/alice/private/rootfs.ext4",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("probe calls = %v, want %v", got, want)
	}
	assertLiveE2EPreflightNoUnsafeFragments(t, result)
}

func TestLiveE2EFirecrackerPreflightMapsAssetAndCapabilityFailuresToSafeSkips(t *testing.T) {
	t.Run("missing kernel file", func(t *testing.T) {
		probe := &fakeLiveE2EPreflightProbe{
			statErrs: map[string]error{
				"/Users/alice/private/vmlinux": fs.ErrNotExist,
			},
		}
		result := preflightWithProbeAndReport(probe, availableLiveE2ECapabilityReport())

		assertLiveE2EPreflightSkip(t, result, LiveE2EPrerequisiteFirecrackerKernel, LiveE2EReasonFirecrackerKernelMissing)
		assertLiveE2EPreflightNoUnsafeFragments(t, result)
	})

	t.Run("unreadable rootfs", func(t *testing.T) {
		probe := &fakeLiveE2EPreflightProbe{
			openErrs: map[string]error{
				"/Users/alice/private/rootfs.ext4": errors.New("permission denied for /Users/alice/private/rootfs.ext4"),
			},
		}
		result := preflightWithProbeAndReport(probe, availableLiveE2ECapabilityReport())

		assertLiveE2EPreflightSkip(t, result, LiveE2EPrerequisiteFirecrackerRootfs, LiveE2EReasonFirecrackerUnavailable)
		assertLiveE2EPreflightNoUnsafeFragments(t, result)
	})

	for _, tt := range []struct {
		name         string
		reportReason CapabilityReasonCode
		prerequisite LiveE2EPrerequisiteName
		reason       LiveE2EReasonCode
	}{
		{
			name:         "missing hypervisor executable",
			reportReason: CapabilityReasonHypervisorExecutableMissing,
			prerequisite: LiveE2EPrerequisiteFirecrackerBinary,
			reason:       LiveE2EReasonFirecrackerUnavailable,
		},
		{
			name:         "missing kvm device",
			reportReason: CapabilityReasonKVMDeviceMissing,
			prerequisite: LiveE2EPrerequisiteKVMCapability,
			reason:       LiveE2EReasonKVMDeviceMissing,
		},
		{
			name:         "unreadable kvm device",
			reportReason: CapabilityReasonKVMDeviceUnreadable,
			prerequisite: LiveE2EPrerequisiteKVMCapability,
			reason:       LiveE2EReasonKVMUnreadable,
		},
		{
			name:         "unsupported host capability",
			reportReason: CapabilityReasonUnsupportedOS,
			prerequisite: LiveE2EPrerequisiteKVMCapability,
			reason:       LiveE2EReasonKVMCapabilityMissing,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := preflightWithProbeAndReport(&fakeLiveE2EPreflightProbe{}, unavailableLiveE2ECapabilityReport(tt.reportReason))

			assertLiveE2EPreflightSkip(t, result, tt.prerequisite, tt.reason)
			assertLiveE2EPreflightNoUnsafeFragments(t, result)
		})
	}
}

func TestLiveE2EFirecrackerPreflightAllowsLiveActionOnlyAfterAssetsAndHostCapability(t *testing.T) {
	probe := &fakeLiveE2EPreflightProbe{}
	detector := &fakeLiveE2ECapabilityDetector{report: availableLiveE2ECapabilityReport()}

	result := PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   true,
		FirecrackerBinaryMarker: "/Users/alice/private/firecracker",
		KernelMarker:            "/Users/alice/private/vmlinux",
		RootfsMarker:            "/Users/alice/private/rootfs.ext4",
		Probe:                   probe,
		CapabilityDetector:      detector,
	})

	if !result.CanRunLiveAction() {
		t.Fatalf("CanRunLiveAction() = false, want true: %#v", result)
	}
	if result.Status != LiveE2EReadinessReady || result.ReasonCode != LiveE2EReasonReady {
		t.Fatalf("result = %#v, want ready", result)
	}
	if detector.calls != 1 {
		t.Fatalf("detector calls = %d, want 1", detector.calls)
	}
	if len(detector.requests) != 1 || detector.requests[0].Config.HypervisorPath == "" {
		t.Fatalf("detector requests = %#v, want configured hypervisor marker", detector.requests)
	}
	if got, want := probe.calls, []string{
		"lookPath:/Users/alice/private/firecracker",
		"stat:/Users/alice/private/vmlinux",
		"open:/Users/alice/private/vmlinux",
		"stat:/Users/alice/private/rootfs.ext4",
		"open:/Users/alice/private/rootfs.ext4",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("probe calls = %v, want %v", got, want)
	}
	assertLiveE2EPreflightNoUnsafeFragments(t, result)
}

func preflightWithProbeAndReport(probe *fakeLiveE2EPreflightProbe, report CapabilityReport) LiveE2EFirecrackerPreflightResult {
	return PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   true,
		FirecrackerBinaryMarker: "/Users/alice/private/firecracker",
		KernelMarker:            "/Users/alice/private/vmlinux",
		RootfsMarker:            "/Users/alice/private/rootfs.ext4",
		Probe:                   probe,
		CapabilityDetector:      &fakeLiveE2ECapabilityDetector{report: report},
	})
}

func assertLiveE2EPreflightSkip(t *testing.T, result LiveE2EFirecrackerPreflightResult, prerequisite LiveE2EPrerequisiteName, reason LiveE2EReasonCode) {
	t.Helper()
	if !result.ShouldSkipLiveAction() {
		t.Fatalf("ShouldSkipLiveAction() = false, want true for %#v", result)
	}
	if result.Status != LiveE2EReadinessSkipped {
		t.Fatalf("status = %q, want %q", result.Status, LiveE2EReadinessSkipped)
	}
	diagnostic := requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, prerequisite)
	if diagnostic.ReasonCode != reason {
		t.Fatalf("%s reason = %q, want %q", prerequisite, diagnostic.ReasonCode, reason)
	}
}

func requireLiveE2EPreflightDiagnostic(t *testing.T, diagnostics []LiveE2EPrerequisiteDiagnostic, prerequisite LiveE2EPrerequisiteName) LiveE2EPrerequisiteDiagnostic {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Prerequisite == prerequisite {
			return diagnostic
		}
	}
	t.Fatalf("diagnostics = %#v, missing prerequisite %q", diagnostics, prerequisite)
	return LiveE2EPrerequisiteDiagnostic{}
}

func assertLiveE2EPreflightNoUnsafeFragments(t *testing.T, result LiveE2EFirecrackerPreflightResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(preflight result) error: %v", err)
	}
	publicText := string(encoded) + " " + LiveE2EFirecrackerPreflightSkipMessage(result)
	for _, unsafe := range []string{
		"/Users/alice",
		"/tmp/",
		"private/firecracker",
		"private/vmlinux",
		"private/rootfs",
		"builder.internal",
		"127.0.0.1",
		"ghp_",
		"token=",
		"permission denied",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("preflight output leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func availableLiveE2ECapabilityReport() CapabilityReport {
	readable := true
	executable := true
	return CapabilityReport{
		OS:                             "linux",
		Architecture:                   "amd64",
		KVMDevicePresent:               true,
		KVMReadable:                    &readable,
		HypervisorExecutableConfigured: true,
		HypervisorExecutableAvailable:  &executable,
		Availability:                   CapabilityAvailabilityAvailable,
		ReasonCode:                     CapabilityReasonAvailable,
	}
}

func unavailableLiveE2ECapabilityReport(reason CapabilityReasonCode) CapabilityReport {
	return CapabilityReport{
		OS:           "linux",
		Architecture: "amd64",
		Availability: CapabilityAvailabilityUnavailable,
		ReasonCode:   reason,
		Error:        NewUnavailableCapabilityError("detect_capability", errors.New("host capability unavailable at /Users/alice/private token=ghp_secret")),
	}
}

type fakeLiveE2EPreflightProbe struct {
	statErrs     map[string]error
	openErrs     map[string]error
	lookPathErrs map[string]error
	calls        []string
}

func (probe *fakeLiveE2EPreflightProbe) RuntimeOS() string {
	return "linux"
}

func (probe *fakeLiveE2EPreflightProbe) RuntimeArch() string {
	return "amd64"
}

func (probe *fakeLiveE2EPreflightProbe) Stat(path string) error {
	probe.calls = append(probe.calls, "stat:"+path)
	return probe.statErrs[path]
}

func (probe *fakeLiveE2EPreflightProbe) OpenReadOnly(path string) error {
	probe.calls = append(probe.calls, "open:"+path)
	return probe.openErrs[path]
}

func (probe *fakeLiveE2EPreflightProbe) LookPath(file string) (string, error) {
	probe.calls = append(probe.calls, "lookPath:"+file)
	if err := probe.lookPathErrs[file]; err != nil {
		return "", err
	}
	return "/fake/bin/firecracker", nil
}

type fakeLiveE2ECapabilityDetector struct {
	report   CapabilityReport
	calls    int
	requests []CapabilityDetectionRequest
}

func (detector *fakeLiveE2ECapabilityDetector) DetectMicroVMCapability(request CapabilityDetectionRequest) CapabilityReport {
	detector.calls++
	detector.requests = append(detector.requests, request)
	return detector.report
}
