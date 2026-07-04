package cmd

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/livegate"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const us015PreparedHostLiveE2EBoundaryGuardFile = "cmd/us015_prepared_host_live_e2e_boundary_test.go"

func TestUS015OptionalPreparedHostLiveE2EStaysTaggedAndMarkerGated(t *testing.T) {
	executionPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_execution_test.go")
	executionSource := phase50ReadFile(t, executionPath)
	executionDisplay := phase50SafeDisplayPath(executionPath)

	for _, tag := range []string{
		"microvm_e2e_live",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
	} {
		if !phase50HasBuildTag(executionSource, tag) {
			t.Fatalf("%s must stay behind live build tag %q", executionDisplay, tag)
		}
	}
	for _, marker := range []string{
		"livegate.RequireLiveGate",
		"livegate.MicroVME2ELiveGate",
		"livegate.MicroVME2ERequiredBuildTags",
		"livegate.MicroVME2ERequiredEnvVars",
		"PreflightLiveE2EFirecrackerRuntime",
		"ProjectLiveE2ENetworkEnforcementReadiness",
		"ProjectLiveE2ECredentialDeliveryMetadata",
		"ProjectLiveE2ETemplateTrustMetadata",
		"microVMLiveE2EForbiddenFragments",
		"t.Skip",
	} {
		if !strings.Contains(executionSource, marker) {
			t.Fatalf("%s missing prepared-host live E2E boundary marker %q", executionDisplay, marker)
		}
	}

	harnessPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_test.go")
	harnessSource := phase50ReadFile(t, harnessPath)
	harnessDisplay := phase50SafeDisplayPath(harnessPath)
	if !phase50HasBuildTag(harnessSource, "microvm_e2e_live") {
		t.Fatalf("%s must stay behind the microvm_e2e_live build tag", harnessDisplay)
	}
	for _, forbidden := range []string{
		"firecrackerhost.NewLiveDriver",
		"NewOSExecProcessRunner",
		"exec.Command(",
		"net.Listen(",
		"http.ListenAndServe(",
		"iptables",
		"pfctl",
		"nft ",
	} {
		if strings.Contains(harnessSource, forbidden) {
			t.Fatalf("%s contains live action marker %q outside the all-tag execution test", harnessDisplay, forbidden)
		}
	}
}

func TestUS015PreparedHostLiveE2ESkipMessagesStayNamesOnly(t *testing.T) {
	messages := []string{
		us015LiveGateMissingMarkerSkipMessage(),
		us015FirecrackerKVMUnavailableSkipMessage(),
		us015NetworkCapabilityUnavailableSkipMessage(),
		us015CredentialUnavailableSkipMessage(),
		us015TemplateRegistryUnavailableSkipMessage(),
	}
	for _, message := range messages {
		us015AssertLiveE2ESkipMessageNamesOnly(t, message)
	}
}

func TestUS015PreparedHostLiveE2EDocumentationNamesSkipPrerequisites(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"prepared-host prerequisite boundary",
		"KVM",
		"Firecracker",
		"root privileges",
		"firewall capability",
		"proxy capability",
		"sandboxd",
		"credentials",
		"registry access",
		"Skip messages name marker variables and prerequisite labels only; they must not print marker values.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("Phase 53 live E2E documentation missing US-015 prerequisite boundary %q", want)
		}
	}
}

func TestUS015LiveBoundaryGuardFileStaysInLiveMarkerAllowlists(t *testing.T) {
	if !phase50ApprovedLiveMarkerFiles()[us015PreparedHostLiveE2EBoundaryGuardFile] {
		t.Fatalf("%s must stay in the Phase 50 live marker allowlist because it verifies optional live marker names", us015PreparedHostLiveE2EBoundaryGuardFile)
	}
	if !us010ApprovedLiveE2EGuardFiles()[us015PreparedHostLiveE2EBoundaryGuardFile] {
		t.Fatalf("%s must stay in the Phase 53 live E2E marker allowlist because it verifies optional live E2E markers", us015PreparedHostLiveE2EBoundaryGuardFile)
	}
}

func us015LiveGateMissingMarkerSkipMessage() string {
	result := livegate.EvaluateGate(livegate.GateEvaluationInput{
		Gate:             livegate.MicroVME2ELiveGate(),
		EnabledBuildTags: livegate.MicroVME2ERequiredBuildTags(),
		PresentEnvVars: []livegate.EnvVarName{
			livegate.EnvVarName("HAL_FIRECRACKER_LIVE=/Users/alice/private/firecracker"),
			livegate.EnvVarName("HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=https://proxy.internal.example.com?token=secret"),
		},
		AvailableCapabilities: livegate.MicroVME2ERequiredCapabilities(),
	})
	return livegate.LiveGateSkipMessage(result)
}

func us015FirecrackerKVMUnavailableSkipMessage() string {
	result := microvm.PreflightLiveE2EFirecrackerRuntime(microvm.LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   true,
		FirecrackerBinaryMarker: "/Users/alice/private/firecracker",
		KernelMarker:            "/Users/alice/private/vmlinux",
		RootfsMarker:            "/Users/alice/private/rootfs.ext4",
		Probe:                   us015LiveE2EPreflightProbe{},
		CapabilityDetector: microvm.CapabilityDetectorFunc(func(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
			return microvm.CapabilityReport{
				OS:           "linux",
				Architecture: "amd64",
				Availability: microvm.CapabilityAvailabilityUnavailable,
				ReasonCode:   microvm.CapabilityReasonKVMDeviceMissing,
				Error:        microvm.NewUnavailableCapabilityError("detect", errors.New("missing /dev/kvm token=secret")),
			}
		}),
	})
	return microvm.LiveE2EFirecrackerPreflightSkipMessage(result)
}

func us015NetworkCapabilityUnavailableSkipMessage() string {
	result := microvm.ProjectLiveE2ENetworkEnforcementReadiness(microvm.LiveE2ENetworkEnforcementReadinessInput{
		LiveMarker:     true,
		ProxyMarker:    true,
		FirewallMarker: true,
	})
	return microvm.LiveE2ENetworkEnforcementReadinessSkipMessage(result)
}

func us015CredentialUnavailableSkipMessage() string {
	result := microvm.ProjectLiveE2ECredentialDeliveryMetadata(microvm.LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:        true,
		EnvDeliveryMarker: true,
		CredentialDelivery: microvm.LiveE2ECredentialDeliveryMetadata{
			ID:             "https://credential.internal.example.com/session?token=secret",
			RequestedModes: []string{"env"},
			ActiveModes:    []string{"env"},
			Status:         "failed",
		},
	})
	return microvm.LiveE2ECredentialDeliveryProjectionSkipMessage(result)
}

func us015TemplateRegistryUnavailableSkipMessage() string {
	result := microvm.ProjectLiveE2ETemplateTrustMetadata(microvm.LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    true,
		TemplateID:    "https://registry.internal.example.com/template?token=secret",
		TrustPolicyID: "policy-01",
	})
	return microvm.LiveE2ETemplateTrustProjectionSkipMessage(result)
}

func us015AssertLiveE2ESkipMessageNamesOnly(t *testing.T, message string) {
	t.Helper()
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, us015LiveE2EForbiddenFragments()...)
	encoded, err := json.Marshal(map[string]string{"message": message})
	if err != nil {
		t.Fatalf("Marshal(skip message) error: %v", err)
	}
	publicText := string(encoded)
	for _, forbidden := range us015LiveE2EForbiddenFragments() {
		if strings.Contains(strings.ToLower(publicText), strings.ToLower(forbidden)) {
			t.Fatalf("US-015 skip message leaked forbidden fragment %q in %s", forbidden, publicText)
		}
	}
	for _, want := range []string{
		"microVM live E2E",
	} {
		if strings.Contains(message, "microVM") && !strings.Contains(message, want) {
			t.Fatalf("US-015 skip message %q missing safe live E2E label %q", message, want)
		}
	}
}

func us015LiveE2EForbiddenFragments() []string {
	return []string{
		"secret",
		"token=",
		"ghp_",
		"bearer",
		"authorization",
		"/Users/alice",
		"/dev/kvm",
		"private/firecracker",
		"private/vmlinux",
		"private/rootfs",
		"https://",
		"proxy.internal.example.com",
		"credential.internal.example.com",
		"registry.internal.example.com",
		"127.0.0.1",
		"localhost",
		".sock",
		"iptables",
		"pfctl",
		"nft ",
		"--api-sock",
	}
}

type us015LiveE2EPreflightProbe struct{}

func (us015LiveE2EPreflightProbe) RuntimeOS() string {
	return "linux"
}

func (us015LiveE2EPreflightProbe) RuntimeArch() string {
	return "amd64"
}

func (us015LiveE2EPreflightProbe) Stat(string) error {
	return nil
}

func (us015LiveE2EPreflightProbe) OpenReadOnly(string) error {
	return nil
}

func (us015LiveE2EPreflightProbe) LookPath(string) (string, error) {
	return "firecracker", nil
}
