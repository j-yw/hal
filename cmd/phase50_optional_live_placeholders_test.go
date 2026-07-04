package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase50OptionalLivePlaceholderTestsStayOutsideDefaultSuiteAndUseSharedGateHelpers(t *testing.T) {
	for _, req := range []struct {
		path          string
		buildTag      string
		buildTagConst string
		envMarkers    []string
		capability    string
	}{
		{
			path:          filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "network_enforcement_live_test.go"),
			buildTag:      "network_enforcement_live",
			buildTagConst: "livegate.BuildTagNetworkEnforcementLive",
			envMarkers: []string{
				"HAL_NETWORK_ENFORCEMENT_LIVE",
				"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
				"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
			},
			capability: "livegate.CapabilityNetworkEnforcement",
		},
		{
			path:          filepath.Join("..", "internal", "credentialdelivery", "credential_delivery_live_test.go"),
			buildTag:      "credential_delivery_live",
			buildTagConst: "livegate.BuildTagCredentialDeliveryLive",
			envMarkers: []string{
				"HAL_CREDENTIAL_DELIVERY_LIVE",
				"HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY",
				"HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS",
				"HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT",
				"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
			},
			capability: "livegate.CapabilityCredentialDelivery",
		},
	} {
		source := phase19ReadFile(t, req.path)
		display := phase34FirecrackerDisplayPath(t, req.path)
		if !phase19HasBuildTag(source, req.buildTag) {
			t.Fatalf("%s must stay behind optional build tag %q so default go test ./... remains fake-only", display, req.buildTag)
		}
		if !strings.Contains(source, "github.com/jywlabs/hal/internal/livegate") {
			t.Fatalf("%s must use the shared livegate helper package", display)
		}
		for _, marker := range []string{
			"livegate.RequireLiveGate",
			req.buildTagConst,
			req.capability,
			"ExpectedEnvVars:",
			"PresentEnvVars:",
			"AvailableCapabilities:",
			"livegate.AssertLiveGateSkipMessageRedactionSafe",
		} {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s missing shared live gate helper marker %q", display, marker)
			}
		}
		for _, marker := range req.envMarkers {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s missing optional live env marker %q", display, marker)
			}
		}
		for _, forbidden := range []string{
			"net.Listen(",
			"http.ListenAndServe(",
			"exec.Command(",
			"os/exec",
			"rootlesspodman.",
			"firecracker.New",
			"NewOSExecProcessRunner",
			"MountTmpfs(",
			"ForwardSSHAgent(",
			"InjectEnv(",
			"iptables",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s placeholder test contains forbidden live behavior marker %q", display, forbidden)
			}
		}
	}
}

func TestUS003MicroVMLiveE2EHarnessComposesExistingLiveGateHelpers(t *testing.T) {
	harnessPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_test.go")
	harness := phase19ReadFile(t, harnessPath)
	composedGate := phase19ReadFile(t, filepath.Join("..", "internal", "livegate", "composed.go"))

	if !phase19HasBuildTag(harness, "microvm_e2e_live") {
		t.Fatalf("%s must stay behind the dedicated microvm_e2e_live build tag", phase34FirecrackerDisplayPath(t, harnessPath))
	}
	for _, marker := range []string{
		"github.com/jywlabs/hal/internal/livegate",
		"livegate.RequireLiveGate",
		"livegate.MicroVME2ELiveGate",
		"livegate.MicroVME2ERequiredEnvVars",
		"livegate.CredentialDeliveryLiveModeEnvVars",
		"microVMLiveE2EEnabledBuildTags",
		"microVMLiveE2EPresentEnvVars",
		"t.Skip",
	} {
		if !strings.Contains(harness, marker) {
			t.Fatalf("%s missing composed live gate marker %q", phase34FirecrackerDisplayPath(t, harnessPath), marker)
		}
	}
	for _, marker := range []string{
		"BuildTagMicroVME2ELive",
		"BuildTagFirecrackerLive",
		"BuildTagNetworkEnforcementLive",
		"BuildTagCredentialDeliveryLive",
		"EnvVarFirecrackerLive",
		"EnvVarFirecrackerLiveFirecracker",
		"EnvVarFirecrackerLiveKernel",
		"EnvVarFirecrackerLiveRootfs",
		"EnvVarNetworkEnforcementLive",
		"EnvVarNetworkEnforcementLiveProxy",
		"EnvVarNetworkEnforcementLiveFirewall",
		"EnvVarCredentialDeliveryLive",
		"EnvVarCredentialDeliveryLiveHTTPProxy",
		"EnvVarCredentialDeliveryLiveFileTmpfs",
		"EnvVarCredentialDeliveryLiveSSHAgent",
		"EnvVarCredentialDeliveryLiveEnv",
		"CapabilityFirecrackerMicroVM",
		"CapabilityNetworkEnforcement",
		"CapabilityCredentialDelivery",
	} {
		if !strings.Contains(composedGate, marker) {
			t.Fatalf("internal/livegate/composed.go missing composed live contract marker %q", marker)
		}
	}

	for _, req := range []struct {
		path      string
		buildTag  string
		component string
	}{
		{path: "live_e2e_firecracker_tag_on_test.go", buildTag: "firecracker_live", component: "Firecracker"},
		{path: "live_e2e_firecracker_tag_off_test.go", buildTag: "!firecracker_live", component: "Firecracker"},
		{path: "live_e2e_network_enforcement_tag_on_test.go", buildTag: "network_enforcement_live", component: "network enforcement"},
		{path: "live_e2e_network_enforcement_tag_off_test.go", buildTag: "!network_enforcement_live", component: "network enforcement"},
		{path: "live_e2e_credential_delivery_tag_on_test.go", buildTag: "credential_delivery_live", component: "credential delivery"},
		{path: "live_e2e_credential_delivery_tag_off_test.go", buildTag: "!credential_delivery_live", component: "credential delivery"},
	} {
		path := filepath.Join("..", "internal", "sandboxruntime", "microvm", req.path)
		source := phase19ReadFile(t, path)
		if !phase19HasBuildTag(source, "microvm_e2e_live") || !strings.Contains(phase19SourceHeader(source), req.buildTag) {
			t.Fatalf("%s must detect %s build tag state behind microvm_e2e_live", phase34FirecrackerDisplayPath(t, path), req.component)
		}
	}

	for _, forbidden := range []string{
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
		"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement",
		"github.com/jywlabs/hal/internal/credentialdelivery",
		"net.Listen(",
		"http.ListenAndServe(",
		"exec.Command(",
		"os/exec",
		"NewBackend(",
		"LiveStart: true",
		"EnforceNetwork(",
		"ActivateCredential",
		"iptables",
	} {
		if strings.Contains(harness, forbidden) {
			t.Fatalf("%s contains forbidden live action marker %q", phase34FirecrackerDisplayPath(t, harnessPath), forbidden)
		}
	}
}
