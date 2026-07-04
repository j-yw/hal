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
