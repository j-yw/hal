package microvm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMissingLiveE2EPrerequisiteDiagnosticsMapDistinctSafeReasonCodes(t *testing.T) {
	tests := []struct {
		name         string
		category     string
		prerequisite LiveE2EPrerequisiteName
		component    LiveE2EReadinessComponent
		reason       LiveE2EReasonCode
		message      string
	}{
		{
			name:         "firecracker live marker",
			category:     "microvm",
			prerequisite: LiveE2EPrerequisiteFirecrackerLiveMarker,
			component:    LiveE2EComponentFirecracker,
			reason:       LiveE2EReasonFirecrackerMarkerMissing,
			message:      "Set the Firecracker live marker before running the live E2E harness.",
		},
		{
			name:         "firecracker binary",
			category:     "microvm",
			prerequisite: LiveE2EPrerequisiteFirecrackerBinary,
			component:    LiveE2EComponentFirecracker,
			reason:       LiveE2EReasonFirecrackerBinaryMissing,
			message:      "Install or enable the Firecracker binary before running the live E2E harness.",
		},
		{
			name:         "firecracker kernel",
			category:     "microvm",
			prerequisite: LiveE2EPrerequisiteFirecrackerKernel,
			component:    LiveE2EComponentFirecracker,
			reason:       LiveE2EReasonFirecrackerKernelMissing,
			message:      "Provide the microVM kernel marker before running the live E2E harness.",
		},
		{
			name:         "firecracker rootfs",
			category:     "microvm",
			prerequisite: LiveE2EPrerequisiteFirecrackerRootfs,
			component:    LiveE2EComponentFirecracker,
			reason:       LiveE2EReasonFirecrackerRootfsMissing,
			message:      "Provide the microVM rootfs marker before running the live E2E harness.",
		},
		{
			name:         "kvm capability",
			category:     "microvm",
			prerequisite: LiveE2EPrerequisiteKVMCapability,
			component:    LiveE2EComponentKVM,
			reason:       LiveE2EReasonKVMCapabilityMissing,
			message:      "Enable host KVM capability before running the live E2E harness.",
		},
		{
			name:         "network proxy marker",
			category:     "network enforcement",
			prerequisite: LiveE2EPrerequisiteNetworkProxyMarker,
			component:    LiveE2EComponentNetworkProxy,
			reason:       LiveE2EReasonNetworkProxyMarkerMissing,
			message:      "Set the network proxy live marker before claiming proxy enforcement readiness.",
		},
		{
			name:         "firewall marker",
			category:     "network enforcement",
			prerequisite: LiveE2EPrerequisiteFirewallMarker,
			component:    LiveE2EComponentFirewall,
			reason:       LiveE2EReasonFirewallMarkerMissing,
			message:      "Set the firewall live marker before claiming firewall enforcement readiness.",
		},
		{
			name:         "credential delivery marker",
			category:     "credential delivery",
			prerequisite: LiveE2EPrerequisiteCredentialMarker,
			component:    LiveE2EComponentCredentialDelivery,
			reason:       LiveE2EReasonCredentialDeliveryMarkerMissing,
			message:      "Set the credential delivery live marker before running credential delivery checks.",
		},
		{
			name:         "credential delivery env marker",
			category:     "credential delivery",
			prerequisite: LiveE2EPrerequisiteCredentialEnvMarker,
			component:    LiveE2EComponentCredentialDelivery,
			reason:       LiveE2EReasonCredentialDeliveryEnvMarkerMissing,
			message:      "Set the credential delivery env marker before running env credential delivery checks.",
		},
		{
			name:         "template trust marker",
			category:     "template trust",
			prerequisite: LiveE2EPrerequisiteTemplateTrustMarker,
			component:    LiveE2EComponentTemplateTrust,
			reason:       LiveE2EReasonTemplateTrustMarkerMissing,
			message:      "Set the template trust marker before running template trust checks.",
		},
	}

	seenReasons := map[LiveE2EReasonCode]LiveE2EPrerequisiteName{}
	seenCategories := map[string]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildMissingLiveE2EPrerequisiteDiagnostic(tt.prerequisite)
			if got.Prerequisite != tt.prerequisite {
				t.Fatalf("prerequisite = %q, want %q", got.Prerequisite, tt.prerequisite)
			}
			if got.Component != tt.component {
				t.Fatalf("component = %q, want %q", got.Component, tt.component)
			}
			if got.Status != LiveE2EReadinessMissing {
				t.Fatalf("status = %q, want %q", got.Status, LiveE2EReadinessMissing)
			}
			if got.ReasonCode != tt.reason {
				t.Fatalf("reason = %q, want %q", got.ReasonCode, tt.reason)
			}
			if got.Message != tt.message {
				t.Fatalf("message = %q, want %q", got.Message, tt.message)
			}
			assertLiveE2EDiagnosticNoUnsafeFragments(t, got, liveE2EDiagnosticUnsafeFragments()...)

			readiness := got.ReadinessMetadata()
			if readiness == nil {
				t.Fatal("ReadinessMetadata() = nil, want metadata")
			}
			if readiness.ID != string(tt.prerequisite) {
				t.Fatalf("readiness ID = %q, want %q", readiness.ID, tt.prerequisite)
			}
			if readiness.ReasonCode != tt.reason {
				t.Fatalf("readiness reason = %q, want %q", readiness.ReasonCode, tt.reason)
			}
			seenCategories[tt.category] = true
		})

		if previous := seenReasons[tt.reason]; previous != "" {
			t.Fatalf("%s and %s share reason code %q", previous, tt.prerequisite, tt.reason)
		}
		seenReasons[tt.reason] = tt.prerequisite
	}

	for _, category := range []string{"microvm", "network enforcement", "credential delivery", "template trust"} {
		if !seenCategories[category] {
			t.Fatalf("missing fake-only diagnostic coverage for category %q", category)
		}
	}
}

func TestMissingLiveE2EPrerequisiteDiagnosticsDropUnknownUnsafeInputs(t *testing.T) {
	got := BuildMissingLiveE2EPrerequisiteDiagnostics([]LiveE2EPrerequisiteName{
		LiveE2EPrerequisiteName("https://builder.example.test/rootfs?token=ghp_secret"),
		LiveE2EPrerequisiteName("FIRECRACKER_BINARY"),
		LiveE2EPrerequisiteCredentialMarker,
		LiveE2EPrerequisiteName("/Users/alice/.cache/kernel"),
	})

	if len(got) != 2 {
		t.Fatalf("diagnostics length = %d, want 2: %#v", len(got), got)
	}
	if got[0].Prerequisite != LiveE2EPrerequisiteFirecrackerBinary {
		t.Fatalf("diagnostics[0].Prerequisite = %q, want %q", got[0].Prerequisite, LiveE2EPrerequisiteFirecrackerBinary)
	}
	if got[1].Prerequisite != LiveE2EPrerequisiteCredentialMarker {
		t.Fatalf("diagnostics[1].Prerequisite = %q, want %q", got[1].Prerequisite, LiveE2EPrerequisiteCredentialMarker)
	}
	assertLiveE2EDiagnosticNoUnsafeFragments(t, got, liveE2EDiagnosticUnsafeFragments()...)
}

func TestLiveE2EPrerequisiteDiagnosticsJSONIsRedactionSafe(t *testing.T) {
	diagnostic := LiveE2EPrerequisiteDiagnostic{
		Prerequisite: LiveE2EPrerequisiteName("https://registry.example.test/private?token=ghp_secret"),
		Component:    LiveE2EReadinessComponent("https://provider.internal/component"),
		Status:       LiveE2EReadinessStatus("MISSING"),
		ReasonCode:   LiveE2EReasonNetworkProxyMarkerMissing,
		Message:      "proxy at https://proxy.example.test:8443 socket=/tmp/proxy.sock HAL_TOKEN=rawvalue provider=aws:sg-123 secret=ghp_secret",
	}

	encoded, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatalf("Marshal(LiveE2EPrerequisiteDiagnostic) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"registry.example.test",
		"proxy.example.test",
		"8443",
		"/tmp",
		"proxy.sock",
		"rawvalue",
		"aws:sg-123",
		"ghp_secret",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("diagnostic JSON leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	for _, want := range []string{
		`"status":"missing"`,
		`"reasonCode":"network_proxy_marker_missing"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("diagnostic JSON %s missing safe fragment %q", publicText, want)
		}
	}
}

func assertLiveE2EDiagnosticNoUnsafeFragments(t *testing.T, value any, fragments ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	publicText := string(encoded)
	for _, fragment := range fragments {
		if strings.Contains(publicText, fragment) {
			t.Fatalf("diagnostic JSON leaked unsafe fragment %q in %s", fragment, publicText)
		}
	}
}

func liveE2EDiagnosticUnsafeFragments() []string {
	return []string{
		"/Users/",
		"/tmp/",
		".sock",
		"://",
		"127.0.0.1",
		"8443",
		"ghp_",
		"sk-",
		"hunter2",
		"provider_handle",
		"provider=",
		"password=",
		"token=",
	}
}
