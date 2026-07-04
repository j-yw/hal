package microvm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLiveE2EMetadataContractFieldsAndJSONNames(t *testing.T) {
	metadataType := reflect.TypeOf(LiveE2EMetadata{})
	readinessPtrType := reflect.TypeOf((*LiveE2EReadinessMetadata)(nil))

	assertConfigField(t, metadataType, "ID", reflect.TypeOf(""), `json:"id,omitempty"`)
	assertConfigField(t, metadataType, "Status", reflect.TypeOf(LiveE2EReadinessStatus("")), `json:"status,omitempty"`)
	assertConfigField(t, metadataType, "ReasonCode", reflect.TypeOf(LiveE2EReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, metadataType, "Message", reflect.TypeOf(""), `json:"message,omitempty"`)
	assertConfigField(t, metadataType, "Firecracker", readinessPtrType, `json:"firecracker,omitempty"`)
	assertConfigField(t, metadataType, "KVM", readinessPtrType, `json:"kvm,omitempty"`)
	assertConfigField(t, metadataType, "NetworkProxy", readinessPtrType, `json:"networkProxy,omitempty"`)
	assertConfigField(t, metadataType, "Firewall", readinessPtrType, `json:"firewall,omitempty"`)
	assertConfigField(t, metadataType, "CredentialDelivery", readinessPtrType, `json:"credentialDelivery,omitempty"`)
	assertConfigField(t, metadataType, "TemplateTrust", readinessPtrType, `json:"templateTrust,omitempty"`)

	readinessType := reflect.TypeOf(LiveE2EReadinessMetadata{})
	assertConfigField(t, readinessType, "Component", reflect.TypeOf(LiveE2EReadinessComponent("")), `json:"component,omitempty"`)
	assertConfigField(t, readinessType, "ID", reflect.TypeOf(""), `json:"id,omitempty"`)
	assertConfigField(t, readinessType, "Status", reflect.TypeOf(LiveE2EReadinessStatus("")), `json:"status,omitempty"`)
	assertConfigField(t, readinessType, "ReasonCode", reflect.TypeOf(LiveE2EReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, readinessType, "Message", reflect.TypeOf(""), `json:"message,omitempty"`)
}

func TestLiveE2EReasonCodesCoverRequiredPrerequisites(t *testing.T) {
	required := map[string]LiveE2EReasonCode{
		"firecracker live marker":     LiveE2EReasonFirecrackerMarkerMissing,
		"firecracker binary":          LiveE2EReasonFirecrackerBinaryMissing,
		"firecracker kernel":          LiveE2EReasonFirecrackerKernelMissing,
		"firecracker rootfs":          LiveE2EReasonFirecrackerRootfsMissing,
		"kvm capability":              LiveE2EReasonKVMCapabilityMissing,
		"network proxy marker":        LiveE2EReasonNetworkProxyMarkerMissing,
		"firewall marker":             LiveE2EReasonFirewallMarkerMissing,
		"credential delivery marker":  LiveE2EReasonCredentialDeliveryMarkerMissing,
		"template trust marker":       LiveE2EReasonTemplateTrustMarkerMissing,
		"network proxy unavailable":   LiveE2EReasonNetworkProxyUnavailable,
		"firewall unavailable":        LiveE2EReasonFirewallUnavailable,
		"credential delivery blocked": LiveE2EReasonCredentialDeliveryUnavailable,
		"template trust unavailable":  LiveE2EReasonTemplateTrustUnavailable,
	}

	seen := map[LiveE2EReasonCode]string{}
	for name, code := range required {
		if code == "" {
			t.Fatalf("%s reason code is empty", name)
		}
		if sanitized := sanitizeLiveE2EReasonCode(code); sanitized != code {
			t.Fatalf("%s reason code sanitizes to %q, want %q", name, sanitized, code)
		}
		if previous := seen[code]; previous != "" {
			t.Fatalf("%s and %s share reason code %q", name, previous, code)
		}
		seen[code] = name
	}
}

func TestLiveE2EMetadataJSONOmitsAbsentOptionalFields(t *testing.T) {
	encoded, err := json.Marshal(LiveE2EMetadata{})
	if err != nil {
		t.Fatalf("Marshal(LiveE2EMetadata{}) error: %v", err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("empty metadata JSON = %s, want {}", encoded)
	}

	unsafeOnly := LiveE2EMetadata{
		Firecracker: &LiveE2EReadinessMetadata{
			Component: "https://firecracker.example.test/component",
			ID:        "https://firecracker.example.test:8443/run?token=ghp_secret",
		},
	}
	encoded, err = json.Marshal(unsafeOnly)
	if err != nil {
		t.Fatalf("Marshal(unsafeOnly) error: %v", err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("unsafe-only metadata JSON = %s, want omitted fields", encoded)
	}
}

func TestLiveE2EMetadataSanitizesUnsafeValues(t *testing.T) {
	metadata := LiveE2EMetadata{
		ID:         "https://builder.internal:8443/run?token=ghp_secret",
		Status:     "READY",
		ReasonCode: LiveE2EReasonReady,
		Message:    "host=builder.internal socket=/tmp/firecracker.sock port=8443 HAL_SECRET=supersecret provider=aws:i-1234567890",
		Firecracker: &LiveE2EReadinessMetadata{
			Component:  "https://wrong.example.test/component",
			ID:         "FC-READY-01",
			Status:     "READY",
			ReasonCode: LiveE2EReasonFirecrackerBinaryMissing,
			Message:    "firecracker binary at /Users/alice/bin/firecracker on fc-builder.local:8443 token=ghp_secret",
		},
		KVM: &LiveE2EReadinessMetadata{
			ID:         "12345",
			Status:     LiveE2EReadinessUnavailable,
			ReasonCode: LiveE2EReasonKVMDeviceMissing,
			Message:    "kvm check failed at /var/run/hypervisor-device host=workstation.local",
		},
		NetworkProxy: &LiveE2EReadinessMetadata{
			ID:         "proxy-01",
			Status:     LiveE2EReadinessReady,
			ReasonCode: LiveE2EReasonReady,
			Message:    "proxy listener tcp://127.0.0.1:18080 secret=ghp_secret",
		},
		Firewall: &LiveE2EReadinessMetadata{
			ID:         "firewall-01",
			Status:     LiveE2EReadinessBlocked,
			ReasonCode: LiveE2EReasonFirewallMarkerMissing,
			Message:    "firewall marker missing provider_handle=aws:sg-123456",
		},
		CredentialDelivery: &LiveE2EReadinessMetadata{
			ID:         "credential-delivery-01",
			Status:     LiveE2EReadinessMissing,
			ReasonCode: LiveE2EReasonCredentialDeliveryMarkerMissing,
			Message:    "env HAL_TOKEN=rawvalue delivered password=hunter2",
		},
		TemplateTrust: &LiveE2EReadinessMetadata{
			ID:         "template-trust-01",
			Status:     LiveE2EReadinessUnavailable,
			ReasonCode: LiveE2EReasonTemplateTrustUnavailable,
			Message:    "registry https://registry.example.com/private?token=ghp_secret cache=/Users/alice/.cache/hal",
		},
	}

	sanitized := SanitizeLiveE2EMetadata(metadata)
	if sanitized.ID != "" {
		t.Fatalf("unsafe top-level ID = %q, want omitted", sanitized.ID)
	}
	if sanitized.Status != LiveE2EReadinessReady {
		t.Fatalf("Status = %q, want normalized ready", sanitized.Status)
	}
	if sanitized.Firecracker == nil || sanitized.Firecracker.Component != LiveE2EComponentFirecracker {
		t.Fatalf("Firecracker component = %#v, want forced firecracker component", sanitized.Firecracker)
	}
	if sanitized.Firecracker.ID != "fc-ready-01" {
		t.Fatalf("Firecracker ID = %q, want lowercase safe ID", sanitized.Firecracker.ID)
	}
	if sanitized.KVM == nil || sanitized.KVM.ID != "" {
		t.Fatalf("KVM unsafe numeric ID = %#v, want ID omitted", sanitized.KVM)
	}
	if sanitized.NetworkProxy == nil || sanitized.NetworkProxy.Component != LiveE2EComponentNetworkProxy {
		t.Fatalf("NetworkProxy component = %#v, want network_proxy", sanitized.NetworkProxy)
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(LiveE2EMetadata) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"builder.internal",
		"8443",
		"ghp_secret",
		"/Users/alice",
		"/tmp",
		"firecracker.sock",
		"fc-builder.local",
		"/var/run",
		"workstation.local",
		"127.0.0.1",
		"18080",
		"aws:i-1234567890",
		"aws:sg-123456",
		"rawvalue",
		"hunter2",
		"registry.example.com",
		"12345",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("live E2E metadata JSON leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	for _, want := range []string{
		`"firecracker"`,
		`"kvm"`,
		`"networkProxy"`,
		`"firewall"`,
		`"credentialDelivery"`,
		`"templateTrust"`,
		`"component":"firecracker"`,
		`"component":"network_proxy"`,
		`"id":"fc-ready-01"`,
		`"id":"credential-delivery-01"`,
		`[redacted-path]`,
		`[redacted-endpoint]`,
		`[redacted]`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("live E2E metadata JSON %s missing expected safe fragment %q", publicText, want)
		}
	}
}

func TestNewLiveE2EReadinessMetadataSanitizesBeforeReturning(t *testing.T) {
	metadata := NewLiveE2EReadinessMetadata(
		LiveE2EComponentCredentialDelivery,
		"delivery-01",
		"ACTIVE",
		LiveE2EReasonCredentialDeliveryMarkerMissing,
		"credential env VALUE=rawsecret token=ghp_secret",
	)
	if metadata == nil {
		t.Fatal("NewLiveE2EReadinessMetadata() = nil, want sanitized metadata")
	}
	if metadata.Status != "" {
		t.Fatalf("unsupported status = %q, want omitted", metadata.Status)
	}
	if metadata.ID != "delivery-01" {
		t.Fatalf("ID = %q, want safe ID", metadata.ID)
	}
	if metadata.Component != LiveE2EComponentCredentialDelivery {
		t.Fatalf("Component = %q, want credential_delivery", metadata.Component)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(readiness metadata) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{"rawsecret", "ghp_secret"} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("readiness metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}
