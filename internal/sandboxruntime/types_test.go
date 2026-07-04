package sandboxruntime

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/credentialdelivery"
)

func TestRuntimeDriverIDConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ssh machine", got: DriverSSHMachine, want: "ssh_machine"},
		{name: "rootless podman", got: DriverRootlessPodman, want: "rootless_podman"},
		{name: "microVM", got: DriverMicroVM, want: "microvm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("driver ID = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestLifecycleDriverInterfaceIncludesCoreOperations(t *testing.T) {
	var _ LifecycleDriver = fakeLifecycleDriver{}

	driver := fakeLifecycleDriver{}
	ctx := context.Background()
	target := Target{Name: "dev", Provider: "daytona", Status: "running"}

	if got, err := driver.Create(ctx, CreateRequest{Name: "dev"}); err != nil || got.Name != "dev" {
		t.Fatalf("Create() = %#v, %v; want target named dev", got, err)
	}
	if got, err := driver.Start(ctx, LifecycleRequest{Target: target}); err != nil || got.Status != "running" {
		t.Fatalf("Start() = %#v, %v; want running target", got, err)
	}
	if got, err := driver.Stop(ctx, LifecycleRequest{Target: target}); err != nil || got.Status != "stopped" {
		t.Fatalf("Stop() = %#v, %v; want stopped target", got, err)
	}
	if err := driver.Delete(ctx, LifecycleRequest{Target: target}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}
	if got, err := driver.Inspect(ctx, InspectRequest{Target: target}); err != nil || got.Name != "dev" {
		t.Fatalf("Inspect() = %#v, %v; want target named dev", got, err)
	}
}

func TestExecRequestContainsStreamingCommandFields(t *testing.T) {
	var _ ExecDriver = fakeExecDriver{}

	requestType := reflect.TypeOf(ExecRequest{})
	assertFieldType(t, requestType, "Target", reflect.TypeOf(Target{}))
	assertFieldType(t, requestType, "Args", reflect.TypeOf([]string{}))
	assertFieldType(t, requestType, "Stdout", reflect.TypeOf((*io.Writer)(nil)).Elem())
	assertFieldType(t, requestType, "Stderr", reflect.TypeOf((*io.Writer)(nil)).Elem())
	assertFieldType(t, requestType, "Stdin", reflect.TypeOf((*io.Reader)(nil)).Elem())
	assertFieldType(t, requestType, "Env", reflect.TypeOf(map[string]string{}))
	assertFieldType(t, requestType, "WorkDir", reflect.TypeOf(""))
}

func TestFileTransportInterfaceIncludesCopyInAndCopyOut(t *testing.T) {
	var _ FileTransport = fakeFileTransport{}

	requestType := reflect.TypeOf(CopyRequest{})
	assertFieldType(t, requestType, "Target", reflect.TypeOf(Target{}))
	assertFieldType(t, requestType, "SourcePath", reflect.TypeOf(""))
	assertFieldType(t, requestType, "DestinationPath", reflect.TypeOf(""))

	transport := fakeFileTransport{}
	ctx := context.Background()
	if err := transport.CopyIn(ctx, CopyRequest{SourcePath: "/host/in", DestinationPath: "/remote/in"}); err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}
	if err := transport.CopyOut(ctx, CopyRequest{SourcePath: "/remote/out", DestinationPath: "/host/out"}); err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}
}

func TestRuntimeMetadataIncludesOptionalProcessLaunchMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "ProcessLaunch", reflect.TypeOf((*RuntimeProcessLaunchMetadata)(nil)))

	launchType := reflect.TypeOf(RuntimeProcessLaunchMetadata{})
	assertFieldType(t, launchType, "State", reflect.TypeOf(""))
	assertFieldType(t, launchType, "Labels", reflect.TypeOf([]string{}))
	assertFieldType(t, launchType, "ProcessID", reflect.TypeOf(""))
	assertFieldType(t, launchType, "ProcessIDSource", reflect.TypeOf(""))

	metadata := RuntimeMetadata{
		Backend: "firecracker",
		ProcessLaunch: &RuntimeProcessLaunchMetadata{
			State:           "process_launch_accepted",
			Labels:          []string{"process_launch_accepted"},
			ProcessID:       "pid-1234",
			ProcessIDSource: "adapter",
		},
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"processLaunch":`,
		`"state":"process_launch_accepted"`,
		`"labels":["process_launch_accepted"]`,
		`"processId":"pid-1234"`,
		`"processIdSource":"adapter"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeMetadataIncludesOptionalGuestReadinessMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "GuestReadiness", reflect.TypeOf((*RuntimeGuestReadinessMetadata)(nil)))

	readinessType := reflect.TypeOf(RuntimeGuestReadinessMetadata{})
	assertFieldType(t, readinessType, "State", reflect.TypeOf(RuntimeGuestReadinessState("")))
	assertFieldType(t, readinessType, "Transport", reflect.TypeOf(""))
	assertFieldType(t, readinessType, "Labels", reflect.TypeOf([]string{}))

	metadata := RuntimeMetadata{
		Backend: "firecracker",
		GuestReadiness: NewRuntimeGuestReadinessMetadata(
			RuntimeGuestReadinessStateWaiting,
			"VSock",
			[]string{"probe_pending", "waiting"},
		),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"guestReadiness":`,
		`"state":"waiting"`,
		`"transport":"vsock"`,
		`"labels":["waiting","probe_pending"]`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeGuestReadinessMetadataStatesAreStable(t *testing.T) {
	tests := []struct {
		name  string
		state RuntimeGuestReadinessState
		want  string
	}{
		{name: "not configured", state: RuntimeGuestReadinessStateNotConfigured, want: "not_configured"},
		{name: "waiting", state: RuntimeGuestReadinessStateWaiting, want: "waiting"},
		{name: "ready", state: RuntimeGuestReadinessStateReady, want: "ready"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.want {
				t.Fatalf("guest readiness state = %q, want %q", tt.state, tt.want)
			}
			metadata := NewRuntimeGuestReadinessMetadata(tt.state, "vsock", nil)
			if metadata == nil {
				t.Fatal("NewRuntimeGuestReadinessMetadata() = nil, want metadata")
			}
			if metadata.State != tt.state {
				t.Fatalf("metadata State = %q, want %q", metadata.State, tt.state)
			}
		})
	}
}

func TestRuntimeGuestReadinessMetadataSanitizesUnsafeValues(t *testing.T) {
	metadata := SanitizeRuntimeGuestReadinessMetadata(&RuntimeGuestReadinessMetadata{
		State:     RuntimeGuestReadinessStateReady,
		Transport: "tcp://127.0.0.1:9000/private/firecracker.sock?token=ghp_secret",
		Labels: []string{
			"ready",
			"probe_ok",
			"/Users/alice/private",
			"https://guest-ready.example.test:8443/status",
			"127.0.0.1",
			"OPENAI_API_KEY",
			"guest_command_payload",
			"exec_support",
			"copy_support",
			"credential_proxy",
			"template_ready",
			"hosted_vendor",
			"secure_runtime",
			"image_ready",
			"provisioned",
			"guest_agent",
			"ssh_ready",
		},
	})
	if metadata == nil {
		t.Fatal("SanitizeRuntimeGuestReadinessMetadata() = nil, want sanitized metadata")
	}
	if metadata.Transport != "" {
		t.Fatalf("unsafe Transport = %q, want omitted", metadata.Transport)
	}
	if !reflect.DeepEqual(metadata.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("Labels = %#v, want canonical ready plus safe label only", metadata.Labels)
	}

	encoded, err := json.Marshal(RuntimeMetadata{GuestReadiness: metadata})
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"127.0.0.1",
		"9000",
		"firecracker.sock",
		"guest-ready.example.test",
		"ghp_secret",
		"OPENAI_API_KEY",
		"guest_command_payload",
		"exec_support",
		"copy_support",
		"credential_proxy",
		"template_ready",
		"hosted_vendor",
		"secure_runtime",
		"image_ready",
		"provisioned",
		"guest_agent",
		"ssh_ready",
		"token=",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("guest readiness metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	for _, want := range []string{
		`"guestReadiness":`,
		`"state":"ready"`,
		`"labels":["ready","probe_ok"]`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("guest readiness metadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeGuestReadinessMetadataDoesNotClaimExecOrCopySupport(t *testing.T) {
	metadata := RuntimeMetadata{
		Backend:        "firecracker",
		GuestReadiness: NewRuntimeGuestReadinessMetadata(RuntimeGuestReadinessStateReady, "vsock", []string{"probe_ok"}),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, unsupported := range []string{
		"exec",
		"copy",
		"copyin",
		"copyout",
		"guest_agent",
		"guest_command",
		"file_transfer",
		"template",
		"image",
		"provision",
		"ssh",
	} {
		if strings.Contains(publicText, unsupported) {
			t.Fatalf("guest readiness metadata claims unsupported capability %q in %s", unsupported, publicText)
		}
	}
}

func TestRuntimeMetadataIncludesOptionalNetworkEnforcementMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "NetworkEnforcement", reflect.TypeOf((*RuntimeNetworkEnforcementMetadata)(nil)))

	networkType := reflect.TypeOf(RuntimeNetworkEnforcementMetadata{})
	assertFieldType(t, networkType, "Plan", reflect.TypeOf((*RuntimeNetworkEnforcementPlanMetadata)(nil)))
	assertFieldType(t, networkType, "Result", reflect.TypeOf((*RuntimeNetworkEnforcementResultMetadata)(nil)))

	resultType := reflect.TypeOf(RuntimeNetworkEnforcementResultMetadata{})
	assertFieldType(t, resultType, "Capability", reflect.TypeOf((*RuntimeNetworkEnforcementCapability)(nil)))

	metadata := RuntimeMetadata{
		Backend: "microvm",
		NetworkEnforcement: SanitizeRuntimeNetworkEnforcementMetadata(&RuntimeNetworkEnforcementMetadata{
			Plan: &RuntimeNetworkEnforcementPlanMetadata{
				ID:               "network-plan-01",
				Source:           "microvm",
				Operation:        "prepare_network",
				PolicySnapshotID: "policy-snapshot-01",
				PolicyPreset:     "deny_by_default",
				DefaultPosture:   "deny_by_default",
				Mechanisms:       []string{"proxy", "firewall"},
				Operations:       []string{"default_deny", "allowlist"},
			},
			Result: &RuntimeNetworkEnforcementResultMetadata{
				PlanID:           "network-plan-01",
				AdapterID:        "fake-adapter-01",
				Outcome:          "success",
				EnforcementMode:  "proxy_firewall",
				Mechanisms:       []string{"proxy", "firewall"},
				Operations:       []string{"proxy_route", "firewall_apply"},
				PolicySnapshotID: "policy-snapshot-01",
				PolicyPreset:     "deny_by_default",
				Capability: &RuntimeNetworkEnforcementCapability{
					Supported:                  true,
					Modes:                      []string{"proxy_firewall"},
					SupportsDomainRules:        true,
					SupportsEndpointRules:      true,
					SupportsDefaultDenyPosture: true,
				},
				ReasonCode: "applied",
			},
		}),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"networkEnforcement":`,
		`"plan":`,
		`"result":`,
		`"source":"microvm"`,
		`"outcome":"success"`,
		`"enforcementMode":"proxy_firewall"`,
		`"supportsDefaultDenyPosture":true`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeMetadataIncludesOptionalCredentialDeliveryMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "CredentialDelivery", reflect.TypeOf((*RuntimeCredentialDeliveryMetadata)(nil)))

	metadata := RuntimeMetadata{
		Backend: "microvm",
		CredentialDelivery: &RuntimeCredentialDeliveryMetadata{
			ID:             "credential-plan-01",
			PlanID:         "credential-plan-01",
			RequestedModes: []string{"http_proxy"},
			Status:         "planned",
		},
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"credentialDelivery":`,
		`"id":"credential-plan-01"`,
		`"requestedModes":["http_proxy"]`,
		`"status":"planned"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
	if strings.Contains(publicText, "activeModes") {
		t.Fatalf("plan-only credentialDelivery must not include activeModes: %s", publicText)
	}
}

func TestRuntimeCredentialDeliveryMetadataSanitizesToCompactStatus(t *testing.T) {
	rawValues := []string{
		"https://proxy.internal.example/token=ghp_raw_secret",
		"/Users/alice/.ssh/id_ed25519",
		"unix:///tmp/hal-credential.sock",
		"Authorization: Bearer raw-token",
		"HAL_TOKEN=raw-env-value",
		"sh -c 'cat /tmp/secret'",
	}
	metadata := RuntimeMetadata{
		Backend: "microvm",
		CredentialDelivery: &RuntimeCredentialDeliveryMetadata{
			ID:             " credential-status-01 ",
			RequestID:      rawValues[0],
			PlanID:         "credential-plan-01",
			ActivationID:   rawValues[1],
			RequestedModes: []string{" HTTP_PROXY ", rawValues[2], "env"},
			ActiveModes:    []string{" HTTP_PROXY ", rawValues[3], "legacy_auth_sync"},
			Status:         " ACTIVE ",
			ReasonCode:     rawValues[4],
			WarningCount:   -1,
			ErrorCount:     2,
		},
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, raw := range rawValues {
		if strings.Contains(publicText, raw) {
			t.Fatalf("runtime credentialDelivery leaked raw value %q in %s", raw, publicText)
		}
	}
	for _, want := range []string{
		`"credentialDelivery":`,
		`"id":"credential-status-01"`,
		`"planId":"credential-plan-01"`,
		`"requestedModes":["http_proxy","env"]`,
		`"status":"skipped"`,
		`"errorCount":2`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
	if strings.Contains(publicText, "activeModes") {
		t.Fatalf("runtime credentialDelivery activeModes must be omitted without safe activation status: %s", publicText)
	}
	if strings.Contains(publicText, "warningCount") {
		t.Fatalf("runtime credentialDelivery warningCount must omit negative counts: %s", publicText)
	}
}

func TestRuntimeCredentialDeliveryMetadataProjectsActiveModesOnlyFromSanitizedActivation(t *testing.T) {
	plan := credentialdelivery.Plan{
		ID:             "credential-plan-activation",
		RequestID:      "credential-request-activation",
		RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.ModeLegacyAuthSync},
		Status:         credentialdelivery.StatusPlanned,
	}
	active := runtimeCredentialDeliveryMetadataFromStatus(credentialdelivery.StatusMetadataFromActivation(plan, credentialdelivery.ActivationResult{
		ID:             "credential-activation-active",
		PlanID:         "credential-plan-activation",
		RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.ModeLegacyAuthSync},
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.ModeLegacyAuthSync},
		Bindings: []credentialdelivery.BindingActivationResult{{
			BindingID:    "binding-http-proxy",
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
			ProofRef:     "credential-proof-http-proxy",
		}},
		ProofRefs: []credentialdelivery.ActivationProofReference{{
			ProofID:      "credential-proof-http-proxy",
			BindingID:    "binding-http-proxy",
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
		}},
		Status: credentialdelivery.StatusActive,
	}))
	sanitizedActive := SanitizeRuntimeCredentialDeliveryMetadata(active)
	if sanitizedActive == nil {
		t.Fatal("active credentialDelivery = nil")
	}
	if sanitizedActive.Status != "active" {
		t.Fatalf("active status = %q, want active", sanitizedActive.Status)
	}
	if !reflect.DeepEqual(sanitizedActive.ActiveModes, []string{"http_proxy"}) {
		t.Fatalf("active modes = %#v, want only sanitized http_proxy", sanitizedActive.ActiveModes)
	}

	skipped := runtimeCredentialDeliveryMetadataFromStatus(credentialdelivery.StatusMetadataFromActivation(plan, credentialdelivery.ActivationResult{
		ID:             "credential-activation-skipped",
		PlanID:         "credential-plan-activation",
		RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Status:         credentialdelivery.StatusSkipped,
		Warnings: []credentialdelivery.Warning{{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: credentialdelivery.ReasonActivationUnavailable,
			Mode:       credentialdelivery.ModeHTTPProxy,
		}},
	}))
	sanitizedSkipped := SanitizeRuntimeCredentialDeliveryMetadata(skipped)
	if sanitizedSkipped == nil {
		t.Fatal("skipped credentialDelivery = nil")
	}
	if sanitizedSkipped.Status != "skipped" {
		t.Fatalf("skipped status = %q, want skipped", sanitizedSkipped.Status)
	}
	if len(sanitizedSkipped.ActiveModes) != 0 {
		t.Fatalf("skipped active modes = %#v, want omitted", sanitizedSkipped.ActiveModes)
	}

	planOnly := runtimeCredentialDeliveryMetadataFromStatus(credentialdelivery.StatusMetadataFromPlan(plan))
	planOnly.ActiveModes = []string{"http_proxy"}
	sanitizedPlan := SanitizeRuntimeCredentialDeliveryMetadata(planOnly)
	if sanitizedPlan == nil {
		t.Fatal("plan-only credentialDelivery = nil")
	}
	if sanitizedPlan.Status != "planned" {
		t.Fatalf("plan-only status = %q, want planned", sanitizedPlan.Status)
	}
	if len(sanitizedPlan.ActiveModes) != 0 {
		t.Fatalf("plan-only active modes = %#v, want omitted", sanitizedPlan.ActiveModes)
	}
}

func TestRuntimeCredentialDeliveryMetadataPreservesCredentialActivationProofReasonCodes(t *testing.T) {
	for _, reason := range []string{"missing_activation_proof", "unsupported_capability"} {
		t.Run(reason, func(t *testing.T) {
			sanitized := SanitizeRuntimeCredentialDeliveryMetadata(&RuntimeCredentialDeliveryMetadata{
				ID:         "credential-status-proof",
				Status:     "skipped",
				ReasonCode: reason,
			})
			if sanitized == nil {
				t.Fatal("credentialDelivery = nil")
			}
			if sanitized.ReasonCode != reason {
				t.Fatalf("reason = %q, want %q", sanitized.ReasonCode, reason)
			}
		})
	}
}

func TestRuntimeNetworkEnforcementMetadataSanitizesUnsafeValues(t *testing.T) {
	metadata := SanitizeRuntimeNetworkEnforcementMetadata(&RuntimeNetworkEnforcementMetadata{
		Plan: &RuntimeNetworkEnforcementPlanMetadata{
			ID:               "https://plan.example.test/path?token=secret",
			Source:           " MICROVM ",
			Operation:        "prepare_network",
			PolicySnapshotID: "/Users/alice/policy.json",
			PolicyPreset:     " DENY_BY_DEFAULT ",
			DefaultPosture:   " DENY_BY_DEFAULT ",
			Mechanisms:       []string{" FIREWALL ", "https://proxy.example.test"},
			Operations:       []string{"default_deny", "/tmp/rules.sock", "Authorization"},
		},
		Result: &RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "network-plan-01",
			AdapterID:       "adapter=secret",
			Outcome:         " SUCCESS ",
			EnforcementMode: " FIREWALL ",
			Mechanisms:      []string{" FIREWALL ", "unix:///tmp/firewall.sock"},
			Operations:      []string{"firewall_apply", "token=raw-secret"},
			PolicyPreset:    " DENY_BY_DEFAULT ",
			Capability: &RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{" FIREWALL ", "https://bad.example.test"},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode:   " APPLIED ",
			WarningCodes: []string{"https://warning.example.test"},
		},
	})
	if metadata == nil || metadata.Plan == nil || metadata.Result == nil {
		t.Fatalf("SanitizeRuntimeNetworkEnforcementMetadata() = %#v, want plan and result", metadata)
	}
	if metadata.Plan.ID != "" || metadata.Plan.PolicySnapshotID != "" {
		t.Fatalf("plan identity = %#v, want unsafe IDs cleared", metadata.Plan)
	}
	if metadata.Plan.Source != "microvm" ||
		metadata.Plan.PolicyPreset != "deny_by_default" ||
		!reflect.DeepEqual(metadata.Plan.Mechanisms, []string{"firewall"}) ||
		!reflect.DeepEqual(metadata.Plan.Operations, []string{"default_deny"}) {
		t.Fatalf("plan metadata = %#v, want sanitized safe labels", metadata.Plan)
	}
	if metadata.Result.AdapterID != "" ||
		metadata.Result.EnforcementMode != "firewall" ||
		metadata.Result.Capability == nil ||
		!reflect.DeepEqual(metadata.Result.Capability.Modes, []string{"firewall"}) ||
		len(metadata.Result.WarningCodes) != 0 {
		t.Fatalf("result metadata = %#v, want sanitized safe result", metadata.Result)
	}

	encoded, err := json.Marshal(RuntimeMetadata{NetworkEnforcement: metadata})
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"example.test",
		"/Users/alice",
		"/tmp/",
		"rules.sock",
		"token",
		"secret",
		"Authorization",
		"://",
		"production",
		"egress",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("network enforcement metadata leaked or claimed %q in %s", unsafe, publicText)
		}
	}
}

func TestRuntimeNetworkEnforcementFailureClearsCapabilityUpgrade(t *testing.T) {
	metadata := SanitizeRuntimeNetworkEnforcementMetadata(&RuntimeNetworkEnforcementMetadata{
		Result: &RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "network-plan-01",
			Outcome:         "failure",
			EnforcementMode: "proxy_firewall",
			Capability: &RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode:   "adapter_failed",
			WarningCodes: []string{"sanitized_adapter_error"},
		},
	})
	if metadata == nil || metadata.Result == nil {
		t.Fatalf("metadata = %#v, want sanitized failure result", metadata)
	}
	if metadata.Result.EnforcementMode != "none" {
		t.Fatalf("failure enforcementMode = %q, want none", metadata.Result.EnforcementMode)
	}
	if metadata.Result.Capability != nil {
		t.Fatalf("failure capability = %#v, want cleared capability upgrade", metadata.Result.Capability)
	}
	if metadata.Result.ReasonCode != "adapter_failed" {
		t.Fatalf("failure reasonCode = %q, want adapter_failed", metadata.Result.ReasonCode)
	}
}

func TestRuntimeNetworkEnforcementProxyOnlyProofCannotClaimProxyFirewall(t *testing.T) {
	metadata := SanitizeRuntimeNetworkEnforcementMetadata(&RuntimeNetworkEnforcementMetadata{
		Plan: &RuntimeNetworkEnforcementPlanMetadata{
			ID:               "network-plan-proxy-only",
			Source:           "microvm",
			Operation:        "prepare_network",
			PolicySnapshotID: "policy-snapshot-proxy-only",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "provider=firecracker", "argv=--api-sock=/tmp/fc.sock"},
		},
		Orchestration: &RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           "network-plan-proxy-only",
			AdapterID:        "policy-proxy-adapter",
			Status:           "active",
			Mechanisms:       []string{"proxy"},
			Operations:       []string{"start_proxy", "listen 127.0.0.1:8080", "/tmp/policy-proxy.sock"},
			PolicySnapshotID: "policy-snapshot-proxy-only",
			PolicyPreset:     "deny_by_default",
			Proxy: &RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               "proxy-session-proxy-only",
				PlanID:           "network-plan-proxy-only",
				AdapterID:        "policy-proxy-adapter",
				Status:           "active",
				Mechanisms:       []string{"proxy"},
				Operations:       []string{"active_proxy", "curl http://localhost:8080"},
				PolicySnapshotID: "policy-snapshot-proxy-only",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"proxy_active", "provider=firecracker"},
				ReasonCode:       "active",
			},
			CapabilityLabels: []string{"proxy_active", "host_path_/Users/alice"},
			ReasonCode:       "active",
		},
		Result: &RuntimeNetworkEnforcementResultMetadata{
			PlanID:           "network-plan-proxy-only",
			AdapterID:        "policy-proxy-adapter",
			Outcome:          "success",
			EnforcementMode:  "proxy_firewall",
			Mechanisms:       []string{"proxy"},
			Operations:       []string{"proxy_route", "argv=--netns=/tmp/netns", "provider=firecracker"},
			PolicySnapshotID: "policy-snapshot-proxy-only",
			PolicyPreset:     "deny_by_default",
			Capability: &RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	})
	if metadata == nil || metadata.Orchestration == nil || metadata.Result == nil {
		t.Fatalf("metadata = %#v, want sanitized proxy-only status", metadata)
	}
	if metadata.Orchestration.Proxy == nil ||
		metadata.Orchestration.Proxy.Status != "active" ||
		!reflect.DeepEqual(metadata.Orchestration.Proxy.CapabilityLabels, []string{"proxy_active"}) {
		t.Fatalf("orchestration proxy = %#v, want sanitized active proxy proof", metadata.Orchestration.Proxy)
	}
	if len(metadata.Orchestration.Rules) != 0 {
		t.Fatalf("orchestration rules = %#v, want no firewall/runtime rule proof", metadata.Orchestration.Rules)
	}
	if metadata.Result.EnforcementMode != "proxy" {
		t.Fatalf("result enforcementMode = %q, want proxy-only downgrade", metadata.Result.EnforcementMode)
	}
	if metadata.Result.Capability == nil ||
		!reflect.DeepEqual(metadata.Result.Capability.Modes, []string{"proxy"}) ||
		metadata.Result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("result capability = %#v, want proxy-only capability without default-deny posture", metadata.Result.Capability)
	}

	encoded, err := json.Marshal(RuntimeMetadata{NetworkEnforcement: metadata})
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"proxy_firewall",
		"supportsDefaultDenyPosture",
		"127.0.0.1",
		"localhost",
		"8080",
		"/tmp",
		".sock",
		"--api-sock",
		"--netns",
		"provider",
		"firecracker",
		"/Users/alice",
		"host_path",
		"://",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("proxy-only runtime status leaked or overclaimed %q in %s", unsafe, publicText)
		}
	}
}

func TestRuntimeNetworkEnforcementProjectionDowngradesNonEnforcingResults(t *testing.T) {
	safePlan := &RuntimeNetworkEnforcementPlanMetadata{
		ID:               "network-plan-downgrade",
		Source:           "microvm",
		Operation:        "prepare_network",
		PolicySnapshotID: "policy-snapshot-downgrade",
		PolicyPreset:     "deny_by_default",
		DefaultPosture:   "deny_by_default",
		Mechanisms:       []string{"proxy", "firewall"},
		Operations: []string{
			"default_deny",
			"allowlist",
			"api.internal.example.com:443",
			"/tmp/live-proxy.sock",
			"iptables -A OUTPUT",
			"process pid=1234 token=secret",
		},
	}
	enforcingCapability := func() *RuntimeNetworkEnforcementCapability {
		return &RuntimeNetworkEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{"proxy_firewall"},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsDefaultDenyPosture: true,
		}
	}
	result := func(outcome, mode, reason string, warnings ...string) *RuntimeNetworkEnforcementResultMetadata {
		return &RuntimeNetworkEnforcementResultMetadata{
			PlanID:           "network-plan-downgrade",
			AdapterID:        "live-adapter-downgrade",
			Outcome:          outcome,
			EnforcementMode:  mode,
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_route", "firewall_apply", "connect api.internal.example.com:443", "/tmp/firewall.rules", "GITHUB_TOKEN"},
			PolicySnapshotID: "policy-snapshot-downgrade",
			PolicyPreset:     "deny_by_default",
			Capability:       enforcingCapability(),
			ReasonCode:       reason,
			WarningCodes:     warnings,
		}
	}

	tests := []struct {
		name         string
		result       *RuntimeNetworkEnforcementResultMetadata
		wantOutcome  string
		wantMode     string
		wantReason   string
		wantWarnings []string
	}{
		{
			name:   "nil result preserves requested plan only",
			result: nil,
		},
		{
			name:        "unsupported result",
			result:      result("unsupported", "proxy_firewall", "adapter_unsupported"),
			wantOutcome: "unsupported",
			wantMode:    "none",
			wantReason:  "adapter_unsupported",
		},
		{
			name:         "failed result",
			result:       result("failure", "proxy_firewall", "adapter_failed", "sanitized_adapter_error"),
			wantOutcome:  "failure",
			wantMode:     "none",
			wantReason:   "adapter_failed",
			wantWarnings: []string{"sanitized_adapter_error"},
		},
		{
			name:         "partial live success",
			result:       result("success", "proxy_firewall", "applied", "partial_enforcement"),
			wantOutcome:  "success",
			wantMode:     "none",
			wantReason:   "applied",
			wantWarnings: []string{"partial_enforcement"},
		},
		{
			name:         "audit-only result",
			result:       result("success", "best_effort", "best_effort", "metadata_only_fallback"),
			wantOutcome:  "success",
			wantMode:     "none",
			wantReason:   "best_effort",
			wantWarnings: []string{"metadata_only_fallback"},
		},
		{
			name:         "best-effort result",
			result:       result("best_effort", "proxy_firewall", "best_effort", "capability_downgraded"),
			wantOutcome:  "best_effort",
			wantMode:     "best_effort",
			wantReason:   "best_effort",
			wantWarnings: []string{"capability_downgraded"},
		},
		{
			name:         "cleanup-failure result",
			result:       result("success", "proxy_firewall", "adapter_failed", "partial_enforcement", "sanitized_adapter_error"),
			wantOutcome:  "success",
			wantMode:     "none",
			wantReason:   "adapter_failed",
			wantWarnings: []string{"partial_enforcement", "sanitized_adapter_error"},
		},
		{
			name:         "rollback-failure result",
			result:       result("success", "runtime", "adapter_failed", "partial_enforcement", "sanitized_adapter_error"),
			wantOutcome:  "success",
			wantMode:     "none",
			wantReason:   "adapter_failed",
			wantWarnings: []string{"partial_enforcement", "sanitized_adapter_error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := SanitizeRuntimeNetworkEnforcementMetadata(&RuntimeNetworkEnforcementMetadata{
				Plan:   safePlan,
				Result: tt.result,
			})
			if metadata == nil || metadata.Plan == nil {
				t.Fatalf("metadata = %#v, want requested plan metadata", metadata)
			}
			if metadata.Plan.PolicyPreset != "deny_by_default" ||
				metadata.Plan.DefaultPosture != "deny_by_default" ||
				!reflect.DeepEqual(metadata.Plan.Mechanisms, []string{"proxy", "firewall"}) ||
				!reflect.DeepEqual(metadata.Plan.Operations, []string{"default_deny", "allowlist"}) {
				t.Fatalf("plan metadata = %#v, want safe requested-policy metadata preserved", metadata.Plan)
			}

			if tt.result == nil {
				if metadata.Result != nil {
					t.Fatalf("Result = %#v, want nil for nil runtime result", metadata.Result)
				}
			} else {
				if metadata.Result == nil {
					t.Fatalf("Result = nil, want downgraded result metadata")
				}
				if metadata.Result.Outcome != tt.wantOutcome {
					t.Fatalf("Outcome = %q, want %q", metadata.Result.Outcome, tt.wantOutcome)
				}
				if metadata.Result.EnforcementMode != tt.wantMode {
					t.Fatalf("EnforcementMode = %q, want %q", metadata.Result.EnforcementMode, tt.wantMode)
				}
				if metadata.Result.Capability != nil {
					t.Fatalf("Capability = %#v, want no enforcing capability claim", metadata.Result.Capability)
				}
				if metadata.Result.PolicyPreset != "deny_by_default" {
					t.Fatalf("PolicyPreset = %q, want safe policy metadata preserved", metadata.Result.PolicyPreset)
				}
				if metadata.Result.ReasonCode != tt.wantReason {
					t.Fatalf("ReasonCode = %q, want %q", metadata.Result.ReasonCode, tt.wantReason)
				}
				if !reflect.DeepEqual(metadata.Result.WarningCodes, tt.wantWarnings) {
					t.Fatalf("WarningCodes = %#v, want %#v", metadata.Result.WarningCodes, tt.wantWarnings)
				}
			}

			encoded, err := json.Marshal(RuntimeMetadata{NetworkEnforcement: metadata})
			if err != nil {
				t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
			}
			publicText := string(encoded)
			for _, unsafe := range []string{
				"api.internal.example.com",
				"127.0.0.1",
				"443",
				"/tmp",
				"live-proxy.sock",
				"iptables",
				"firewall.rules",
				"process",
				"pid=",
				"token",
				"secret",
				"GITHUB_TOKEN",
				"://",
				`"capability":`,
				"supportsDefaultDenyPosture",
			} {
				if strings.Contains(publicText, unsafe) {
					t.Fatalf("runtime projection leaked or claimed unsafe fragment %q in %s", unsafe, publicText)
				}
			}
		})
	}
}

func assertFieldType(t *testing.T, typ reflect.Type, fieldName string, want reflect.Type) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s field missing from %s", fieldName, typ.Name())
	}
	if field.Type != want {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, want)
	}
}

func runtimeCredentialDeliveryMetadataFromStatus(status credentialdelivery.StatusMetadata) *RuntimeCredentialDeliveryMetadata {
	return &RuntimeCredentialDeliveryMetadata{
		ID:             status.ID,
		RequestID:      status.RequestID,
		PlanID:         status.PlanID,
		ActivationID:   status.ActivationID,
		RequestedModes: runtimeCredentialDeliveryModeStrings(status.RequestedModes),
		ActiveModes:    runtimeCredentialDeliveryModeStrings(status.ActiveModes),
		Status:         string(status.Status),
		ReasonCode:     string(status.ReasonCode),
		WarningCount:   status.WarningCount,
		ErrorCount:     status.ErrorCount,
	}
}

func runtimeCredentialDeliveryModeStrings(modes []credentialdelivery.Mode) []string {
	if len(modes) == 0 {
		return nil
	}
	out := make([]string, len(modes))
	for i, mode := range modes {
		out[i] = string(mode)
	}
	return out
}

type fakeLifecycleDriver struct{}

func (fakeLifecycleDriver) Create(context.Context, CreateRequest) (*Target, error) {
	return &Target{Name: "dev"}, nil
}

func (fakeLifecycleDriver) Start(_ context.Context, req LifecycleRequest) (*Target, error) {
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (fakeLifecycleDriver) Stop(_ context.Context, req LifecycleRequest) (*Target, error) {
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (fakeLifecycleDriver) Delete(context.Context, LifecycleRequest) error {
	return nil
}

func (fakeLifecycleDriver) Inspect(_ context.Context, req InspectRequest) (*Target, error) {
	return &req.Target, nil
}

type fakeExecDriver struct{}

func (fakeExecDriver) Exec(context.Context, ExecRequest) (*ExecResult, error) {
	return &ExecResult{}, nil
}

type fakeFileTransport struct{}

func (fakeFileTransport) CopyIn(context.Context, CopyRequest) error {
	return nil
}

func (fakeFileTransport) CopyOut(context.Context, CopyRequest) error {
	return nil
}
