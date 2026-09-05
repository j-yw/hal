package sandboxworker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerProtocolDefaultsAndValidation(t *testing.T) {
	req := Request{Operation: OperationStatus}.WithDefaults()
	if req.ProtocolVersion != ProtocolVersion {
		t.Fatalf("request protocolVersion = %q, want %q", req.ProtocolVersion, ProtocolVersion)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	resp := Response{Operation: OperationStatus, OK: true}.WithDefaults()
	if resp.ProtocolVersion != ProtocolVersion {
		t.Fatalf("response protocolVersion = %q, want %q", resp.ProtocolVersion, ProtocolVersion)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() unexpected error: %v", err)
	}

	if err := (Request{ProtocolVersion: "sandboxworker-v0", Operation: OperationStatus}).Validate(); err == nil {
		t.Fatal("request Validate() error = nil, want unsupported protocol version error")
	}
	if err := (Request{Operation: "launch"}).Validate(); err == nil {
		t.Fatal("request Validate() error = nil, want unsupported operation error")
	}
	if err := (Response{Operation: OperationStatus, OK: false}).Validate(); err == nil {
		t.Fatal("response Validate() error = nil, want error payload requirement")
	}
}

func TestWorkerProtocolRequestResponseJSONRoundTripPreservesRequiredFields(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-001",
		Operation:       OperationCreate,
		DriverID:        RuntimeDriverRootlessPodman,
		Create: &CreateRequest{
			Name:     "dev-sandbox",
			Env:      map[string]string{"HAL_SANDBOX": "1"},
			Security: honestSecurityPolicy(),
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	var decodedReq Request
	roundTripJSON(t, req, &decodedReq)
	if !reflect.DeepEqual(decodedReq, req) {
		t.Fatalf("decoded request = %#v, want %#v", decodedReq, req)
	}
	if decodedReq.ProtocolVersion == "" || decodedReq.Operation == "" || decodedReq.DriverID == "" || decodedReq.Create == nil {
		t.Fatalf("decoded request missing required protocol fields: %#v", decodedReq)
	}

	resp := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-001",
		Operation:       OperationCreate,
		OK:              true,
		Target: &Target{
			ID:     "sandbox-001",
			Name:   "dev-sandbox",
			Status: "running",
			Runtime: RuntimeTarget{
				Driver:         RuntimeDriverRootlessPodman,
				RuntimeID:      "container-001",
				WorkerID:       "worker-001",
				IsolationLevel: IsolationLevelContainer,
			},
		},
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() unexpected error: %v", err)
	}

	var decodedResp Response
	roundTripJSON(t, resp, &decodedResp)
	if !reflect.DeepEqual(decodedResp, resp) {
		t.Fatalf("decoded response = %#v, want %#v", decodedResp, resp)
	}
	if decodedResp.ProtocolVersion == "" || decodedResp.Operation == "" || decodedResp.Target == nil {
		t.Fatalf("decoded response missing required protocol fields: %#v", decodedResp)
	}
}

func TestWorkerLifecycleRequestJSONRoundTripPreservesPayloads(t *testing.T) {
	target := Target{
		ID:     "sandbox-001",
		Name:   "dev-sandbox",
		Status: "stopped",
		Runtime: RuntimeTarget{
			Driver:         RuntimeDriverRootlessPodman,
			RuntimeID:      "container-001",
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
	}

	for _, operation := range []string{OperationStart, OperationStop, OperationDelete} {
		t.Run(operation, func(t *testing.T) {
			req := Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "req-" + operation,
				Operation:       operation,
				DriverID:        RuntimeDriverRootlessPodman,
				Lifecycle:       &LifecycleRequest{Target: target},
			}
			if err := req.Validate(); err != nil {
				t.Fatalf("request Validate() unexpected error: %v", err)
			}

			var decoded Request
			roundTripJSON(t, req, &decoded)
			if !reflect.DeepEqual(decoded, req) {
				t.Fatalf("decoded request = %#v, want %#v", decoded, req)
			}
			if decoded.Lifecycle == nil || decoded.Lifecycle.Target.Runtime.Driver != RuntimeDriverRootlessPodman {
				t.Fatalf("decoded request missing lifecycle target metadata: %#v", decoded)
			}
		})
	}
}

func TestWorkerStatusValidationAndJSONRoundTrip(t *testing.T) {
	status := Status{
		ProtocolVersion: ProtocolVersion,
		WorkerID:        "worker-001",
		HostKind:        HostKindLocal,
		SocketPath:      "/tmp/hal-sandboxworker.sock",
		SupportedRuntimeDrivers: []string{
			RuntimeDriverRootlessPodman,
			RuntimeDriverSSHMachine,
		},
		Health: WorkerHealth{
			Status:  HealthStatusHealthy,
			Message: "ready",
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 4,
			ActiveSandboxes:        1,
		},
		Security: honestSecurityPolicy(),
	}
	if err := status.Validate(); err != nil {
		t.Fatalf("status Validate() unexpected error: %v", err)
	}

	var decoded Status
	roundTripJSON(t, status, &decoded)
	if !reflect.DeepEqual(decoded, status) {
		t.Fatalf("decoded status = %#v, want %#v", decoded, status)
	}
	if decoded.WorkerID == "" || decoded.HostKind == "" || decoded.Health.Status == "" || decoded.Capacity.MaxConcurrentSandboxes == 0 {
		t.Fatalf("decoded status missing required status fields: %#v", decoded)
	}
}

func TestWorkerCapabilitiesValidationAndJSONRoundTrip(t *testing.T) {
	capabilities := Capabilities{
		ProtocolVersion: ProtocolVersion,
		WorkerID:        "worker-001",
		SupportedOperations: []string{
			OperationStatus,
			OperationCapabilities,
			OperationCreate,
			OperationInspect,
		},
		RuntimeDrivers: []RuntimeDriver{
			{
				ID:             RuntimeDriverRootlessPodman,
				HostKind:       HostKindLocal,
				IsolationLevel: IsolationLevelContainer,
				Operations: []string{
					OperationCreate,
					OperationStart,
					OperationStop,
					OperationDelete,
					OperationInspect,
				},
				Security: honestSecurityPolicy(),
			},
		},
		Security: honestSecurityPolicy(),
	}
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("capabilities Validate() unexpected error: %v", err)
	}

	var decoded Capabilities
	roundTripJSON(t, capabilities, &decoded)
	if !reflect.DeepEqual(decoded, capabilities) {
		t.Fatalf("decoded capabilities = %#v, want %#v", decoded, capabilities)
	}
	if decoded.WorkerID == "" || len(decoded.SupportedOperations) == 0 || len(decoded.RuntimeDrivers) == 0 {
		t.Fatalf("decoded capabilities missing required fields: %#v", decoded)
	}
	if containsString(decoded.SupportedOperations, unsupportedNetworkEnforcementFirewall) {
		t.Fatalf("supported operations overclaim firewall support: %#v", decoded.SupportedOperations)
	}
}

func TestWorkerProtocolOmitsSecurityReadinessGateDecisionFields(t *testing.T) {
	payloads := []struct {
		name  string
		value any
	}{
		{
			name: "request",
			value: Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "req-001",
				Operation:       OperationCreate,
				DriverID:        RuntimeDriverRootlessPodman,
				Create: &CreateRequest{
					Name:     "dev-sandbox",
					Security: honestSecurityPolicy(),
				},
			},
		},
		{
			name: "response",
			value: Response{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "req-001",
				Operation:       OperationStart,
				OK:              true,
				Target: &Target{
					ID:     "target-001",
					Name:   "dev-sandbox",
					Status: "running",
					Runtime: RuntimeTarget{
						Driver:         RuntimeDriverRootlessPodman,
						RuntimeID:      "runtime-001",
						WorkerID:       "worker-001",
						IsolationLevel: IsolationLevelContainer,
					},
				},
			},
		},
		{
			name: "status",
			value: Status{
				ProtocolVersion:         ProtocolVersion,
				WorkerID:                "worker-001",
				HostKind:                HostKindLocal,
				SupportedRuntimeDrivers: []string{RuntimeDriverRootlessPodman},
				Health:                  WorkerHealth{Status: HealthStatusHealthy},
				Capacity:                WorkerCapacity{MaxConcurrentSandboxes: 1},
				Security:                honestSecurityPolicy(),
			},
		},
		{
			name: "capabilities",
			value: Capabilities{
				ProtocolVersion: ProtocolVersion,
				WorkerID:        "worker-001",
				RuntimeDrivers: []RuntimeDriver{
					{
						ID:             RuntimeDriverRootlessPodman,
						HostKind:       HostKindLocal,
						IsolationLevel: IsolationLevelContainer,
						Security:       honestSecurityPolicy(),
					},
				},
				Security: honestSecurityPolicy(),
			},
		},
	}
	for _, payload := range payloads {
		t.Run(payload.name, func(t *testing.T) {
			data, err := json.Marshal(payload.value)
			if err != nil {
				t.Fatalf("Marshal(%s) error: %v", payload.name, err)
			}
			assertWorkerProtocolReadinessGateFieldsAbsent(t, string(data))
		})
	}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(Request{}),
		reflect.TypeOf(Response{}),
		reflect.TypeOf(Status{}),
		reflect.TypeOf(Capabilities{}),
		reflect.TypeOf(RuntimeDriver{}),
		reflect.TypeOf(SecurityPolicy{}),
		reflect.TypeOf(SecurityControls{}),
		reflect.TypeOf(Target{}),
		reflect.TypeOf(RuntimeTarget{}),
		reflect.TypeOf(WorkerHealth{}),
		reflect.TypeOf(WorkerCapacity{}),
		reflect.TypeOf(CreateRequest{}),
		reflect.TypeOf(LifecycleRequest{}),
		reflect.TypeOf(InspectRequest{}),
	} {
		assertWorkerProtocolTypeOmitsReadinessGateFields(t, typ)
	}
}

func TestWorkerSecurityPolicyDistinguishesRequestedFromEnforcedControls(t *testing.T) {
	policy := honestSecurityPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("security Validate() unexpected error: %v", err)
	}

	if policy.Requested.NetworkPolicy != NetworkPolicyDenyByDefault {
		t.Fatalf("requested networkPolicy = %q, want %q", policy.Requested.NetworkPolicy, NetworkPolicyDenyByDefault)
	}
	if policy.Enforced.NetworkPolicy == NetworkPolicyDenyByDefault {
		t.Fatalf("enforced networkPolicy = %q, worker metadata must not claim deny-by-default enforcement", policy.Enforced.NetworkPolicy)
	}
	if policy.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("enforced networkPolicy = %q, want %q", policy.Enforced.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Enforced.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("enforced networkEnforcement = %q, want %q", policy.Enforced.NetworkEnforcement, NetworkEnforcementNone)
	}
	if containsString(policy.Enforced.CredentialModes, unsupportedCredentialModeProxy) || policy.Enforced.CredentialProxyMode {
		t.Fatalf("enforced credential controls overclaim credential proxy support: %#v", policy.Enforced)
	}
	if policy.Enforced.IsolationLevel == unsupportedIsolationLevelMicroVM {
		t.Fatalf("enforced isolationLevel = %q, worker metadata must not claim microVM isolation", policy.Enforced.IsolationLevel)
	}
}

func TestWorkerSecurityControlsCarryOptionalCredentialDeliveryMetadata(t *testing.T) {
	controlsType := reflect.TypeOf(SecurityControls{})
	assertFieldType(t, controlsType, "CredentialDelivery", reflect.TypeOf((*sandboxruntime.RuntimeCredentialDeliveryMetadata)(nil)))

	controls := SecurityControls{
		CredentialModes: []string{CredentialModeLegacyAuthSync},
		CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
			ID:             "credential-plan-01",
			PlanID:         "credential-plan-01",
			RequestedModes: []string{"legacy_auth_sync"},
			Status:         "planned",
		},
	}
	encoded, err := json.Marshal(controls)
	if err != nil {
		t.Fatalf("Marshal(SecurityControls) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"credentialModes":["legacy_auth_sync"]`,
		`"credentialDelivery":`,
		`"requestedModes":["legacy_auth_sync"]`,
		`"status":"planned"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("SecurityControls JSON %s missing %s", publicText, want)
		}
	}
	if strings.Contains(publicText, "activeModes") {
		t.Fatalf("plan-only credentialDelivery must not include activeModes: %s", publicText)
	}
}

func TestWorkerProtocolCredentialDeliveryMetadataOmitsRawActivationValues(t *testing.T) {
	rawValues := []string{
		"https://credential-proxy.internal.example/token=ghp_raw_secret",
		"/Users/alice/.config/hal/credential.json",
		"unix:///tmp/hal-credential.sock",
		"Authorization: Bearer raw-token",
		"HAL_TOKEN=raw-env-value",
		"sh -c 'printenv HAL_TOKEN'",
	}
	controls := SecurityControls{
		CredentialModes: []string{CredentialModeEnv},
		CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
			ID:             "credential-status-worker",
			RequestID:      rawValues[0],
			PlanID:         "credential-plan-worker",
			ActivationID:   rawValues[1],
			RequestedModes: []string{CredentialModeEnv, rawValues[2], CredentialModeSSHAgent},
			ActiveModes:    []string{CredentialModeEnv, rawValues[3]},
			Status:         " ACTIVE ",
			ReasonCode:     rawValues[4],
			WarningCount:   1,
		},
		IsolationLevel: IsolationLevelContainer,
	}
	policy := SecurityPolicy{
		Requested: controls,
		Enforced: SecurityControls{
			CredentialModes: []string{CredentialModeEnv},
			CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
				ID:             "credential-status-enforced",
				PlanID:         "credential-plan-worker",
				ActivationID:   "credential-activation-worker",
				RequestedModes: []string{CredentialModeEnv},
				ActiveModes:    []string{CredentialModeEnv, rawValues[5]},
				Status:         "active",
			},
			IsolationLevel: IsolationLevelContainer,
		},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("security policy Validate() unexpected error: %v", err)
	}

	payloads := []struct {
		name  string
		value any
	}{
		{
			name: "status",
			value: Status{
				ProtocolVersion:         ProtocolVersion,
				WorkerID:                "worker-001",
				HostKind:                HostKindLocal,
				SupportedRuntimeDrivers: []string{RuntimeDriverRootlessPodman},
				Health:                  WorkerHealth{Status: HealthStatusHealthy},
				Capacity:                WorkerCapacity{MaxConcurrentSandboxes: 1},
				Security:                policy,
			},
		},
		{
			name: "capabilities",
			value: Capabilities{
				ProtocolVersion: ProtocolVersion,
				WorkerID:        "worker-001",
				RuntimeDrivers: []RuntimeDriver{{
					ID:             RuntimeDriverRootlessPodman,
					HostKind:       HostKindLocal,
					IsolationLevel: IsolationLevelContainer,
					Security:       policy,
				}},
				Security: policy,
			},
		},
		{
			name: "create request security",
			value: Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "req-credential-delivery",
				Operation:       OperationCreate,
				DriverID:        RuntimeDriverRootlessPodman,
				Create: &CreateRequest{
					Name:     "dev-sandbox",
					Security: policy,
				},
			},
		},
	}
	for _, payload := range payloads {
		t.Run(payload.name, func(t *testing.T) {
			data, err := json.Marshal(payload.value)
			if err != nil {
				t.Fatalf("Marshal(%s) error: %v", payload.name, err)
			}
			publicText := string(data)
			for _, raw := range rawValues {
				if strings.Contains(publicText, raw) {
					t.Fatalf("%s leaked raw credential delivery value %q in %s", payload.name, raw, publicText)
				}
			}
			for _, want := range []string{
				`"credentialDelivery":`,
				`"id":"credential-status-enforced"`,
				`"activationId":"credential-activation-worker"`,
				`"requestedModes":["env"]`,
				`"activeModes":["env"]`,
				`"status":"active"`,
			} {
				if !strings.Contains(publicText, want) {
					t.Fatalf("%s JSON %s missing %s", payload.name, publicText, want)
				}
			}
			if strings.Contains(publicText, `"activeModes":["env","legacy_auth_sync"]`) {
				t.Fatalf("%s overreported compatibility mode as active delivery: %s", payload.name, publicText)
			}
		})
	}
}

func TestWorkerCredentialDeliveryActiveModesRequireSanitizedActivationStatus(t *testing.T) {
	controls := SecurityControls{
		CredentialModes: []string{CredentialModeEnv},
		CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
			ID:             "credential-status-worker",
			PlanID:         "credential-plan-worker",
			RequestedModes: []string{CredentialModeEnv},
			ActiveModes:    []string{CredentialModeEnv},
			Status:         "planned",
		},
	}
	encoded, err := json.Marshal(controls)
	if err != nil {
		t.Fatalf("Marshal(SecurityControls) error = %v", err)
	}
	if strings.Contains(string(encoded), "activeModes") {
		t.Fatalf("planned worker credentialDelivery must omit activeModes: %s", string(encoded))
	}

	controls.CredentialDelivery.Status = "active"
	controls.CredentialDelivery.ActivationID = "/tmp/raw-activation.sock"
	encoded, err = json.Marshal(controls)
	if err != nil {
		t.Fatalf("Marshal(SecurityControls) active error = %v", err)
	}
	if strings.Contains(string(encoded), "activeModes") {
		t.Fatalf("active worker credentialDelivery without safe activation ID must omit activeModes: %s", string(encoded))
	}

	controls.CredentialDelivery.ActivationID = "credential-activation-worker"
	encoded, err = json.Marshal(controls)
	if err != nil {
		t.Fatalf("Marshal(SecurityControls) safe active error = %v", err)
	}
	if !strings.Contains(string(encoded), `"activeModes":["env"]`) {
		t.Fatalf("active worker credentialDelivery with safe activation result missing activeModes: %s", string(encoded))
	}
}

func TestWorkerSecurityPolicyRejectsOverstatedCapabilityClaims(t *testing.T) {
	tests := []struct {
		name   string
		policy SecurityPolicy
		want   string
	}{
		{
			name: "deny by default enforced network",
			policy: SecurityPolicy{
				Requested: honestSecurityPolicy().Requested,
				Enforced: SecurityControls{
					NetworkPolicy:      NetworkPolicyDenyByDefault,
					NetworkEnforcement: NetworkEnforcementNone,
					IsolationLevel:     IsolationLevelContainer,
				},
			},
			want: "overstates worker enforcement",
		},
		{
			name: "firewall enforced network",
			policy: SecurityPolicy{
				Requested: honestSecurityPolicy().Requested,
				Enforced: SecurityControls{
					NetworkPolicy:      NetworkPolicyBestEffort,
					NetworkEnforcement: unsupportedNetworkEnforcementFirewall,
					IsolationLevel:     IsolationLevelContainer,
				},
			},
			want: "overstates worker enforcement",
		},
		{
			name: "proxy enforced network",
			policy: SecurityPolicy{
				Requested: honestSecurityPolicy().Requested,
				Enforced: SecurityControls{
					NetworkPolicy:      NetworkPolicyBestEffort,
					NetworkEnforcement: unsupportedNetworkEnforcementProxy,
					IsolationLevel:     IsolationLevelContainer,
				},
			},
			want: "overstates worker enforcement",
		},
		{
			name: "credential proxy mode",
			policy: SecurityPolicy{
				Requested: honestSecurityPolicy().Requested,
				Enforced: SecurityControls{
					NetworkPolicy:       NetworkPolicyBestEffort,
					NetworkEnforcement:  NetworkEnforcementNone,
					CredentialModes:     []string{unsupportedCredentialModeProxy},
					IsolationLevel:      IsolationLevelContainer,
					CredentialProxyMode: true,
				},
			},
			want: "credential",
		},
		{
			name: "microvm isolation",
			policy: SecurityPolicy{
				Requested: honestSecurityPolicy().Requested,
				Enforced: SecurityControls{
					NetworkPolicy:      NetworkPolicyBestEffort,
					NetworkEnforcement: NetworkEnforcementNone,
					IsolationLevel:     unsupportedIsolationLevelMicroVM,
				},
			},
			want: "isolationLevel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want overclaim error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestWorkerSecurityPolicyAllowsExplicitNetworkEnforcementCapability(t *testing.T) {
	policy := SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementProxyFirewall,
			IsolationLevel:     IsolationLevelVM,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementProxyFirewall,
			NetworkEnforcementCapability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{NetworkEnforcementProxyFirewall},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsDefaultDenyPosture: true,
			},
			IsolationLevel: IsolationLevelVM,
		},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	withoutCapability := policy
	withoutCapability.Enforced.NetworkEnforcementCapability = nil
	if err := withoutCapability.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want explicit capability required for proxy_firewall enforcement")
	}

	withoutEnforcingMode := policy
	withoutEnforcingMode.Enforced.NetworkEnforcement = NetworkEnforcementNone
	if err := withoutEnforcingMode.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want enforcing mode required for deny-by-default enforcement")
	}
}

func TestWorkerRuntimeDriverAllowsVMIsolationMetadata(t *testing.T) {
	driver := RuntimeDriver{
		ID:             RuntimeDriverMicroVM,
		HostKind:       HostKindLocal,
		IsolationLevel: IsolationLevelVM,
		Operations:     []string{OperationCreate},
		Security: SecurityPolicy{
			Requested: SecurityControls{
				NetworkPolicy:      NetworkPolicyBestEffort,
				NetworkEnforcement: NetworkEnforcementNone,
				IsolationLevel:     IsolationLevelVM,
			},
			Enforced: SecurityControls{
				NetworkPolicy:      NetworkPolicyBestEffort,
				NetworkEnforcement: NetworkEnforcementNone,
				IsolationLevel:     IsolationLevelVM,
			},
		},
	}
	if err := driver.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestWorkerRuntimeDriverRejectsMicroVMIsolationClaim(t *testing.T) {
	driver := RuntimeDriver{
		ID:             "microvm",
		HostKind:       HostKindLocal,
		IsolationLevel: unsupportedIsolationLevelMicroVM,
		Operations:     []string{OperationCreate},
		Security:       honestSecurityPolicy(),
	}
	err := driver.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want microVM isolation overclaim error")
	}
	if !strings.Contains(err.Error(), "isolationLevel") {
		t.Fatalf("Validate() error = %q, want isolationLevel error", err.Error())
	}
}

func honestSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementRuntime,
			CredentialModes: []string{
				CredentialModeSSHAgent,
			},
			IsolationLevel: IsolationLevelContainer,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			CredentialModes: []string{
				CredentialModeEnv,
				CredentialModeLegacyAuthSync,
			},
			IsolationLevel: IsolationLevelContainer,
		},
	}
}

func roundTripJSON(t *testing.T, input any, output any) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", input, err)
	}
	if err := json.Unmarshal(data, output); err != nil {
		t.Fatalf("Unmarshal(%T) error: %v", output, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertWorkerProtocolReadinessGateFieldsAbsent(t *testing.T, payload string) {
	t.Helper()
	for _, forbidden := range []string{
		"capabilityReadiness",
		"capabilityReadinessDiagnostics",
		"securityReadinessGate",
		"readinessGate",
		"wouldBlockStrictGate",
		"policyMode",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("worker protocol payload included readiness gate field %q: %s", forbidden, payload)
		}
	}
}

func assertWorkerProtocolTypeOmitsReadinessGateFields(t *testing.T, typ reflect.Type) {
	t.Helper()
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		for _, forbidden := range []string{
			"CapabilityReadiness",
			"ReadinessGate",
			"SecurityReadinessGate",
			"WouldBlockStrictGate",
			"capabilityReadiness",
			"readinessGate",
			"securityReadinessGate",
			"wouldBlockStrictGate",
		} {
			if strings.Contains(field.Name, forbidden) || strings.Contains(jsonName, forbidden) {
				t.Fatalf("%s.%s exposes readiness gate field %q", typ.Name(), field.Name, forbidden)
			}
		}
	}
}

func assertFieldType(t *testing.T, typ reflect.Type, fieldName string, want reflect.Type) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s.%s field missing", typ, fieldName)
	}
	if field.Type != want {
		t.Fatalf("%s.%s type = %v, want %v", typ, fieldName, field.Type, want)
	}
}
