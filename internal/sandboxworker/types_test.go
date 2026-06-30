package sandboxworker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
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
