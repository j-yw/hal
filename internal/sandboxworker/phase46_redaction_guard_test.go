package sandboxworker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestPhase46WorkerMetadataRedactionGuards(t *testing.T) {
	fixture := phase46WorkerRedactionFixture()
	policy := SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementProxyFirewall,
			CredentialModes:    []string{CredentialModeEnv, CredentialModeSSHAgent},
			CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
				ID:             "worker-credential-request-phase46",
				RequestID:      fixture.rawEndpoint,
				PlanID:         "worker-credential-plan-phase46",
				ActivationID:   fixture.socketPath,
				RequestedModes: []string{CredentialModeEnv, CredentialModeSSHAgent, fixture.envValue, fixture.rawCredentialMetadata},
				ActiveModes:    []string{CredentialModeEnv, fixture.commandLine},
				Status:         " PLANNED ",
				ReasonCode:     fixture.headerValue,
				WarningCount:   1,
			},
			IsolationLevel: IsolationLevelContainer,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			CredentialModes:    []string{CredentialModeEnv, CredentialModeLegacyAuthSync},
			CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
				ID:             "worker-credential-active-phase46",
				PlanID:         "worker-credential-plan-phase46",
				ActivationID:   "worker-credential-activation-phase46",
				RequestedModes: []string{CredentialModeEnv, fixture.rawEndpoint},
				ActiveModes:    []string{CredentialModeEnv, CredentialModeLegacyAuthSync, fixture.secretValue, fixture.commandLine},
				Status:         " ACTIVE ",
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
				WorkerID:                "worker-phase46",
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
				WorkerID:        "worker-phase46",
				SupportedOperations: []string{
					OperationStatus,
					OperationCapabilities,
					OperationCreate,
				},
				RuntimeDrivers: []RuntimeDriver{{
					ID:                 RuntimeDriverRootlessPodman,
					HostKind:           HostKindLocal,
					IsolationLevel:     IsolationLevelContainer,
					Operations:         []string{OperationCreate, OperationInspect},
					Security:           policy,
					NetworkEnforcement: phase46WorkerNetworkMetadata(fixture),
				}},
				Security: policy,
			},
		},
		{
			name: "create request",
			value: Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "request-phase46",
				Operation:       OperationCreate,
				DriverID:        RuntimeDriverRootlessPodman,
				Create: &CreateRequest{
					Name:     "worker-phase46",
					Security: policy,
				},
			},
		},
	}

	for _, payload := range payloads {
		t.Run(payload.name, func(t *testing.T) {
			data, err := json.Marshal(payload.value)
			if err != nil {
				t.Fatalf("Marshal(%s) error = %v", payload.name, err)
			}
			publicText := string(data)
			fixture.assertAbsent(t, payload.name, publicText)
			for _, want := range []string{
				`"credentialDelivery":`,
				`"id":"worker-credential-active-phase46"`,
				`"activationId":"worker-credential-activation-phase46"`,
				`"requestedModes":["env"]`,
				`"activeModes":["env"]`,
				`"status":"active"`,
			} {
				if !strings.Contains(publicText, want) {
					t.Fatalf("%s JSON %s missing %s", payload.name, publicText, want)
				}
			}
			if strings.Contains(publicText, `"activeModes":["env","legacy_auth_sync"]`) {
				t.Fatalf("%s exposed compatibility auth sync as active credential delivery: %s", payload.name, publicText)
			}
		})
	}
}

type phase46WorkerFixture struct {
	secretValue           string
	envValue              string
	headerValue           string
	commandLine           string
	rawEndpoint           string
	socketPath            string
	localPath             string
	rawCredentialMetadata string
}

func phase46WorkerRedactionFixture() phase46WorkerFixture {
	return phase46WorkerFixture{
		secretValue:           "phase46-worker-secret-value",
		envValue:              "OPENAI_API_KEY=phase46-worker-env-value",
		headerValue:           "Authorization: Bearer phase46-worker-token",
		commandLine:           "git clone https://phase46-worker-token@example.invalid/repo.git",
		rawEndpoint:           "https://user:phase46-worker-secret@example.invalid/path?token=phase46-worker-token",
		socketPath:            "unix:///tmp/phase46-worker-credential.sock",
		localPath:             "/Users/alice/.config/hal/phase46-worker-secret.json",
		rawCredentialMetadata: `{"secretId":"env:OPENAI_API_KEY","credentialProxyBinding":"binding-secret"}`,
	}
}

func phase46WorkerNetworkMetadata(f phase46WorkerFixture) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               "worker-network-plan-phase46",
			Source:           " WORKER ",
			Operation:        f.commandLine,
			PolicySnapshotID: f.localPath,
			PolicyPreset:     " DENY_BY_DEFAULT ",
			DefaultPosture:   " DENY_BY_DEFAULT ",
			Mechanisms:       []string{" RUNTIME ", f.rawEndpoint},
			Operations:       []string{"default_deny", f.socketPath, f.headerValue},
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "worker-network-plan-phase46",
			AdapterID:       f.rawEndpoint,
			Outcome:         " FAILURE ",
			EnforcementMode: " PROXY_FIREWALL ",
			Mechanisms:      []string{" RUNTIME ", f.socketPath},
			Operations:      []string{"runtime_rule_apply", f.commandLine},
			PolicyPreset:    " DENY_BY_DEFAULT ",
			ReasonCode:      " ADAPTER_FAILED ",
		},
	}
}

func (f phase46WorkerFixture) forbiddenValues() []string {
	return []string{
		f.secretValue,
		f.envValue,
		f.headerValue,
		f.commandLine,
		f.rawEndpoint,
		f.socketPath,
		f.localPath,
		f.rawCredentialMetadata,
		"phase46-worker-env-value",
		"phase46-worker-token",
		"phase46-worker-token@example.invalid",
		"phase46-worker-secret",
		"example.invalid",
		"/Users/alice",
		"/tmp/phase46-worker-credential.sock",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"credentialProxyBinding",
	}
}

func (f phase46WorkerFixture) assertAbsent(t *testing.T, label string, payload string) {
	t.Helper()
	for _, forbidden := range f.forbiddenValues() {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked raw value %q in %s", label, forbidden, payload)
		}
	}
}
