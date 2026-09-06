package sandboxruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPhase46RuntimeMetadataRedactionGuards(t *testing.T) {
	fixture := phase46RuntimeRedactionFixture()
	metadata := RuntimeMetadata{
		Backend: "microvm",
		CredentialDelivery: &RuntimeCredentialDeliveryMetadata{
			ID:             " credential-status-phase46 ",
			RequestID:      fixture.rawEndpoint,
			PlanID:         "credential-plan-phase46",
			ActivationID:   fixture.localPath,
			RequestedModes: []string{" HTTP_PROXY ", "SSH_AGENT", fixture.socketPath, fixture.envValue, fixture.rawCredentialMetadata},
			ActiveModes:    []string{" HTTP_PROXY ", "ENV", fixture.headerValue, fixture.commandLine, "legacy_auth_sync"},
			Status:         " ACTIVE ",
			ReasonCode:     fixture.secretValue,
			WarningCount:   1,
			ErrorCount:     2,
		},
		NetworkEnforcement: &RuntimeNetworkEnforcementMetadata{
			Plan: &RuntimeNetworkEnforcementPlanMetadata{
				ID:               "network-plan-phase46",
				Source:           " MICROVM ",
				Operation:        fixture.commandLine,
				PolicySnapshotID: fixture.localPath,
				PolicyPreset:     " DENY_BY_DEFAULT ",
				DefaultPosture:   " DENY_BY_DEFAULT ",
				Mechanisms:       []string{" PROXY ", fixture.rawEndpoint},
				Operations:       []string{"default_deny", fixture.socketPath, fixture.headerValue},
			},
			Result: &RuntimeNetworkEnforcementResultMetadata{
				PlanID:          "network-plan-phase46",
				AdapterID:       fixture.rawEndpoint,
				Outcome:         " FAILURE ",
				EnforcementMode: " PROXY_FIREWALL ",
				Mechanisms:      []string{" PROXY ", "FIREWALL", fixture.socketPath},
				Operations:      []string{"proxy_route", fixture.commandLine},
				PolicyPreset:    " DENY_BY_DEFAULT ",
				Capability: &RuntimeNetworkEnforcementCapability{
					Supported:                  true,
					Modes:                      []string{" PROXY_FIREWALL ", fixture.rawCredentialMetadata},
					SupportsDefaultDenyPosture: true,
				},
				ReasonCode:   " ADAPTER_FAILED ",
				WarningCodes: []string{"sanitized_adapter_error", fixture.headerValue},
			},
		},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(data)
	fixture.assertAbsent(t, "runtime metadata", publicText)

	for _, want := range []string{
		`"credentialDelivery":`,
		`"id":"credential-status-phase46"`,
		`"planId":"credential-plan-phase46"`,
		`"requestedModes":["http_proxy","ssh_agent"]`,
		`"status":"skipped"`,
		`"networkEnforcement":`,
		`"source":"microvm"`,
		`"policyPreset":"deny_by_default"`,
		`"outcome":"failure"`,
		`"enforcementMode":"none"`,
		`"reasonCode":"adapter_failed"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("runtime metadata JSON %s missing %s", publicText, want)
		}
	}
	for _, forbidden := range []string{
		`"requestId"`,
		`"activationId"`,
		`"activeModes"`,
		`"capability"`,
	} {
		if strings.Contains(publicText, forbidden) {
			t.Fatalf("runtime metadata exposed unsafe credential/enforcement field %s in %s", forbidden, publicText)
		}
	}
}

type phase46RuntimeFixture struct {
	secretValue           string
	envValue              string
	headerValue           string
	commandLine           string
	rawEndpoint           string
	socketPath            string
	localPath             string
	rawCredentialMetadata string
}

func phase46RuntimeRedactionFixture() phase46RuntimeFixture {
	return phase46RuntimeFixture{
		secretValue:           "phase46-runtime-secret-value",
		envValue:              "OPENAI_API_KEY=phase46-runtime-env-value",
		headerValue:           "Authorization: Bearer phase46-runtime-token",
		commandLine:           "git clone https://phase46-runtime-token@example.invalid/repo.git",
		rawEndpoint:           "https://user:phase46-runtime-secret@example.invalid/path?token=phase46-runtime-token",
		socketPath:            "unix:///tmp/phase46-runtime-credential.sock",
		localPath:             "/Users/alice/.config/hal/phase46-runtime-secret.json",
		rawCredentialMetadata: `{"secretId":"env:OPENAI_API_KEY","credentialProxySession":"unix:///tmp/phase46-runtime-credential.sock"}`,
	}
}

func (f phase46RuntimeFixture) forbiddenValues() []string {
	return []string{
		f.secretValue,
		f.envValue,
		f.headerValue,
		f.commandLine,
		f.rawEndpoint,
		f.socketPath,
		f.localPath,
		f.rawCredentialMetadata,
		"phase46-runtime-env-value",
		"phase46-runtime-token",
		"phase46-runtime-token@example.invalid",
		"phase46-runtime-secret",
		"example.invalid",
		"/Users/alice",
		"/tmp/phase46-runtime-credential.sock",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"credentialProxySession",
	}
}

func (f phase46RuntimeFixture) assertAbsent(t *testing.T, label string, payload string) {
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
