package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

type phase26CredentialProxyUnsafeValueFixture struct {
	UnsafeIDs           []string
	UnsafeReferences    []string
	Hostnames           []string
	URLs                []string
	Ports               []string
	Headers             []string
	EnvironmentValues   []string
	SocketPaths         []string
	LocalPaths          []string
	Tokens              []string
	Credentials         []string
	NetworkDestinations []string
	SecretLookingValues []string
}

func phase26CredentialProxyUnsafeValues() phase26CredentialProxyUnsafeValueFixture {
	return phase26CredentialProxyUnsafeValueFixture{
		UnsafeIDs: []string{
			"phase26 unsafe id",
			"phase26/unsafe-id",
			"8443",
		},
		UnsafeReferences: []string{
			"phase26.unsafe.reference",
			"env:bad-secret-name",
			"secretValue=phase26-secret-value-123",
		},
		Hostnames: []string{
			"credential-proxy.internal.example",
			"metadata.google.internal",
		},
		URLs: []string{
			"https://credential-proxy.internal.example:8443/path?token=phase26-raw-token-123",
		},
		Ports: []string{
			":8443",
			"8443",
		},
		Headers: []string{
			"Authorization: Bearer phase26-raw-token-123",
			"Cookie: session=phase26-cookie-secret",
		},
		EnvironmentValues: []string{
			"OPENAI_API_KEY=phase26-env-secret-value",
			"AWS_SECRET_ACCESS_KEY=phase26-secret-value-123",
		},
		SocketPaths: []string{
			"unix:///tmp/phase26-credential-proxy.sock",
			"/tmp/phase26-credential-proxy.sock",
		},
		LocalPaths: []string{
			"/Users/v/.ssh/phase26_id_rsa",
			"/private/tmp/phase26-secret-file",
		},
		Tokens: []string{
			"phase26-raw-token-123",
			"ghp_phase26RawToken123",
		},
		Credentials: []string{
			"deploy:phase26-password@credential-proxy.internal.example",
			"credentialValue=phase26-raw-credential",
		},
		NetworkDestinations: []string{
			"credential-proxy.internal.example:8443",
			"10.0.0.5:5432",
		},
		SecretLookingValues: []string{
			"secretValue=phase26-secret-value-123",
			"password=phase26-password",
			"private_key=phase26-private-key",
		},
	}
}

func TestPhase26CredentialProxyUnsafeFixtureEnumeratesRequiredValueClasses(t *testing.T) {
	assertPhase26CredentialProxyFixtureEnumeratesUnsafeClasses(t, phase26CredentialProxyUnsafeValues())
}

func (f phase26CredentialProxyUnsafeValueFixture) ForbiddenValues() []string {
	var values []string
	values = append(values, f.UnsafeIDs...)
	values = append(values, f.UnsafeReferences...)
	values = append(values, f.Hostnames...)
	values = append(values, f.URLs...)
	values = append(values, f.Ports...)
	values = append(values, f.Headers...)
	values = append(values, f.EnvironmentValues...)
	values = append(values, f.SocketPaths...)
	values = append(values, f.LocalPaths...)
	values = append(values, f.Tokens...)
	values = append(values, f.Credentials...)
	values = append(values, f.NetworkDestinations...)
	values = append(values, f.SecretLookingValues...)
	return dedupePhase26CredentialProxyFixtureValues(values)
}

func (f phase26CredentialProxyUnsafeValueFixture) NetworkProxySession(source sandbox.SandboxNetworkPolicyDecisionSource, sessionID, policySnapshotID string) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " " + sessionID + " ",
		Source: sandbox.SandboxNetworkPolicyDecisionSource(" " + strings.ToUpper(string(source)) + " "),
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " " + policySnapshotID + " ",
			Version:   f.URLs[0],
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: f.LocalPaths[0],
		},
		EnforcementMode: f.NetworkDestinations[0],
	}
}

func (f phase26CredentialProxyUnsafeValueFixture) SecurityRequest(requestedSafeModes, activeSafeModes []string) sandbox.SecurityEvaluationRequest {
	requestedModes := append([]string(nil), requestedSafeModes...)
	activeModes := append([]string(nil), activeSafeModes...)
	unsafeValues := f.ForbiddenValues()
	requestedModes = append(requestedModes, unsafeValues...)
	activeModes = append(activeModes, unsafeValues...)
	return sandbox.SecurityEvaluationRequest{
		RequestedSecretModes:  requestedModes,
		ActiveSecretModes:     activeModes,
		CompatibilityAuthSync: true,
	}
}

func (f phase26CredentialProxyUnsafeValueFixture) Projection(source sandbox.SandboxCredentialProxySource) sandbox.SandboxCredentialProxyProjection {
	sourceValue := sandbox.SandboxCredentialProxySource(" " + strings.ToUpper(string(source)) + " ")
	return sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:                    " credential-plan-01 ",
			Source:                sourceValue,
			SecretBrokerSessionID: f.URLs[0],
			NetworkProxySessionID: " network-proxy-session-01 ",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   f.UnsafeReferences[0],
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: f.Headers[0],
			},
			Mode:   sandbox.SandboxCredentialProxyMode(" NETWORK_PROXY_REFERENCE "),
			Status: sandbox.SandboxCredentialProxyStatus(" PLANNED "),
		},
		Session: &sandbox.SandboxCredentialProxySessionMetadata{
			ID:                    " credential-session-01 ",
			PlanID:                " credential-plan-01 ",
			Source:                sourceValue,
			SecretBrokerSessionID: f.SecretLookingValues[0],
			NetworkProxySessionID: " network-proxy-session-01 ",
			Status:                sandbox.SandboxCredentialProxyStatus(" READY "),
			WarningCode:           sandbox.SandboxCredentialProxyWarningCode(" BINDING_OMITTED "),
			ReasonCode:            sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
		},
		Bindings: []sandbox.SandboxCredentialProxyBindingMetadata{
			{
				ID:              " credential-binding-01 ",
				PlanID:          " credential-plan-01 ",
				SessionID:       " credential-session-01 ",
				SecretID:        "env:GITHUB_TOKEN",
				DeliveryMode:    sandbox.SandboxCredentialProxyDeliveryMode(" HTTP_PROXY "),
				RequestCategory: sandbox.SandboxCredentialProxyRequestCategory(" NETWORK_AUTH "),
				Outcome:         sandbox.SandboxCredentialProxyBindingOutcome(" PLANNED "),
				Status:          sandbox.SandboxCredentialProxyStatus(" PLANNED "),
				ReasonCode:      sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
			},
			{
				ID:           "credential-binding-02",
				PlanID:       "credential-plan-01",
				SecretID:     f.UnsafeReferences[1],
				DeliveryMode: sandbox.SandboxCredentialProxyDeliveryModeEnv,
			},
			{
				ID:           f.UnsafeIDs[0],
				PlanID:       "credential-plan-01",
				SecretID:     "env:GITHUB_TOKEN",
				DeliveryMode: sandbox.SandboxCredentialProxyDeliveryModeEnv,
			},
		},
	}
}

func (f phase26CredentialProxyUnsafeValueFixture) TimelineSeed() (factory.RunSecretRedactor, map[string]any, []string) {
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{
		{Name: "PHASE26_TOKEN", Value: f.Tokens[0]},
		{Name: "PHASE26_ENV_VALUE", Value: "phase26-secret-value-123"},
	})
	plan := sandbox.SandboxCredentialProxyPlanMetadata{
		ID:                    "timeline-plan-01",
		Source:                sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: f.Tokens[0],
		NetworkProxySessionID: f.URLs[0],
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        "timeline-policy-01",
			RuleSetID: f.URLs[0],
		},
		Mode:   sandbox.SandboxCredentialProxyModeBrokeredNetworkReference,
		Status: sandbox.SandboxCredentialProxyStatusActive,
	}
	session := sandbox.SandboxCredentialProxySessionMetadata{
		ID:                    "timeline-session-01",
		PlanID:                "timeline-plan-01",
		Source:                sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: f.Headers[0],
		NetworkProxySessionID: f.SocketPaths[1],
		Status:                sandbox.SandboxCredentialProxyStatusActive,
	}
	bindings := []sandbox.SandboxCredentialProxyBindingMetadata{{
		ID:              "timeline-binding-01",
		PlanID:          "timeline-plan-01",
		SessionID:       "timeline-session-01",
		SecretID:        "env:GITHUB_TOKEN",
		DeliveryMode:    sandbox.SandboxCredentialProxyDeliveryModeSSHAgent,
		RequestCategory: sandbox.SandboxCredentialProxyRequestSecretDelivery,
		Outcome:         sandbox.SandboxCredentialProxyBindingOutcomeBound,
		Status:          sandbox.SandboxCredentialProxyStatusActive,
	}}
	metadata := map[string]any{
		"safeDetail":                  "kept",
		"credentialProxy":             map[string]any{"unsafeURL": f.URLs[0]},
		"credentialProxyMode":         true,
		"credentialProxyPlan":         plan,
		"credentialProxyDelivery":     "active " + f.Headers[0],
		"credentialDelivery":          "delivered " + f.EnvironmentValues[1],
		"proxyEnforcement":            sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		"networkEnforcement":          sandbox.SandboxNetworkPolicyDenyByDefault,
		"sshAgentForwarding":          true,
		"tmpfsWrites":                 true,
		"runtimeSupport":              "rootless_podman",
		"credentialProxyProjection":   sandbox.SandboxCredentialProxyProjection{Plan: &plan, Session: &session, Bindings: bindings},
		"credentialProxyUnsafePath":   f.LocalPaths[0],
		"credentialProxyUnsafeValues": f.ForbiddenValues(),
		"credential_proxy_delivery":   "active",
		"credential-delivery-status":  "complete",
		"nested":                      map[string]any{"credentialProxySession": &session, "credentialProxyBindings": bindings},
		"nestedCredentialProxyRecord": []sandbox.SandboxCredentialProxyBindingMetadata(bindings),
	}
	forbidden := append(f.ForbiddenValues(),
		"credentialProxyMode",
		"credentialProxyDelivery",
		"credentialDelivery",
		"credential_proxy_delivery",
		"credential-delivery-status",
		"proxyEnforcement",
		"networkEnforcement",
		"sshAgentForwarding",
		"tmpfsWrites",
		"runtimeSupport",
		"rootless_podman",
		string(sandbox.SandboxNetworkEnforcementModeProxyFirewall),
		string(sandbox.SandboxNetworkPolicyDenyByDefault),
		string(sandbox.SandboxCredentialProxyStatusActive),
		string(sandbox.SandboxCredentialProxyBindingOutcomeBound),
		string(sandbox.SandboxCredentialProxyDeliveryModeSSHAgent),
		string(sandbox.SandboxCredentialProxyDeliveryModeFileTmpfs),
	)
	return redactor, metadata, dedupePhase26CredentialProxyFixtureValues(forbidden)
}

func assertPhase26CredentialProxyFixtureEnumeratesUnsafeClasses(t *testing.T, fixture phase26CredentialProxyUnsafeValueFixture) {
	t.Helper()
	categories := map[string][]string{
		"unsafe ids":            fixture.UnsafeIDs,
		"unsafe references":     fixture.UnsafeReferences,
		"hostnames":             fixture.Hostnames,
		"urls":                  fixture.URLs,
		"ports":                 fixture.Ports,
		"headers":               fixture.Headers,
		"environment values":    fixture.EnvironmentValues,
		"socket paths":          fixture.SocketPaths,
		"local paths":           fixture.LocalPaths,
		"tokens":                fixture.Tokens,
		"credentials":           fixture.Credentials,
		"network destinations":  fixture.NetworkDestinations,
		"secret-looking values": fixture.SecretLookingValues,
	}
	for category, values := range categories {
		if len(values) == 0 {
			t.Fatalf("shared Phase 26 unsafe fixture does not enumerate %s", category)
		}
	}
}

func assertPhase26CredentialProxyUnsafeValuesAbsent(t *testing.T, label string, payload string, fixture phase26CredentialProxyUnsafeValueFixture) {
	t.Helper()
	for _, forbidden := range fixture.ForbiddenValues() {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked unsafe fixture value %q: %s", label, forbidden, payload)
		}
	}
}

func assertPhase26CredentialProxyValuesPresent(t *testing.T, label string, payload string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value == "" {
			continue
		}
		if !strings.Contains(payload, value) {
			t.Fatalf("%s omitted safe credential proxy value %q: %s", label, value, payload)
		}
	}
}

func assertPhase26CredentialProxyNoRedactionPlaceholders(t *testing.T, label string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	payload := string(data)
	for _, placeholder := range []string{"[REDACTED]", "<redacted>", "REDACTED", "redacted"} {
		if strings.Contains(payload, placeholder) {
			t.Fatalf("%s replaced unsafe optional references with redaction placeholder %q: %s", label, placeholder, payload)
		}
	}
}

func dedupePhase26CredentialProxyFixtureValues(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
