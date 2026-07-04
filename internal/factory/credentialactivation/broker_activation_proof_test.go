package credentialactivation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	halfactory "github.com/jywlabs/hal/internal/factory"
)

func TestBrokerActivationProofRefsMatchSupportedModeProofMetadata(t *testing.T) {
	t.Run("http_proxy", func(t *testing.T) {
		request := phase51HTTPProxyActivationRequest()
		activation := credentialdelivery.ActivateDelivery(request, NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true}))

		assertBrokerActivationActiveProof(t, activation, credentialdelivery.ModeHTTPProxy, "binding-http-proxy-one", request.Plan.HTTPProxyProof.CredentialProxyBindingID)
		assertBrokerActivationNoLeak(t, activation)
	})

	t.Run("ssh_agent", func(t *testing.T) {
		request := phase51SSHAgentActivationRequest()
		activation := credentialdelivery.ActivateDelivery(request, NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true}))

		assertBrokerActivationActiveProof(t, activation, credentialdelivery.ModeSSHAgent, "binding-ssh-one", request.Plan.SSHAgentProof.HandoffID)
		assertBrokerActivationNoLeak(t, activation)
	})

	t.Run("file_tmpfs", func(t *testing.T) {
		request := phase51FileTmpfsActivationRequest()
		activation := credentialdelivery.ActivateDelivery(request, NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
			Enabled:               true,
			Broker:                phase58TmpfsBrokerSession(t, []string{halfactory.SecretBrokerDeliveryModeFileTmpfs}, []string{halfactory.SecretBrokerDeliveryModeFileTmpfs}),
			SecretBrokerSessionID: "broker-session-tmpfs",
		}))

		for _, binding := range request.Bindings {
			wantProofID := "broker-session-tmpfs-" + binding.ID + "-tmpfs-simulation-proof"
			assertBrokerActivationActiveProof(t, activation, credentialdelivery.ModeFileTmpfs, binding.ID, wantProofID)
		}
		assertBrokerActivationNoLeak(t, activation)
	})
}

func TestBrokerActivationMissingProofOrSessionDataFailsClosed(t *testing.T) {
	t.Run("http_proxy missing credential proxy session", func(t *testing.T) {
		request := phase51HTTPProxyActivationRequest()
		request.Plan.HTTPProxyProof.CredentialProxySessionID = ""

		activation := credentialdelivery.ActivateDelivery(request, NewHTTPProxyHandoffAdapter(HTTPProxyHandoffOptions{Enabled: true}))

		assertBrokerActivationNotActive(t, activation, credentialdelivery.ModeHTTPProxy, credentialdelivery.ReasonMissingActivationProof)
	})

	t.Run("ssh_agent missing handoff proof", func(t *testing.T) {
		request := phase51SSHAgentActivationRequest()
		request.Plan.SSHAgentProof.HandoffID = ""

		activation := credentialdelivery.ActivateDelivery(request, NewSSHAgentHandoffAdapter(SSHAgentHandoffOptions{Enabled: true}))

		assertBrokerActivationNotActive(t, activation, credentialdelivery.ModeSSHAgent, credentialdelivery.ReasonMissingActivationProof)
	})

	t.Run("file_tmpfs missing active broker delivery mode", func(t *testing.T) {
		request := phase51FileTmpfsActivationRequest()

		activation := credentialdelivery.ActivateDelivery(request, NewFileTmpfsSimulationAdapter(FileTmpfsSimulationOptions{
			Enabled:               true,
			Broker:                phase58TmpfsBrokerSession(t, []string{halfactory.SecretBrokerDeliveryModeFileTmpfs}, nil),
			SecretBrokerSessionID: "broker-session-tmpfs",
		}))

		assertBrokerActivationNotActive(t, activation, credentialdelivery.ModeFileTmpfs, credentialdelivery.ReasonMissingActivationProof)
	})
}

func TestCompatibilityModesDoNotSatisfySecureDefaultBrokerActivation(t *testing.T) {
	t.Run("env projects to compatibility-only status", func(t *testing.T) {
		broker := halfactory.NewInMemorySecretBroker()
		activation := credentialdelivery.ActivateDelivery(phase51EnvActivationRequest(), NewEnvAdapter(EnvOptions{
			Enabled:        true,
			Broker:         broker,
			Environment:    mapEnvLookup(phase51EnvFixture()),
			SecretBrokerID: "broker-session-env",
		}))
		status := credentialdelivery.StatusMetadataFromActivation(phase51EnvActivationRequest().Plan, activation)

		if status.Status == credentialdelivery.StatusActive || len(status.ActiveModes) != 0 {
			t.Fatalf("env status = %#v, want compatibility-only non-active secure-default projection", status)
		}
		assertBrokerActivationNoLeak(t, activation, status)
	})

	t.Run("legacy_auth_sync projects to compatibility-only status", func(t *testing.T) {
		plan := credentialdelivery.Plan{
			ID:             "delivery-plan-legacy-compat",
			RequestID:      "delivery-request-legacy-compat",
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeLegacyAuthSync},
			Status:         credentialdelivery.StatusPlanned,
		}
		activation := credentialdelivery.ActivateDelivery(credentialdelivery.ActivationRequest{
			Plan: plan,
			Bindings: []credentialdelivery.Binding{{
				ID:           "binding-legacy-compat",
				SecretRef:    "env:PHASE51_LEGACY_COMPAT",
				DeliveryMode: credentialdelivery.ModeLegacyAuthSync,
				Status:       credentialdelivery.StatusPlanned,
				ReasonCode:   credentialdelivery.ReasonRequested,
			}},
		}, brokerActivationFakeActiveAdapter{})
		status := credentialdelivery.StatusMetadataFromActivation(plan, activation)

		if activation.Status == credentialdelivery.StatusActive || len(activation.ActiveModes) != 0 {
			t.Fatalf("legacy activation = %#v, want compatibility-only non-active result", activation)
		}
		if status.Status == credentialdelivery.StatusActive || len(status.ActiveModes) != 0 {
			t.Fatalf("legacy status = %#v, want compatibility-only non-active secure-default projection", status)
		}
		assertBrokerActivationNoLeak(t, activation, status)
	})
}

type brokerActivationFakeActiveAdapter struct{}

func (brokerActivationFakeActiveAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	result := credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    request.Plan.RequestedModes,
		Status:         credentialdelivery.StatusActive,
		ReasonCode:     credentialdelivery.ReasonRequested,
	}
	for _, binding := range request.Bindings {
		result.Bindings = append(result.Bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
		})
	}
	return result, nil
}

func phase58TmpfsBrokerSession(t *testing.T, requestedModes, activeModes []string) *halfactory.InMemorySecretBroker {
	t.Helper()

	broker := halfactory.NewInMemorySecretBroker()
	if _, err := broker.CreateSession(halfactory.SecretBrokerSessionRequest{
		ID: "broker-session-tmpfs",
		ResolvedSecrets: []halfactory.ResolvedRunSecret{
			{Name: "PHASE51_TMPFS_ONE", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "ghp_phase51_secret"},
			{Name: "PHASE51_TMPFS_TWO", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "sk-phase51-secret"},
			{Name: "PHASE51_TMPFS_THREE", Source: halfactory.RunSecretSourceEnv, Required: true, Value: "PHASE51_SECRET_VALUE"},
		},
		RequestedDeliveryModes: requestedModes,
		ActiveDeliveryModes:    activeModes,
	}); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	return broker
}

func assertBrokerActivationActiveProof(t *testing.T, activation credentialdelivery.ActivationResult, mode credentialdelivery.Mode, bindingID string, proofID string) {
	t.Helper()

	if activation.Status != credentialdelivery.StatusActive {
		t.Fatalf("activation status = %q, want active: %#v", activation.Status, activation)
	}
	if !brokerActivationModesContain(activation.ActiveModes, mode) {
		t.Fatalf("active modes = %#v, want %q", activation.ActiveModes, mode)
	}
	foundProof := false
	for _, proof := range activation.ProofRefs {
		if proof.ProofID == proofID && proof.BindingID == bindingID && proof.DeliveryMode == mode {
			foundProof = true
			break
		}
	}
	if !foundProof {
		t.Fatalf("proof refs = %#v, want proof %q for binding %q mode %q", activation.ProofRefs, proofID, bindingID, mode)
	}
	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID && binding.DeliveryMode == mode {
			if binding.Status != credentialdelivery.StatusActive || binding.ReasonCode != credentialdelivery.ReasonRequested || binding.ProofRef != proofID {
				t.Fatalf("binding activation = %#v, want active requested proof %q", binding, proofID)
			}
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q", activation.Bindings, bindingID, mode)
}

func assertBrokerActivationNotActive(t *testing.T, activation credentialdelivery.ActivationResult, mode credentialdelivery.Mode, reason credentialdelivery.ReasonCode) {
	t.Helper()

	if activation.Status == credentialdelivery.StatusActive || brokerActivationModesContain(activation.ActiveModes, mode) || len(activation.ProofRefs) != 0 {
		t.Fatalf("activation = %#v, want no active/proof metadata for %q", activation, mode)
	}
	if reason != "" && activation.ReasonCode != reason {
		t.Fatalf("activation reason = %q, want %q in %#v", activation.ReasonCode, reason, activation)
	}
}

func brokerActivationModesContain(modes []credentialdelivery.Mode, mode credentialdelivery.Mode) bool {
	for _, candidate := range modes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func assertBrokerActivationNoLeak(t *testing.T, values ...any) {
	t.Helper()

	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload := string(data)
	for _, raw := range []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"phase51-agent.sock",
		"phase51-http-proxy.sock",
		"proxy.example.invalid",
		"Proxy-Authorization",
		"Authorization",
		"Bearer",
		"/tmp/",
		"/Users/",
		"OPENSSH PRIVATE KEY",
	} {
		if strings.Contains(payload, raw) {
			t.Fatalf("credential activation payload leaked raw value %q in %s", raw, payload)
		}
	}
}
