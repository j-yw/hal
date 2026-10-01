package credentialdelivery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialActivationProofSSHAgentSanitizesUnsafeMetadata(t *testing.T) {
	rawSocket := "/tmp/ssh-agent.sock"
	rawKey := "-----BEGIN OPENSSH PRIVATE KEY-----"
	rawCommand := "ssh-add -l returned ghp_phase51_secret"
	rawURL := "https://agent.example.invalid/socket?token=sk-phase51-secret"
	rawSecretValue := "PHASE51_SECRET_VALUE"
	proof := SanitizeSSHAgentProofMetadata(SSHAgentProof{
		BindingID:             "binding-ssh",
		SecretID:              "env:PHASE51_SSH_ONE",
		SecretBrokerSessionID: "secret-broker-session-ssh",
		DeliveryPlanID:        "delivery-plan-proof-ssh",
		DeliverySessionID:     "delivery-session-proof-ssh",
		DeliveryBindingID:     "delivery-binding-proof-ssh",
		HandoffID:             rawSocket,
		HandoffStatus:         StatusReady,
		HandoffReasonCode:     ReasonRequested,
		CapabilityID:          rawURL,
		CapabilityMode:        ModeSSHAgent,
		CapabilityStatus:      StatusReady,
		CapabilityReady:       true,
	})

	if proof.HandoffID != "" || proof.CapabilityID != "" {
		t.Fatalf("proof = %#v, want unsafe optional ssh_agent metadata dropped", proof)
	}
	if proof.BindingID != "binding-ssh" || proof.SecretID != "env:PHASE51_SSH_ONE" {
		t.Fatalf("proof = %#v, want safe binding and secret IDs preserved", proof)
	}
	assertActivationNoLeak(t, proof, rawSocket, rawKey, rawCommand, rawURL, rawSecretValue, "ghp_phase51_secret", "sk-phase51-secret")

	unsafe := SanitizeSSHAgentProofMetadata(SSHAgentProof{
		BindingID: "binding-ssh",
		SecretID:  "ghp_phase51_secret",
	})
	if unsafe != (SSHAgentProof{}) {
		t.Fatalf("unsafe proof = %#v, want zero proof when required secret metadata is unsafe", unsafe)
	}
}

func assertActivationNoLeak(t *testing.T, value any, rejectedValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	payloads := []string{string(data)}
	if text, ok := value.(string); ok {
		payloads = append(payloads, text)
	}
	for _, payload := range payloads {
		for _, forbidden := range []string{
			"https://",
			"example.invalid",
			"/Users/",
			"/tmp/",
			"/var/run/",
			"Authorization",
			"Bearer",
			"X-Api-Key",
			"GITHUB_TOKEN=",
			"ghp_",
			"credentialValue",
			"secretValue",
			"provider_credential",
			"providerCredential",
			"raw_secret",
			"\n",
			"\u001f",
		} {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("activation payload leaked unsafe value %q in %s", forbidden, payload)
			}
		}
		for _, rejected := range rejectedValues {
			if rejected == "" {
				continue
			}
			if strings.Contains(payload, rejected) {
				t.Fatalf("activation leaked rejected value %q in %s", rejected, payload)
			}
		}
	}
}
