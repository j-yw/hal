package credentialdelivery

import "testing"

func TestSSHAgentCredentialActivationProofAllowsSafeHandoffMetadata(t *testing.T) {
	binding := sshAgentProofBindingFixture()
	plan := sshAgentProofPlanFixture(binding)

	got := ActivateDelivery(ActivationRequest{
		Plan:     plan,
		Bindings: []Binding{binding},
	}, &fakeActivationAdapter{})

	if got.Status != StatusActive {
		t.Fatalf("activation status = %q, want active with safe ssh_agent proof", got.Status)
	}
	assertPlanModes(t, got.ActiveModes, []Mode{ModeSSHAgent})
	assertActivationBindingStatus(t, got, binding.ID, ModeSSHAgent, StatusActive)
	if len(got.Warnings) != 0 {
		t.Fatalf("activation warnings = %#v, want none for safe ssh_agent proof", got.Warnings)
	}
	assertActivationNoLeak(t, got)
}

func TestSSHAgentCredentialActivationProofMissingFailsClosed(t *testing.T) {
	binding := sshAgentProofBindingFixture()
	plan := sshAgentProofPlanFixture(binding)
	plan.SSHAgentProof = nil

	got := ActivateDelivery(ActivationRequest{
		Plan:     plan,
		Bindings: []Binding{binding},
	}, &fakeActivationAdapter{})

	if got.Status != StatusSkipped {
		t.Fatalf("activation status = %q, want skipped without ssh_agent proof", got.Status)
	}
	assertPlanModes(t, got.ActiveModes, nil)
	assertActivationReason(t, got, ReasonMissingActivationProof)
	assertActivationWarning(t, got, WarningActivationSkipped, ReasonMissingActivationProof, ModeSSHAgent)
	assertActivationBindingStatus(t, got, binding.ID, ModeSSHAgent, StatusSkipped)
	assertActivationNoLeak(t, got)
}

func TestSSHAgentCredentialActivationProofUnsupportedCapabilityFailsClosed(t *testing.T) {
	binding := sshAgentProofBindingFixture()
	tests := []struct {
		name      string
		configure func(*SSHAgentProof)
	}{
		{
			name: "unsupported capability",
			configure: func(proof *SSHAgentProof) {
				proof.CapabilityReady = false
			},
		},
		{
			name: "wrong capability mode",
			configure: func(proof *SSHAgentProof) {
				proof.CapabilityMode = ModeFileTmpfs
			},
		},
		{
			name: "failed handoff status",
			configure: func(proof *SSHAgentProof) {
				proof.HandoffStatus = StatusFailed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := sshAgentProofPlanFixture(binding)
			tt.configure(plan.SSHAgentProof)

			got := ActivateDelivery(ActivationRequest{
				Plan:     plan,
				Bindings: []Binding{binding},
			}, &fakeActivationAdapter{})

			if got.Status != StatusSkipped {
				t.Fatalf("activation status = %q, want skipped for unsupported ssh_agent capability", got.Status)
			}
			assertPlanModes(t, got.ActiveModes, nil)
			assertActivationReason(t, got, ReasonUnsupportedCapability)
			assertActivationWarning(t, got, WarningActivationSkipped, ReasonUnsupportedCapability, ModeSSHAgent)
			assertActivationBindingStatus(t, got, binding.ID, ModeSSHAgent, StatusSkipped)
			assertActivationNoLeak(t, got)
		})
	}
}

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

func sshAgentProofBindingFixture() Binding {
	binding := planBindingFixture(ModeSSHAgent)
	binding.ID = "binding-ssh"
	binding.SecretRef = "env:PHASE51_SSH_ONE"
	binding.PolicySnapshotID = "policy-snapshot-ssh"
	return binding
}

func sshAgentProofPlanFixture(binding Binding) Plan {
	return Plan{
		ID:             "delivery-plan-ssh",
		RequestID:      "delivery-request-ssh",
		RequestedModes: []Mode{ModeSSHAgent},
		ActiveModes:    []Mode{ModeSSHAgent},
		SSHAgentProof: &SSHAgentProof{
			BindingID:             binding.ID,
			SecretID:              binding.SecretRef,
			SecretBrokerSessionID: "secret-broker-session-ssh",
			DeliveryPlanID:        "delivery-plan-proof-ssh",
			DeliverySessionID:     "delivery-session-proof-ssh",
			DeliveryBindingID:     "delivery-binding-proof-ssh",
			HandoffID:             "ssh-agent-handoff-01",
			HandoffStatus:         StatusReady,
			HandoffReasonCode:     ReasonRequested,
			CapabilityID:          "ssh-agent-capability-01",
			CapabilityMode:        ModeSSHAgent,
			CapabilityStatus:      StatusReady,
			CapabilityReady:       true,
		},
		Status: StatusPlanned,
	}
}
