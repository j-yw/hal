package sandboxruntime

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeCredentialDeliveryProjectsActiveSecureProofSummaries(t *testing.T) {
	metadata := SanitizeRuntimeCredentialDeliveryMetadata(&RuntimeCredentialDeliveryMetadata{
		ID:             "runtime-credential-delivery-01",
		RequestID:      "runtime-credential-request-01",
		PlanID:         "runtime-credential-plan-01",
		ActivationID:   "runtime-credential-activation-01",
		RequestedModes: []string{"http_proxy", "ssh_agent", "file_tmpfs", "env", "legacy_auth_sync"},
		ActiveModes:    []string{"http_proxy", "ssh_agent", "file_tmpfs", "env", "legacy_auth_sync"},
		ActiveProofs: []RuntimeCredentialDeliveryProofSummary{
			{
				ProofID:      "http-proxy-proof-01",
				BindingID:    "binding-http-proxy-01",
				DeliveryMode: " HTTP_PROXY ",
				Status:       " ACTIVE ",
				Source:       " broker ",
			},
			{
				ProofID:      "ssh-agent-proof-01",
				BindingID:    "binding-ssh-agent-01",
				DeliveryMode: "SSH_AGENT",
				Status:       "active",
				Source:       "handoff",
			},
			{
				ProofID:      "file-tmpfs-proof-01",
				BindingID:    "binding-file-tmpfs-01",
				DeliveryMode: "file_tmpfs",
				Status:       "active",
				Source:       "simulation",
			},
			{
				ProofID:      "env-proof-01",
				BindingID:    "binding-env-01",
				DeliveryMode: "env",
				Status:       "active",
				Source:       "legacy",
			},
			{
				ProofID:      "legacy-proof-01",
				BindingID:    "binding-legacy-01",
				DeliveryMode: "legacy_auth_sync",
				Status:       "active",
				Source:       "legacy",
			},
		},
		Status: "ACTIVE",
	})
	if metadata == nil {
		t.Fatal("SanitizeRuntimeCredentialDeliveryMetadata() = nil, want sanitized metadata")
	}
	if got, want := runtimeCredentialDeliveryProofModes(metadata.ActiveProofs), []string{"http_proxy", "ssh_agent", "file_tmpfs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active proof modes = %#v, want %#v", got, want)
	}
	if got, want := metadata.ActiveModes, []string{"http_proxy", "ssh_agent", "file_tmpfs", "env"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active modes = %#v, want compatibility env retained but legacy omitted: %#v", got, want)
	}
	if metadata.Status != "active" {
		t.Fatalf("status = %q, want active", metadata.Status)
	}

	data, err := json.Marshal(RuntimeMetadata{CredentialDelivery: metadata})
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(data)
	for _, want := range []string{
		`"activeProofs":[`,
		`"proofId":"http-proxy-proof-01"`,
		`"bindingId":"binding-http-proxy-01"`,
		`"deliveryMode":"http_proxy"`,
		`"proofId":"ssh-agent-proof-01"`,
		`"deliveryMode":"ssh_agent"`,
		`"proofId":"file-tmpfs-proof-01"`,
		`"deliveryMode":"file_tmpfs"`,
		`"status":"active"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("runtime credential delivery JSON %s missing %s", publicText, want)
		}
	}
	for _, forbidden := range []string{
		`"proofId":"env-proof-01"`,
		`"proofId":"legacy-proof-01"`,
		`"deliveryMode":"legacy_auth_sync"`,
	} {
		if strings.Contains(publicText, forbidden) {
			t.Fatalf("runtime credential delivery JSON exposed compatibility proof %s in %s", forbidden, publicText)
		}
	}
}

func TestRuntimeCredentialDeliveryProofSummariesRejectUnsafeFields(t *testing.T) {
	metadata := SanitizeRuntimeCredentialDeliveryMetadata(&RuntimeCredentialDeliveryMetadata{
		ID:             "runtime-credential-delivery-unsafe",
		PlanID:         "runtime-credential-plan-unsafe",
		ActivationID:   "runtime-credential-activation-unsafe",
		RequestedModes: []string{"http_proxy", "ssh_agent", "file_tmpfs"},
		ActiveModes:    []string{"http_proxy", "ssh_agent", "file_tmpfs"},
		ActiveProofs: []RuntimeCredentialDeliveryProofSummary{
			{
				ProofID:      "https://proxy.example.invalid/session?token=ghp_secret",
				BindingID:    "binding-http-proxy-01",
				DeliveryMode: "http_proxy",
				Status:       "active",
				Source:       "broker",
			},
			{
				ProofID:      "ssh-agent-proof-01",
				BindingID:    "/tmp/phase58-agent.sock",
				DeliveryMode: "ssh_agent",
				Status:       "active",
				Source:       "handoff",
			},
			{
				ProofID:      "file-tmpfs-proof-01",
				BindingID:    "binding-file-tmpfs-01",
				DeliveryMode: "file_tmpfs",
				Status:       "active",
				Source:       "Authorization: Bearer raw-token",
			},
			{
				ProofID:      "file-tmpfs-proof-02",
				BindingID:    "binding-file-tmpfs-02",
				DeliveryMode: "file_tmpfs",
				Status:       "planned",
				Source:       "simulation",
			},
			{
				ProofID:      "http-proxy-proof-safe",
				BindingID:    "binding-http-proxy-safe",
				DeliveryMode: "http_proxy",
				Status:       "active",
				Source:       "broker",
			},
		},
		Status: "active",
	})
	if metadata == nil {
		t.Fatal("SanitizeRuntimeCredentialDeliveryMetadata() = nil, want sanitized metadata")
	}
	if got, want := runtimeCredentialDeliveryProofModes(metadata.ActiveProofs), []string{"http_proxy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active proof modes = %#v, want only safe http_proxy proof %#v", got, want)
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeCredentialDeliveryMetadata) error = %v", err)
	}
	publicText := string(data)
	for _, forbidden := range []string{
		"proxy.example.invalid",
		"ghp_secret",
		"/tmp/phase58-agent.sock",
		"Authorization",
		"Bearer",
		"file-tmpfs-proof-01",
		"file-tmpfs-proof-02",
		"ssh-agent-proof-01",
	} {
		if strings.Contains(publicText, forbidden) {
			t.Fatalf("runtime credential delivery proof leaked unsafe fragment %q in %s", forbidden, publicText)
		}
	}
	if !strings.Contains(publicText, `"proofId":"http-proxy-proof-safe"`) {
		t.Fatalf("runtime credential delivery JSON %s missing safe proof summary", publicText)
	}
}

func TestRuntimeCredentialDeliveryMetadataOnlyDoesNotProduceSecureDefaultProof(t *testing.T) {
	for _, tt := range []struct {
		name string
		mode string
	}{
		{name: "http proxy mode without proof", mode: "http_proxy"},
		{name: "ssh agent mode without proof", mode: "ssh_agent"},
		{name: "file tmpfs mode without proof", mode: "file_tmpfs"},
		{name: "env compatibility proof", mode: "env"},
		{name: "legacy compatibility proof", mode: "legacy_auth_sync"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			metadata := SanitizeRuntimeCredentialDeliveryMetadata(&RuntimeCredentialDeliveryMetadata{
				ID:             "runtime-credential-delivery-" + strings.ReplaceAll(tt.name, " ", "-"),
				PlanID:         "runtime-credential-plan-" + strings.ReplaceAll(tt.name, " ", "-"),
				ActivationID:   "runtime-credential-activation-" + strings.ReplaceAll(tt.name, " ", "-"),
				RequestedModes: []string{tt.mode},
				ActiveModes:    []string{tt.mode},
				ActiveProofs: []RuntimeCredentialDeliveryProofSummary{{
					ProofID:      "proof-" + strings.ReplaceAll(tt.name, " ", "-"),
					BindingID:    "binding-" + strings.ReplaceAll(tt.name, " ", "-"),
					DeliveryMode: tt.mode,
					Status:       "active",
					Source:       "broker",
				}},
				Status: "active",
			})
			if metadata == nil {
				t.Fatal("SanitizeRuntimeCredentialDeliveryMetadata() = nil, want sanitized metadata")
			}
			if tt.mode == "http_proxy" || tt.mode == "ssh_agent" || tt.mode == "file_tmpfs" {
				metadataWithoutProof := SanitizeRuntimeCredentialDeliveryMetadata(&RuntimeCredentialDeliveryMetadata{
					ID:             metadata.ID,
					PlanID:         metadata.PlanID,
					ActivationID:   metadata.ActivationID,
					RequestedModes: []string{tt.mode},
					ActiveModes:    []string{tt.mode},
					Status:         "active",
				})
				if len(metadataWithoutProof.ActiveProofs) != 0 {
					t.Fatalf("metadata-only %s active proofs = %#v, want none", tt.mode, metadataWithoutProof.ActiveProofs)
				}
				if got := runtimeCredentialDeliveryProofModes(metadata.ActiveProofs); !reflect.DeepEqual(got, []string{tt.mode}) {
					t.Fatalf("%s proof modes = %#v, want active secure proof", tt.mode, got)
				}
				return
			}
			if len(metadata.ActiveProofs) != 0 {
				t.Fatalf("%s compatibility active proofs = %#v, want none", tt.mode, metadata.ActiveProofs)
			}
		})
	}
}

func runtimeCredentialDeliveryProofModes(proofs []RuntimeCredentialDeliveryProofSummary) []string {
	out := make([]string, 0, len(proofs))
	for _, proof := range proofs {
		out = append(out, proof.DeliveryMode)
	}
	return out
}
