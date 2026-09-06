package sandboxworker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerSecurityProjectsRuntimeCredentialDeliveryProofSummaries(t *testing.T) {
	policy := SecurityPolicy{
		Requested: SecurityControls{
			CredentialModes: []string{CredentialModeEnv, CredentialModeSSHAgent, CredentialModeFileTmpfs, CredentialModeLegacyAuthSync},
			CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
				ID:             "worker-credential-request-58",
				PlanID:         "worker-credential-plan-58",
				RequestedModes: []string{"http_proxy", CredentialModeSSHAgent, CredentialModeFileTmpfs, CredentialModeEnv, CredentialModeLegacyAuthSync},
				Status:         "planned",
			},
		},
		Enforced: SecurityControls{
			CredentialModes: []string{CredentialModeEnv, CredentialModeSSHAgent, CredentialModeFileTmpfs, CredentialModeLegacyAuthSync},
			CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
				ID:             "worker-credential-active-58",
				PlanID:         "worker-credential-plan-58",
				ActivationID:   "worker-credential-activation-58",
				RequestedModes: []string{"http_proxy", CredentialModeSSHAgent, CredentialModeFileTmpfs, CredentialModeEnv, CredentialModeLegacyAuthSync},
				ActiveModes:    []string{"http_proxy", CredentialModeSSHAgent, CredentialModeFileTmpfs, CredentialModeEnv, CredentialModeLegacyAuthSync},
				ActiveProofs: []sandboxruntime.RuntimeCredentialDeliveryProofSummary{
					{ProofID: "http-proxy-proof-58", BindingID: "binding-http-proxy-58", DeliveryMode: "http_proxy", Status: "active", Source: "broker"},
					{ProofID: "ssh-agent-proof-58", BindingID: "binding-ssh-agent-58", DeliveryMode: CredentialModeSSHAgent, Status: "active", Source: "handoff"},
					{ProofID: "file-tmpfs-proof-58", BindingID: "binding-file-tmpfs-58", DeliveryMode: CredentialModeFileTmpfs, Status: "active", Source: "simulation"},
					{ProofID: "env-proof-58", BindingID: "binding-env-58", DeliveryMode: CredentialModeEnv, Status: "active", Source: "legacy"},
					{ProofID: "legacy-proof-58", BindingID: "binding-legacy-58", DeliveryMode: CredentialModeLegacyAuthSync, Status: "active", Source: "legacy"},
				},
				Status: "active",
			},
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
				WorkerID:                "worker-phase58",
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
				WorkerID:        "worker-phase58",
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
			name: "create request",
			value: Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "worker-phase58-request",
				Operation:       OperationCreate,
				DriverID:        RuntimeDriverRootlessPodman,
				Create: &CreateRequest{
					Name:     "worker-phase58",
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
			for _, want := range []string{
				`"activeProofs":[`,
				`"proofId":"http-proxy-proof-58"`,
				`"deliveryMode":"http_proxy"`,
				`"proofId":"ssh-agent-proof-58"`,
				`"deliveryMode":"ssh_agent"`,
				`"proofId":"file-tmpfs-proof-58"`,
				`"deliveryMode":"file_tmpfs"`,
			} {
				if !strings.Contains(publicText, want) {
					t.Fatalf("%s JSON %s missing %s", payload.name, publicText, want)
				}
			}
			for _, forbidden := range []string{
				`"proofId":"env-proof-58"`,
				`"proofId":"legacy-proof-58"`,
				`"deliveryMode":"legacy_auth_sync"`,
			} {
				if strings.Contains(publicText, forbidden) {
					t.Fatalf("%s JSON exposed compatibility proof %s in %s", payload.name, forbidden, publicText)
				}
			}
		})
	}
}

func TestWorkerCredentialDeliveryRejectsUnsafeProofSummaries(t *testing.T) {
	controls := SecurityControls{
		CredentialDelivery: &sandboxruntime.RuntimeCredentialDeliveryMetadata{
			ID:             "worker-credential-unsafe-58",
			PlanID:         "worker-credential-plan-58",
			ActivationID:   "worker-credential-activation-58",
			RequestedModes: []string{"http_proxy"},
			ActiveModes:    []string{"http_proxy"},
			ActiveProofs: []sandboxruntime.RuntimeCredentialDeliveryProofSummary{{
				ProofID:      "https://proxy.example.invalid/session?token=raw-token",
				BindingID:    "binding-http-proxy-58",
				DeliveryMode: "http_proxy",
				Status:       "active",
				Source:       "broker",
			}},
			Status: "active",
		},
	}
	if err := validateCredentialDeliveryMetadata(controls.CredentialDelivery); err == nil {
		t.Fatal("validateCredentialDeliveryMetadata() error = nil, want unsafe proof metadata rejected")
	}

	controls.CredentialDelivery.ActiveProofs = []sandboxruntime.RuntimeCredentialDeliveryProofSummary{{
		ProofID:      "http-proxy-proof-58",
		BindingID:    "binding-http-proxy-58",
		DeliveryMode: "http_proxy",
		Status:       "active",
		Source:       "broker",
	}}
	if err := validateCredentialDeliveryMetadata(controls.CredentialDelivery); err != nil {
		t.Fatalf("validateCredentialDeliveryMetadata() unexpected error for safe proof metadata: %v", err)
	}
}

func TestWorkerCredentialDeliveryCompatibilityMetadataDoesNotProduceSecureDefaultProof(t *testing.T) {
	metadata := sandboxruntime.SanitizeRuntimeCredentialDeliveryMetadata(&sandboxruntime.RuntimeCredentialDeliveryMetadata{
		ID:             "worker-credential-compat-58",
		PlanID:         "worker-credential-plan-compat-58",
		ActivationID:   "worker-credential-activation-compat-58",
		RequestedModes: []string{CredentialModeEnv, CredentialModeLegacyAuthSync},
		ActiveModes:    []string{CredentialModeEnv, CredentialModeLegacyAuthSync},
		ActiveProofs: []sandboxruntime.RuntimeCredentialDeliveryProofSummary{
			{ProofID: "env-proof-58", BindingID: "binding-env-58", DeliveryMode: CredentialModeEnv, Status: "active", Source: "legacy"},
			{ProofID: "legacy-proof-58", BindingID: "binding-legacy-58", DeliveryMode: CredentialModeLegacyAuthSync, Status: "active", Source: "legacy"},
		},
		Status: "active",
	})
	if metadata == nil {
		t.Fatal("SanitizeRuntimeCredentialDeliveryMetadata() = nil, want compatibility metadata")
	}
	if len(metadata.ActiveProofs) != 0 {
		t.Fatalf("compatibility active proofs = %#v, want none", metadata.ActiveProofs)
	}
	if got, want := metadata.ActiveModes, []string{CredentialModeEnv}; !reflect.DeepEqual(got, want) {
		t.Fatalf("compatibility active modes = %#v, want env retained and legacy omitted %#v", got, want)
	}
}
