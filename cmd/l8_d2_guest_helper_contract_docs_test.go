package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2GuestHelperContractsAreNormative(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"GuestAgentV1Port = 1024",
		"GuestAgentV2ControlPort = 1025",
		"GuestAgentV2SSHRelayPort = 1026",
		`{"protocolVersion":"guest-agent-v2","operation":"readiness"}`,
		"A payload beginning with `HL8H`",
		"512-byte compatibility limit",
		"same-stream positional correlation",
		"no request ID exists in the frozen v1 envelope",
		"AES-256-GCM",
		"HKDF-SHA-256",
		`ASCII "HL8H"`,
		`ASCII "HL8F"`,
		"wire = header[52]",
		"2^32-1",
		"full GuestHello, ControllerAuth, both Finished frames",
		"guest-to-controller `Finished`",
		"controller-to-guest `Finished`",
		"application records begin at sequence 1",
		"HTTP-proxy mode requires the complete network tuple",
		"file-only and SSH-only modes require that tuple to be absent",
		"credentialsource.validAdmissionRequest",
		"TemplatePolicyID",
		"JobCredentialRuntimePreflight",
		"prefix `sha256-` followed by exactly 64",
		"GuestCredentialSessionIdentity",
		"CLONE_INTO_CGROUP",
		"CLONE_PIDFD",
		`magic[4] = "HL8P"`,
		"The fixed header is 100 bytes",
		"at most 72 KiB",
		"0x01 helper_ready",
		"prepare_begin",
		`magic[4]="HL8B"`,
		"`0x13 control_private`",
		"bootstrapSHA256 = SHA256",
		"manifestSHA256 = SHA256",
		"All packets in one prepare transaction carry the same nonzero request ID",
		"The `ExecPlan` body is encoded exactly",
		"targetPath:optional-relative-path",
		"SECBIT_NOROOT",
		"SSH_AGENTC_REQUEST_IDENTITIES",
		"SSH_AGENT_RSA_SHA2_512",
		"cleanup_complete",
		"retry_required",
		"stop_vm_required",
		"D2 owns immutable contracts",
		"D4 owns live helper",
		"D5 owns live SSH-agent",
		"D6 owns whole-VM stop",
		"MaxGuestCredentialSessionLifetime = 35 minutes",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D2 architecture omits normative contract %q", required)
		}
	}
}

func TestL8D2GuestHelperContractsRejectImpossibleV1Correlation(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, forbidden := range []string{
		"matching request ID and operation",
		"a v1 response echoes the v2 request ID",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D2 architecture retains impossible frozen-v1 contract %q", forbidden)
		}
	}
}
