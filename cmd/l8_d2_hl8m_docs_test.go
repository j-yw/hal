package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2HL8MControllerMonitorABIIsImplementationReady(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))

	for _, required := range []string{
		"### Normative HL8M controller-monitor ABI",
		"HL8MHeaderBytes = 68",
		"HL8MMaxBodyBytes = 73728",
		"HL8MMaxDatagramBytes = 73796",
		"HL8MMaxPacketsPerDirection = 4294967296",
		"CredentialCount:uint32 = 1",
		"HL8MRightKind:u8",
		"RightsCount:uint32 | Rights:[2]HL8MRightMetadata",
		"rejects `RightsCount > 2` before indexing",
		"2..2147483647",
		"no signed or narrower conversion",
		"PID1 bootstrap relay",
		"bootstrap side at FD 10 solely for the one ready send",
		"closes FDs 9 and 10",
		"| `0x01` | `monitor_ready`",
		"| `0x10` | `prepare_begin`",
		"| `0x11` | `prepare_file`",
		"| `0x12` | `prepare_commit`",
		"| `0x13` | `create_ssh_endpoint`",
		"| `0x14` | `revoke`",
		"| `0x20` | `response`",
		"| `0x21` | `monitor_event`",
		"| `0x7f` | `close_notify`",
		"exactly one inspected mount-namespace capability",
		"ordered monitor endpoint then",
		"direct monitor receive counter at",
		"one fixed 64-KiB locked",
		"The bodies are exact, in the displayed byte order",
		"prepare_begin: 18 + 1..16 encoded manifest records = 60..68258",
		"delegated helper codec rejects zero bindings before HL8M state",
		"create_ssh_endpoint: 8 + 2 + (2 + 1..128) + (2 + 1..128) + 32 + 32 = 80..334",
		"monitor_event: 4 + 8 + (2 + 22) + (2 + 1..128) + 32 = 71..198",
		"SSH response: 11 + 2 + (2 + 1..128) + (2 + 1..128) + 32 = 51..305",
		"0x01 monitor_ready:",
		"0x10 prepare_begin:",
		"0x11 prepare_file:",
		"0x12 prepare_commit:",
		"0x13 create_ssh_endpoint:",
		"0x14 revoke:",
		"0x20 response:",
		"0x21 monitor_event:",
		"0x7f close_notify:",
		"response disposition: 1 accepted",
		"monitor failure code: 0 none",
		"monitor event code: 1 expired",
		"monitor cleanup category: 1 not_applicable",
		"close reason: 1 normal",
		"hal/l8/controller-monitor/monitor-ready/v1",
		"hal/l8/controller-monitor/prepare-postinspection/v1",
		"hal/l8/controller-monitor/ssh-endpoint-config/v1",
		"hal/l8/controller-monitor/ssh-endpoint/v1",
		"hal/l8/controller-monitor/event-postinspection/v1",
		"hal/l8/controller-monitor/cleanup/v1",
		"Canonical monitor-ready vector",
		"ancillary right metadata[0]",
		"ancillary right metadata[1]",
		"one logical outstanding request",
		"one active job",
		"AuthenticatedSessionHardExpiryUnixNano:int64",
		"TrustedObservationUnixNano:int64",
		"cannot authorize an extension",
		"exactly one pending-event slot",
		"bilateral normal-close",
		"response loss is monitor loss",
		"prepare semantic failure",
		"stop_vm_required",
		"State and correlation matrix",
		"Response outcome and next-state matrix",
		"Local observation transition matrix",
		"`revoke_required`",
		"`stop_pending_event`",
		"no outstanding response",
		"sets the next state before sending",
		"returns to `ready_transferred`",
		"returns to `prepared`",
		"while `preparing` no new request, including revoke",
		"Failure and cleanup matrix",
		"PID1 never requests monitor cleanup",
		"only then does",
		"Formerly ambiguous HL8M choices are closed as follows",
		"D2 owns the pure HL8M codec",
		"D4 owns the PID1 bootstrap relay",
		"owns only the optional live Unix endpoint creation",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 architecture omits implementation-ready HL8M contract %q", required)
		}
	}
}

func TestL8D2HL8MSupplementsPreserveOwnershipBoundary(t *testing.T) {
	requiredByFile := map[string][]string{
		"sandbox-runtime-v2-l8-helper-syscall-policy.md": {
			"normative HL8M controller-monitor ABI",
			"PID1 bootstrap relay",
			"controller-owned locked",
			"monitor sends sequence-zero `monitor_ready` on FD 10",
			"requests HL8M cleanup",
			"one fixed 64-KiB locked receive slot",
			"`create_ssh_endpoint` accepted response carries exactly one",
		},
		"sandbox-runtime-v2-l8-guest-extension-seams.md": {
			"normative HL8M controller-monitor ABI",
			"CreateSSHAgentEndpoint",
			"one `create_ssh_endpoint`",
			"exactly one inspected listening `AF_UNIX` capability",
			"D5 cannot add an HL8M packet type",
		},
	}

	for file, required := range requiredByFile {
		doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", file))
		for _, marker := range required {
			if !strings.Contains(doc, marker) {
				t.Fatalf("L8 D2 supplement %q omits HL8M ownership contract %q", file, marker)
			}
		}
	}
}

func TestL8D2HL8MArchitectureRejectsOpenEndedWireChoices(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))

	for _, forbidden := range []string{
		"implementation-defined HL8M",
		"HL8M fields may be reordered",
		"HL8M may carry additional rights",
		"HL8M may infer success",
		"HL8M may use JSON",
		"PID1 forwards credential bytes",
		"endpointPostinspectionSHA256",
		"zero-binding helper encoding remains structurally decodable",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 architecture permits open-ended HL8M behavior %q", forbidden)
		}
	}
}
