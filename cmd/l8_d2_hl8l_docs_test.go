package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2HL8LControllerSupervisorABIIsImplementationReady(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	syscallDoc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))

	for _, required := range []string{
		"### Normative HL8L controller-supervisor ABI",
		"HL8LHeaderBytes = 68",
		"HL8LMaxBodyBytes = 8192",
		"HL8LMaxDatagramBytes = 8260",
		"CredentialCount:uint32 = 1",
		"`RightsCount > 8` is rejected before any array index",
		"PID from 2 through `math.MaxInt32`",
		"D2 retains all kernel PID/UID/GID metadata as `uint32`",
		"| `0x01` | `supervisor_ready`",
		"| `0x02` | `create_job`",
		"| `0x03` | `job_created`",
		"| `0x04` | `launch_shim`",
		"| `0x05` | `shim_started`",
		"| `0x06` | `terminate_job`",
		"| `0x07` | `destroy_job`",
		"| `0x08` | `supervisor_event`",
		"| `0x09` | `controller_attestation`",
		"| `0x0a` | `composition_accepted`",
		"| `0x7f` | `close_notify`",
		"monitor namespace, workdir, executable, child stdin-read, stdout-write, stderr-write, start-gate read, and sealed launch-block read",
		"job_created` transfers exactly one monitor endpoint right",
		"`HL8M monitor_ready` sequence-zero packet sends exactly two rights over monitor",
		"FD 10 to PID1 in this order",
		"PID1 relays those same two",
		"authorities in `job_created` in the same order",
		"right kind: 1 monitor_endpoint, 2 monitor_namespace, 3 workdir",
		"Rights:[8]HL8LRightMetadata",
		"`job_created/1` | `2 monitor_namespace` | `2 namespace_enter` | `mountGeneration` | `monitorReadySHA256`",
		"`launch_shim/7` | `9 launch_block_read` | `7 sealed_pipe_read` | `launchID` | `launchBlockSHA256`",
		"supervisorReadySHA256:[32]byte",
		"createJobSHA256:[32]byte",
		"monitorReadySHA256:[32]byte",
		"launchShimSHA256:[32]byte",
		"jobGeneration:token | monitorGeneration:token |",
		"mountGeneration:token | cgroupGeneration:token",
		"cgroupGeneration:token",
		"launchID:token",
		"exitCategory:u8 | exitCode:i32",
		"zeroPopulation:u8 |",
		"monitorState:u8 | cleanupCategory:u8",
		"supervisor reason: 1 requested",
		"1 exited, 2 signaled",
		"monitor state:    0 not_applicable, 1 starting, 2 ready",
		"3 cleanup_pending, 4 absent, 5 lost",
		"1 not_applicable, 2 cleanup_complete",
		"close reason: 1 normal",
		"hal/l8/controller-supervisor/supervisor-ready/v1",
		"hal/l8/controller-supervisor/create-job/v1",
		"hal/l8/controller-monitor/monitor-ready/v1",
		"hal/l8/controller-supervisor/launch-shim/v1",
		"hal/l8/process-composition/v1",
		"helper-limits-v1",
		"one active credential-aware execution",
		"ProcessRoleHelper",
		"one outstanding request",
		"completed-launch ledger",
		"This event correlation does not reuse the ID",
		"pending asynchronous-event slot",
		"accepted semantic rejection",
		"stop_vm_required",
		"response loss is supervisor loss",
		"A committed create failure is the final HL8L packet",
		"returns `stop_vm_required` after that result commits",
		"one shared cleanup-attempt counter",
		"1 + 4096 + 3 = 4100",
		"closed_clean",
		"post-accept packet",
		"D2 owns the pure codec",
		"D4 owns every live",
		"syscall, socketpair, credentials/rights receive",
		"Formerly ambiguous choices are closed as follows",
		"canonical fixed body and digest vector table",
		"long-lived controller peer at launch-only FD 9",
		"temporary bootstrap",
		"endpoint at launch-only FD 10",
		"PID1 fixed FD 10 remains the monitor pidfd",
		"PID1 never contacts the monitor",
		"supervisorReadySHA256 = f184ff36331fa69007751e7a567f03dd",
		"monitorConfigSHA256   = 8f77e47200fe4b9fc5f8cb48f2840a50",
		"cgroupConfigSHA256    = 4c0b5daf0102f695bfa60c63c5a99361",
		"createJobSHA256       = f4ff4d17dfe08c11946ddb35dbb7c7c5",
		"monitorReadySHA256    = fef4fb8972101ac91c792380e1f06cc3",
		"launchShimSHA256      = 8b2dedea6f00f15c8d1e404ee84efee4",
		"Canonical no-rights composition vector",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 architecture omits implementation-ready HL8L contract %q", required)
		}
	}

	for _, required := range []string{
		"monitor bootstrap traffic only monitor",
		"Launch-only long-lived controller peer",
		"Launch-only PID1 bootstrap endpoint",
		"controller-minted job/monitor/mount/cgroup generations",
		"`createJobSHA256`, and canonical `monitorReadySHA256`",
		"same ready digest",
	} {
		if !strings.Contains(syscallDoc, required) {
			t.Fatalf("L8 syscall policy omits coordinated HL8M-to-HL8L transfer contract %q", required)
		}
	}
}

func TestL8D2HL8LArchitectureRejectsOpenEndedWireChoices(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))

	for _, forbidden := range []string{
		"implementation-defined HL8L",
		"HL8L fields may be reordered",
		"HL8L may carry additional rights",
		"HL8L may infer success",
		"HL8L may use JSON",
		"l8-job-limits-v1",
		"monitorNamespaceSHA256",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 architecture permits open-ended HL8L behavior %q", forbidden)
		}
	}
}
