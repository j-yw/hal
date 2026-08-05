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
		"type JobCredentialIdentitySeed struct",
		"CloneJobCredentialIdentitySeed",
		"credentialState,omitempty",
		"sandboxjob-credential-private-v1",
		"Abort(context.Context) (JobCredentialCleanupProof, error)",
		"There is deliberately no seed digest",
		"prefix `sha256-` followed by exactly 64",
		"GuestCredentialSessionIdentity",
		"CLONE_INTO_CGROUP",
		"CLONE_PIDFD",
		"PID1 launch supervisor",
		"hal-guest-workload-shim",
		"hal-guest-role-bootstrap",
		"single-threaded native role bootstrap",
		"before any Go runtime starts",
		"monitor exits the entire process",
		"mount monitor",
		"CAP_SYS_CHROOT",
		"CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD",
		"CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP",
		"CLONE_VFORK|CLONE_VM|CLONE_PIDFD|SIGCHLD",
		"syscall.ForkExec",
		"agent-bootstrap",
		"launch-bootstrap",
		"PID1 inheritable and ambient sets are exactly the same six bits",
		"SECBIT_NO_SETUID_FIXUP` is unset and locked off",
		"`Finished` is the first encrypted record and counts",
		"`SysProcAttr.Cloneflags=0`",
		"PID1 preopens the three fixed `AF_VSOCK` listeners",
		"controller proves agent liveness by pidfd polling only",
		"The agent never retains or autonomously replays",
		"root-owned mode-`0711`",
		"eight controller-supplied rights",
		"controller closes the published listener",
		"controller_attestation",
		"client_attestation",
		"composition_accepted",
		`magic[4] = "HL8A"`,
		"agent-supervisor",
		"descriptorLength:u16",
		`magic[4] = "HL8P"`,
		"The fixed header is 100 bytes",
		"at most 72 KiB",
		"0x01 helper_ready",
		"prepare_begin",
		`magic[4]="HL8B"`,
		"`0x13 control_private`",
		"`0x14 control_stream`",
		"`0x15 control_stream_credit`",
		`magic[4]="HL8S"`,
		`magic[4]="HL8C"`,
		"credential request is malformed",
		"`HTTP_PROXY`, `HTTPS_PROXY`",
		"bootstrapSHA256 = SHA256",
		"manifestSHA256 = SHA256",
		"All packets in one prepare transaction carry the same nonzero request ID",
		"The `ExecPlan` body is encoded exactly",
		"0x17 exec_private",
		"0x18 exec_stream",
		"0x19 exec_credit",
		"At most one unused credit exists per stream",
		"Credit records are transport flow control only",
		"stdinTranscriptSHA256",
		"execTransactionSHA256",
		"packets carry no rights",
		"comparison-only mode",
		"concurrently forwards stdin",
		"prepare accepted:",
		"wire-to-neutral cleanup mapping",
		"targetPath:optional-relative-path",
		"SECBIT_NOROOT",
		"SSH_AGENTC_REQUEST_IDENTITIES",
		"SSH_AGENT_RSA_SHA2_512",
		"cleanup_complete",
		"retry_required",
		"stop_vm_required",
		"D2 owns immutable contracts",
		"D4 owns live PID1/controller/monitor/shim/agent composition",
		"D5 owns live SSH-agent",
		"D6 owns whole-VM stop",
		"MaxGuestCredentialSessionLifetime = 35 minutes",
		"type RequestTarget struct",
		"RequestHeaderValues interface",
		"ApplicationRoutes applicationroute.Handler",
		"runtime-local reserved base unchanged",
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
		"backpressures only the corresponding pipe",
		"D2 intentionally does not choose a live composition mechanism",
		"fchdir(6)",
		"all five capability sets empty",
		"os/exec.Cmd.Path",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D2 architecture retains impossible frozen-v1 contract %q", forbidden)
		}
	}
}

func TestL8D2GuestHelperSupplementContractsAreNormative(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		required []string
	}{
		{
			name: "syscall policy",
			file: "sandbox-runtime-v2-l8-helper-syscall-policy.md",
			required: []string{
				"deny-by-default",
				"AUDIT_ARCH_X86_64",
				"Pinned Go 1.25.7 runtime envelope",
				"decoratemappings=0",
				"size=4194304",
				"launch-base",
				"launch-bootstrap",
				"steady controller never launches",
				"monitor uses exact `clone`",
				"shim uses exact `clone3`",
				"service launch uses exact `clone`",
				"`syscall.ForkExec`",
				"FD 8 is closed",
				"controller closes every published listener",
				"verified_proc_root_fd",
				".resolve = 0",
				"service-agent FDs 5, 6, and 7",
				"native shim enters the mount namespace before any Go runtime starts",
				"PID1 never signals a UID-1000 workload",
				"getresuid getresgid getgroups capget",
				"mode=0711",
				"native bootstrap commits role state, not a child role filter",
				"NS_GET_NSTYPE",
				"SECCOMP_RET_KILL_PROCESS",
				"observed - policy",
				"live PID1/controller/monitor/shim/agent role composition",
			},
		},
		{
			name: "extension seams",
			file: "sandbox-runtime-v2-l8-guest-extension-seams.md",
			required: []string{
				"type ExtensionDescriptor struct",
				"ValidateMatchingExtensionSets",
				"func NewExtensionRegistry",
				"NewHelperExtension",
				"NewClientExtension",
				"OpenVerifiedConnection",
				"ImageProfileL8ProductionCredentials",
				"D7 creates and locks",
				"No package uses `init`",
				"CompositionDescriptor",
				"ProcessDescriptor",
				"ValidateProcessDescriptors",
				`magic[4] = "HL8D"`,
				"The complete encoding is at most 1,898 bytes",
				"func NewHelper(HelperOptions)",
				"func NewClient(ClientOptions)",
				"BeginPrepare(context.Context, CorePrepareRequest)",
				"Descriptor() PolicyDescriptor",
				"helper-policy-v1",
				"client-policy-v1",
				"CreateSSHAgentEndpoint",
				"PublishSSHAcceptedConnection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", tt.file))
			for _, required := range tt.required {
				if !strings.Contains(doc, required) {
					t.Fatalf("L8 D2 supplement %q omits normative contract %q", tt.file, required)
				}
			}
		})
	}
}

func TestL8D2GuestHelperSyscallPolicyRejectsImplicitOSPidfdProbe(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, forbidden := range []string{
		"os/exec.Cmd.Path",
		"Go 1.25.7 `os/exec`",
		"The inheritable and ambient sets are empty.",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D2 syscall policy retains implicit os pidfd-probe path %q", forbidden)
		}
	}
}
