package cmd

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
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
		"guest relay accepts exact UID/GID 1000",
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
		"Two safe reads of `Names`",
		"Registry does not",
		"invoke `CopyValue`",
		"denies JSON/text/binary marshaling",
		"No new public error identity is introduced",
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
		"It has no public listener",
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
				"pinned Linux 6.1.178 guest kernel",
				"umask(0177)",
				"sole D5 bind",
				"monitor-only `getsockname`",
				"SO_ACCEPTCONN",
				"SO_PEERCRED",
				"accepted `struct ucred`",
				"accepted peer identity only after `accept4`",
				"sets mode 0600 before changing the D5 socket to fixed UID/GID 1000",
				"ownership last",
				"AT_SYMLINK_NOFOLLOW",
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

func TestL8D2GuestHelperCoreContractClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		"### Core contract concrete closure",
		"type RelativePathCapability struct",
		"type CorePrepareRequest struct",
		"type CoreExecRequest struct",
		"type CoreRenewRequest struct",
		"type CoreRevokeRequest struct",
		"type CoreInspectRequest struct",
		"type CoreFileRequest struct",
		"type CoreCommitRequest struct",
		"type CorePreparedResult struct",
		"type CoreOutputRequest struct",
		"type CoreOutputResult struct",
		"type CoreExecResult struct",
		"type CoreCleanupResult struct",
		"type CoreInspection struct",
		"type ReceiveRequest struct",
		"type ReceivedPacket struct",
		"type SendPacket struct",
		"type PolicyRequest struct",
		"type PolicyDecision struct",
		"type PolicyDescriptor struct",
		"PolicyOperationPrepare",
		"PolicyRejectionIdentityMismatch",
		"NewRelativePathCapability",
		"NewManifestCapability",
		"NewExecPlanCapability",
		"NewCorePrepareRequest",
		"BeginExec(context.Context, CoreExecRequest, credentialmemory.BorrowedView)",
		"NewReceiveRequest",
		"NewReceivedBootstrapPacket",
		"NewReceivedBootstrapPacket(context.Context, ReceiveRequest",
		"NewReceivedExecStreamPacket",
		"ExpectedRights() uint32",
		"type ReceivedBodyCapability interface",
		"type ReceivedKernelCredential struct",
		"NewReceivedKernelCredential",
		"no public credential, body, or right accessor",
		"recvmsg` adapter as the datagram",
		"No private payload\nis copied to an ordinary heap allocation",
		"Configured D4 Transport",
		"one-shot atomic consumed latch",
		"all supplied live inputs remain\ncaller-owned in those pre-transfer cases",
		"Capability validation\nprecedence is context, then the applicable Exec-plan precondition, then body,\nthen right",
		"typed-nil context with\n`ErrContractTypedNil`",
		"leaves its `ReceiveRequest`, body, and\nright unconsumed and caller-owned",
		"preconditions, it atomically claims\nthe `ExecPlanCapability`",
		"caller-owned; it does not\ndestroy the winner-owned state",
		"Constructors\nnever return or wrap `ctx.Err()`",
		"after the latch consumes the write",
		"checks cancellation before\nand immediately after every such external callback",
		"A cleanup panic\nnever skips another owner and never escapes the transport constructor",
		"newSendPacket",
		"WriteCanonicalBody(context.Context, credentialmemory.CredentialSink)",
		"func NewPolicyRequest",
		"ExecBodyBytes() uint32",
		"PrivateBytes() uint32",
		"ContractErrorCode",
		"CoreCleanupCapability",
		"NewHelperPolicy",
		"Transport owns a right",
		"service owns the private credential/body/right fields thereafter",
		"typed-nil",
		"no public constructor",
		"No request or result contains a raw",
		"### Core value validation matrices",
		"Safe-ID narrowing is intentional",
		"`EncodedLength` and `SHA256` return zero after destruction",
		"claimed       bool",
		"synchronized destruction state",
		"`destroy` waits for any in-flight `CopyCanonicalTo` call",
		"`clear` plus `runtime.KeepAlive`",
		"CoreOutputResult matrix",
		"CoreExecResult matrix",
		"CoreCleanupResult matrix",
		"CoreInspection matrix",
		"issued once and never reassigned to another\nlifecycle or correlation. It is not consumed on every valid echo",
		"The prepared capability remains as non-authoritative cleanup\ncorrelation",
		"repeat Revoke and Inspect",
		"fixed lifecycle ledger",
		"lifecycle-correlation checks",
		"prepared capability remains bound to its issuing Prepare correlation",
		"another\nissuing Prepare correlation or activation",
		"SHA-256 of empty bytes",
		"1 through 64 for `signaled`",
		"`stop_vm_required` accepts exactly the other three boolean pairs",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits implementation-ready core contract %q", required)
		}
	}

	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"Pre-production transcript correction",
		"for each stdin record, including the final EOF, in offset order:",
		"uint32_be(stdinRecordCount)",
		"The record\ncount is appended after the last record",
		"one-pass",
		"O(1) hash state",
		"full-capacity wipe",
		"No D4 producer",
		"Two-pass replay",
		"retained leaf digests",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 D2 architecture omits stream-computable transcript closure %q", required)
		}
	}
}

func TestL8D2GuestHelperServiceIndependentReviewClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		"### Helper Service normative closure",
		"Host       ExtensionHost",
		"Runtime    ServiceRuntime",
		"type ServiceDisposition uint8",
		"ServiceClosed",
		"ServiceStopVMRequired",
		"type ServiceResult struct",
		"func (s *Service) Serve(context.Context) (ServiceResult, error)",
		"There is no public `Close` or `Wait` method",
		"type ServiceRuntime interface",
		"Bootstrap(context.Context) (ServiceBootstrap, error)",
		"BindAgent(context.Context, ServiceAgentBindingRequest, ReceivedCapability) error",
		"ObserveJob(context.Context, ServiceJobObservationRequest) (ServiceJobObservation, error)",
		"Loss() <-chan ServiceLoss",
		"BeginCleanup() (ServiceCleanupBudget, error)",
		"type ServiceCleanupBudget interface",
		"Limit() time.Duration",
		"DeadlineExceeded() bool",
		"func NewServiceBootstrap(",
		"func (b ServiceBootstrap) BootNonce() [32]byte",
		"func (r ServiceAgentBindingRequest) AgentIdentitySHA256() [32]byte",
		"func (r ServiceJobObservationRequest) Operation() ServiceOperation",
		"func NewServiceJobObservation(",
		"func (o ServiceJobObservation) Generations() CoreGenerations",
		"func NewServiceLoss(category ServiceLossCategory) (ServiceLoss, error)",
		"func (l ServiceLoss) Category() ServiceLossCategory",
		"func ValidateServiceDisposition(ServiceDisposition) error",
		"func ValidateServiceOperation(ServiceOperation) error",
		"func ValidateServiceLossCategory(ServiceLossCategory) error",
		"`ServiceResult` is minted",
		"has no public constructor",
		"The observation matrix is exact",
		"canonical nonempty generations",
		"hardExpiryUnixNano >= observedUnixNano",
		"equal the exact Bootstrap Boot and Helper generations",
		"The first prepare latches",
		"latched generations and that exact hard horizon",
		"observation time advances",
		"monotonically and never regresses",
		"cannot extend or replace the hard horizon",
		"revision == current revision + 1",
		"expiry > the prior expiry",
		"The loss-channel matrix is exact",
		"stable non-nil receive-only",
		"Exactly one valid nonzero `ServiceLoss`",
		"close-before-value",
		"More than one value",
		"owns exactly one loss watcher",
		"joins it before `Serve` returns",
		"BindAgent ownership is exact",
		"atomically transfers the sole bootstrap pidfd capability to Runtime",
		"Service retains that capability",
		"numeric PID accessor",
		"Ambiguous transfer is forbidden",
		"exactly 30 seconds",
		"does not promise forced in-process return",
		"CoreExecution event loop",
		"WriteStdin",
		"GrantOutput",
		"Next",
		"NewCoreExecutionOutputEvent",
		"NewCoreExecutionCompleteEvent",
		"owned full canonical `0x18`",
		"ownership transfers only after the non-nil context and non-nil, non-typed-nil",
		"body preconditions pass",
		`opaque16("hal/l8/guest-helper/core-capability/v1")`,
		"all six generation positions",
		"`active.`",
		"`binding.`",
		"`exec.`",
		"`cleanup.`",
		"one Service-lifetime private nonzero monotonic `uint32`",
		"prepare-cleanup capabilities use the partial generation tuple",
		"revoke-cleanup capabilities require all six generations",
		"event ID",
		"opaque extension values",
		"deep-clones the descriptor on construction",
		"fresh deep clone on every `Descriptor` accessor call",
		"preserve nil-versus-explicit-empty slice shape",
		"type ExtensionCleanupResult struct",
		"func NewExtensionCleanupResult(",
		"func (r ExtensionCleanupResult) ResourcesAbsent() bool",
		"func (r ExtensionCleanupResult) Category() ExtensionCleanupCategory",
		`opaque16("hal/l8/guest-helper/extension-exec-binding/v1")`,
		"fixed 4,096-entry non-exec",
		"last three slots are reserved for fresh Revoke",
		"fixed 4,096-entry exec ledger",
		"terminal overflow exception",
		"type HelperExecTransactionSeed struct",
		"`*credentialprotocol.HelperPrepareTransaction`",
		"AcceptObservedFileObservation",
		"Replays use a fresh prepare transaction",
		"decoded credentialprotocol.HelperExecBody, plan ExecPlanCapability",
		"private `credentialprotocol.HelperExecTransactionSeed`",
		"no public transaction",
		"seed accessor",
		"complete\npublic `ReceivedExec` value-method set is exactly `Revision`, `ExecBindingID`,\n`PrivateBindingLength`, `PrivateBindingSHA256`, `Plan`, `Format`, `GoString`,\n`MarshalBinary`, `MarshalJSON`, `MarshalText`, and `String`",
		"ownership transfers on",
		"constructor\nentry",
		"uses that exact context\nto clean post-transfer constructor failure",
		"never substitutes `context.Background()`",
		"three-pass cleanup",
		"repeatable absence pass",
		"one-time finalization pass",
		"only a `retry_required` Core Revoke result is followed by Core Inspect",
		"open manifest-selected extension sessions in order before `Core.BeginPrepare`",
		"complete Core file staging and Core Commit, then call extension `Prepare`",
		"call `CorePreparation.Rollback` before closing",
		"never Rollback after commit",
		"Close exactly once never substitutes for Revoke or absence proof",
		"Close correlation is exact",
		"caller cancellation latches drain",
		"`ServiceClosed` is legal after either",
		"committed bilateral `normal` or `shutdown`",
		"ContractTransition",
		"`cleanup_retry` is Revoke-only",
		"PrepareCommit, Renew, Exec, or Revoke",
		"CleanupIncomplete",
		"WriteCanonicalBody(context.Context, credentialmemory.CredentialSink) error",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits helper-Service review closure %q", required)
		}
	}
	for _, forbidden := range []string{
		"ReadOutput(context.Context, CoreOutputRequest, credentialmemory.CredentialSink)",
		"Wait(context.Context) (CoreExecResult, error)",
		"Wait is accepted",
		"Constructors always return the complete zero value with the exact\nerror and do not consume an input capability.",
	} {
		if strings.Contains(seam, forbidden) {
			t.Fatalf("L8 D2 extension seam retains superseded helper-Service contract %q", forbidden)
		}
	}

	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"helper-Service normative closure",
		"ServiceStopVMRequired",
		"CoreExecution event loop",
		"4,096-entry non-exec ledger",
		"three reserved Revoke slots",
		"outer wire attempt correlations",
		"one inner Core cleanup correlation",
		"never replaces or remints the retained cleanup capability",
		"peer-driven cleanup episode",
		"internally driven cleanup episode",
		"only the next fresh-ID Revoke",
		"exact duplicate outer Revoke remains replayable",
		"without starting absence work",
		"wait for that retry under the same cleanup budget",
		"third incomplete attempt",
		"after its frozen context/body preconditions",
		"the additional Exec-plan precondition when applicable, then owns on entry",
		"cancellation checks before and immediately after every\nexternal callback",
		"cannot skip another live owner's mandatory\ncleanup or escape the transport constructor",
		"three-pass cleanup",
		"repeatable absence pass",
		"one-time finalization pass",
		"only a retry-required Core Revoke is followed by Core Inspect",
		"stop-VM response correction",
		"Precommit Rollback before reverse extension Close",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 D2 architecture omits helper-Service review closure %q", required)
		}
	}

	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	for _, required := range []string{
		"helper-Service normative closure",
		"runtime-owned 30-second cleanup budget",
		"CoreExecution event/body ownership",
		"non-reassignable lifecycle correlation capabilities",
		"reserved Revoke ledger capacity",
		"opaque extension lifecycle",
		"response-disposition correction",
		"repeatable absence passes before\n  one-time finalization",
		"lifecycle correlation capabilities",
	} {
		if !strings.Contains(verification, required) {
			t.Fatalf("L8 verification omits helper-Service review closure %q", required)
		}
	}
	if strings.Contains(verification, "one-shot correlation capabilities") {
		t.Fatal("L8 verification retains stale one-shot prepared-capability wording")
	}
}

func TestL8D2GuestHelperTransportDigestClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		`opaque16("hal/l8/guest-helper/agent-identity/v1")`,
		`agentPID:u32 || agentUID:u32 || agentGID:u32`,
		`opaque16("hal/l8/guest-helper/renew-proof/v1")`,
		`opaque16(priorProofID)`,
		"There is no separate descriptor-length constructor argument",
		"the canonical body-owned",
		"`descriptorLength:u16`",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits transport digest closure %q", required)
		}
	}
}

func TestL8D2GuestHelperTransmitScratchClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		"safe-metadata transmit scratch correction",
		"deep immutable snapshot",
		"bounded transient ordinary-heap scratch",
		"full capacity immediately after",
		"payload bytes never use that scratch",
		"`WriteCanonicalBody` again for `EAGAIN`",
		"and SHA-256, advances sequence only after commit",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits transmit-scratch closure %q", required)
		}
	}

	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"Safe-metadata transmit scratch correction",
		"redaction-safe metadata body",
		"does not retain or re-encode a `SendPacket` on `EAGAIN`",
		"encoded transmit slot without an ordinary-heap payload copy",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 D2 architecture omits transmit-scratch closure %q", required)
		}
	}
}

func TestL8D2CredentialClientContractClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		"### Credential client concrete closure",
		"credentialclient -> v2control",
		"must not import `credentialclient`",
		"type ClientOptions struct",
		"Descriptor  ClientProcessDescriptor",
		"type ClientProcessDescriptor interface",
		"ContractVersion() uint8",
		"Role() uint8",
		"WriteCanonical(credentialmemory.CredentialSink) error",
		"`l8composition.ProcessDescriptor`",
		"func NewClient(ClientOptions) (*Client, error)",
		"func (c *Client) Serve(context.Context) error",
		"func (c *Client) Close(context.Context) error",
		"exactly one successful call to `Serve`",
		"type ControllerReceiveRequest struct",
		"type ControllerPacket struct",
		"type ControllerSendPacket struct",
		"type HelperReceiveRequest struct",
		"type HelperPacket struct",
		"type HelperSendPacket struct",
		"ControllerBodyCapability",
		"NewControllerReadinessPacket",
		"NewControllerPreparePacket",
		"NewControllerRenewPacket",
		"NewControllerRevokePacket",
		"NewControllerExecPacket",
		"NewControllerPrivatePacket",
		"NewControllerStreamPacket",
		"NewControllerCreditPacket",
		"constructors perform no Client-ledger validation",
		"Client dispatch validates outstanding operation",
		"fixed datagram slot and a bounded rights array of capacity one",
		"rejects and closes all received rights before indexing",
		"parses and authenticates the fixed header",
		"constructors rely on that inspected-cardinality Transport TCB check",
		"projectV2ManifestToHelperRecords",
		"credentialprotocol.ComputeHelperManifestSHA256",
		"encoded in `credentialprotocol.HelperPrepareBeginBody.Bindings`",
		"sent only in `credentialprotocol.HelperPrepareCommitBody.ManifestSHA256`",
		"full immutable v2 manifest",
		"does not hash v2 JSON",
		"before any helper send",
		"*controllerSendPacketState",
		"type controllerSendPacketOwner struct",
		"*helperSendPacketState",
		"type helperSendPacketOwner struct",
		"deep-snapshots every safe graph",
		"Transport calls `WriteCanonicalBody` exactly once",
		"retained filled slot",
		"never by re-encoding",
		"BodySHA256 remains pinned",
		"safe typed arm accessors return zero/false after consumption",
		"30-second internal cleanup deadline",
		"v2control.FailureResponse",
		"credentialprotocol.HelperPrepareBeginBody",
		"credentialprotocol.HelperResponseBody",
		"one-slot",
		"### Credential client request/result correlation matrix",
		"### Credential client policy closure",
		"func NewClientPolicy() Policy",
		"type PolicyDescriptor struct",
		"operation v2control.Operation",
		"rejectionCode v2control.ErrorCode",
		"v2control.OperationReadiness",
		"v2control.ErrorCodeExecFailed",
		"v2control.ValidateOperationErrorCode",
		"type SSHConnectionCapability interface",
		"Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error)",
		"Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error)",
		"SSHAccepted() (SSHAcceptedPacket, bool)",
		"Transport is the sole trusted issuer",
		"Connection methods return `ClientContractOwnership` while Client-owned",
		"### Credential client validation and ownership matrices",
		"ClientContractErrorCode",
		"ClientContractSerialization",
		"ClientContractServeState",
		"full-capacity wipe",
		"MarshalBinary",
		"UnmarshalBinary",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits implementation-ready credential client contract %q", required)
		}
	}

	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	for _, required := range []string{
		"credential-client concrete closure",
		"one-way read-only `credentialclient -> v2control`",
		"single-Serve lifecycle",
		"SSH connection-capability ownership",
		"constructor/dispatch authority split",
		"one-shot send ownership",
		"retained-slot `EAGAIN` retry",
		"fixed 30-second internal cleanup deadline",
		"full-v2-to-helper manifest projection",
		"ordered proof mapping",
	} {
		if !strings.Contains(verification, required) {
			t.Fatalf("L8 verification omits credential-client closure guard %q", required)
		}
	}

	v2controlFiles, err := filepath.Glob(filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "v2control", "*.go"))
	if err != nil || len(v2controlFiles) == 0 {
		t.Fatalf("locate v2control sources: files=%d err=%v", len(v2controlFiles), err)
	}
	const forbiddenReverseImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
	for _, file := range v2controlFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse v2control source %q: %v", file, err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote v2control import in %q: %v", file, err)
			}
			if path == forbiddenReverseImport {
				t.Fatalf("v2control source %q imports credentialclient and would reverse the one-way authority edge", file)
			}
		}
	}
}

func TestL8D2CredentialClientIndependentReviewClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	for _, required := range []string{
		"D4 bootstrap owns `agent_hello`",
		"helper send sequence 1",
		"helper receive sequence 2",
		"first operational helper send sequence is 2",
		"first operational helper receive sequence is 3",
		"same immutable validated `l8composition.ProcessDescriptor` snapshot",
		"destroys the temporary mapping before returning",
		"Client never retains descriptor bytes and never sends agent hello",
		"type InspectedRequest struct",
		"InspectCredentialRequestRoot",
		"`OperationToken` owns only the validated private operation string",
		"no unvalidated or raw string echo",
		"DecodeInitialCredentialPrepareRequest(sessionID [32]byte, wire []byte)",
		"`CredentialPrepareRequest` exposes only `JobIdentity`",
		"NewGuestCredentialSessionIdentity(sessionID, request.Identity())",
		"verifies the reconstructed identity digest against the inspected root",
		"exactly one syntactically complete bounded JSON value",
		"schema or canonical concrete-decoder failure",
		"Malformed root or body syntax that prevents complete inspection",
		"root keys in exact canonical order `protocolVersion,operation,requestId,identityDigest,body`",
		"compact JSON with no insignificant whitespace",
		"exact colon and comma placement",
		"alternate scalar encodings",
		"token-skips exactly one syntactically complete bounded body value and then requires EOF",
		"safe unknown operation leaves body schema uninterpreted",
		"known operation's concrete decoder owns body schema and canonical re-encode failures",
		"wrong root order, whitespace, extra, missing, or duplicate root field",
		"ControllerUnknownOperation",
		"ControllerMalformedKnown",
		"static fail-closed formatting",
		"deny JSON, text, and binary marshaling on both value and pointer forms",
		"deny JSON, text, and binary marshal and unmarshal operations",
		"seeded receiver nonmutation",
		"value and pointer forms as applicable",
		"expose no mutator",
		"response is `unknown_operation`",
		"job identity is active",
		"activation is unsafe for response",
		"known initial prepare",
		"establish pre-active correlation",
		"unsafe or unreadable operation",
		"malformed known request receives only `malformed_request`",
		"does not promise an in-process forced return",
		"D6 process/VM kill and reap",
		"expectedRequestIDSet bool",
		"ExpectedRequestID() ([16]byte, bool)",
		"false in exactly two Client-owned phase cases",
		"drain/close handshake permits only `close_notify`",
		"close-notify header request ID is exactly zero",
		"ordinary response, stream, and credit packets require expected=true",
		"ReceiveRequest intentionally carries no phase enum",
		"type BodySegmentSink interface",
		"Capacity() uint32",
		"WriteSegment(offset uint32, source []byte) error",
		"exact contiguous, nonoverlapping coverage",
		"package-private offset `credentialmemory.CredentialSink` adapter",
		"no combined private scratch",
		"SSHIOResult constructor validates only intrinsic shape",
		"Read versus Write contract",
		"policy-subset allowlist before `v2control.ValidateOperationErrorCode`",
		"globally valid but policy-forbidden",
		"projectV2ExecPlanToHelper",
		"literal/inherited/generated to 1/2/3",
		"timeout/deadline to 1/2",
		"decodePrivateAggregateSHA256",
		"projectV2RevokeReasonToHelper",
		"requested/expired/session_loss/source_revoked/worker_cancel/daemon_shutdown to 1/2/3/4/5/6",
		"mapHelperPrepareSuccessToV2",
		"mapHelperRenewSuccessToV2",
		"mapHelperRevokeSuccessToV2",
		"mapHelperExecSuccessToV2",
		"no default mapping",
	} {
		if !strings.Contains(seam, required) {
			t.Fatalf("L8 D2 extension seam omits independent-review closure %q", required)
		}
	}
	for _, forbidden := range []string{
		"the one agent-hello send body",
		"descriptorBody   *credentialmemory.LockedMapping",
		"At the start of `Serve`",
		"ExpectedRequestID`, and",
	} {
		if strings.Contains(seam, forbidden) {
			t.Fatalf("L8 D2 extension seam retains superseded credential-client contract %q", forbidden)
		}
	}
	if count := strings.Count(seam, "WriteCanonicalBody(credentialmemory.CredentialSink) error"); count != 0 {
		t.Fatalf("L8 D2 extension seam retains %d context-free credential-sink WriteCanonicalBody signatures; want none", count)
	}

	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"two-stage, bodyless request-root inspection",
		"exact canonical root-key order",
		"compact scalar spellings and punctuation",
		"DecodeInitialCredentialPrepareRequest",
		"safe unknown operation receives `unknown_operation`",
		"malformed known operation receives `malformed_request`",
		"unsafe or unusably correlated root closes without a response",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 D2 architecture omits independent-review closure %q", required)
		}
	}

	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	for _, required := range []string{
		"D4-owned helper bootstrap before Client construction",
		"bodyless request-root inspection",
		"complete-root versus schema/canonical-decode boundary",
		"exact lexical root boundary",
		"initial identity reconstruction and root-digest recheck",
		"static formatting and JSON/text/binary denial",
		"marshal/unmarshal denial with seeded nonmutation",
		"conditional helper request-ID correlation",
		"segmented exact-coverage send sinks",
		"policy-subset error allowlist",
		"pure v2/helper conversion functions",
	} {
		if !strings.Contains(verification, required) {
			t.Fatalf("L8 verification omits independent-review closure %q", required)
		}
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

func TestL8D2GuestHelperSyscallPolicyMatchesPinnedGuestKernel(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-helper-syscall-policy.md"))
	for _, forbidden := range []string{
		"fchmodat2",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D2 syscall policy requires primitive unavailable on the pinned guest kernel %q", forbidden)
		}
	}
}
