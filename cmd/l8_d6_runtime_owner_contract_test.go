package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const l8D6RuntimeOwnerRecoveryAPIDocBlock = `const (
	MaxJobCredentialRuntimeAbsenceObservationAge = 5 * time.Minute
	JobCredentialRuntimeStopReapTimeout          = 30 * time.Second
	JobCredentialRuntimeRecoveryCloseTimeout     = 5 * time.Second
)

type JobCredentialRuntimeAbsenceProofInput struct {
	Seed               JobCredentialIdentitySeed
	AbsenceInspectedAt time.Time
}

type JobCredentialRuntimeAbsenceProof struct {
	token [41]byte
}

func NewJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProofInput) (JobCredentialRuntimeAbsenceProof, error)
func ValidateJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProof, JobCredentialIdentitySeed, time.Time) error

type JobCredentialRuntimeRecoveryCommitReceipt struct {
	CommitID string ` + "`json:\"-\" xml:\"-\"`" + `
	FinalizedRevision uint64 ` + "`json:\"-\" xml:\"-\"`" + `
}

func ValidateJobCredentialRuntimeRecoveryCommitReceipt(JobCredentialRuntimeRecoveryCommitReceipt) error
func (JobCredentialRuntimeRecoveryCommitReceipt) String() string
func (JobCredentialRuntimeRecoveryCommitReceipt) Format(fmt.State, rune)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalJSON() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalText() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalBinary() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) GobEncode() ([]byte, error)

type JobCredentialRuntimeRecoveryProvider interface {
	BindJobCredentialRuntimeRecovery(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimeRecoveryBinding, error)
}

type JobCredentialRuntimeRecoveryBinding interface {
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
	StopReapJobCredentialRuntime(context.Context) (JobCredentialRuntimeAbsenceProof, error)
	FinalizeJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeAbsenceProof) (JobCredentialRuntimeRecoveryCommitReceipt, error)
	CommitJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeRecoveryCommitReceipt) error
	Close(context.Context) error
}`

const l8D6RuntimeOwnerRecordDocBlock = `type firecrackerRuntimeOwnerRecordV1 struct {
	ContractVersion              string ` + "`json:\"contractVersion\"`" + `
	Revision                     uint64 ` + "`json:\"revision\"`" + `
	State                        string ` + "`json:\"state\"`" + `
	HostBootID                   string ` + "`json:\"hostBootId\"`" + `
	SeedCorrelationDigest        string ` + "`json:\"seedCorrelationDigest\"`" + `
	SupervisorGeneration         string ` + "`json:\"supervisorGeneration\"`" + `
	SupervisorPID                uint32 ` + "`json:\"supervisorPid\"`" + `
	SupervisorStartTime          uint64 ` + "`json:\"supervisorStartTime\"`" + `
	FirecrackerPID               uint32 ` + "`json:\"firecrackerPid\"`" + `
	FirecrackerStartTime         uint64 ` + "`json:\"firecrackerStartTime\"`" + `
	FinalizedCommitID            string ` + "`json:\"finalizedCommitId\"`" + `
	SandboxID                    string ` + "`json:\"sandboxId\"`" + `
	ExecutionID                  string ` + "`json:\"executionId\"`" + `
	WorkerID                     string ` + "`json:\"workerId\"`" + `
	HostID                       string ` + "`json:\"hostId\"`" + `
	RuntimeDriver                string ` + "`json:\"runtimeDriver\"`" + `
	RuntimeID                    string ` + "`json:\"runtimeId\"`" + `
	RuntimeGeneration            string ` + "`json:\"runtimeGeneration\"`" + `
	FirecrackerProcessGeneration string ` + "`json:\"firecrackerProcessGeneration\"`" + `
	VsockGeneration              string ` + "`json:\"vsockGeneration\"`" + `
	NetworkPlanID                string ` + "`json:\"networkPlanId\"`" + `
	PolicySnapshotID             string ` + "`json:\"policySnapshotId\"`" + `
	ProxySessionID               string ` + "`json:\"proxySessionId\"`" + `
	ProxyGenerationID            string ` + "`json:\"proxyGenerationId\"`" + `
	TopologyGenerationID         string ` + "`json:\"topologyGenerationId\"`" + `
	RuleGenerationID             string ` + "`json:\"ruleGenerationId\"`" + `
	ReconnectListenerIdentity    string ` + "`json:\"reconnectListenerIdentity\"`" + `
	ReconnectSecret              string ` + "`json:\"reconnectSecret\"`" + `
}`

const l8D6RuntimeOwnerWorkerReceiptDocBlock = `type storedJobCredentialRuntimeRecoveryReceiptV1 struct {
	ContractVersion string ` + "`json:\"contractVersion\"`" + `
	Seed storedJobCredentialIdentitySeedV1 ` + "`json:\"seed\"`" + `
	CommitID string ` + "`json:\"commitId\"`" + `
	FinalizedRevision uint64 ` + "`json:\"finalizedRevision\"`" + `
}`

const (
	l8D6RuntimeOwnerBootMismatchRule = "A host-boot mismatch never authorizes signaling a current PID."
	l8D6RuntimeOwnerPublicationRule  = "The revision-one `starting` record is durable before Firecracker publication or acknowledgement."
	l8D6RuntimeOwnerCompleteStopRule = "Complete-identity recovery always proceeds to `StopReapJobCredentialRuntime` after `RecoverJobCredentials`, including after a valid cleanup proof."
	l8D6RuntimeOwnerCloseRule        = "Close does not imply process or resource absence"
	l8D6RuntimeOwnerFinalizeRule     = "The worker validates the retained absence proof before calling `FinalizeJobCredentialRuntimeRecovery`."
	l8D6RuntimeOwnerCommitRule       = "A rename followed by directory-sync failure is commit-uncertain"
	l8D6RuntimeOwnerNoIssuerRule     = "the default-off R1 foundation contains no host production constructor call"
	l8D6RuntimeOwnerRootReceiptRule  = "receipt-type references are confined to the exact type declaration"
	l8D6RuntimeOwnerJSONTypeRule     = "`null` or a wrong JSON scalar type"
)

func TestL8D6RuntimeOwnerContractArchitectureIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	if err := validateL8D6RuntimeOwnerArchitecture(doc); err != nil {
		t.Fatal(err)
	}
}

func validateL8D6RuntimeOwnerArchitecture(doc string) error {
	for _, block := range []string{l8D6RuntimeOwnerRecoveryAPIDocBlock, l8D6RuntimeOwnerRecordDocBlock, l8D6RuntimeOwnerWorkerReceiptDocBlock} {
		if strings.Count(doc, "```go\n"+block+"\n```") != 1 {
			return fmt.Errorf("L8 D6 runtime-owner architecture must contain one exact canonical block:\n%s", block)
		}
	}
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, required := range []string{
		"## Restart-stable Firecracker runtime owner",
		"firecracker-runtime-owner-private-v1",
		"exactly 16 KiB",
		"mode `0700`",
		"mode `0600`",
		"before Firecracker publication",
		"same-UID `SO_PEERCRED`",
		"one-use reconnect secret",
		"exactly one live controller",
		"TERM -> KILL -> Wait/reap",
		"one shared 30-second budget",
		"private bootstrap pipe and start gate",
		"revision-one `starting` durability",
		"`AbortStart`",
		"`PR_SET_PDEATHSIG`",
		"`pidfd_open`",
		"`/proc/sys/kernel/random/boot_id`",
		"every `JobCredentialIdentitySeed` field",
		"externally reaped",
		"PID reuse",
		"`l7network.NewReconciler`",
		"`CleanupAfterVMQuiesced`",
		"private recovered `TerminatedVMBinding`",
		"owner record is retired only after",
		"Old-boot owner and L7 journals remain quarantined",
		"child-armed acknowledgement",
		"mandatory for both seed-only and complete-identity restart",
		l8D6RuntimeOwnerBootMismatchRule,
		l8D6RuntimeOwnerPublicationRule,
		l8D6RuntimeOwnerCompleteStopRule,
		l8D6RuntimeOwnerFinalizeRule,
		l8D6RuntimeOwnerCommitRule,
		l8D6RuntimeOwnerNoIssuerRule,
		l8D6RuntimeOwnerRootReceiptRule,
		l8D6RuntimeOwnerJSONTypeRule,
		"atomically replaces CredentialState with a private recovery receipt",
		"`CredentialRecoveryReceipt *storedJobCredentialRuntimeRecoveryReceiptV1`",
		"exactly one of CredentialState or CredentialRecoveryReceipt",
		"post-commit restart validates the same receipt and accepts the idempotent committed result",
		"firecracker-runtime-owner-receipt-hmac-v1",
		"stable private owner-root HMAC key",
		"`renameat2(RENAME_NOREPLACE)`",
		"strictly reopens and validates the winner",
		"commit-only/record-absent binding",
		"`CommitID` carries `json:\"-\" xml:\"-\"`",
		"String and every fmt verb return only `[job-credential-runtime-recovery-commit-receipt]`",
		"JSON, gob, text, and binary encoding fail closed; XML encoding omits the field",
		"only `internal/sandboxworker/job_store_v2.go` may copy `CommitID`",
		"`firecrackerhost.commitJobCredentialRuntimeRecovery`",
		"`storedJobCredentialRuntimeRecoveryReceiptV1FromRuntime`",
		"direct selector on the exact receipt-typed parameter object",
		"Reflection, unsafe conversion, receipt aliases, receiver methods, closures, and helper escape are forbidden",
		"A receipt-bearing allowlisted file also fails if it imports `reflect` or `unsafe`",
		"func (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error)",
		"The root validator and owner verifier land together; the private-store converter remains optional until worker receipt persistence lands",
		"The digest has no accessor",
		l8D6RuntimeOwnerCloseRule,
		"Non-Linux implementations fail closed",
		"Default and v1 constructors remain byte-for-byte inert",
	} {
		if !strings.Contains(normalized, required) {
			return fmt.Errorf("L8 D6 runtime-owner architecture omits %q", required)
		}
	}
	return nil
}

func TestL8D6RuntimeOwnerContractArchitectureMutationGuards(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	mutations := []struct {
		name          string
		before, after string
	}{
		{name: "missing host boot ID", before: "\tHostBootID                   string `json:\"hostBootId\"`\n", after: ""},
		{name: "missing seed correlation digest", before: "\tSeedCorrelationDigest        string `json:\"seedCorrelationDigest\"`\n", after: ""},
		{name: "missing finalized commit ID", before: "\tFinalizedCommitID            string `json:\"finalizedCommitId\"`\n", after: ""},
		{name: "ephemeral receipt key", before: "stable private owner-root HMAC key", after: "ephemeral per-runtime HMAC key"},
		{name: "overwriting key publication", before: "`renameat2(RENAME_NOREPLACE)`", after: "ordinary replacing rename"},
		{name: "missing commit-only replay", before: "commit-only/record-absent binding", after: "caller-provided commit result"},
		{name: "boot mismatch may signal", before: l8D6RuntimeOwnerBootMismatchRule, after: "A host-boot mismatch may authorize signaling a current PID."},
		{name: "publication precedes revision one", before: l8D6RuntimeOwnerPublicationRule, after: "Firecracker publication may precede revision-one durability."},
		{name: "complete recovery skips stop reap", before: l8D6RuntimeOwnerCompleteStopRule, after: "A valid recovery proof permits the runtime to remain live."},
		{name: "worker cannot finalize after proof validation", before: l8D6RuntimeOwnerFinalizeRule, after: "StopReap retires all recovery ownership before returning."},
		{name: "rename sync failure retries old record", before: l8D6RuntimeOwnerCommitRule, after: "A directory-sync failure always retains the old record."},
		{name: "close implies absence", before: l8D6RuntimeOwnerCloseRule, after: "Close implies process and resource absence"},
		{name: "premature proof issuer", before: l8D6RuntimeOwnerNoIssuerRule, after: "the default-off R1 foundation contains a caller-provided production constructor call"},
		{name: "root receipt helper escape", before: l8D6RuntimeOwnerRootReceiptRule, after: "receipt-type references may appear in arbitrary root helpers"},
		{name: "nullable owner fields", before: l8D6RuntimeOwnerJSONTypeRule, after: "`null` may represent a scalar zero value"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if strings.Count(doc, mutation.before) != 1 {
				t.Fatalf("mutation source count for %q = %d, want 1", mutation.before, strings.Count(doc, mutation.before))
			}
			mutated := strings.Replace(doc, mutation.before, mutation.after, 1)
			if err := validateL8D6RuntimeOwnerArchitecture(mutated); err == nil {
				t.Fatal("weakened runtime-owner architecture passed validation")
			}
		})
	}
}

func TestL8D6RuntimeOwnerContractVerificationIsFrozen(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d6-runtime-owner-contract-verification.md"))
	for _, required := range []string{
		"# L8 D6 Restart-Stable Runtime Owner Contract Verification",
		"R1 now adds the exact neutral recovery contracts plus default-off private",
		"TestL8D6RuntimeOwnerContractArchitectureIsExact",
		"TestL8D6RuntimeOwnerContractVerificationIsFrozen",
		"TestL8D6RuntimeOwnerContractDefaultsRemainInert",
		"go test -count=20 ./cmd -run '^TestL8D6RuntimeOwnerContract'",
		"go test -race -count=5 ./cmd -run '^TestL8D6RuntimeOwnerContract'",
		"go test -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"does not implement the supervisor",
		"does not open a listener, launch, signal,",
		"read-only `/proc` plus pidfd identity inspection",
		"does not wire worker, command, provider, scheduler, or default runtime paths",
		"bootstrap pipe/start-gate loss before revision-one publication",
		"No test requires KVM, root, Firecracker, a live guest, or a daemon.",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D6 runtime-owner verification omits %q", required)
		}
	}
}

func TestL8D6RuntimeOwnerContractProofConstructorHasNoPrematureProductionIssuer(t *testing.T) {
	const (
		declarationOwner = "../internal/sandboxruntime/job_credential_runtime_recovery.go"
		issuerOwner      = "../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go"
	)
	var total l8D6RuntimeOwnerProofConstructorUsage
	scan := func(root string) error {
		return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			usage, err := l8D6RuntimeOwnerProofConstructorReferences(path, payload, declarationOwner, issuerOwner)
			if err != nil {
				return err
			}
			total.declarations += usage.declarations
			total.references += usage.references
			total.directCalls += usage.directCalls
			if usage.forbidden {
				t.Fatalf("production proof constructor reference outside exact owners %s and %s: %s", declarationOwner, issuerOwner, filepath.ToSlash(path))
			}
			return nil
		})
	}
	if err := scan(".."); err != nil {
		t.Fatalf("scan production proof constructor calls: %v", err)
	}
	_, declarationErr := os.Stat(declarationOwner)
	_, issuerErr := os.Stat(issuerOwner)
	contractOnly := os.IsNotExist(declarationErr) && os.IsNotExist(issuerErr)
	if contractOnly {
		if total != (l8D6RuntimeOwnerProofConstructorUsage{}) {
			t.Fatalf("contract-only proof constructor usage = %#v, want zero", total)
		}
		return
	}
	if declarationErr != nil || issuerErr != nil || total.declarations != 1 || total.references != 0 || total.directCalls != 0 {
		t.Fatalf("production proof constructor usage = %#v, declaration error %v, issuer error %v; want the root declaration and no issuer before StopReap", total, declarationErr, issuerErr)
	}
}

func TestL8D6RuntimeOwnerContractProofConstructorGuardRejectsPrematureOrSecondIssuer(t *testing.T) {
	const (
		declarationOwner = "../internal/sandboxruntime/job_credential_runtime_recovery.go"
		issuerOwner      = "../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go"
	)
	declaration := []byte("package sandboxruntime\nfunc NewJobCredentialRuntimeAbsenceProof(input JobCredentialRuntimeAbsenceProofInput) (JobCredentialRuntimeAbsenceProof, error) { return JobCredentialRuntimeAbsenceProof{}, nil }\n")
	usage, err := l8D6RuntimeOwnerProofConstructorReferences(declarationOwner, declaration, declarationOwner, issuerOwner)
	if err != nil || usage != (l8D6RuntimeOwnerProofConstructorUsage{declarations: 1}) {
		t.Fatalf("declaration owner fixture = %#v, error %v", usage, err)
	}
	directCall := []byte("package firecrackerhost\nfunc mint() { sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{}) }\n")
	usage, err = l8D6RuntimeOwnerProofConstructorReferences(issuerOwner, directCall, declarationOwner, issuerOwner)
	if err != nil || usage.references != 1 || usage.directCalls != 1 || !usage.forbidden {
		t.Fatalf("premature direct owner call fixture = %#v, error %v", usage, err)
	}
	for name, fixture := range map[string][]byte{
		"second issuer":  []byte("package sandboxworker\nfunc mint() { sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{}) }\n"),
		"function alias": []byte("package firecrackerhost\nvar mint = sandboxruntime.NewJobCredentialRuntimeAbsenceProof\n"),
	} {
		t.Run(name, func(t *testing.T) {
			path := issuerOwner
			if name == "second issuer" {
				path = "../internal/sandboxworker/issuer.go"
			}
			usage, err := l8D6RuntimeOwnerProofConstructorReferences(path, fixture, declarationOwner, issuerOwner)
			if err != nil || usage.references != 1 || !usage.forbidden {
				t.Fatalf("forbidden fixture = %#v, error %v", usage, err)
			}
		})
	}
}

func TestL8D6RuntimeOwnerContractCommitReceiptHasOnePrivateStoreProjection(t *testing.T) {
	const (
		rootValidator = "../internal/sandboxruntime/job_credential_runtime_recovery.go"
		ownerVerifier = "../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go"
		privateStore  = "../internal/sandboxworker/job_store_v2.go"
	)
	expected := map[string]l8D6RuntimeOwnerCommitReceiptFunction{
		rootValidator: {name: "ValidateJobCredentialRuntimeRecoveryCommitReceipt", rootType: true, exactOneParameter: true},
		ownerVerifier: {name: "commitJobCredentialRuntimeRecovery", allowFinalizerResult: true},
		privateStore:  {name: "storedJobCredentialRuntimeRecoveryReceiptV1FromRuntime", storeConverter: true},
	}
	audits := make(map[string]l8D6RuntimeOwnerCommitReceiptAudit)
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		normalizedPath := filepath.ToSlash(path)
		audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(payload, expected[normalizedPath])
		if err != nil {
			return err
		}
		if len(audit.issues) != 0 {
			t.Fatalf("runtime recovery commit receipt access is not exact in %s: %s", normalizedPath, strings.Join(audit.issues, "; "))
		}
		if audit.present || audit.receiptReferences != 0 {
			audits[normalizedPath] = audit
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan runtime recovery commit receipt projections: %v", err)
	}
	if _, err := os.Stat(rootValidator); os.IsNotExist(err) {
		if len(audits) != 0 {
			t.Fatalf("contract-only commit receipt accesses = %#v, want zero", audits)
		}
	} else if err != nil || !audits[rootValidator].exact() || !audits[ownerVerifier].exact() {
		t.Fatalf("production commit receipt accesses = %#v, root API error %v; want exact root and owner functions", audits, err)
	} else if private, ok := audits[privateStore]; ok && !private.exact() {
		t.Fatalf("private-store commit receipt access = %#v, want absent or exact future converter", private)
	}

	validFixture := []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { commitID := receipt.CommitID; _ = commitID; return nil }\n")
	if audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(validFixture, expected[ownerVerifier]); err != nil || !audit.exact() || len(audit.issues) != 0 {
		t.Fatalf("valid owner fixture audit = %#v, error %v", audit, err)
	}
	allowedFinalizeFixture := []byte("package firecrackerhost\nimport (\"context\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\ntype l8RuntimeOwnerRecoveryBinding struct{}\nfunc (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error) { panic(\"fixture\") }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n")
	if audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(allowedFinalizeFixture, expected[ownerVerifier]); err != nil || !audit.exact() || len(audit.issues) != 0 {
		t.Fatalf("exact future finalizer fixture audit = %#v, error %v", audit, err)
	}
	rootReceiptType := "type JobCredentialRuntimeRecoveryCommitReceipt struct { CommitID string; FinalizedRevision uint64 }\n"
	rootValidatorFunction := "func ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"
	rootFixtures := map[string][]byte{
		"extra root helper":  []byte("package sandboxruntime\n" + rootReceiptType + rootValidatorFunction + "func retain(receipt JobCredentialRuntimeRecoveryCommitReceipt) { _ = receipt.FinalizedRevision }\n"),
		"root any retention": []byte("package sandboxruntime\n" + rootReceiptType + rootValidatorFunction + "var retained any\nfunc retain(receipt JobCredentialRuntimeRecoveryCommitReceipt) { retained = receipt }\n"),
		"extra root method":  []byte("package sandboxruntime\n" + rootReceiptType + rootValidatorFunction + "func (receipt JobCredentialRuntimeRecoveryCommitReceipt) Expose() any { return receipt }\n"),
	}
	for name, fixture := range rootFixtures {
		t.Run(name, func(t *testing.T) {
			audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(fixture, expected[rootValidator])
			if err != nil {
				t.Fatal(err)
			}
			if audit.exact() && len(audit.issues) == 0 {
				t.Fatalf("root-file receipt helper passed audit: %#v", audit)
			}
		})
	}
	fixtures := map[string][]byte{
		"function name spoof":      []byte("package firecrackerhost\ntype unrelated struct { CommitID string }\nfunc commitJobCredentialRuntimeRecovery(value unrelated) error { _ = value.CommitID; return nil }\n"),
		"unrelated field":          []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\ntype unrelated struct { CommitID string }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = unrelated{}.CommitID; return nil }\n"),
		"reflection field":         []byte("package firecrackerhost\nimport (\"reflect\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = reflect.ValueOf(receipt).Field(0).String(); return nil }\n"),
		"reflection field by name": []byte("package firecrackerhost\nimport (\"reflect\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = reflect.ValueOf(receipt).FieldByName(\"CommitID\").String(); return nil }\n"),
		"unsafe conversion":        []byte("package firecrackerhost\nimport (\"unsafe\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = unsafe.Pointer(&receipt); return nil }\n"),
		"receipt value alias":      []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { alias := receipt; _ = alias.CommitID; return nil }\n"),
		"receipt type alias":       []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\ntype receiptAlias = sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt\nfunc commitJobCredentialRuntimeRecovery(receipt receiptAlias) error { _ = receipt.CommitID; return nil }\n"),
		"same name wrong result":   []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) int { _ = receipt.CommitID; return 0 }\n"),
		"receiver method":          []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\ntype owner struct{}\nfunc (owner) commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"),
		"closure escape":           []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { leak := func() string { return receipt.CommitID }; _ = leak; return nil }\n"),
		"helper escape":            []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc leak(any) {}\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { leak(receipt); return nil }\n"),
		"validator package spoof":  []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\ntype leakValidator struct{}\nvar retained any\nfunc (leakValidator) ValidateJobCredentialRuntimeRecoveryCommitReceipt(value any) error { retained = value; return nil }\nvar leak leakValidator\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return leak.ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt) }\n"),
		"validator variable spoof": []byte("package firecrackerhost\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nvar retained any\nvar ValidateJobCredentialRuntimeRecoveryCommitReceipt = func(value any) error { retained = value; return nil }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt) }\n"),
		"finalizer wrong receiver": []byte("package firecrackerhost\nimport (\"context\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\ntype l8RuntimeOwnerRecoveryBinding struct{}\nfunc (l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error) { panic(\"fixture\") }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"),
		"finalizer wrong input":    []byte("package firecrackerhost\nimport (\"context\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\ntype l8RuntimeOwnerRecoveryBinding struct{}\nfunc (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error) { panic(\"fixture\") }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"),
		"finalizer wrong result":   []byte("package firecrackerhost\nimport (\"context\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\ntype l8RuntimeOwnerRecoveryBinding struct{}\nfunc (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (string, error) { panic(\"fixture\") }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"),
		"finalizer field read":     []byte("package firecrackerhost\nimport (\"context\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\ntype l8RuntimeOwnerRecoveryBinding struct{}\nfunc (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error) { receipt := sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{}; _ = receipt.CommitID; panic(\"fixture\") }\nfunc commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) error { _ = receipt.CommitID; return nil }\n"),
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(fixture, expected[ownerVerifier])
			if err != nil {
				t.Fatal(err)
			}
			if audit.exact() && len(audit.issues) == 0 {
				t.Fatalf("bypass fixture passed audit: %#v", audit)
			}
		})
	}
	t.Run("finalizer wrong file", func(t *testing.T) {
		audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(allowedFinalizeFixture, l8D6RuntimeOwnerCommitReceiptFunction{})
		if err != nil {
			t.Fatal(err)
		}
		if len(audit.issues) == 0 {
			t.Fatalf("future finalizer passed outside owner file: %#v", audit)
		}
	})
	outsideFixtures := map[string][]byte{
		"outside reflection field":         []byte("package sandboxworker\nimport (\"reflect\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc leak(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) string { return reflect.ValueOf(receipt).Field(0).String() }\n"),
		"outside reflection field by name": []byte("package sandboxworker\nimport (\"reflect\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc leak(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) string { return reflect.ValueOf(receipt).FieldByName(\"CommitID\").String() }\n"),
		"outside unsafe":                   []byte("package sandboxworker\nimport (\"unsafe\"; sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\")\nfunc leak(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) unsafe.Pointer { return unsafe.Pointer(&receipt) }\n"),
		"outside direct type":              []byte("package sandboxworker\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc leak(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) uint64 { return receipt.FinalizedRevision }\n"),
		"outside import alias":             []byte("package sandboxworker\nimport runtimeapi \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc leak(receipt runtimeapi.JobCredentialRuntimeRecoveryCommitReceipt) any { return receipt }\n"),
		"outside raw import":               []byte("package sandboxworker\nimport runtimeapi `github.com/jywlabs/hal/internal/sandboxruntime`\nfunc leak(receipt runtimeapi.JobCredentialRuntimeRecoveryCommitReceipt) any { return receipt }\n"),
		"outside dot import":               []byte("package sandboxworker\nimport . \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc leak(receipt JobCredentialRuntimeRecoveryCommitReceipt) any { return receipt }\n"),
		"outside type alias":               []byte("package sandboxworker\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\ntype leakedReceipt = sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt\n"),
	}
	for name, fixture := range outsideFixtures {
		t.Run(name, func(t *testing.T) {
			audit, err := l8D6RuntimeOwnerCommitReceiptAccessAudit(fixture, l8D6RuntimeOwnerCommitReceiptFunction{})
			if err != nil {
				t.Fatal(err)
			}
			if len(audit.issues) == 0 {
				t.Fatalf("outside-file receipt access passed audit: %#v", audit)
			}
		})
	}
}

type l8D6RuntimeOwnerCommitReceiptFunction struct {
	name                 string
	rootType             bool
	exactOneParameter    bool
	storeConverter       bool
	allowFinalizerResult bool
}

type l8D6RuntimeOwnerCommitReceiptAudit struct {
	present           bool
	commitIDReads     int
	receiptReferences int
	issues            []string
}

func (audit l8D6RuntimeOwnerCommitReceiptAudit) exact() bool {
	return audit.present && audit.commitIDReads == 1 && audit.receiptReferences >= 1 && len(audit.issues) == 0
}

func l8D6RuntimeOwnerCommitReceiptAccessAudit(payload []byte, expected l8D6RuntimeOwnerCommitReceiptFunction) (l8D6RuntimeOwnerCommitReceiptAudit, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "receipt.go", payload, 0)
	if err != nil {
		return l8D6RuntimeOwnerCommitReceiptAudit{}, err
	}
	audit := l8D6RuntimeOwnerCommitReceiptAudit{}
	parents := make(map[ast.Node]ast.Node)
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		ast.Inspect(node, func(child ast.Node) bool {
			if child != nil && child != node {
				if _, exists := parents[child]; !exists {
					parents[child] = node
				}
				return false
			}
			return true
		})
		return true
	})
	receiptTypeReferences := l8D6RuntimeOwnerReceiptTypeReferences(file, expected.rootType)
	var target *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != expected.name {
			continue
		}
		if target != nil {
			audit.issues = append(audit.issues, "duplicate expected function")
			continue
		}
		target = function
	}
	if target == nil {
		if len(receiptTypeReferences) != 0 {
			audit.issues = append(audit.issues, "receipt type referenced outside an allowlisted function and file")
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "CommitID" {
				audit.issues = append(audit.issues, "CommitID selector outside expected function")
			}
			return true
		})
		return audit, nil
	}
	audit.present = true
	if expected.allowFinalizerResult {
		finalizers, exactFinalizers := 0, 0
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != "FinalizeJobCredentialRuntimeRecovery" {
				continue
			}
			finalizers++
			for _, reference := range receiptTypeReferences {
				if l8D6RuntimeOwnerContainingFunction(reference, parents) == function && l8D6RuntimeOwnerReceiptTypeIsExactFinalizerResult(file, reference, parents) {
					exactFinalizers++
					break
				}
			}
		}
		if finalizers != exactFinalizers {
			audit.issues = append(audit.issues, "future finalizer signature is not exact")
		}
	}
	for _, reference := range receiptTypeReferences {
		if l8D6RuntimeOwnerReceiptTypeAlias(reference, parents) {
			audit.issues = append(audit.issues, "receipt type alias is forbidden")
			continue
		}
		if expected.rootType && !l8D6RuntimeOwnerRootReceiptReferenceIsExact(file, reference, target, parents) {
			audit.issues = append(audit.issues, "root receipt type referenced outside the exact declaration, validator, redaction methods, or recovery interface")
			continue
		}
		if !expected.rootType && !l8D6RuntimeOwnerReceiptTypeIsTargetParameter(reference, target) &&
			!(expected.allowFinalizerResult && l8D6RuntimeOwnerReceiptTypeIsExactFinalizerResult(file, reference, parents)) {
			audit.issues = append(audit.issues, "receipt type referenced outside the exact allowlisted function parameter")
		}
	}
	if len(receiptTypeReferences) != 0 && l8D6RuntimeOwnerHasIndirectAccessImport(file) {
		audit.issues = append(audit.issues, "receipt file imports reflection or unsafe access")
	}
	if target.Recv != nil {
		audit.issues = append(audit.issues, "expected package function is a receiver method")
	}
	receiptObjects := l8D6RuntimeOwnerReceiptParameterObjects(file, target, expected.rootType)
	if len(receiptObjects) != 1 {
		audit.issues = append(audit.issues, fmt.Sprintf("receipt-typed parameter count = %d", len(receiptObjects)))
	}
	if expected.exactOneParameter && l8D6RuntimeOwnerParameterNameCount(target) != 1 {
		audit.issues = append(audit.issues, "root validator signature is not one parameter")
	}
	if expected.storeConverter && !l8D6RuntimeOwnerReturnsStoredReceiptAndError(target) {
		audit.issues = append(audit.issues, "private-store converter result signature is not exact")
	} else if !expected.storeConverter && !l8D6RuntimeOwnerReturnsOnlyError(target) {
		audit.issues = append(audit.issues, "expected function does not return only error")
	}
	receiptObject := (*ast.Object)(nil)
	if len(receiptObjects) == 1 {
		receiptObject = receiptObjects[0]
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "CommitID" {
			return true
		}
		owner := l8D6RuntimeOwnerContainingFunction(selector, parents)
		identifier, direct := selector.X.(*ast.Ident)
		if owner != target || !direct || receiptObject == nil || identifier.Obj != receiptObject || l8D6RuntimeOwnerInsideClosure(selector, target, parents) {
			audit.issues = append(audit.issues, "CommitID read is not the direct receipt parameter in the exact function")
			return true
		}
		audit.commitIDReads++
		return true
	})
	if receiptObject != nil {
		runtimeAliases := l8D6RuntimeOwnerImportAliases(file, "github.com/jywlabs/hal/internal/sandboxruntime")
		ast.Inspect(target.Body, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Obj != receiptObject {
				return true
			}
			audit.receiptReferences++
			parent := parents[identifier]
			if selector, ok := parent.(*ast.SelectorExpr); ok && selector.X == identifier && (selector.Sel.Name == "CommitID" || selector.Sel.Name == "FinalizedRevision") && !l8D6RuntimeOwnerInsideClosure(selector, target, parents) {
				return true
			}
			if call, ok := parent.(*ast.CallExpr); ok && l8D6RuntimeOwnerIsReceiptValidatorCall(call.Fun, runtimeAliases) && !expected.rootType {
				return true
			}
			audit.issues = append(audit.issues, "receipt parameter escapes direct field validation")
			return true
		})
	}
	return audit, nil
}

func l8D6RuntimeOwnerReceiptTypeReferences(file *ast.File, rootType bool) []ast.Expr {
	aliases := make(map[string]bool)
	dotImport := false
	for _, spec := range file.Imports {
		if l8D6RuntimeOwnerImportPath(spec) != "github.com/jywlabs/hal/internal/sandboxruntime" {
			continue
		}
		alias := "sandboxruntime"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." {
			dotImport = true
			continue
		}
		aliases[alias] = true
	}
	var references []ast.Expr
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.SelectorExpr:
			qualifier, ok := value.X.(*ast.Ident)
			if ok && aliases[qualifier.Name] && value.Sel.Name == "JobCredentialRuntimeRecoveryCommitReceipt" {
				references = append(references, value)
				return false
			}
		case *ast.Ident:
			if value.Name != "JobCredentialRuntimeRecoveryCommitReceipt" {
				return true
			}
			if rootType && value.Obj != nil {
				references = append(references, value)
			} else if dotImport && value.Obj == nil {
				references = append(references, value)
			}
		}
		return true
	})
	return references
}

func l8D6RuntimeOwnerReceiptTypeAlias(reference ast.Expr, parents map[ast.Node]ast.Node) bool {
	for current := ast.Node(reference); current != nil; current = parents[current] {
		typeSpec, ok := current.(*ast.TypeSpec)
		if ok {
			return typeSpec.Assign.IsValid()
		}
	}
	return false
}

func l8D6RuntimeOwnerReceiptTypeIsTargetParameter(reference ast.Expr, target *ast.FuncDecl) bool {
	for _, field := range target.Type.Params.List {
		if field.Type == reference {
			return true
		}
	}
	return false
}

func l8D6RuntimeOwnerRootReceiptReferenceIsExact(file *ast.File, reference ast.Expr, target *ast.FuncDecl, parents map[ast.Node]ast.Node) bool {
	if l8D6RuntimeOwnerReceiptTypeIsTargetParameter(reference, target) {
		return true
	}
	if identifier, ok := reference.(*ast.Ident); ok {
		if typeSpec, ok := parents[identifier].(*ast.TypeSpec); ok && typeSpec.Name == identifier && l8D6RuntimeOwnerExactRootReceiptType(identifier) {
			return true
		}
	}
	return l8D6RuntimeOwnerRootReceiptMethodIsExact(file, reference, parents) ||
		l8D6RuntimeOwnerRootReceiptInterfaceReferenceIsExact(file, reference, parents)
}

func l8D6RuntimeOwnerRootReceiptMethodIsExact(file *ast.File, reference ast.Expr, parents map[ast.Node]ast.Node) bool {
	function := l8D6RuntimeOwnerContainingFunction(reference, parents)
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 0 ||
		function.Recv.List[0].Type != reference || function.Type.Params == nil {
		return false
	}
	identifier, ok := reference.(*ast.Ident)
	if !ok || !l8D6RuntimeOwnerExactRootReceiptType(identifier) {
		return false
	}
	switch function.Name.Name {
	case "String", "GoString":
		return len(function.Type.Params.List) == 0 && l8D6RuntimeOwnerReturnsExactType(function, "string")
	case "MarshalJSON", "MarshalText", "MarshalBinary", "GobEncode":
		return len(function.Type.Params.List) == 0 && l8D6RuntimeOwnerReturnsBytesAndError(function)
	case "Format":
		if function.Type.Results != nil && len(function.Type.Results.List) != 0 || len(function.Type.Params.List) != 2 {
			return false
		}
		fmtAliases := l8D6RuntimeOwnerImportAliases(file, "fmt")
		return l8D6RuntimeOwnerExactImportedType(function.Type.Params.List[0].Type, fmtAliases, "State") &&
			l8D6RuntimeOwnerTypeName(function.Type.Params.List[1].Type) == "rune"
	default:
		return false
	}
}

func l8D6RuntimeOwnerRootReceiptInterfaceReferenceIsExact(file *ast.File, reference ast.Expr, parents map[ast.Node]ast.Node) bool {
	var field *ast.Field
	var typeSpec *ast.TypeSpec
	for current := ast.Node(reference); current != nil; current = parents[current] {
		switch value := current.(type) {
		case *ast.Field:
			if len(value.Names) == 1 {
				field = value
			}
		case *ast.TypeSpec:
			typeSpec = value
			current = nil
		}
		if typeSpec != nil {
			break
		}
	}
	if field == nil || typeSpec == nil || typeSpec.Name.Name != "JobCredentialRuntimeRecoveryBinding" || typeSpec.Assign.IsValid() || len(field.Names) != 1 {
		return false
	}
	if _, ok := typeSpec.Type.(*ast.InterfaceType); !ok {
		return false
	}
	function, ok := field.Type.(*ast.FuncType)
	if !ok || function.Params == nil || len(function.Params.List) != 2 || function.Results == nil {
		return false
	}
	contextAliases := l8D6RuntimeOwnerImportAliases(file, "context")
	if !l8D6RuntimeOwnerExactImportedType(function.Params.List[0].Type, contextAliases, "Context") {
		return false
	}
	switch field.Names[0].Name {
	case "FinalizeJobCredentialRuntimeRecovery":
		return function.Results != nil && len(function.Results.List) == 2 && function.Results.List[0].Type == reference &&
			l8D6RuntimeOwnerTypeName(function.Params.List[1].Type) == "JobCredentialRuntimeAbsenceProof" &&
			l8D6RuntimeOwnerTypeName(function.Results.List[1].Type) == "error"
	case "CommitJobCredentialRuntimeRecovery":
		return function.Params.List[1].Type == reference && len(function.Results.List) == 1 &&
			l8D6RuntimeOwnerTypeName(function.Results.List[0].Type) == "error"
	default:
		return false
	}
}

func l8D6RuntimeOwnerReturnsExactType(function *ast.FuncDecl, name string) bool {
	return function.Type.Results != nil && len(function.Type.Results.List) == 1 &&
		len(function.Type.Results.List[0].Names) == 0 && l8D6RuntimeOwnerTypeName(function.Type.Results.List[0].Type) == name
}

func l8D6RuntimeOwnerReturnsBytesAndError(function *ast.FuncDecl) bool {
	if function.Type.Results == nil || len(function.Type.Results.List) != 2 {
		return false
	}
	bytesResult, ok := function.Type.Results.List[0].Type.(*ast.ArrayType)
	return ok && bytesResult.Len == nil && l8D6RuntimeOwnerTypeName(bytesResult.Elt) == "byte" &&
		len(function.Type.Results.List[0].Names) == 0 && len(function.Type.Results.List[1].Names) == 0 &&
		l8D6RuntimeOwnerTypeName(function.Type.Results.List[1].Type) == "error"
}

func l8D6RuntimeOwnerReceiptTypeIsExactFinalizerResult(file *ast.File, reference ast.Expr, parents map[ast.Node]ast.Node) bool {
	function := l8D6RuntimeOwnerContainingFunction(reference, parents)
	if function == nil || function.Name.Name != "FinalizeJobCredentialRuntimeRecovery" || function.Recv == nil || len(function.Recv.List) != 1 ||
		function.Type.Params == nil || len(function.Type.Params.List) != 2 || function.Type.Results == nil || len(function.Type.Results.List) != 2 {
		return false
	}
	receiver := function.Recv.List[0]
	pointer, ok := receiver.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	receiverType, ok := pointer.X.(*ast.Ident)
	if !ok || receiverType.Name != "l8RuntimeOwnerRecoveryBinding" || receiverType.Obj == nil {
		return false
	}
	typeSpec, ok := receiverType.Obj.Decl.(*ast.TypeSpec)
	if !ok || typeSpec.Assign.IsValid() || typeSpec.Name.Name != "l8RuntimeOwnerRecoveryBinding" {
		return false
	}
	contextAliases, runtimeAliases := map[string]bool{}, map[string]bool{}
	for _, spec := range file.Imports {
		alias := ""
		switch l8D6RuntimeOwnerImportPath(spec) {
		case "context":
			alias = "context"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			contextAliases[alias] = true
		case "github.com/jywlabs/hal/internal/sandboxruntime":
			alias = "sandboxruntime"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			runtimeAliases[alias] = true
		}
	}
	firstParameter := l8D6RuntimeOwnerExactImportedType(function.Type.Params.List[0].Type, contextAliases, "Context")
	secondParameter := l8D6RuntimeOwnerExactImportedType(function.Type.Params.List[1].Type, runtimeAliases, "JobCredentialRuntimeAbsenceProof")
	firstResult := function.Type.Results.List[0]
	secondResult := function.Type.Results.List[1]
	return len(function.Type.Params.List[0].Names) == 0 && len(function.Type.Params.List[1].Names) == 0 &&
		len(firstResult.Names) == 0 && firstResult.Type == reference &&
		len(secondResult.Names) == 0 && l8D6RuntimeOwnerTypeName(secondResult.Type) == "error" && firstParameter && secondParameter
}

func l8D6RuntimeOwnerExactImportedType(expression ast.Expr, aliases map[string]bool, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	return ok && aliases[qualifier.Name] && qualifier.Obj == nil
}

func l8D6RuntimeOwnerHasIndirectAccessImport(file *ast.File) bool {
	for _, spec := range file.Imports {
		if path := l8D6RuntimeOwnerImportPath(spec); path == "reflect" || path == "unsafe" {
			return true
		}
	}
	return false
}

func l8D6RuntimeOwnerImportPath(spec *ast.ImportSpec) string {
	if spec == nil || spec.Path == nil {
		return ""
	}
	path, err := strconv.Unquote(spec.Path.Value)
	if err != nil {
		return ""
	}
	return path
}

func l8D6RuntimeOwnerReceiptParameterObjects(file *ast.File, function *ast.FuncDecl, rootType bool) []*ast.Object {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if l8D6RuntimeOwnerImportPath(spec) != "github.com/jywlabs/hal/internal/sandboxruntime" {
			continue
		}
		alias := "sandboxruntime"
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = true
	}
	var objects []*ast.Object
	for _, field := range function.Type.Params.List {
		exactType := false
		if rootType {
			identifier, ok := field.Type.(*ast.Ident)
			exactType = ok && identifier.Name == "JobCredentialRuntimeRecoveryCommitReceipt" && l8D6RuntimeOwnerExactRootReceiptType(identifier)
		} else if selector, ok := field.Type.(*ast.SelectorExpr); ok && selector.Sel.Name == "JobCredentialRuntimeRecoveryCommitReceipt" {
			qualifier, ok := selector.X.(*ast.Ident)
			exactType = ok && aliases[qualifier.Name]
		}
		if !exactType || len(field.Names) != 1 || field.Names[0].Obj == nil {
			continue
		}
		objects = append(objects, field.Names[0].Obj)
	}
	return objects
}

func l8D6RuntimeOwnerExactRootReceiptType(identifier *ast.Ident) bool {
	if identifier == nil || identifier.Obj == nil {
		return false
	}
	typeSpec, ok := identifier.Obj.Decl.(*ast.TypeSpec)
	if !ok || typeSpec.Assign.IsValid() || typeSpec.Name.Name != "JobCredentialRuntimeRecoveryCommitReceipt" {
		return false
	}
	structure, ok := typeSpec.Type.(*ast.StructType)
	if !ok || len(structure.Fields.List) != 2 {
		return false
	}
	return len(structure.Fields.List[0].Names) == 1 && structure.Fields.List[0].Names[0].Name == "CommitID" &&
		l8D6RuntimeOwnerTypeName(structure.Fields.List[0].Type) == "string" &&
		len(structure.Fields.List[1].Names) == 1 && structure.Fields.List[1].Names[0].Name == "FinalizedRevision" &&
		l8D6RuntimeOwnerTypeName(structure.Fields.List[1].Type) == "uint64"
}

func l8D6RuntimeOwnerTypeName(expression ast.Expr) string {
	identifier, _ := expression.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}

func l8D6RuntimeOwnerParameterNameCount(function *ast.FuncDecl) int {
	count := 0
	for _, field := range function.Type.Params.List {
		count += len(field.Names)
	}
	return count
}

func l8D6RuntimeOwnerReturnsOnlyError(function *ast.FuncDecl) bool {
	if function.Type.Results == nil || len(function.Type.Results.List) != 1 {
		return false
	}
	field := function.Type.Results.List[0]
	return len(field.Names) == 0 && l8D6RuntimeOwnerTypeName(field.Type) == "error"
}

func l8D6RuntimeOwnerReturnsStoredReceiptAndError(function *ast.FuncDecl) bool {
	if function.Type.Results == nil || len(function.Type.Results.List) != 2 {
		return false
	}
	first, second := function.Type.Results.List[0], function.Type.Results.List[1]
	return len(first.Names) == 0 && l8D6RuntimeOwnerTypeName(first.Type) == "storedJobCredentialRuntimeRecoveryReceiptV1" &&
		len(second.Names) == 0 && l8D6RuntimeOwnerTypeName(second.Type) == "error"
}

func l8D6RuntimeOwnerContainingFunction(node ast.Node, parents map[ast.Node]ast.Node) *ast.FuncDecl {
	for current := node; current != nil; current = parents[current] {
		if function, ok := current.(*ast.FuncDecl); ok {
			return function
		}
	}
	return nil
}

func l8D6RuntimeOwnerInsideClosure(node ast.Node, function *ast.FuncDecl, parents map[ast.Node]ast.Node) bool {
	for current := parents[node]; current != nil && current != function; current = parents[current] {
		if _, ok := current.(*ast.FuncLit); ok {
			return true
		}
	}
	return false
}

func l8D6RuntimeOwnerIsReceiptValidatorCall(expression ast.Expr, runtimeAliases map[string]bool) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ValidateJobCredentialRuntimeRecoveryCommitReceipt" {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	return ok && qualifier.Obj == nil && runtimeAliases[qualifier.Name]
}

func l8D6RuntimeOwnerImportAliases(file *ast.File, path string) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if l8D6RuntimeOwnerImportPath(spec) != path {
			continue
		}
		alias := filepath.Base(path)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias != "." && alias != "_" {
			aliases[alias] = true
		}
	}
	return aliases
}

type l8D6RuntimeOwnerProofConstructorUsage struct {
	declarations int
	references   int
	directCalls  int
	forbidden    bool
}

func l8D6RuntimeOwnerProofConstructorReferences(path string, payload []byte, declarationOwner, issuerOwner string) (l8D6RuntimeOwnerProofConstructorUsage, error) {
	_ = issuerOwner
	file, err := parser.ParseFile(token.NewFileSet(), path, payload, 0)
	if err != nil {
		return l8D6RuntimeOwnerProofConstructorUsage{}, err
	}
	declarationNames := make(map[*ast.Ident]bool)
	directReferences := make(map[ast.Expr]bool)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "NewJobCredentialRuntimeAbsenceProof" {
			continue
		}
		declarationNames[function.Name] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			directReferences[call.Fun] = true
		}
		return true
	})
	usage := l8D6RuntimeOwnerProofConstructorUsage{}
	for range declarationNames {
		usage.declarations++
		if filepath.ToSlash(path) != declarationOwner {
			usage.forbidden = true
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.SelectorExpr:
			if value.Sel.Name != "NewJobCredentialRuntimeAbsenceProof" {
				return true
			}
			usage.references++
			if directReferences[value] {
				usage.directCalls++
			}
			usage.forbidden = true
			return false
		case *ast.Ident:
			if value.Name != "NewJobCredentialRuntimeAbsenceProof" || declarationNames[value] {
				return true
			}
			usage.references++
			if directReferences[value] {
				usage.directCalls++
			}
			usage.forbidden = true
		}
		return true
	})
	return usage, nil
}

func TestL8D6RuntimeOwnerContractDefaultsRemainInert(t *testing.T) {
	paths := []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		"factory_sandbox_executor.go",
		filepath.Join("..", "internal", "sandboxworker", "job_manager.go"),
		filepath.Join("..", "internal", "sandboxworker", "server.go"),
	}
	for _, path := range paths {
		source := readL8CredentialDeliveryFile(t, path)
		for _, forbidden := range []string{
			"BindJobCredentialRuntimeRecovery(",
			"NewJobCredentialRuntimeAbsenceProof(",
			"firecracker-runtime-owner-private-v1",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("default/v1 production path %s contains runtime-owner marker %q", filepath.ToSlash(path), forbidden)
			}
		}
	}
}
