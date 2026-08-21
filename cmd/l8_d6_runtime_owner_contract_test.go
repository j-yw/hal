package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
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

type JobCredentialRuntimeRecoveryProvider interface {
	BindJobCredentialRuntimeRecovery(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimeRecoveryBinding, error)
}

type JobCredentialRuntimeRecoveryBinding interface {
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
	StopReapJobCredentialRuntime(context.Context) (JobCredentialRuntimeAbsenceProof, error)
	FinalizeJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeAbsenceProof) error
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

const (
	l8D6RuntimeOwnerBootMismatchRule = "A host-boot mismatch never authorizes signaling a current PID."
	l8D6RuntimeOwnerPublicationRule  = "The revision-one `starting` record is durable before Firecracker publication or acknowledgement."
	l8D6RuntimeOwnerCompleteStopRule = "Complete-identity recovery always proceeds to `StopReapJobCredentialRuntime` after `RecoverJobCredentials`, including after a valid cleanup proof."
	l8D6RuntimeOwnerCloseRule        = "Close does not imply process or resource absence"
	l8D6RuntimeOwnerFinalizeRule     = "The worker validates the retained absence proof before calling `FinalizeJobCredentialRuntimeRecovery`."
	l8D6RuntimeOwnerCommitRule       = "A rename followed by directory-sync failure is commit-uncertain"
)

func TestL8D6RuntimeOwnerContractArchitectureIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	if err := validateL8D6RuntimeOwnerArchitecture(doc); err != nil {
		t.Fatal(err)
	}
}

func validateL8D6RuntimeOwnerArchitecture(doc string) error {
	for _, block := range []string{l8D6RuntimeOwnerRecoveryAPIDocBlock, l8D6RuntimeOwnerRecordDocBlock} {
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
		"`L7OldBootJournalRetirer`",
		"child-armed acknowledgement",
		"mandatory for both seed-only and complete-identity restart",
		l8D6RuntimeOwnerBootMismatchRule,
		l8D6RuntimeOwnerPublicationRule,
		l8D6RuntimeOwnerCompleteStopRule,
		l8D6RuntimeOwnerFinalizeRule,
		l8D6RuntimeOwnerCommitRule,
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
		{name: "boot mismatch may signal", before: l8D6RuntimeOwnerBootMismatchRule, after: "A host-boot mismatch may authorize signaling a current PID."},
		{name: "publication precedes revision one", before: l8D6RuntimeOwnerPublicationRule, after: "Firecracker publication may precede revision-one durability."},
		{name: "complete recovery skips stop reap", before: l8D6RuntimeOwnerCompleteStopRule, after: "A valid recovery proof permits the runtime to remain live."},
		{name: "worker cannot finalize after proof validation", before: l8D6RuntimeOwnerFinalizeRule, after: "StopReap retires all recovery ownership before returning."},
		{name: "rename sync failure retries old record", before: l8D6RuntimeOwnerCommitRule, after: "A directory-sync failure always retains the old record."},
		{name: "close implies absence", before: l8D6RuntimeOwnerCloseRule, after: "Close implies process and resource absence"},
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
		"This slice changes documentation and documentation guards only.",
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
		"does not add the neutral root API",
		"does not open a listener, launch or signal a process, access `/proc`, or call pidfd syscalls",
		"does not wire worker, command, provider, scheduler, or default runtime paths",
		"bootstrap pipe/start-gate loss before revision-one publication",
		"No test requires KVM, root, Firecracker, a live guest, or a daemon.",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D6 runtime-owner verification omits %q", required)
		}
	}
}

func TestL8D6RuntimeOwnerContractProofConstructorHasOneProductionOwner(t *testing.T) {
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
	if declarationErr != nil || issuerErr != nil || total.declarations != 1 || total.references != 1 || total.directCalls != 1 {
		t.Fatalf("production proof constructor usage = %#v, declaration error %v, issuer error %v; want one declaration and one direct owner call", total, declarationErr, issuerErr)
	}
}

func TestL8D6RuntimeOwnerContractProofConstructorGuardRejectsSecondIssuer(t *testing.T) {
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
	if err != nil || usage != (l8D6RuntimeOwnerProofConstructorUsage{references: 1, directCalls: 1}) {
		t.Fatalf("direct owner call fixture = %#v, error %v", usage, err)
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

type l8D6RuntimeOwnerProofConstructorUsage struct {
	declarations int
	references   int
	directCalls  int
	forbidden    bool
}

func l8D6RuntimeOwnerProofConstructorReferences(path string, payload []byte, declarationOwner, issuerOwner string) (l8D6RuntimeOwnerProofConstructorUsage, error) {
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
			if filepath.ToSlash(path) != issuerOwner || !directReferences[value] {
				usage.forbidden = true
			}
			return false
		case *ast.Ident:
			if value.Name != "NewJobCredentialRuntimeAbsenceProof" || declarationNames[value] {
				return true
			}
			usage.references++
			if directReferences[value] {
				usage.directCalls++
			}
			if filepath.ToSlash(path) != issuerOwner || !directReferences[value] {
				usage.forbidden = true
			}
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
