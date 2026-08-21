package cmd

import (
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
	Close(context.Context) error
}`

const l8D6RuntimeOwnerRecordDocBlock = `type firecrackerRuntimeOwnerRecordV1 struct {
	ContractVersion              string ` + "`json:\"contractVersion\"`" + `
	Revision                     uint64 ` + "`json:\"revision\"`" + `
	State                        string ` + "`json:\"state\"`" + `
	HostBootID                   string ` + "`json:\"hostBootId\"`" + `
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

func TestL8D6RuntimeOwnerContractArchitectureIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, block := range []string{l8D6RuntimeOwnerRecoveryAPIDocBlock, l8D6RuntimeOwnerRecordDocBlock} {
		if strings.Count(doc, "```go\n"+block+"\n```") != 1 {
			t.Fatalf("L8 D6 runtime-owner architecture must contain one exact canonical block:\n%s", block)
		}
	}
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
		"PID reuse",
		"`l7network.NewReconciler`",
		"`CleanupAfterVMQuiesced`",
		"private recovered `TerminatedVMBinding`",
		"owner record is retired only after",
		"mandatory for both seed-only and complete-identity restart",
		"The digest has no accessor",
		"Close does not imply process or resource absence",
		"Non-Linux implementations fail closed",
		"Default and v1 constructors remain byte-for-byte inert",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D6 runtime-owner architecture omits %q", required)
		}
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
	const allowed = "../internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go"
	err := filepath.WalkDir(filepath.Join("..", "internal"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, payload, 0)
		if err != nil {
			return err
		}
		var forbidden bool
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if name == "NewJobCredentialRuntimeAbsenceProof" && filepath.ToSlash(path) != allowed {
				forbidden = true
				return false
			}
			return true
		})
		if forbidden {
			t.Fatalf("production proof constructor call outside sole owner %s: %s", allowed, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production proof constructor calls: %v", err)
	}
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
