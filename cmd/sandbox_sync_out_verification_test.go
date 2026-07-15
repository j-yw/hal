package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase21VerificationDocsCurrent(t *testing.T) {
	doc := readSandboxSyncOutVerificationDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase21-workspace-syncout-apply-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 21 covers explicit non-factory workspace sync-out and safe host apply",
		"`hal run --sandbox` and `hal auto --sandbox`",
		"`hal run --sandbox --sandbox-sync-out`",
		"`hal run --sandbox --sandbox-apply`",
		"`hal auto --sandbox --sandbox-sync-out`",
		"`hal auto --sandbox --sandbox-apply`",
		"`hal sandbox apply EXECUTION_ID`",
		"The run/auto `--sandbox-apply` flags apply artifacts from the new execution they launch.",
		"Sandbox JSON with explicit sync-out metadata includes `sandboxExecutionId`",
		"`hal sandbox apply EXECUTION_ID` is the apply-only path for a prior completed execution.",
		"must not resolve, provision, start, materialize, or execute a sandbox",
		"a collected `.hal/prd.json` with every story passing",
		"a stored project and branch matching the current host worktree",
		"A commit-valued stored sync ref must also match the current host HEAD.",
		"Already-applied executions are rejected",
		"Tracked uncommitted output, including PRD completion metadata, remains a separate manual-review handoff",
		"default no-mutation behavior",
		"must not invoke sync-out apply, host dry-run apply, host Git mutation, or host worktree lock acquisition",
		"Default manifests must omit `syncOut` and `syncOutApply` fields.",
		"Recovery-before-apply is required.",
		"persist durable core, generated, output, and recovery artifact metadata before host dry-run or mutation",
		"Safe host apply accepts only explicitly eligible committed patch or bundle artifacts selected by command code.",
		"Untracked archives, raw artifact directories, recovery payloads, warning-only outputs, uncommitted diffs, and otherwise ineligible artifacts are handoff-only.",
		"Explicit sync-out collection generates committed and tracked-uncommitted artifacts separately.",
		"The uncommitted diff contains staged and unstaged tracked changes, is omitted when empty, and always requires manual review rather than automatic host apply.",
		"production generation of those artifacts is not included in this phase",
		"go test -timeout=120s ./internal/sandboxworkspace -run 'TestWorkspaceSyncOutContractShape|TestSyncOutImportBoundaries|TestSyncOutForbiddenImportListCoversRequiredBoundaries|TestSyncOutImportBoundaryAllowsStableContractsOnly'",
		"go test -timeout=120s ./internal/sandboxexecution -run 'TestBuildSyncOutSummaryFromArtifacts|TestBuildSyncOutSummaryRedaction|TestCollectUncommittedSyncOutArtifactBestEffort|TestUncommittedSyncOutDiffGenerationScript|TestPackageImportBoundaries'",
		"go test -timeout=120s ./internal/sandboxworkspace -run 'TestSafeApply(RunsDryRunBeforePatchMutation|DryRunValidatesEligibleBundle|DryRunRejectsIncompatiblePatch|RefusesDirtyWorktreeByDefault|UsesWorkspaceLock|LockFailurePreventsApply|Redaction)'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRunAutoDefaultDoesNotMutateHostWorktree|TestSandboxSyncOutApplyFlagsAreExplicitAndScoped|TestSandboxApplyPersistsRecoveryBeforeHostMutation|TestSandboxApplyOnlyUsesEligibleSyncOutArtifacts|TestSandboxSyncOutHandoffInstructions|TestSandboxSyncOutManifestJSONAdditiveContract|TestSandboxSyncOutApplyRedaction|TestRunSandboxApplyExecution|TestSandboxAugmentedJSONExposesStoredExecutionID'",
		"go test -timeout=120s ./cmd -run 'TestContractDocsIncludeAutoV2Fields|TestContractDocsIncludeAutoV2Examples|TestMachineContractFields_AutoV2Examples|TestSandboxSyncOutManifestJSONAdditiveContract'",
		"go test -timeout=120s ./cmd -run 'TestPhase21VerificationDocsCurrent'",
		"make docs-check",
		"git diff --check",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"make build",
		"make lint",
		"Run `make docs-cli` before `make docs-check` when command metadata, examples, or generated CLI surfaces change.",
		"Phase 21 verification is fake-only.",
		"temporary repositories",
		"temporary execution stores",
		"fake runtime drivers",
		"fake providers",
		"fake locks",
		"fake Git adapters",
		"fake clocks",
		"temporary `HAL_CONFIG_HOME`",
		"Phase 21 verification has no real worker daemon, Podman, Docker, cloud, network, microVM, scheduler daemon, policy proxy, or secret broker requirement.",
		"Do not start a real worker daemon, run `hal sandboxd`, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows",
		"pull images, access cloud APIs, open network connections, execute microVM runtimes, start a scheduler daemon, configure a policy proxy, configure a secret broker",
		"`internal/sandboxworkspace` sync-out files must stay data-only and command-agnostic.",
		"Production `sync_out*.go` files may use only standard library imports plus the root `internal/sandbox` and `internal/sandboxruntime` data contracts.",
		"Command code owns local host apply intent.",
		"`--sandbox-sync-out` records durable sync-out and handoff metadata without mutating the host",
		"`--sandbox-apply` is the explicit opt-in path for automatic eligible host apply from the new run/auto execution.",
		"Use `hal sandbox apply EXECUTION_ID` to apply a prior completed execution without launching another sandbox run.",
		"Redaction belongs at shared contract boundaries.",
		"must not include raw worker endpoints, Unix socket paths, host temp paths, remote temp paths, credentials, provider secrets, or secret-bearing repository URLs.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 21 sync-out/apply verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"requires Podman",
		"requires Docker",
		"requires cloud",
		"requires network",
		"requires microVM",
		"requires a scheduler daemon",
		"requires a policy proxy",
		"requires a secret broker",
		"requires provider credentials",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 21 sync-out/apply verification documentation makes unsupported requirement claim %q", claim)
		}
	}
}

func readSandboxSyncOutVerificationDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
