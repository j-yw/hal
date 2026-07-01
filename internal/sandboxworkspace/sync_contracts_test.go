package sandboxworkspace

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestWorkspaceMaterializerContractReturnsPlanMetadata(t *testing.T) {
	plan := Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
		Repository:  "git@github.com:jywlabs/hal.git",
		Branch:      "phase/workspace",
		SyncRef:     "abc123",
	}
	details := MaterializationDetails{
		WorkspaceDir: "/root/workspace/hal",
		Bundle: &BundleMaterialization{
			ID:         "bundle-abc123",
			RemotePath: "/tmp/hal/bundles/abc123.bundle",
			SyncRef:    "abc123",
		},
		Operations: []MaterializationOperation{
			{Phase: MaterializationPhaseBundleCopy, Summary: "copied bundle to sandbox"},
		},
	}

	materializer := MaterializerFunc(func(_ context.Context, req MaterializeRequest) (MaterializationResult, error) {
		return NewMaterializationResult(req.Plan, details), nil
	})

	result, err := materializer.MaterializeWorkspace(context.Background(), MaterializeRequest{
		Plan:         plan,
		WorkspaceDir: details.WorkspaceDir,
	})
	if err != nil {
		t.Fatalf("MaterializeWorkspace() error = %v", err)
	}
	if result.Mode != plan.Mode ||
		result.InputSource != plan.InputSource ||
		result.Repository != plan.Repository ||
		result.Branch != plan.Branch ||
		result.SyncRef != plan.SyncRef {
		t.Fatalf("result metadata = %#v, want plan metadata from %#v", result, plan)
	}
	if result.WorkspaceDir != details.WorkspaceDir {
		t.Fatalf("WorkspaceDir = %q, want %q", result.WorkspaceDir, details.WorkspaceDir)
	}
	if result.Bundle == nil || result.Bundle.ID != "bundle-abc123" || result.Bundle.RemotePath != "/tmp/hal/bundles/abc123.bundle" || result.Bundle.SyncRef != "abc123" {
		t.Fatalf("Bundle = %#v, want redaction-safe bundle metadata", result.Bundle)
	}
	if len(result.Operations) != 1 || result.Operations[0].Phase != MaterializationPhaseBundleCopy {
		t.Fatalf("Operations = %#v, want bundle copy operation", result.Operations)
	}
}

func TestBundleMaterializationOmitsLocalBundlePath(t *testing.T) {
	const unsafeLocalPath = "/var/folders/secret/hal.bundle"
	createResult := CreateBundleResult{
		Path:    unsafeLocalPath,
		ID:      "bundle-abc123",
		SyncRef: "abc123",
	}

	result := NewMaterializationResult(Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
		Repository:  "git@github.com:jywlabs/hal.git",
		Branch:      "phase/workspace",
		SyncRef:     "abc123",
	}, MaterializationDetails{
		Bundle: BundleMaterializationFromCreateResult(createResult, "/tmp/hal/bundles/abc123.bundle"),
	})

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	if strings.Contains(string(encoded), unsafeLocalPath) {
		t.Fatalf("materialization metadata leaked local bundle path: %s", encoded)
	}
	if result.Bundle == nil || result.Bundle.RemotePath == "" {
		t.Fatalf("Bundle = %#v, want remote bundle identifier", result.Bundle)
	}
}

func TestWorkspaceSyncOutContractShape(t *testing.T) {
	summary := SyncOutSummary{
		Workspace: SyncOutWorkspaceRef{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Branch:      "phase/workspace",
			SyncRef:     "abc123",
		},
		Committed: SyncOutCommittedArtifacts{
			Patch: &SyncOutArtifact{
				ID:          "committed-patch",
				DisplayName: "Committed Patch",
				Kind:        SyncOutArtifactKindPatch,
				DisplayPath: ".hal/sync/committed.patch",
				StoredPath:  "exec-1/artifacts/committed.patch",
				ApplyEligibility: &SyncOutApplyEligibility{
					Eligible: true,
					Mode:     SyncOutApplyModePatch,
					Reasons:  []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonEligiblePatch},
				},
			},
			Bundle: &SyncOutArtifact{
				ID:          "committed-bundle",
				DisplayName: "Committed Bundle",
				Kind:        SyncOutArtifactKindBundle,
				DisplayPath: ".hal/sync/committed.bundle",
				StoredPath:  "exec-1/artifacts/committed.bundle",
				ApplyEligibility: &SyncOutApplyEligibility{
					Eligible: true,
					Mode:     SyncOutApplyModeBundle,
					Reasons:  []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonEligibleBundle},
				},
			},
		},
		Uncommitted: SyncOutUncommittedArtifacts{
			Diff: &SyncOutArtifact{
				ID:          "uncommitted-diff",
				DisplayName: "Uncommitted Diff",
				Kind:        SyncOutArtifactKindDiff,
				DisplayPath: ".hal/sync/uncommitted.diff",
				StoredPath:  "exec-1/artifacts/uncommitted.diff",
				ApplyEligibility: &SyncOutApplyEligibility{
					Eligible: false,
					Reasons:  []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonManualReviewRequired},
				},
			},
		},
		Untracked: SyncOutUntrackedArtifacts{
			Archive: &SyncOutArtifact{
				ID:          "untracked-archive",
				DisplayName: "Untracked Files Archive",
				Kind:        SyncOutArtifactKindArchive,
				DisplayPath: ".hal/sync/untracked.tar",
				StoredPath:  "exec-1/artifacts/untracked.tar",
			},
			List: &SyncOutArtifact{
				ID:          "untracked-list",
				DisplayName: "Untracked Files",
				Kind:        SyncOutArtifactKindFileList,
				DisplayPath: ".hal/sync/untracked.txt",
				StoredPath:  "exec-1/artifacts/untracked.txt",
			},
		},
		CoreArtifacts: []SyncOutArtifact{{
			ID:          "prd",
			DisplayName: "PRD",
			Kind:        SyncOutArtifactKindCore,
			DisplayPath: ".hal/prd.json",
			StoredPath:  "exec-1/artifacts/hal-prd.json",
		}},
		Recovery: SyncOutRecoveryState{
			Status: SyncOutRecoveryStatusCollected,
			Artifacts: []SyncOutArtifact{{
				ID:          "recovery-patch",
				DisplayName: "Recovery Patch",
				Kind:        SyncOutArtifactKindRecovery,
				DisplayPath: ".hal/recovery/workspace.patch",
				StoredPath:  "exec-1/recovery/workspace.patch",
			}},
		},
		Warnings: []SyncOutWarning{{
			Code:       "copy_out_partial",
			Message:    "optional artifact unavailable",
			ArtifactID: "reports-archive",
		}},
		Apply: SyncOutApplyDecision{
			Eligible:   true,
			Mode:       SyncOutApplyModePatch,
			ArtifactID: "committed-patch",
			Reasons:    []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonEligiblePatch},
		},
	}

	got := mustSyncOutJSONMap(t, summary)
	assertSyncOutJSONKeys(t, got, []string{
		"workspace", "committed", "uncommitted", "untracked",
		"coreArtifacts", "recovery", "warnings", "apply",
	})
	committed := syncOutJSONObject(t, got, "committed")
	assertSyncOutJSONKeys(t, committed, []string{"patch", "bundle"})
	patch := syncOutJSONObject(t, committed, "patch")
	assertSyncOutJSONKeys(t, patch, []string{
		"id", "displayName", "kind", "displayPath", "storedPath", "applyEligibility",
	})
	apply := syncOutJSONObject(t, got, "apply")
	assertSyncOutJSONKeys(t, apply, []string{"eligible", "mode", "artifactId", "reasons"})

	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Marshal(sync-out summary) error = %v", err)
	}
	for _, unsafeFragment := range []string{
		"remotePath", "localPath", "sourcePath", "tempPath", "endpoint", "credential", "providerSecret",
	} {
		if strings.Contains(string(encoded), unsafeFragment) {
			t.Fatalf("sync-out contract leaked unsafe field fragment %q: %s", unsafeFragment, encoded)
		}
	}
}

func TestWorkspaceSyncContractsCompileWithNarrowAdapters(t *testing.T) {
	var _ WorkspaceMaterializer = MaterializerFunc(func(context.Context, MaterializeRequest) (MaterializationResult, error) {
		return MaterializationResult{}, nil
	})
	var _ WorkspaceMaterializer = BundleMaterializer{}
	var _ LocalGit = GitCLIInspector{}
	var _ LocalGit = fakeLocalGitBundle{}
	var _ RemoteClient = fakeRemoteClient{}
}

func TestSandboxworkspaceImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(package) error: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", name, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, name, err)
			}
			assertSandboxworkspaceAllowedImport(t, name, importPath)
		}
	}
}

func assertSandboxworkspaceAllowedImport(t *testing.T, fileName, importPath string) {
	t.Helper()
	forbiddenPrefixes := []string{
		"github.com/jywlabs/hal/cmd",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/prd",
		"github.com/jywlabs/hal/internal/compound",
		"github.com/jywlabs/hal/internal/loop",
		"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine",
	}
	for _, prefix := range forbiddenPrefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			t.Fatalf("%s imports forbidden command/provider package %q", fileName, importPath)
		}
	}
	if importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra") {
		t.Fatalf("%s imports Cobra package %q", fileName, importPath)
	}
}

func mustSyncOutJSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return got
}

func syncOutJSONObject(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key]
	if !ok {
		t.Fatalf("missing JSON key %q in %#v", key, object)
	}
	child, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("JSON key %q has type %T, want object", key, value)
	}
	return child
}

func assertSyncOutJSONKeys(t *testing.T, got map[string]any, want []string) {
	t.Helper()
	wantSet := make(map[string]struct{}, len(want))
	for _, key := range want {
		wantSet[key] = struct{}{}
		if _, ok := got[key]; !ok {
			t.Fatalf("missing JSON key %q in %#v", key, got)
		}
	}
	for key := range got {
		if _, ok := wantSet[key]; !ok {
			t.Fatalf("unexpected JSON key %q in %#v", key, got)
		}
	}
}

type fakeLocalGitBundle struct{}

func (fakeLocalGitBundle) CreateBundle(context.Context, CreateBundleRequest) (CreateBundleResult, error) {
	return CreateBundleResult{}, nil
}

func (fakeLocalGitBundle) VerifyBundle(context.Context, VerifyBundleRequest) error {
	return nil
}

type fakeRemoteClient struct{}

func (fakeRemoteClient) CopyIn(context.Context, RemoteCopyRequest) error {
	return nil
}

func (fakeRemoteClient) Exec(context.Context, RemoteCommandRequest) (RemoteCommandResult, error) {
	return RemoteCommandResult{}, nil
}
