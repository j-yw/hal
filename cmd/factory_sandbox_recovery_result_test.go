package cmd

import (
	"context"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestFactoryFinalizationRecoveryRequiresSuccessfulExecResult(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    *sandboxruntime.ExecResult
		err       error
		wantError bool
	}{
		{name: "success", result: &sandboxruntime.ExecResult{}},
		{name: "missing", wantError: true},
		{name: "nonzero", result: &sandboxruntime.ExecResult{ExitCode: 2}, wantError: true},
		{name: "driver_error", result: &sandboxruntime.ExecResult{}, err: errors.New("injected driver failure"), wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := workerRootlessCachedSandbox("recovery-result")
			driver := fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if req.Target.Runtime.RuntimeID != target.Runtime.RuntimeID || req.Env != nil {
					t.Fatal("recovery changed exact identity or delivered an environment")
				}
				return tc.result, tc.err
			}}
			err := generateFactorySandboxRuntimeRecoveryArtifacts(context.Background(), factory.RunRecord{RepoPath: "/workspace/repo", BaseBranch: "main"}, target, driver, nil)
			if (err != nil) != tc.wantError {
				t.Fatalf("recovery error=%v wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestFactoryFinalizationRecoveryCollectionUsesDurableRuntime(t *testing.T) {
	for _, scenario := range []string{"present", "missing", "copy_error"} {
		t.Run(scenario, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			record := factory.RunRecord{RunID: "recovery-collection", ExecutorMode: factory.ExecutorModeSandbox, SandboxName: "recovery-target", RepoPath: "/workspace/repo"}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			target := workerRootlessCachedSandbox(record.SandboxName)
			var copied bool
			driver := fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					if req.Target.Runtime.RuntimeID != target.Runtime.RuntimeID || len(req.Args) != 3 || req.Args[2] != path.Join(record.RepoPath, ".hal/recovery/git-bundle.bundle") {
						t.Fatal("collection probe lost durable identity or workspace routing")
					}
					if scenario == "missing" {
						return &sandboxruntime.ExecResult{ExitCode: 1}, errors.New("not found")
					}
					return &sandboxruntime.ExecResult{}, nil
				},
				copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
					copied = true
					if req.Target.Runtime.RuntimeID != target.Runtime.RuntimeID || req.SourcePath != path.Join(record.RepoPath, ".hal/recovery/git-bundle.bundle") {
						t.Fatal("copy lost durable identity or workspace routing")
					}
					if scenario == "copy_error" {
						return errors.New("injected copy failure")
					}
					return os.WriteFile(req.DestinationPath, []byte("fake recovery bundle"), 0600)
				},
			}
			err := collectAndStoreFactorySandboxArtifacts(context.Background(), store, t.TempDir(), factoryRunRequest{}, record, factoryRunDeps{
				now:         time.Now,
				loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
				resolveSandboxRuntime: func(_ string, state *sandbox.SandboxState) (sandboxruntime.Driver, error) {
					if state != target {
						t.Fatal("not the durable target")
					}
					return driver, nil
				},
				resolveProvider: func(string, string) (sandbox.Provider, error) {
					t.Fatal("worker collection used provider")
					return nil, nil
				},
				sandboxRequests: func(dir string, record factory.RunRecord) []factory.SandboxArtifactRequest {
					for _, req := range defaultFactorySandboxArtifactRequests(dir, record) {
						if req.ID == "sandbox-recovery-bundle" {
							return []factory.SandboxArtifactRequest{req}
						}
					}
					t.Fatal("default recovery bundle request missing")
					return nil
				},
			})
			if (err != nil) != (scenario == "copy_error") {
				t.Fatalf("collection error=%v", err)
			}
			if copied != (scenario != "missing") {
				t.Fatal("missing recovery artifact was copied")
			}
			if scenario == "copy_error" {
				return
			}
			saved, err := store.LoadRun(record.RunID)
			if err != nil || len(saved.Artifacts) != 1 {
				t.Fatalf("stored recovery evidence: %v", err)
			}
			if (saved.Artifacts[0].StoredPath != "") != (scenario == "present") {
				t.Fatal("missing recovery evidence was advertised as a stored payload")
			}
		})
	}
}
