package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
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
