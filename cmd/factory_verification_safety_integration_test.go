//go:build integration

package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// Exercise the actual verification CLI/config runner and worker shell wrapper
// in a private local fixture. No worker daemon, container or external API runs.
func TestFactoryVerificationSafetyConfiguredWorkerChecks(t *testing.T) {
	for _, checkCommand := range []string{"printf configured-check-passed", "printf configured-check-failed; exit 7"} {
		t.Run(checkCommand, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			workspace := t.TempDir()
			if err := os.Mkdir(filepath.Join(workspace, ".hal"), 0o700); err != nil {
				t.Fatal(err)
			}
			config := "verify:\n  checks:\n    - id: required-check\n      name: Required check\n      command: " + checkCommand + "\n      required: true\n      timeoutSeconds: 5\n"
			if err := os.WriteFile(filepath.Join(workspace, ".hal", "config.yaml"), []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			helper := "#!/bin/sh\nexec " + shellQuote(os.Args[0]) + " -test.run=^TestFactoryVerificationSafetyCLIHelper$ -- \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "hal"), []byte(helper), 0o700); err != nil {
				t.Fatal(err)
			}
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			const remoteWorkspace = "/workspace/repo"
			record := factory.RunRecord{RunID: "configured-verification", ExecutorMode: factory.ExecutorModeSandbox, RepoPath: remoteWorkspace, SandboxName: "configured-worker"}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			target := workerRootlessCachedSandbox(record.SandboxName)
			execCalls := 0
			driver := fakeRunSandboxRuntimeDriver{
				id: sandboxruntime.DriverRootlessPodman,
				exec: func(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					execCalls++
					// Fake only the remote-to-local workspace mapping; execute the
					// production completion shell and actual verification CLI.
					args := append([]string(nil), req.Args...)
					for i := range args {
						args[i] = strings.ReplaceAll(args[i], remoteWorkspace, workspace)
					}
					command := exec.CommandContext(ctx, args[0], args[1:]...)
					command.Dir = workspace
					command.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "HAL_FACTORY_VERIFY_SAFETY_HELPER=1"}
					command.Stdout, command.Stderr = req.Stdout, req.Stderr
					err := command.Run()
					if command.ProcessState == nil {
						return nil, err
					}
					return &sandboxruntime.ExecResult{ExitCode: command.ProcessState.ExitCode()}, err
				},
				copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
					if !strings.HasPrefix(req.SourcePath, remoteWorkspace+"/") {
						t.Fatal("artifact source escaped local fixture")
					}
					data, err := os.ReadFile(workspace + strings.TrimPrefix(req.SourcePath, remoteWorkspace))
					if err != nil {
						return err
					}
					return os.WriteFile(req.DestinationPath, data, 0o600)
				},
			}
			deps := factoryRunDeps{
				now:                   func() time.Time { return time.Now().UTC() },
				loadSandbox:           func(string) (*sandbox.SandboxState, error) { return target, nil },
				resolveSandboxRuntime: func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) { return driver, nil },
			}
			policy := factory.DefaultFactoryPolicy()
			policy.VerificationRequired = true
			_, _, err := recordFactoryRunVerification(ctx, store, record, workspace, deps, policy, nil, factory.RunSecretRedactor{})
			wantFailure := strings.Contains(checkCommand, "exit 7")
			if (err != nil) != wantFailure || execCalls == 0 {
				t.Fatalf("required-check result: error=%v calls=%d", err, execCalls)
			}
			stored, err := store.LoadRun(record.RunID)
			if err != nil || stored.Verification == nil || stored.Verification.Summary.Total != 1 || len(stored.Artifacts) != 1 {
				t.Fatalf("configured verification metadata/artifacts missing: error=%v", err)
			}
			if wantFailure && stored.Verification.Summary.Failed != 1 || !wantFailure && stored.Verification.Summary.Passed != 1 {
				t.Fatalf("required check summary = %#v", stored.Verification.Summary)
			}
		})
	}
}

func TestFactoryVerificationSafetyCLIHelper(t *testing.T) {
	if os.Getenv("HAL_FACTORY_VERIFY_SAFETY_HELPER") != "1" {
		return
	}
	err := runVerifyWithDeps(context.Background(), ".", true, os.Stdout, io.Discard, verifyDeps{}, nil)
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
