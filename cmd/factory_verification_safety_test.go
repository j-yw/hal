package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/verify"
)

func TestFactoryVerificationSafetyRejectsUnprovenExecution(t *testing.T) {
	pass := factoryVerificationSafetyPayload(t, verify.StatusPass)
	fail := factoryVerificationSafetyPayload(t, verify.StatusFail)
	transportErr := errors.New("transport /private/operator/socket secret-verification-canary")
	for _, tt := range []struct {
		name    string
		worker  bool
		output  string
		result  *sandboxruntime.ExecResult
		execErr error
	}{
		{name: "provider transport with pass JSON", output: pass, execErr: transportErr},
		{name: "provider transport with fail JSON", output: fail, execErr: transportErr},
		{name: "provider exit4 contradicts pass", output: pass, execErr: factoryVerificationSafetyExit(4)},
		{name: "provider exit127 with pass JSON", output: pass, execErr: factoryVerificationSafetyExit(127)},
		{name: "provider exit0 contradicts fail", output: fail},
		{name: "provider cancelled with pass JSON", output: pass, execErr: context.Canceled},
		{name: "worker transport with pass JSON", worker: true, output: pass, result: &sandboxruntime.ExecResult{}, execErr: transportErr},
		{name: "worker missing result", worker: true, output: pass},
		{name: "worker exit4 plus transport is not a check failure", worker: true, output: fail, result: &sandboxruntime.ExecResult{ExitCode: 4}, execErr: transportErr},
		{name: "worker missing completion footer", worker: true, output: pass, result: &sandboxruntime.ExecResult{}},
		{name: "worker interrupted footer", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=", result: &sandboxruntime.ExecResult{}},
		{name: "worker duplicated footer", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=0\nHAL_FACTORY_VERIFY_EXIT=0\n", result: &sandboxruntime.ExecResult{}},
		{name: "worker footer before JSON", worker: true, output: "\nHAL_FACTORY_VERIFY_EXIT=0\n" + pass, result: &sandboxruntime.ExecResult{}},
		{name: "worker footer trailing garbage", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=0\ngarbage", result: &sandboxruntime.ExecResult{}},
		{name: "worker exit4 contradicts pass", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=4\n", result: &sandboxruntime.ExecResult{}},
		{name: "worker exit0 contradicts fail", worker: true, output: fail + "\nHAL_FACTORY_VERIFY_EXIT=0\n", result: &sandboxruntime.ExecResult{}},
		{name: "worker unknown exit", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=127\n", result: &sandboxruntime.ExecResult{}},
		{name: "null JSON", output: "null"},
		{name: "empty object", output: "{}"},
		{name: "wrong version", output: strings.Replace(pass, "verify-v1", "verify-v0", 1)},
		{name: "unknown status", output: strings.Replace(pass, `"status":"pass"`, `"status":"unknown"`, 1)},
		{name: "multiple documents", output: pass + pass},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, record, deps, copies := factoryVerificationSafetyFixture(t, tt.worker, tt.output, tt.result, tt.execErr)
			result, _, err := runFactorySandboxRemoteVerification(context.Background(), store, ".", record, deps, nil, factory.RunSecretRedactor{})
			if err == nil || result != nil {
				t.Errorf("unproven verification accepted: result=%v error=%v", result != nil, err)
			}
			if err != nil && (strings.Contains(err.Error(), "secret-verification-canary") || strings.Contains(err.Error(), "/private/operator")) {
				t.Error("verification error exposed raw execution details")
			}
			if tt.execErr != nil && !errors.Is(err, tt.execErr) {
				t.Error("verification error lost original execution error identity")
			}
			stored, loadErr := store.LoadRun(record.RunID)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if *copies != 0 || len(stored.Artifacts) != 0 || stored.Verification != nil {
				t.Error("rejected execution collected or persisted verification artifacts")
			}
		})
	}
}

func factoryVerificationSafetyPayload(t *testing.T, status string) string {
	t.Helper()
	result := verify.Result{
		SchemaVersion: verify.SchemaVersion, Status: status,
		Summary:   verify.Summary{Total: 1, Passed: 1},
		Checks:    []verify.CheckResult{{ID: "required-check", Status: verify.CheckStatusPass, Required: true}},
		Artifacts: []verify.ArtifactReference{{CheckID: "required-check", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/check.txt"}},
	}
	if status == verify.StatusFail {
		result.Summary = verify.Summary{Total: 1, Failed: 1}
		result.Checks[0].Status = verify.CheckStatusFail
		result.Checks[0].ExitCode = 1
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func factoryVerificationSafetyFixture(t *testing.T, worker bool, output string, result *sandboxruntime.ExecResult, execErr error) (factory.Store, factory.RunRecord, factoryRunDeps, *int) {
	t.Helper()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	record := factory.RunRecord{RunID: "verification-safety", ExecutorMode: factory.ExecutorModeSandbox, RepoPath: "/workspace/repo", SandboxName: "verification-sandbox"}
	if err := store.SaveRun(&record); err != nil {
		t.Fatal(err)
	}
	target := &sandbox.SandboxState{Name: record.SandboxName, Provider: "legacy-provider"}
	if worker {
		target = workerRootlessCachedSandbox(record.SandboxName)
	}
	copies := 0
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if len(req.Args) > 0 && req.Args[0] == "test" {
				copies++
				return &sandboxruntime.ExecResult{ExitCode: 1}, errors.New("unexpected artifact inspection")
			}
			_, _ = io.WriteString(req.Stdout, output)
			return result, execErr
		},
		copyOut: func(context.Context, sandboxruntime.CopyRequest) error {
			copies++
			return errors.New("unexpected artifact copy")
		},
	}
	deps := factoryRunDeps{
		loadSandbox:           func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveSandboxRuntime: func(string, *sandbox.SandboxState) (sandboxruntime.Driver, error) { return driver, nil },
		resolveProvider:       func(string, string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, out io.Writer) error {
			_, _ = io.WriteString(out, output)
			return execErr
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			copies++
			return errors.New("unexpected artifact copy")
		},
	}
	return store, record, deps, &copies
}

type factoryVerificationSafetyExit int

func (err factoryVerificationSafetyExit) Error() string { return fmt.Sprintf("exit status %d", err) }
func (err factoryVerificationSafetyExit) ExitCode() int { return int(err) }
