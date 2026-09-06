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
	"time"

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
		{name: "provider joined exit4 and transport", output: fail, execErr: errors.Join(factoryVerificationSafetyExit(4), transportErr)},
		{name: "provider wrapped joined exit4 and transport", output: fail, execErr: fmt.Errorf("wrapped: %w", errors.Join(factoryVerificationSafetyExit(4), transportErr))},
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
		{name: "worker outer failure with complete output", worker: true, output: pass + "\nHAL_FACTORY_VERIFY_EXIT=0\n", result: &sandboxruntime.ExecResult{ExitCode: 4}},
		{name: "worker bounded output overflow", worker: true, output: pass + strings.Repeat(" ", factoryVerificationOutputLimit) + "\nHAL_FACTORY_VERIFY_EXIT=0\n", result: &sandboxruntime.ExecResult{}},
		{name: "provider bounded output overflow", output: pass + strings.Repeat(" ", factoryVerificationOutputLimit)},
		{name: "null JSON", output: "null"},
		{name: "empty object", output: "{}"},
		{name: "wrong version", output: strings.Replace(pass, "verify-v1", "verify-v0", 1)},
		{name: "unknown status", output: strings.Replace(pass, `"status":"pass"`, `"status":"unknown"`, 1)},
		{name: "summary contradicts checks", output: strings.Replace(pass, `"passed":1`, `"passed":0`, 1)},
		{name: "required failed check contradicts pass", output: strings.Replace(fail, `"status":"fail"`, `"status":"pass"`, 1)},
		{name: "duplicate status", output: strings.Replace(pass, `"status":"pass"`, `"status":"fail","status":"pass"`, 1)},
		{name: "case alias status", output: strings.Replace(pass, `"status":"pass"`, `"status":"fail","Status":"pass"`, 1)},
		{name: "duplicate summary count", output: strings.Replace(pass, `"passed":1`, `"passed":0,"passed":1`, 1)},
		{name: "case alias summary count", output: strings.Replace(pass, `"passed":1`, `"passed":0,"Passed":1`, 1)},
		{name: "duplicate check status", output: strings.Replace(pass, `"status":"pass","required"`, `"status":"fail","status":"pass","required"`, 1)},
		{name: "case alias check status", output: strings.Replace(pass, `"status":"pass","required"`, `"status":"fail","Status":"pass","required"`, 1)},
		{name: "duplicate check requirement", output: strings.Replace(pass, `"required":true`, `"required":false,"required":true`, 1)},
		{name: "case alias check requirement", output: strings.Replace(pass, `"required":true`, `"required":false,"Required":true`, 1)},
		{name: "null check requirement", output: strings.Replace(pass, `"required":true`, `"required":null`, 1)},
		{name: "missing check requirement", output: strings.Replace(pass, `"required":true,`, ``, 1)},
		{name: "null summary count", output: strings.Replace(pass, `"failed":0`, `"failed":null`, 1)},
		{name: "null checks", output: `{"schemaVersion":"verify-v1","status":"pass","summary":{},"checks":null}`},
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

func TestFactoryVerificationSafetyPreservesEmptyChecksAndAdditiveFields(t *testing.T) {
	data, err := json.Marshal(verify.Result{SchemaVersion: verify.SchemaVersion, Status: verify.StatusPass, Checks: []verify.CheckResult{}})
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"total":0`, `"total":0,"futureCount":42`, 1))
	result, err := parseFactorySandboxVerifyResult(data)
	if err != nil || result == nil || result.Checks == nil || result.Summary.Total != 0 {
		t.Fatalf("valid empty checks rejected: result=%v error=%v", result, err)
	}
	if _, err := parseFactorySandboxVerifyResult([]byte(strings.Replace(string(data), `"checks":[]`, `"checks":null`, 1))); err == nil {
		t.Fatal("null checks accepted with otherwise valid empty result")
	}
	data = []byte(strings.Replace(factoryVerificationSafetyPayload(t, verify.StatusPass), `"required":true`, `"required":true,"futureCheck":{"allowed":true}`, 1))
	if _, err := parseFactorySandboxVerifyResult(data); err != nil {
		t.Fatalf("additive check fields rejected: %v", err)
	}
}

func TestFactoryVerificationSafetyPreservesCompletedPolicyResults(t *testing.T) {
	for _, worker := range []bool{false, true} {
		for _, status := range []string{verify.StatusPass, verify.StatusWarn, verify.StatusFail} {
			for _, required := range []bool{false, true} {
				t.Run(fmt.Sprintf("worker=%t/status=%s/required=%t", worker, status, required), func(t *testing.T) {
					var result verify.Result
					if err := json.Unmarshal([]byte(factoryVerificationSafetyPayload(t, status)), &result); err != nil {
						t.Fatal(err)
					}
					result.Artifacts = nil
					data, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					// Additive public fields remain compatible with verify-v1.
					output := strings.TrimSuffix(string(data), "}") + `,"futureField":{"allowed":true}}`
					code := 0
					var execErr error
					if status == verify.StatusFail {
						code = 4
						execErr = fmt.Errorf("wrapped exit: %w", factoryVerificationSafetyExit(4))
					}
					if worker {
						output += fmt.Sprintf("\nHAL_FACTORY_VERIFY_EXIT=%d\n", code)
						execErr = nil
					}
					store, record, deps, copies := factoryVerificationSafetyFixture(t, worker, output, &sandboxruntime.ExecResult{}, execErr)
					deps.now = func() time.Time { return time.Date(2026, 9, 6, 1, 0, 0, 0, time.UTC) }
					policy := factory.DefaultFactoryPolicy()
					policy.VerificationRequired = required
					_, _, err = recordFactoryRunVerification(context.Background(), store, record, ".", deps, policy, nil, factory.RunSecretRedactor{})
					if wantErr := required && status == verify.StatusFail; (err != nil) != wantErr {
						t.Fatalf("verification policy error=%v, want failure=%t", err, wantErr)
					}
					stored, err := store.LoadRun(record.RunID)
					if err != nil || stored.Verification == nil || stored.Verification.Summary != result.Summary || *copies != 0 {
						t.Fatalf("completed verification facts not preserved: error=%v", err)
					}
				})
			}
		}
	}
}

func TestFactoryVerificationSafetyRejectsCancelledCallerAfterCompletion(t *testing.T) {
	for _, worker := range []bool{false, true} {
		for _, status := range []string{verify.StatusPass, verify.StatusFail} {
			t.Run(fmt.Sprintf("worker=%t/status=%s", worker, status), func(t *testing.T) {
				output := factoryVerificationSafetyPayload(t, status)
				var execErr error
				code := 0
				if status == verify.StatusFail {
					code = 4
					execErr = factoryVerificationSafetyExit(4)
				}
				if worker {
					output += fmt.Sprintf("\nHAL_FACTORY_VERIFY_EXIT=%d\n", code)
					execErr = nil
				}
				store, record, deps, copies := factoryVerificationSafetyFixture(t, worker, output, &sandboxruntime.ExecResult{}, execErr)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				result, _, err := runFactorySandboxRemoteVerification(ctx, store, ".", record, deps, nil, factory.RunSecretRedactor{})
				if !errors.Is(err, context.Canceled) || result != nil || *copies != 0 {
					t.Fatalf("cancelled caller accepted completed output: result=%v err=%v", result != nil, err)
				}
			})
		}
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
	} else if status == verify.StatusWarn {
		result.Summary = verify.Summary{Total: 1, Failed: 1, Warnings: 1}
		result.Checks[0].Required = false
		result.Checks[0].Status = verify.CheckStatusFail
		result.Checks[0].ExitCode = 1
		result.Warnings = []verify.Warning{{CheckID: "required-check", Status: verify.CheckStatusFail}}
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
