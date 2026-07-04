package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestUS006RunSandboxStrictSelectionJSONRendersAndPersistsDecision(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 4, 16, 10, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := filepath.Join(t.TempDir(), "repo")
	writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))
	target := us007UnsafeCommandTarget("us006-strict-microvm-target", sandbox.SandboxRuntimeDriverMicroVM)

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		Base:                  "main",
		BaseChanged:           true,
		SandboxName:           target.Name,
		SandboxNameChanged:    true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
		newExecutionID: func(time.Time) string {
			return "run-us006-strict-selection-json"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return us007WorkspacePlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{us007MicroVMHost()}, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default target fallback should not run for strict secure-default selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provisioning should not run for strict secure-default missing proof")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed after strict secure-default block")
			return nil, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			t.Fatal("credential discovery should not run after strict secure-default block")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want JSON error result\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if result.OK {
		t.Fatalf("RunResult.OK = true, want false")
	}
	us006AssertStrictBlockedDecision(t, "run JSON", result.SecurityReadinessGate)
	us007AssertSecureDefaultDecisionSafe(t, "run JSON output", out.String(), us007ForbiddenSecureDefaultFragments()...)

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-us006-strict-selection-json")
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest status = %q, want failed strict block", manifest.Status)
	}
	if manifest.Security == nil {
		t.Fatal("manifest security = nil, want persisted readiness decision")
	}
	us006AssertStrictBlockedDecision(t, "run manifest", manifest.Security.SecurityReadinessGate)
	us007AssertSecureDefaultDecisionSafe(t, "run manifest", manifest.Security, us007ForbiddenSecureDefaultFragments()...)
}

func TestUS006AutoSandboxStrictSelectionJSONRendersAndPersistsDecision(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 4, 16, 15, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := filepath.Join(t.TempDir(), "repo")
	writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions"))
	target := us007UnsafeCommandTarget("us006-auto-strict-microvm-target", sandbox.SandboxRuntimeDriverMicroVM)

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		Base:                  "main",
		BaseChanged:           true,
		SandboxName:           target.Name,
		SandboxNameChanged:    true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
		newExecutionID: func(time.Time) string {
			return "auto-us006-strict-selection-json"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return us007WorkspacePlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{us007MicroVMHost()}, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default target fallback should not run for strict secure-default selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provisioning should not run for strict secure-default missing proof")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed after strict secure-default block")
			return nil, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			t.Fatal("credential discovery should not run after strict secure-default block")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want JSON error result\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if result.OK {
		t.Fatalf("AutoResult.OK = true, want false")
	}
	us006AssertStrictBlockedDecision(t, "auto JSON", result.SecurityReadinessGate)
	us007AssertSecureDefaultDecisionSafe(t, "auto JSON output", out.String(), us007ForbiddenSecureDefaultFragments()...)

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-us006-strict-selection-json")
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest status = %q, want failed strict block", manifest.Status)
	}
	if manifest.Security == nil {
		t.Fatal("manifest security = nil, want persisted readiness decision")
	}
	us006AssertStrictBlockedDecision(t, "auto manifest", manifest.Security.SecurityReadinessGate)
	us007AssertSecureDefaultDecisionSafe(t, "auto manifest", manifest.Security, us007ForbiddenSecureDefaultFragments()...)
}

func TestUS006RunSandboxJSONAugmentsAllowedAndCompatibilityGateDecisions(t *testing.T) {
	tests := []struct {
		name          string
		strictConfig  bool
		target        *sandbox.SandboxState
		wantMode      sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
		wantOutcome   sandbox.SandboxSecurityCapabilityReadinessGateOutcome
		wantReason    sandbox.SandboxSecurityCapabilityReadinessGateReasonCode
		wantStrictMin int
	}{
		{
			name:         "proof complete strict allowed",
			strictConfig: true,
			target:       us006ProofCompleteRunTarget(),
			wantMode:     sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			wantOutcome:  sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			wantReason:   sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		},
		{
			name:          "compatibility advisory",
			target:        runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest()),
			wantMode:      sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
			wantOutcome:   sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
			wantReason:    sandbox.SandboxSecurityCapabilityReadinessGateReasonPolicyCompatibility,
			wantStrictMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())
			startedAt := time.Date(2026, 7, 4, 16, 20, 0, 0, time.UTC)
			finishedAt := startedAt.Add(time.Second)
			projectDir := filepath.Join(t.TempDir(), "repo")
			if tt.strictConfig {
				writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
			}
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))

			var out bytes.Buffer
			var errOut bytes.Buffer
			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				JSON:        true,
				JSONChanged: true,
				Base:        "main",
				BaseChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
				newExecutionID: func(time.Time) string {
					return "run-us006-" + strings.ReplaceAll(tt.name, " ", "-")
				},
				now:        runSandboxTestClock(startedAt, finishedAt),
				workingDir: func() (string, error) { return projectDir, nil },
				planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return us007WorkspacePlan(projectDir), nil
				},
				execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					if hooks.OnTargetReady != nil {
						if err := hooks.OnTargetReady(tt.target); err != nil {
							return runSandboxExecutionResult{}, err
						}
					}
					if _, err := io.WriteString(out, `{"contractVersion":1,"ok":true,"summary":"us006 complete"}`+"\n"); err != nil {
						return runSandboxExecutionResult{}, err
					}
					return runSandboxExecutionResult{
						Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(tt.target)},
						RemoteStarted: true,
					}, nil
				},
			})
			if err != nil {
				t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
			}

			var result RunResult
			decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
			gate := result.SecurityReadinessGate
			if gate == nil {
				t.Fatalf("RunResult.SecurityReadinessGate = nil; stdout=%s", out.String())
			}
			if gate.PolicyMode != tt.wantMode || gate.Outcome != tt.wantOutcome || gate.Reason != tt.wantReason {
				t.Fatalf("RunResult.SecurityReadinessGate = %#v, want mode=%s outcome=%s reason=%s", gate, tt.wantMode, tt.wantOutcome, tt.wantReason)
			}
			if gate.Counts == nil {
				t.Fatalf("RunResult.SecurityReadinessGate counts = nil, want aggregate counts")
			}
			if gate.Counts.StrictBlocking < tt.wantStrictMin {
				t.Fatalf("RunResult.SecurityReadinessGate counts = %#v, want strictBlocking >= %d", gate.Counts, tt.wantStrictMin)
			}
			us007AssertSecureDefaultDecisionSafe(t, tt.name+" JSON output", out.String(), us007ForbiddenSecureDefaultFragments()...)
		})
	}
}

func TestUS006RunSandboxStrictHumanErrorIncludesGateCountsAndReasons(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 4, 16, 25, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := filepath.Join(t.TempDir(), "repo")
	writeUnsupportedRunAutoReadinessGateConfig(t, projectDir, string(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict))
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
		newExecutionID: func(time.Time) string {
			return "run-us006-strict-human-error"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return us007WorkspacePlan(projectDir), nil
		},
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			target := runSandboxCapabilityReadinessTarget(req.Security)
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			t.Fatal("strict readiness gate should block before remote command output")
			return runSandboxExecutionResult{}, nil
		},
	})
	if err == nil {
		t.Fatalf("runRunSandboxWithWriter() error = nil, want strict readiness gate block\nstdout=%s\nstderr=%s", out.String(), errOut.String())
	}
	message := err.Error()
	for _, want := range []string{
		"security readiness gate blocked",
		"Secure default readiness: strict blocked",
		"strict secure-default would block",
		"strictBlocking=",
		"reason codes ",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("human error = %q, want %q", message, want)
		}
	}
	us007AssertSecureDefaultDecisionSafe(t, "human strict error", message, projectDir, us007UnsafeRemote())
}

func us006ProofCompleteRunTarget() *sandbox.SandboxState {
	readiness := us007ProofCompleteReadinessOutput()
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		*readiness,
	)
	return &sandbox.SandboxState{
		ID:       "us006-proof-complete-id",
		Name:     "us006-proof-complete",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
		Security: &sandbox.SandboxSecurity{
			CapabilityReadiness:   readiness,
			SecurityReadinessGate: &decision,
		},
	}
}

func writeStrictOnlyRunAutoReadinessGateConfig(t *testing.T, projectDir string) {
	t.Helper()
	halDir := filepath.Join(projectDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("create .hal dir: %v", err)
	}
	config := `sandbox:
  securityReadinessGatePolicyMode: strict
`
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
}

func us006AssertStrictBlockedDecision(t *testing.T, label string, gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	if gate == nil {
		t.Fatalf("%s securityReadinessGate = nil, want strict blocked decision", label)
	}
	if gate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict ||
		gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked ||
		gate.Code != sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked {
		t.Fatalf("%s securityReadinessGate = %#v, want strict blocked decision", label, gate)
	}
	if gate.Counts == nil || gate.Counts.StrictBlocking == 0 || len(gate.Counts.ReasonCodeCounts) == 0 {
		t.Fatalf("%s securityReadinessGate counts = %#v, want strict-blocking reason-code counts", label, gate.Counts)
	}
	if gate.Counts.ReasonCodeCounts[sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing] == 0 {
		t.Fatalf("%s reasonCodeCounts = %#v, want microVM readiness missing", label, gate.Counts.ReasonCodeCounts)
	}
}
