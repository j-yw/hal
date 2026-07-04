package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestRunSandboxLocalReadinessGateConfigPropagatesDecision(t *testing.T) {
	for _, mode := range []string{"strict", "advisory"} {
		t.Run(mode, func(t *testing.T) {
			startedAt := time.Date(2026, 7, 2, 12, 10, 0, 0, time.UTC)
			finishedAt := startedAt.Add(2 * time.Second)
			projectDir := t.TempDir()
			writeUnsupportedRunAutoReadinessGateConfig(t, projectDir, mode)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			wantCommand := []string{"hal", "run", "--base", "main"}

			var executed bool
			var remoteCommand []string
			var out bytes.Buffer
			var errOut bytes.Buffer
			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				Base:        "main",
				BaseChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "run-local-readiness-gate-" + mode
				},
				now:           runSandboxTestClock(startedAt, finishedAt),
				workingDir:    func() (string, error) { return projectDir, nil },
				repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
				currentBranch: func(string) (string, error) { return "feature/readiness-gate-config-" + mode, nil },
				execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					executed = true
					remoteCommand = append([]string(nil), req.RemoteCommand...)
					assertRunAutoSandboxSecurityConfigLoaded(t, req.Security)
					target := runSandboxCapabilityReadinessTarget(req.Security)
					if hooks.OnTargetReady != nil {
						if err := hooks.OnTargetReady(target); err != nil {
							return runSandboxExecutionResult{}, err
						}
					}
					if _, err := io.WriteString(out, "run executed without strict readiness gate\n"); err != nil {
						return runSandboxExecutionResult{}, err
					}
					return runSandboxExecutionResult{
						Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
					}, nil
				},
			})
			if mode == "strict" {
				if err == nil {
					t.Fatalf("runRunSandboxWithWriter() error = nil for strict config, want readiness gate block\nstdout=%s\nstderr=%s", out.String(), errOut.String())
				}
			} else if err != nil {
				t.Fatalf("runRunSandboxWithWriter() unexpected error for %s config: %v\nstdout=%s\nstderr=%s", mode, err, out.String(), errOut.String())
			}
			if !executed {
				t.Fatalf("execute hook was not called for %s local readiness gate config", mode)
			}
			if !reflect.DeepEqual(remoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
			}

			manifest := mustLoadSandboxExecutionManifest(t, store, "run-local-readiness-gate-"+mode)
			wantStatus := sandboxexecution.StatusSucceeded
			wantOutcome := sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory
			wantCode := sandbox.SandboxSecurityCapabilityReadinessGateCodeAdvisory
			wantMode := sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory
			if mode == "strict" {
				wantStatus = sandboxexecution.StatusFailed
				wantOutcome = sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked
				wantCode = sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked
				wantMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
			}
			if manifest.Status != wantStatus {
				t.Fatalf("Status = %q, want %q", manifest.Status, wantStatus)
			}
			requireAdvisoryOnlyReadinessDiagnostics(t, manifest.Security)
			requireRunAutoReadinessGateDecision(t, manifest.Security, wantMode, wantOutcome, wantCode)
		})
	}
}

func TestAutoSandboxLocalReadinessGateConfigPropagatesDecision(t *testing.T) {
	for _, mode := range []string{"strict", "advisory"} {
		t.Run(mode, func(t *testing.T) {
			startedAt := time.Date(2026, 7, 2, 12, 20, 0, 0, time.UTC)
			finishedAt := startedAt.Add(3 * time.Second)
			projectDir := t.TempDir()
			writeUnsupportedRunAutoReadinessGateConfig(t, projectDir, mode)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			wantCommand := []string{"hal", "auto", "--base", "main"}

			var executed bool
			var remoteCommand []string
			var out bytes.Buffer
			var errOut bytes.Buffer
			err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
				Base:        "main",
				BaseChanged: true,
			}, &out, &errOut, autoSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "auto-local-readiness-gate-" + mode
				},
				now: runSandboxTestClock(startedAt, finishedAt),
				planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return autoSandboxTestPlan(projectDir), nil
				},
				execute: func(_ context.Context, req autoSandboxRequest, out io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
					executed = true
					remoteCommand = append([]string(nil), req.RemoteCommand...)
					assertRunAutoSandboxSecurityConfigLoaded(t, req.Security)
					target := runSandboxCapabilityReadinessTarget(req.Security)
					if hooks.OnTargetReady != nil {
						if err := hooks.OnTargetReady(target); err != nil {
							return autoSandboxExecutionResult{}, err
						}
					}
					if _, err := io.WriteString(out, autoSandboxRemoteSuccessJSON("auto executed without strict readiness gate")+"\n"); err != nil {
						return autoSandboxExecutionResult{}, err
					}
					return autoSandboxExecutionResult{
						Result:          &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
						PreparedCommand: append([]string(nil), req.RemoteCommand...),
					}, nil
				},
			})
			if mode == "strict" {
				if err == nil {
					t.Fatalf("runAutoSandboxWithWriter() error = nil for strict config, want readiness gate block\nstdout=%s\nstderr=%s", out.String(), errOut.String())
				}
			} else if err != nil {
				t.Fatalf("runAutoSandboxWithWriter() unexpected error for %s config: %v\nstdout=%s\nstderr=%s", mode, err, out.String(), errOut.String())
			}
			if !executed {
				t.Fatalf("execute hook was not called for %s local readiness gate config", mode)
			}
			if !reflect.DeepEqual(remoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
			}

			manifest := mustLoadSandboxExecutionManifest(t, store, "auto-local-readiness-gate-"+mode)
			wantStatus := sandboxexecution.StatusSucceeded
			wantOutcome := sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory
			wantCode := sandbox.SandboxSecurityCapabilityReadinessGateCodeAdvisory
			wantMode := sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory
			if mode == "strict" {
				wantStatus = sandboxexecution.StatusFailed
				wantOutcome = sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked
				wantCode = sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked
				wantMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
			}
			if manifest.Status != wantStatus {
				t.Fatalf("Status = %q, want %q", manifest.Status, wantStatus)
			}
			requireAdvisoryOnlyReadinessDiagnostics(t, manifest.Security)
			requireRunAutoReadinessGateDecision(t, manifest.Security, wantMode, wantOutcome, wantCode)
		})
	}
}

func TestRunAutoReadinessGateWiringDocumented(t *testing.T) {
	docPath := filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase30-security-readiness-gate-verification.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read Phase 30 verification doc: %v", err)
	}
	doc := string(data)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"`hal run --sandbox` and `hal auto --sandbox` attach readiness-gate decisions from local `sandbox.securityReadinessGatePolicyMode` when configured.",
		"`compound.LoadSandboxConfig` maps `sandbox.networkPolicy`, `sandbox.secrets`, and `sandbox.securityReadinessGatePolicyMode` into command security settings.",
		"Strict run/auto readiness-gate decisions block before remote command execution.",
		"Default run/auto behavior remains compatibility-mode advisory metadata.",
		"No run or auto command flag is added for readiness-gate strict mode.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("Phase 30 verification doc missing run/auto non-wiring statement %q", want)
		}
	}
}

func writeUnsupportedRunAutoReadinessGateConfig(t *testing.T, projectDir, mode string) {
	t.Helper()
	halDir := filepath.Join(projectDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("create .hal dir: %v", err)
	}
	config := fmt.Sprintf(`sandbox:
  provider: daytona
  securityReadinessGatePolicyMode: %s
  networkPolicy:
    preset: deny_by_default
  secrets:
    requestedModes:
      - http_proxy
    activeModes:
      - http_proxy
`, mode)
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
}

func assertRunAutoSandboxSecurityConfigLoaded(t *testing.T, security sandbox.SecurityEvaluationRequest) {
	t.Helper()
	if security.RequestedNetworkPolicyIntent == nil {
		t.Fatalf("RequestedNetworkPolicyIntent = nil, want configured sandbox.networkPolicy loaded")
	}
	if security.RequestedNetworkPolicyIntent.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("RequestedNetworkPolicyIntent.Preset = %q, want %q", security.RequestedNetworkPolicyIntent.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if !reflect.DeepEqual(security.RequestedSecretModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("RequestedSecretModes = %#v, want http_proxy from sandbox.secrets", security.RequestedSecretModes)
	}
	if !reflect.DeepEqual(security.ActiveSecretModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("ActiveSecretModes = %#v, want http_proxy from sandbox.secrets", security.ActiveSecretModes)
	}
	if !security.CompatibilityAuthSync {
		t.Fatal("CompatibilityAuthSync = false, want legacy auth sync preserved")
	}
}

func requireAdvisoryOnlyReadinessDiagnostics(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("Security = %#v, want advisory readiness diagnostics", security)
	}
	if !security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("CapabilityReadinessDiagnostics = %#v, want wouldBlockStrictGate advisory metadata", security.CapabilityReadinessDiagnostics)
	}
	if security.CapabilityReadinessDiagnostics.Status != sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory ||
		security.CapabilityReadinessDiagnostics.HighestSeverity != sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning ||
		!security.CapabilityReadinessDiagnostics.AdvisoryOnly {
		t.Fatalf("CapabilityReadinessDiagnostics = %#v, want advisory-only warning summary", security.CapabilityReadinessDiagnostics)
	}
}

func requireRunAutoReadinessGateDecision(t *testing.T, security *sandbox.SandboxSecurity, wantMode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode, wantOutcome sandbox.SandboxSecurityCapabilityReadinessGateOutcome, wantCode sandbox.SandboxSecurityCapabilityReadinessGateCode) {
	t.Helper()
	if security == nil || security.SecurityReadinessGate == nil {
		t.Fatalf("Security = %#v, want readiness gate decision", security)
	}
	gate := security.SecurityReadinessGate
	if gate.PolicyMode != wantMode || gate.Outcome != wantOutcome || gate.Code != wantCode {
		t.Fatalf("securityReadinessGate = %#v, want mode=%s outcome=%s code=%s", gate, wantMode, wantOutcome, wantCode)
	}
	if gate.Counts == nil || gate.Counts.StrictBlocking == 0 || len(gate.Counts.ReasonCodeCounts) == 0 {
		t.Fatalf("securityReadinessGate counts = %#v, want strict-blocking aggregate counts", gate.Counts)
	}
}
