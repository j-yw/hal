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

func TestRunSandboxLocalReadinessGateConfigRemainsAdvisoryOnly(t *testing.T) {
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
			if err != nil {
				t.Fatalf("runRunSandboxWithWriter() unexpected error for %s config: %v\nstdout=%s\nstderr=%s", mode, err, out.String(), errOut.String())
			}
			if !executed {
				t.Fatalf("execute hook was not called for %s local readiness gate config", mode)
			}
			if !reflect.DeepEqual(remoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
			}

			manifest := mustLoadSandboxExecutionManifest(t, store, "run-local-readiness-gate-"+mode)
			if manifest.Status != sandboxexecution.StatusSucceeded {
				t.Fatalf("Status = %q, want succeeded", manifest.Status)
			}
			requireAdvisoryOnlyReadinessDiagnostics(t, manifest.Security)
			assertRunAutoReadinessGateMetadataAbsent(t, manifest)
		})
	}
}

func TestAutoSandboxLocalReadinessGateConfigRemainsAdvisoryOnly(t *testing.T) {
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
			if err != nil {
				t.Fatalf("runAutoSandboxWithWriter() unexpected error for %s config: %v\nstdout=%s\nstderr=%s", mode, err, out.String(), errOut.String())
			}
			if !executed {
				t.Fatalf("execute hook was not called for %s local readiness gate config", mode)
			}
			if !reflect.DeepEqual(remoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
			}

			manifest := mustLoadSandboxExecutionManifest(t, store, "auto-local-readiness-gate-"+mode)
			if manifest.Status != sandboxexecution.StatusSucceeded {
				t.Fatalf("Status = %q, want succeeded", manifest.Status)
			}
			requireAdvisoryOnlyReadinessDiagnostics(t, manifest.Security)
			assertRunAutoReadinessGateMetadataAbsent(t, manifest)
		})
	}
}

func TestRunAutoReadinessGateNonWiringDocumented(t *testing.T) {
	docPath := filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase30-security-readiness-gate-verification.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read Phase 30 verification doc: %v", err)
	}
	doc := string(data)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"`hal run --sandbox` and `hal auto --sandbox` remain advisory-only for readiness diagnostics in Phase 30.",
		"factory is the first strict blocking path",
		"`compound.LoadSandboxConfig` maps `sandbox.networkPolicy` and `sandbox.secrets` into `sandbox.SecurityEvaluationRequest`.",
		"No run/auto config hook currently represents `off`, `advisory`, and `strict` readiness-gate policy modes before workspace planning, auth sync, or remote execution.",
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

func assertRunAutoReadinessGateMetadataAbsent(t *testing.T, value any) {
	t.Helper()
	encoded := mustMarshalSandboxSecurityMetadata(t, value)
	for _, forbidden := range []string{
		"securityReadinessGatePolicyMode",
		"security_readiness_gate",
		"readinessGate",
		"policyField",
		"policyMode",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("run/auto manifest recorded readiness gate metadata %q: %s", forbidden, encoded)
		}
	}
}
