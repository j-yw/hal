package cmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestRunSandboxCapabilityReadinessOmittedWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 10, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID: "run-readiness-unavailable",
		ProjectDir:  "/repo",
		Security:    runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-unavailable")
	if manifest.Security == nil {
		t.Fatal("Security = nil, want existing run security metadata preserved")
	}
	if manifest.Security.CapabilityReadiness != nil {
		t.Fatalf("capabilityReadiness = %#v, want omitted without run projection inputs", manifest.Security.CapabilityReadiness)
	}
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if strings.Contains(encoded, "capabilityReadiness") {
		t.Fatalf("security JSON included capabilityReadiness without run projection inputs: %s", encoded)
	}
}

func TestRunSandboxManifestAttachesSanitizedProjectedCapabilityReadiness(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 15, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	req := runSandboxRequest{
		ExecutionID:         "run-readiness-projected",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	target := runSandboxCapabilityReadinessTarget(req.Security)

	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &startedAt, target); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-projected")
	readiness := manifest.Security.CapabilityReadiness
	if readiness == nil {
		t.Fatal("capabilityReadiness = nil, want projected readiness output")
	}
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessUnsupported,
		sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
	)
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyNetworkProxy,
		sandbox.SandboxSecurityCapabilityNetworkProxyEnforcement,
	)
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyCredentialProxy,
		sandbox.SandboxSecurityCapabilityCredentialProxy,
	)
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}

	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if !strings.Contains(encoded, "capabilityReadiness") {
		t.Fatalf("security JSON omitted capabilityReadiness: %s", encoded)
	}
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "run sandbox capability readiness", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "run sandbox capability readiness", readiness)
}

func TestRunSandboxCapabilityReadinessDoesNotBlockOrAlterExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest())

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
			return "run-readiness-nonblocking"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/readiness", nil },
		execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			executed = true
			remoteCommand = append([]string(nil), req.RemoteCommand...)
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			if _, err := io.WriteString(out, "remote-output\n"); err != nil {
				return runSandboxExecutionResult{}, err
			}
			return runSandboxExecutionResult{
				Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed {
		t.Fatal("execute hook was not called")
	}
	wantCommand := []string{"hal", "run", "--base", "main"}
	if !reflect.DeepEqual(remoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
	}
	if out.String() != "remote-output\n" {
		t.Fatalf("stdout = %q, want remote output unchanged", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-nonblocking")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Security == nil || manifest.Security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want non-blocking readiness metadata attached", manifest.Security)
	}
}

func runSandboxCapabilityReadinessTarget(securityReq sandbox.SecurityEvaluationRequest) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       "sandbox-readiness-01",
		Name:     "readiness-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "host-readiness-01",
			Name: "readiness-host",
			Kind: sandbox.SandboxHostKindSSH,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-readiness-01",
		},
		Security: sandbox.EvaluateSandboxSecurity(securityReq),
	}
}

func requireRunSandboxCapabilityReadinessResult(t *testing.T, output *sandbox.SandboxSecurityCapabilityReadinessOutput, state sandbox.SandboxSecurityCapabilityReadinessState, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName) {
	t.Helper()
	if output == nil {
		t.Fatal("capabilityReadiness = nil")
	}
	for _, result := range output.Results {
		if result.State != state {
			continue
		}
		for _, metadata := range []*sandbox.SandboxSecurityCapabilityMetadata{result.Metadata, result.Requested, result.Ready} {
			if metadata == nil {
				continue
			}
			if metadata.Family == family && metadata.Capability == capability {
				return
			}
		}
	}
	t.Fatalf("capabilityReadiness missing %s result for %s/%s: %#v", state, family, capability, output.Results)
}
