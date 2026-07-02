package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestAutoSandboxManifestOmitsCapabilityReadinessWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 0, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-readiness-unavailable",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-unavailable")
	if manifest.Security != nil && manifest.Security.CapabilityReadiness != nil {
		t.Fatalf("capabilityReadiness = %#v, want omitted without readiness inputs", manifest.Security.CapabilityReadiness)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	if strings.Contains(string(payload), "capabilityReadiness") {
		t.Fatalf("manifest JSON included capabilityReadiness without readiness inputs: %s", string(payload))
	}
}

func TestRunAutoSandboxWithWriterAttachesCapabilityReadinessWithoutChangingExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 5, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(t.TempDir())
	target := autoSandboxCapabilityReadinessTarget()
	wantCommand := []string{"hal", "auto", "--base", "main"}

	var executed bool
	var targetReadyCalled bool
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-readiness-execution"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		execute: func(_ context.Context, req autoSandboxRequest, out io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			executed = true
			if !reflect.DeepEqual(req.RemoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", req.RemoteCommand, wantCommand)
			}
			if strings.Contains(strings.Join(req.RemoteCommand, " "), "readiness") {
				t.Fatalf("RemoteCommand added readiness flag: %#v", req.RemoteCommand)
			}
			if hooks.OnTargetReady == nil {
				t.Fatal("OnTargetReady hook = nil")
			}
			targetReadyCalled = true
			if err := hooks.OnTargetReady(target); err != nil {
				return autoSandboxExecutionResult{}, err
			}
			_, _ = io.WriteString(out, autoSandboxRemoteSuccessJSON("readiness preserved execution")+"\n")
			return autoSandboxExecutionResult{
				Result:          &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
				PreparedCommand: append([]string(nil), req.RemoteCommand...),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed || !targetReadyCalled {
		t.Fatalf("executed=%v targetReadyCalled=%v, want auto execution path to complete", executed, targetReadyCalled)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-execution")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("manifest Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	if manifest.WorkerRouting == nil || manifest.WorkerRouting.RuntimeDriverID != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("WorkerRouting = %#v, want unchanged rootless worker routing metadata", manifest.WorkerRouting)
	}
	requireAutoSandboxCapabilityReadinessOutput(t, manifest.Security)
}

func autoSandboxCapabilityReadinessTarget() *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     "auto-readiness",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "worker-readiness-01",
			Name:     "worker-readiness",
			Kind:     sandbox.SandboxHostKindWorker,
			Endpoint: "unix:///tmp/raw-worker-readiness.sock",
			Security: &sandbox.SandboxSecurity{
				Network: &sandbox.SandboxNetworkSecurity{
					PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
					EnforcementMode: sandbox.SandboxNetworkEnforcementModeFirewall,
				},
				Secrets: &sandbox.SandboxSecretSecurity{
					ActiveModes: []string{sandbox.SandboxSecretModeEnv},
				},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-readiness-01",
			Image:          "ghcr.io/private/raw-readiness-image:latest",
			WorkerID:       "worker-readiness-01",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
			},
		},
	}
}

func requireAutoSandboxCapabilityReadinessOutput(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want capabilityReadiness", security)
	}
	readiness := security.CapabilityReadiness
	if len(readiness.Results) == 0 {
		t.Fatal("capabilityReadiness results = empty")
	}
	var sawUnsupported bool
	var sawMetadataOnly bool
	for _, result := range readiness.Results {
		if result.State == sandbox.SandboxSecurityCapabilityReadinessUnsupported {
			sawUnsupported = true
		}
		if result.State == sandbox.SandboxSecurityCapabilityReadinessMetadataOnly {
			sawMetadataOnly = true
		}
	}
	if !sawUnsupported || !sawMetadataOnly {
		t.Fatalf("capabilityReadiness results = %#v, want unsupported request and metadata-only posture", readiness.Results)
	}
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}
	payload, err := json.Marshal(readiness)
	if err != nil {
		t.Fatalf("Marshal(capabilityReadiness) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"unix://", "/tmp/raw-worker-readiness.sock", "ghcr.io/private", "raw-readiness-image"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("capabilityReadiness leaked %q: %s", forbidden, encoded)
		}
	}
}
