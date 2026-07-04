package cmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/securedefaultfixtures"
)

func TestUS009RunSandboxJSONAndManifestUseSharedSecureDefaultDecision(t *testing.T) {
	tests := []struct {
		name       string
		fixture    securedefaultfixtures.EvidenceSet
		wantOK     bool
		wantStatus sandboxexecution.Status
	}{
		{
			name:       "accepted complete evidence",
			fixture:    securedefaultfixtures.CompleteAcceptedEvidenceSet(),
			wantOK:     true,
			wantStatus: sandboxexecution.StatusSucceeded,
		},
		{
			name: "rejected missing microvm proof",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(
				securedefaultfixtures.OmitProof(securedefaultfixtures.ProofMicroVMReadiness),
			),
			wantOK:     false,
			wantStatus: sandboxexecution.StatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())

			startedAt := time.Date(2026, 7, 4, 18, 9, 0, 0, time.UTC)
			finishedAt := startedAt.Add(time.Second)
			projectDir := filepath.Join(t.TempDir(), "repo")
			writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))
			executionID := "run-us009-" + us009RunSurfaceSlug(tt.name)
			target := us009RunSurfaceTarget(executionID, tt.fixture)

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
					return executionID
				},
				now:        runSandboxTestClock(startedAt, finishedAt),
				workingDir: func() (string, error) { return projectDir, nil },
				planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return us009RunSurfaceWorkspacePlan(projectDir), nil
				},
				execute: func(_ context.Context, _ runSandboxRequest, stdout io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					if hooks.OnTargetReady != nil {
						if err := hooks.OnTargetReady(target); err != nil {
							return runSandboxExecutionResult{}, err
						}
					}
					if _, err := io.WriteString(stdout, `{"contractVersion":1,"ok":true,"iterations":1,"complete":false,"summary":"us009 run surface"}`+"\n"); err != nil {
						return runSandboxExecutionResult{}, err
					}
					return runSandboxExecutionResult{
						Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
						RemoteStarted: true,
					}, nil
				},
			})
			if err != nil {
				t.Fatalf("runRunSandboxWithWriter() error = %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
			}

			var result RunResult
			decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
			if result.OK != tt.wantOK {
				t.Fatalf("RunResult.OK = %v, want %v\nstdout=%s", result.OK, tt.wantOK, out.String())
			}
			us009AssertRunSurfaceGateMatchesFixture(t, "run JSON", result.SecurityReadinessGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "run JSON", out.String())

			manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
			if manifest.Status != tt.wantStatus {
				t.Fatalf("manifest status = %q, want %q", manifest.Status, tt.wantStatus)
			}
			if manifest.Security == nil {
				t.Fatal("manifest security = nil, want secure-default decision metadata")
			}
			us009AssertRunSurfaceGateMatchesFixture(t, "run manifest", manifest.Security.SecurityReadinessGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "run manifest security", manifest.Security)
		})
	}
}

func us009RunSurfaceTarget(name string, fixture securedefaultfixtures.EvidenceSet) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name + "-target",
		Name:     name,
		Provider: "phase60",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "us009-host",
			Name:              "us009 host",
			Kind:              sandbox.SandboxHostKindLocal,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			TemplateLock:   fixture.WorkerRuntime.TemplateLock,
		},
		Workspace: fixture.WorkerRuntime.Workspace,
		Security:  fixture.Security(),
	}
}

func us009RunSurfaceWorkspacePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.invalid:org/repo.git",
		Branch:      "phase60-secure-default",
		Upstream:    "origin/phase60-secure-default",
		SyncRef:     "refs/remotes/origin/phase60-secure-default",
	}
}

func us009AssertRunSurfaceGateMatchesFixture(t *testing.T, label string, got *sandbox.SandboxSecurityCapabilityReadinessGateDecision, want sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	sanitizedWant := sandbox.SanitizeSandboxSecurityCapabilityReadinessGateDecision(want)
	sanitizedGot := sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(got)
	if sanitizedGot == nil {
		t.Fatalf("%s securityReadinessGate = nil, want %#v", label, sanitizedWant)
	}
	if !reflect.DeepEqual(*sanitizedGot, sanitizedWant) {
		t.Fatalf("%s securityReadinessGate = %#v, want shared fixture decision %#v", label, *sanitizedGot, sanitizedWant)
	}
}

func us009AssertRunSurfaceSafe(t *testing.T, label string, value any) {
	t.Helper()
	payload := us007JSONString(t, value)
	for _, forbidden := range []string{
		"ghp_",
		"github_pat_",
		"GITHUB_TOKEN",
		"SERVICE_TOKEN",
		"credential_value",
		"secret_value",
		"Authorization",
		"Bearer",
		"iptables",
		"nft ",
		"firewall-rule",
		"/private/",
		".sock",
		"raw-template",
		"registry-token",
	} {
		if bytes.Contains([]byte(payload), []byte(forbidden)) {
			t.Fatalf("%s leaked forbidden fragment %q: %s", label, forbidden, payload)
		}
	}
}

func us009RunSurfaceSlug(value string) string {
	out := make([]byte, 0, len(value))
	lastDash := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			out = append(out, ch)
			lastDash = false
			continue
		}
		if !lastDash {
			out = append(out, '-')
			lastDash = true
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}
