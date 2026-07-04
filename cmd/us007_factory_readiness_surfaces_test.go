package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS007FactoryRunResultSurfacesSecurityReadinessGateOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		decision  sandbox.SandboxSecurityCapabilityReadinessGateDecision
		status    string
		wantHuman []string
	}{
		{
			name:     "strict blocked",
			decision: sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, nil),
			status:   factory.RunStatusFailed,
			wantHuman: []string{
				"Secure default readiness: strict blocked",
				"strict secure-default would block",
				"strictBlocking=1",
				"reason codes readiness_missing=1",
				"reason=readiness_missing",
			},
		},
		{
			name: "proof complete strict allowed",
			decision: sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(
				sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				*us007ProofCompleteReadinessOutput(),
			),
			status: factory.RunStatusSucceeded,
			wantHuman: []string{
				"Secure default readiness: strict allowed",
				"proof-complete",
				"ready=5",
				"reason=readiness_ready",
			},
		},
		{
			name:     "compatibility advisory",
			decision: sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility, nil),
			status:   factory.RunStatusSucceeded,
			wantHuman: []string{
				"Secure default readiness: compatibility advisory",
				"strict secure-default would block",
				"strictBlocking=1",
				"reason=policy_compatibility",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			record := us007FactorySurfaceRunRecord("run-us007-factory-surface-"+strings.ReplaceAll(tt.name, " ", "-"), tt.status, tt.decision)
			if err := store.SaveRun(&record); err != nil {
				t.Fatalf("SaveRun() error = %v", err)
			}
			if err := recordFactoryPolicyDecision(store, record.RunID, record.UpdatedAt, factorySandboxReadinessGatePolicyDecisionMetadata(tt.decision)); err != nil {
				t.Fatalf("recordFactoryPolicyDecision() error = %v", err)
			}

			var jsonOut bytes.Buffer
			if err := renderFactoryRunResult(&jsonOut, store, record.RunID, true); err != nil {
				t.Fatalf("renderFactoryRunResult(json) error = %v", err)
			}
			root := us007DecodeJSONObject(t, jsonOut.Bytes())
			gate := us007RequireJSONGate(t, "factory run result JSON", root)
			us007AssertSecurityReadinessGateDecision(t, "factory run result JSON", gate, tt.decision)
			us007AssertSecureDefaultDecisionSafe(t, "factory run result JSON", root, us007ForbiddenSecureDefaultFragments()...)

			var humanOut bytes.Buffer
			if err := renderFactoryRunResult(&humanOut, store, record.RunID, false); err != nil {
				t.Fatalf("renderFactoryRunResult(human) error = %v", err)
			}
			for _, want := range tt.wantHuman {
				if !strings.Contains(humanOut.String(), want) {
					t.Fatalf("factory run human output missing %q:\n%s", want, humanOut.String())
				}
			}
			us007AssertSecureDefaultDecisionSafe(t, "factory run result human", humanOut.String(), us007ForbiddenSecureDefaultFragments()...)
		})
	}
}

func TestUS007FactoryStatusSurfacesSecurityReadinessGateSummary(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, nil)
	record := us007FactorySurfaceRunRecord("run-us007-factory-status-surface", factory.RunStatusFailed, decision)
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}
	if err := recordFactoryPolicyDecision(store, record.RunID, record.UpdatedAt, factorySandboxReadinessGatePolicyDecisionMetadata(decision)); err != nil {
		t.Fatalf("recordFactoryPolicyDecision() error = %v", err)
	}

	var jsonOut bytes.Buffer
	if err := runFactoryStatusWithDeps(&jsonOut, record.RunID, true, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryStatusWithDeps(json) error = %v", err)
	}
	root := us007DecodeJSONObject(t, jsonOut.Bytes())
	run, ok := root["run"].(map[string]any)
	if !ok {
		t.Fatalf("factory status run = %#v, want object", root["run"])
	}
	topLevelGate := us007RequireJSONGate(t, "factory status JSON run", run)
	us007AssertSecurityReadinessGateDecision(t, "factory status JSON run", topLevelGate, decision)
	sandboxValue, ok := run["sandbox"].(map[string]any)
	if !ok {
		t.Fatalf("factory status sandbox = %#v, want object", run["sandbox"])
	}
	security, ok := sandboxValue["security"].(map[string]any)
	if !ok {
		t.Fatalf("factory status sandbox.security = %#v, want object", sandboxValue["security"])
	}
	nestedGate := us007RequireJSONGate(t, "factory status JSON nested sandbox security", security)
	us007AssertSecurityReadinessGateDecision(t, "factory status JSON nested sandbox security", nestedGate, decision)
	us007AssertSecureDefaultDecisionSafe(t, "factory status JSON", root, us007ForbiddenSecureDefaultFragments()...)

	var humanOut bytes.Buffer
	if err := runFactoryStatusWithDeps(&humanOut, record.RunID, false, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryStatusWithDeps(human) error = %v", err)
	}
	for _, want := range []string{
		"Secure default readiness: strict blocked",
		"strict secure-default would block",
		"strictBlocking=1",
		"reason codes readiness_missing=1",
		"reason=readiness_missing",
	} {
		if !strings.Contains(humanOut.String(), want) {
			t.Fatalf("factory status human output missing %q:\n%s", want, humanOut.String())
		}
	}
	us007AssertSecureDefaultDecisionSafe(t, "factory status human", humanOut.String(), us007ForbiddenSecureDefaultFragments()...)
}

func us007FactorySurfaceRunRecord(runID, runStatus string, decision sandbox.SandboxSecurityCapabilityReadinessGateDecision) factory.RunRecord {
	createdAt := time.Date(2026, 7, 4, 18, 30, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Second)
	finishedAt := updatedAt
	record := factory.RunRecord{
		RunID:        runID,
		Status:       runStatus,
		ExecutorMode: factory.ExecutorModeSandbox,
		Source:       factory.SourceMetadata{Kind: factory.SourceKindPRD, Path: ".hal/prd.json"},
		RepoPath:     "repo",
		RepoRemote:   "origin",
		BranchName:   "hal/us007-factory-status-surface",
		BaseBranch:   "main",
		SandboxName:  "us007-factory-status-sandbox",
		Sandbox: &factory.SandboxMetadata{
			Name:   "us007-factory-status-sandbox",
			Status: sandbox.StatusRunning,
			Security: &factory.SandboxSecurityMetadata{
				SecurityReadinessGate: sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&decision),
			},
		},
		CurrentStep: "prepare_inputs",
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if runStatus == factory.RunStatusFailed {
		record.FinishedAt = &finishedAt
		record.Failure = &factory.FailureSummary{
			Step:        "prepare_inputs",
			Category:    factory.FailureCategorySandbox,
			Message:     "factory security readiness gate blocked: policyMode=strict outcome=blocked code=security_readiness_gate_blocked reason=readiness_missing",
			Recoverable: true,
		}
	}
	return record
}

func us007DecodeJSONObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nraw: %s", err, string(data))
	}
	return root
}

func us007RequireJSONGate(t *testing.T, label string, root map[string]any) map[string]any {
	t.Helper()
	gate, ok := root["securityReadinessGate"].(map[string]any)
	if !ok {
		t.Fatalf("%s securityReadinessGate = %#v, want object; keys=%v", label, root["securityReadinessGate"], us007MapKeys(root))
	}
	return gate
}
