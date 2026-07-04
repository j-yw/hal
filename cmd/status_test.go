package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunStatusFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	var buf bytes.Buffer
	if err := runStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	var result status.StatusResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != status.ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, status.ContractVersion)
	}
	if result.State != status.StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, status.StateInitializedNoPRD)
	}
}

func TestRunStatusFn_JSONDecodesWorkflowStates(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T, halDir string)
		wantTrack     string
		wantState     string
		wantArtifacts status.Artifacts
		wantAction    string
		assert        func(t *testing.T, result statusWithEngine)
	}{
		{
			name: "initialized without PRD",
			setup: func(t *testing.T, halDir string) {
				writeStatusTestFile(t, filepath.Join(halDir, template.ProgressFile), "")
			},
			wantTrack: status.TrackManual,
			wantState: status.StateInitializedNoPRD,
			wantArtifacts: status.Artifacts{
				HalDir:       true,
				ProgressFile: true,
			},
			wantAction: status.ActionRunPlan,
		},
		{
			name: "manual in progress",
			setup: func(t *testing.T, halDir string) {
				writeStatusTestFile(t, filepath.Join(halDir, template.ProgressFile), "")
				writeStatusTestFile(t, filepath.Join(halDir, template.PRDFile), `{
  "branchName": "hal/status-json",
  "userStories": [
    {"id": "US-001", "title": "Setup", "passes": true},
    {"id": "US-002", "title": "Inspect status", "passes": false}
  ]
}`)
			},
			wantTrack: status.TrackManual,
			wantState: status.StateManualInProgress,
			wantArtifacts: status.Artifacts{
				HalDir:       true,
				JSONPRD:      true,
				ProgressFile: true,
			},
			wantAction: status.ActionRunManual,
			assert: func(t *testing.T, result statusWithEngine) {
				t.Helper()
				if result.Paths == nil || result.Paths.PRDJson != filepath.Join(template.HalDir, template.PRDFile) {
					t.Fatalf("paths.prdJson = %#v, want .hal/prd.json", result.Paths)
				}
				if result.Manual == nil {
					t.Fatal("manual detail is nil")
				}
				if result.Manual.BranchName != "hal/status-json" {
					t.Fatalf("manual.branchName = %q, want hal/status-json", result.Manual.BranchName)
				}
				if result.Manual.TotalStories != 2 || result.Manual.CompletedStories != 1 {
					t.Fatalf("manual story progress = %d/%d, want 1/2", result.Manual.CompletedStories, result.Manual.TotalStories)
				}
				if result.Manual.NextStory == nil || result.Manual.NextStory.ID != "US-002" {
					t.Fatalf("manual.nextStory = %#v, want US-002", result.Manual.NextStory)
				}
			},
		},
		{
			name: "manual complete",
			setup: func(t *testing.T, halDir string) {
				writeStatusTestFile(t, filepath.Join(halDir, template.ProgressFile), "")
				writeStatusTestFile(t, filepath.Join(halDir, template.PRDFile), `{
  "branchName": "hal/status-json-complete",
  "stories": [
    {"id": "US-001", "title": "Setup", "status": "passed"},
    {"id": "US-002", "title": "Inspect status", "status": "passed"}
  ]
}`)
			},
			wantTrack: status.TrackManual,
			wantState: status.StateManualComplete,
			wantArtifacts: status.Artifacts{
				HalDir:       true,
				JSONPRD:      true,
				ProgressFile: true,
			},
			wantAction: status.ActionRunReport,
			assert: func(t *testing.T, result statusWithEngine) {
				t.Helper()
				if result.Paths == nil || result.Paths.PRDJson != filepath.Join(template.HalDir, template.PRDFile) {
					t.Fatalf("paths.prdJson = %#v, want .hal/prd.json", result.Paths)
				}
				if result.Manual == nil {
					t.Fatal("manual detail is nil")
				}
				if result.Manual.BranchName != "hal/status-json-complete" {
					t.Fatalf("manual.branchName = %q, want hal/status-json-complete", result.Manual.BranchName)
				}
				if result.Manual.TotalStories != 2 || result.Manual.CompletedStories != 2 {
					t.Fatalf("manual story progress = %d/%d, want 2/2", result.Manual.CompletedStories, result.Manual.TotalStories)
				}
				if result.Manual.NextStory != nil {
					t.Fatalf("manual.nextStory = %#v, want nil", result.Manual.NextStory)
				}
			},
		},
		{
			name: "auto active",
			setup: func(t *testing.T, halDir string) {
				writeStatusTestFile(t, filepath.Join(halDir, template.AutoStateFile), `{"step":"loop","branchName":"hal/status-auto-active"}`)
			},
			wantTrack: status.TrackAuto,
			wantState: status.StateAutoActive,
			wantArtifacts: status.Artifacts{
				HalDir:    true,
				AutoState: true,
			},
			wantAction: status.ActionResumeAuto,
			assert: func(t *testing.T, result statusWithEngine) {
				t.Helper()
				if result.Paths == nil || result.Paths.AutoState != filepath.Join(template.HalDir, template.AutoStateFile) {
					t.Fatalf("paths.autoState = %#v, want .hal/auto-state.json", result.Paths)
				}
				if result.Compound == nil {
					t.Fatal("compound detail is nil")
				}
				if result.Compound.Step != "run" || result.Compound.BranchName != "hal/status-auto-active" {
					t.Fatalf("compound detail = %#v, want run on hal/status-auto-active", result.Compound)
				}
			},
		},
		{
			name: "auto inactive",
			setup: func(t *testing.T, halDir string) {
				writeStatusTestFile(t, filepath.Join(halDir, template.AutoStateFile), `{"step":"done","branchName":"hal/status-auto-inactive"}`)
			},
			wantTrack: status.TrackAuto,
			wantState: status.StateAutoInactive,
			wantArtifacts: status.Artifacts{
				HalDir:    true,
				AutoState: true,
			},
			wantAction: status.ActionRunAuto,
			assert: func(t *testing.T, result statusWithEngine) {
				t.Helper()
				if result.Paths == nil || result.Paths.AutoState != filepath.Join(template.HalDir, template.AutoStateFile) {
					t.Fatalf("paths.autoState = %#v, want .hal/auto-state.json", result.Paths)
				}
				if result.Compound == nil {
					t.Fatal("compound detail is nil")
				}
				if result.Compound.Step != "done" || result.Compound.BranchName != "hal/status-auto-inactive" {
					t.Fatalf("compound detail = %#v, want done on hal/status-auto-inactive", result.Compound)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("MkdirAll(.hal) error: %v", err)
			}
			tt.setup(t, halDir)

			var buf bytes.Buffer
			if err := runStatusFn(dir, true, &buf); err != nil {
				t.Fatalf("runStatusFn() error = %v", err)
			}

			result := decodeStatusJSON(t, buf.String())
			if result.ContractVersion != status.ContractVersion {
				t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, status.ContractVersion)
			}
			if result.Engine != "codex" {
				t.Fatalf("engine = %q, want codex", result.Engine)
			}
			if result.WorkflowTrack != tt.wantTrack {
				t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, tt.wantTrack)
			}
			if result.State != tt.wantState {
				t.Fatalf("state = %q, want %q", result.State, tt.wantState)
			}
			if result.Artifacts != tt.wantArtifacts {
				t.Fatalf("artifacts = %#v, want %#v", result.Artifacts, tt.wantArtifacts)
			}
			if result.NextAction.ID != tt.wantAction {
				t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, tt.wantAction)
			}
			if result.NextAction.Command == "" {
				t.Fatal("nextAction.command is empty")
			}
			assertNoLiveProviderStatusRecommendation(t, result.NextAction)
			if tt.assert != nil {
				tt.assert(t, result)
			}
		})
	}
}

func TestRunStatusFn_DoesNotExposeSandboxSecretsOrProviderConfig(t *testing.T) {
	const (
		githubToken = "ghp_StatusSecretToken1234567890"
		openAIToken = "sk-statusSecretToken1234567890"
		sshKeyPath  = "/Users/alice/.ssh/id_ed25519"
		awsCredPath = "/Users/alice/.aws/credentials"
		remoteURL   = "https://user:pass@example.com/org/repo.git?token=ghp_RemoteSecretToken1234567890"
	)
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	writeStatusTestFile(t, filepath.Join(halDir, template.ConfigFile), `engine: codex
sandbox:
  provider: hetzner
  env:
    GITHUB_TOKEN: `+githubToken+`
    OPENAI_API_KEY: `+openAIToken+`
    AWS_SHARED_CREDENTIALS_FILE: `+awsCredPath+`
  hetzner:
    sshKey: `+sshKeyPath+`
    serverType: cx22
    image: ubuntu-24.04
`)
	writeStatusTestFile(t, filepath.Join(halDir, template.ProgressFile), "")
	writeStatusTestFile(t, filepath.Join(halDir, template.PRDFile), `{
  "branchName": "hal/status-`+githubToken+`",
  "stories": [
    {"id": "US-001", "title": "Setup", "status": "passed"},
    {"id": "US-002", "title": "Use `+sshKeyPath+` and `+openAIToken+` from `+remoteURL+`", "status": "pending"}
  ]
}`)

	var jsonOut bytes.Buffer
	if err := runStatusFn(dir, true, &jsonOut); err != nil {
		t.Fatalf("runStatusFn(json) error = %v", err)
	}
	jsonResult := decodeStatusJSON(t, jsonOut.String())
	if jsonResult.Manual == nil || jsonResult.Manual.NextStory == nil {
		t.Fatalf("manual detail missing from JSON: %#v", jsonResult.Manual)
	}
	if !strings.Contains(jsonOut.String(), "[redacted]") {
		t.Fatalf("JSON output should include redaction marker:\n%s", jsonOut.String())
	}

	var humanOut bytes.Buffer
	if err := runStatusFn(dir, false, &humanOut); err != nil {
		t.Fatalf("runStatusFn(human) error = %v", err)
	}
	if !strings.Contains(humanOut.String(), "Workflow:") || !strings.Contains(humanOut.String(), "Stories:") || !strings.Contains(humanOut.String(), "Action:") {
		t.Fatalf("human output missing operator status fields:\n%s", humanOut.String())
	}
	if !strings.Contains(humanOut.String(), "[redacted]") {
		t.Fatalf("human output should include redaction marker:\n%s", humanOut.String())
	}

	forbidden := []string{
		githubToken,
		openAIToken,
		sshKeyPath,
		awsCredPath,
		remoteURL,
		"user:pass@example.com",
		"example.com/org/repo.git",
		"hetzner",
		"cx22",
		"ubuntu-24.04",
		"GITHUB_TOKEN",
		"OPENAI_API_KEY",
		"AWS_SHARED_CREDENTIALS_FILE",
	}
	assertStatusOutputOmits(t, "status JSON", jsonOut.String(), forbidden)
	assertStatusOutputOmits(t, "human status", humanOut.String(), forbidden)
	assertNoLiveProviderStatusRecommendation(t, jsonResult.NextAction)
}

func TestUS007RunStatusRedactsWorkflowAndProgressInputs(t *testing.T) {
	const (
		githubToken        = "ghp_US007StatusToken1234567890"
		openAIToken        = "sk-us007StatusToken1234567890"
		localKeyPath       = "/Users/alice/.ssh/id_ed25519"
		credentialURL      = "https://user:pass@example.invalid/repo.git?token=ghp_US007StatusRemote1234567890"
		progressOnlySecret = "ghp_US007ProgressOnly1234567890"
	)
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	writeStatusTestFile(t, filepath.Join(halDir, template.ConfigFile), "engine: codex-"+githubToken+"\n")
	writeStatusTestFile(t, filepath.Join(halDir, template.ProgressFile), "Progress used "+progressOnlySecret+" from "+localKeyPath+" and "+credentialURL+"\n")
	writeStatusTestFile(t, filepath.Join(halDir, template.PRDFile), `{
  "branchName": "hal/status-`+githubToken+`",
  "stories": [
    {"id": "US-001", "title": "Done", "status": "passed"},
    {"id": "US-007-`+openAIToken+`", "title": "Check `+credentialURL+` and `+localKeyPath+`", "status": "pending"}
  ]
}`)

	var jsonOut bytes.Buffer
	if err := runStatusFn(dir, true, &jsonOut); err != nil {
		t.Fatalf("runStatusFn(json) error = %v", err)
	}
	jsonResult := decodeStatusJSON(t, jsonOut.String())
	if jsonResult.Manual == nil || jsonResult.Manual.NextStory == nil {
		t.Fatalf("manual detail missing from JSON: %#v", jsonResult.Manual)
	}
	if !strings.Contains(jsonOut.String(), "[redacted]") {
		t.Fatalf("status JSON missing stable redaction marker:\n%s", jsonOut.String())
	}

	var humanOut bytes.Buffer
	if err := runStatusFn(dir, false, &humanOut); err != nil {
		t.Fatalf("runStatusFn(human) error = %v", err)
	}
	if !strings.Contains(humanOut.String(), "[redacted]") {
		t.Fatalf("human status missing stable redaction marker:\n%s", humanOut.String())
	}

	forbidden := []string{
		githubToken,
		openAIToken,
		localKeyPath,
		credentialURL,
		progressOnlySecret,
		"user:pass@example.invalid",
		"ghp_US007StatusRemote1234567890",
	}
	assertStatusOutputOmits(t, "status JSON", jsonOut.String(), forbidden)
	assertStatusOutputOmits(t, "human status", humanOut.String(), forbidden)
	assertNoLiveProviderStatusRecommendation(t, jsonResult.NextAction)
}

func TestRunStatusFn_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	var buf bytes.Buffer
	if err := runStatusFn(dir, false, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Workflow:") {
		t.Fatalf("human output missing 'Workflow:'\n%s", output)
	}
	if !strings.Contains(output, "State:") {
		t.Fatalf("human output missing 'State:'\n%s", output)
	}
	if !strings.Contains(output, "Action:") {
		t.Fatalf("human output missing 'Action:'\n%s", output)
	}
}

func TestRunStatusFn_HumanOutput_WithStories(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"branchName": "hal/test",
		"stories": []map[string]interface{}{
			{"id": "US-001", "title": "Setup", "status": "passed"},
			{"id": "US-002", "title": "Build", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	var buf bytes.Buffer
	if err := runStatusFn(dir, false, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Stories:  1/2 complete") {
		t.Fatalf("human output missing story counts\n%s", output)
	}
	if !strings.Contains(output, "Branch:") {
		t.Fatalf("human output missing branch\n%s", output)
	}
	if !strings.Contains(output, "US-002") {
		t.Fatalf("human output missing next story ID\n%s", output)
	}
}

func TestRunStatusFn_JSONStdoutOnly(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	// JSON should be valid and parseable
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON output is not valid: %v\n%s", err, buf.String())
	}

	// Required fields
	for _, field := range []string{"contractVersion", "workflowTrack", "state", "artifacts", "nextAction", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("JSON missing required field %q", field)
		}
	}
}

func TestStatusCmdHelp(t *testing.T) {
	cmd := statusCmd

	if cmd.Use != "status" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "status")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if cmd.Long == "" {
		t.Fatal("Long is empty")
	}
	if !strings.Contains(cmd.Long, "auto.sourcePriority") {
		t.Fatalf("Long should describe config-driven auto source priority: %q", cmd.Long)
	}
	if cmd.Example == "" {
		t.Fatal("Example is empty")
	}
	if !strings.Contains(cmd.Example, "hal status") {
		t.Fatalf("Example missing 'hal status': %s", cmd.Example)
	}
}

func decodeStatusJSON(t *testing.T, output string) statusWithEngine {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(output))
	var result statusWithEngine
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("JSON decode error: %v\noutput: %s", err, output)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("JSON output should contain exactly one document, got trailing data err=%v\noutput: %s", err, output)
	}
	return result
}

func writeStatusTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", path, err)
	}
}

func assertStatusOutputOmits(t *testing.T, label, output string, forbidden []string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("%s leaked forbidden value %q:\n%s", label, value, output)
		}
	}
}

func assertNoLiveProviderStatusRecommendation(t *testing.T, action status.NextAction) {
	t.Helper()
	recommendation := strings.ToLower(action.Command + " " + action.Description)
	for _, forbidden := range []string{"--live", "live provider", "live-provider"} {
		if strings.Contains(recommendation, forbidden) {
			t.Fatalf("nextAction recommends live-provider execution: %#v", action)
		}
	}
}
