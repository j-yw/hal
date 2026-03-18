package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestGet_NotInitialized(t *testing.T) {
	dir := t.TempDir()

	result := Get(dir)

	if result.ContractVersion != ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, ContractVersion)
	}
	if result.WorkflowTrack != TrackUnknown {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackUnknown)
	}
	if result.State != StateNotInitialized {
		t.Fatalf("state = %q, want %q", result.State, StateNotInitialized)
	}
	if result.NextAction.ID != ActionRunInit {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionRunInit)
	}
	if result.Artifacts.HalDir {
		t.Fatal("artifacts.halDir = true, want false")
	}
}

func TestGet_InitializedNoPRD(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte(""), 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackManual {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackManual)
	}
	if result.State != StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, StateInitializedNoPRD)
	}
	if result.NextAction.ID != ActionRunPlan {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionRunPlan)
	}
	if !result.Artifacts.HalDir {
		t.Fatal("artifacts.halDir = false, want true")
	}
	if !result.Artifacts.ProgressFile {
		t.Fatal("artifacts.progressFile = false, want true")
	}
}

func TestGet_ManualInProgress(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "status": "passed"},
			{"id": "US-002", "status": "pending"},
			{"id": "US-003", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackManual {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackManual)
	}
	if result.State != StateManualInProgress {
		t.Fatalf("state = %q, want %q", result.State, StateManualInProgress)
	}
	if result.NextAction.ID != ActionRunManual {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionRunManual)
	}
	if !result.Artifacts.JSONPRD {
		t.Fatal("artifacts.jsonPRD = false, want true")
	}
}

func TestGet_ManualComplete(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "status": "passed"},
			{"id": "US-002", "status": "passed"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackManual {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackManual)
	}
	if result.State != StateManualComplete {
		t.Fatalf("state = %q, want %q", result.State, StateManualComplete)
	}
	if result.NextAction.ID != ActionRunReport {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionRunReport)
	}
}

func TestGet_CompoundActive(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(`{"step":"loop"}`), 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackCompound {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackCompound)
	}
	if result.State != StateCompoundActive {
		t.Fatalf("state = %q, want %q", result.State, StateCompoundActive)
	}
	if result.NextAction.ID != ActionResumeAuto {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionResumeAuto)
	}
	if !result.Artifacts.AutoState {
		t.Fatal("artifacts.autoState = false, want true")
	}
}

func TestGet_CompoundTakesPrecedenceOverManual(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Both manual PRD and auto state exist
	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(`{"step":"loop"}`), 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackCompound {
		t.Fatalf("workflowTrack = %q, want %q (compound should take precedence)", result.WorkflowTrack, TrackCompound)
	}
}

func TestGet_ReportDetected(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)
	os.WriteFile(filepath.Join(reportsDir, "review-2026-03-18.md"), []byte("# Report"), 0644)

	result := Get(dir)

	if !result.Artifacts.ReportAvailable {
		t.Fatal("artifacts.reportAvailable = false, want true")
	}
}

func TestGet_GitkeepNotCountedAsReport(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)
	os.WriteFile(filepath.Join(reportsDir, ".gitkeep"), []byte(""), 0644)

	result := Get(dir)

	if result.Artifacts.ReportAvailable {
		t.Fatal("artifacts.reportAvailable = true, want false (only .gitkeep)")
	}
}

func TestGet_MarkdownPRDDetected(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, "prd-auth.md"), []byte("# PRD"), 0644)

	result := Get(dir)

	if !result.Artifacts.MarkdownPRD {
		t.Fatal("artifacts.markdownPRD = false, want true")
	}
}

func TestStatusResult_JSONRoundTrip(t *testing.T) {
	original := StatusResult{
		ContractVersion: ContractVersion,
		WorkflowTrack:   TrackManual,
		State:           StateManualInProgress,
		Artifacts: Artifacts{
			HalDir:  true,
			JSONPRD: true,
		},
		NextAction: NextAction{
			ID:      ActionRunManual,
			Command: "hal run",
		},
		Summary: "test",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded StatusResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.ContractVersion != original.ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", decoded.ContractVersion, original.ContractVersion)
	}
	if decoded.WorkflowTrack != original.WorkflowTrack {
		t.Fatalf("workflowTrack = %q, want %q", decoded.WorkflowTrack, original.WorkflowTrack)
	}
	if decoded.State != original.State {
		t.Fatalf("state = %q, want %q", decoded.State, original.State)
	}
	if decoded.NextAction.ID != original.NextAction.ID {
		t.Fatalf("nextAction.id = %q, want %q", decoded.NextAction.ID, original.NextAction.ID)
	}
}
