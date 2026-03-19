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

func TestGet_ManualInProgress_DetailFields(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"branchName": "hal/test-feature",
		"stories": []map[string]interface{}{
			{"id": "US-001", "title": "Setup DB", "status": "passed"},
			{"id": "US-002", "title": "Add API", "status": "pending"},
			{"id": "US-003", "title": "Add UI", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	if result.Manual == nil {
		t.Fatal("manual detail should not be nil")
	}
	if result.Manual.BranchName != "hal/test-feature" {
		t.Fatalf("branchName = %q, want %q", result.Manual.BranchName, "hal/test-feature")
	}
	if result.Manual.TotalStories != 3 {
		t.Fatalf("totalStories = %d, want 3", result.Manual.TotalStories)
	}
	if result.Manual.CompletedStories != 1 {
		t.Fatalf("completedStories = %d, want 1", result.Manual.CompletedStories)
	}
	if result.Manual.NextStory == nil {
		t.Fatal("nextStory should not be nil")
	}
	if result.Manual.NextStory.ID != "US-002" {
		t.Fatalf("nextStory.id = %q, want %q", result.Manual.NextStory.ID, "US-002")
	}
	if result.Manual.NextStory.Title != "Add API" {
		t.Fatalf("nextStory.title = %q, want %q", result.Manual.NextStory.Title, "Add API")
	}
	if result.Paths == nil || result.Paths.PRDJson == "" {
		t.Fatal("paths.prdJson should be set")
	}
}

func TestGet_ManualComplete_NoNextStory(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "title": "Done", "status": "passed"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	if result.Manual == nil {
		t.Fatal("manual detail should not be nil")
	}
	if result.Manual.NextStory != nil {
		t.Fatal("nextStory should be nil when all complete")
	}
	if result.Manual.CompletedStories != 1 {
		t.Fatalf("completedStories = %d, want 1", result.Manual.CompletedStories)
	}
}

func TestGet_CompoundActive_DetailFields(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	autoState := `{"step":"loop","branchName":"compound/my-feature"}`
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(autoState), 0644)

	result := Get(dir)

	if result.Compound == nil {
		t.Fatal("compound detail should not be nil")
	}
	if result.Compound.Step != "loop" {
		t.Fatalf("step = %q, want %q", result.Compound.Step, "loop")
	}
	if result.Compound.BranchName != "compound/my-feature" {
		t.Fatalf("branchName = %q, want %q", result.Compound.BranchName, "compound/my-feature")
	}
	if result.Paths == nil || result.Paths.AutoState == "" {
		t.Fatal("paths.autoState should be set")
	}
}

func TestGet_UserStoriesKey(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	// Use "userStories" instead of "stories"
	prd := map[string]interface{}{
		"userStories": []map[string]interface{}{
			{"id": "US-001", "title": "First", "status": "passed"},
			{"id": "US-002", "title": "Second", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	if result.Manual == nil {
		t.Fatal("manual detail should not be nil")
	}
	if result.Manual.TotalStories != 2 {
		t.Fatalf("totalStories = %d, want 2", result.Manual.TotalStories)
	}
	if result.Manual.CompletedStories != 1 {
		t.Fatalf("completedStories = %d, want 1", result.Manual.CompletedStories)
	}
}

func TestStatusResult_DetailFieldsJSONRoundTrip(t *testing.T) {
	original := StatusResult{
		ContractVersion: ContractVersion,
		WorkflowTrack:   TrackManual,
		State:           StateManualInProgress,
		Manual: &ManualDetail{
			BranchName:       "hal/test",
			TotalStories:     5,
			CompletedStories: 2,
			NextStory:        &StoryRef{ID: "US-003", Title: "Impl"},
		},
		Paths: &StatusPaths{PRDJson: ".hal/prd.json"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded StatusResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Manual == nil {
		t.Fatal("decoded.Manual is nil")
	}
	if decoded.Manual.TotalStories != 5 {
		t.Fatalf("totalStories = %d, want 5", decoded.Manual.TotalStories)
	}
	if decoded.Manual.NextStory == nil || decoded.Manual.NextStory.ID != "US-003" {
		t.Fatalf("nextStory mismatch")
	}
	if decoded.Paths == nil || decoded.Paths.PRDJson != ".hal/prd.json" {
		t.Fatalf("paths mismatch")
	}

	// Verify omitempty: compound should NOT appear in JSON
	if decoded.Compound != nil {
		t.Fatal("compound should be nil when not set")
	}
	rawMap := map[string]interface{}{}
	json.Unmarshal(data, &rawMap)
	if _, ok := rawMap["compound"]; ok {
		t.Fatal("compound key should not appear in JSON when nil (omitempty)")
	}
}

func TestGet_ReviewLoopComplete_NoPRD(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)
	// Create a review-loop report
	os.WriteFile(filepath.Join(reportsDir, "review-loop-20260318-120000.json"), []byte(`{"command":"hal review"}`), 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackReviewLoop {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackReviewLoop)
	}
	if result.State != StateReviewLoopComplete {
		t.Fatalf("state = %q, want %q", result.State, StateReviewLoopComplete)
	}
	if result.ReviewLoop == nil {
		t.Fatal("reviewLoop should not be nil")
	}
	if result.ReviewLoop.LatestReport == "" {
		t.Fatal("reviewLoop.latestReport should be set")
	}
}

func TestGet_ManualWithReviewLoopReport(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)

	// Both PRD and review-loop report
	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)
	os.WriteFile(filepath.Join(reportsDir, "review-loop-20260318-120000.json"), []byte(`{}`), 0644)

	result := Get(dir)

	// Should be manual (PRD takes precedence), but reviewLoop detail should be present
	if result.WorkflowTrack != TrackManual {
		t.Fatalf("workflowTrack = %q, want %q (manual should win when PRD exists)", result.WorkflowTrack, TrackManual)
	}
	if result.ReviewLoop == nil {
		t.Fatal("reviewLoop detail should be present as supplementary info")
	}
}

func TestGet_CompoundComplete(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	autoState := `{"step":"done","branchName":"compound/feature-x"}`
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(autoState), 0644)

	result := Get(dir)

	if result.WorkflowTrack != TrackCompound {
		t.Fatalf("workflowTrack = %q, want %q", result.WorkflowTrack, TrackCompound)
	}
	if result.State != StateCompoundComplete {
		t.Fatalf("state = %q, want %q", result.State, StateCompoundComplete)
	}
	if result.NextAction.ID != ActionRunReport {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, ActionRunReport)
	}
	if result.Compound == nil || result.Compound.Step != "done" {
		t.Fatal("compound.step should be 'done'")
	}
}

func TestGet_Deterministic(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"branchName": "hal/test",
		"stories": []map[string]interface{}{
			{"id": "US-001", "title": "A", "status": "passed"},
			{"id": "US-002", "title": "B", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	r1 := Get(dir)
	r2 := Get(dir)

	if r1.State != r2.State {
		t.Fatalf("state not deterministic: %q vs %q", r1.State, r2.State)
	}
	if r1.WorkflowTrack != r2.WorkflowTrack {
		t.Fatalf("track not deterministic: %q vs %q", r1.WorkflowTrack, r2.WorkflowTrack)
	}
	if r1.Summary != r2.Summary {
		t.Fatalf("summary not deterministic: %q vs %q", r1.Summary, r2.Summary)
	}
	if r1.Manual != nil && r2.Manual != nil {
		if r1.Manual.TotalStories != r2.Manual.TotalStories {
			t.Fatalf("totalStories not deterministic")
		}
		if r1.Manual.CompletedStories != r2.Manual.CompletedStories {
			t.Fatalf("completedStories not deterministic")
		}
	}
}

func TestGet_MarkdownPRDSuggestsConvert(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Create markdown PRD but no JSON PRD
	os.WriteFile(filepath.Join(halDir, "prd-feature.md"), []byte("# Feature"), 0644)

	result := Get(dir)

	if result.State != StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, StateInitializedNoPRD)
	}
	if result.NextAction.Command != "hal convert" {
		t.Fatalf("nextAction.command = %q, want %q", result.NextAction.Command, "hal convert")
	}
	if result.NextAction.ID != "run_convert" {
		t.Fatalf("nextAction.id = %q, want %q", result.NextAction.ID, "run_convert")
	}
}

func TestGet_NoPRDAtAll(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// No markdown or JSON PRD

	result := Get(dir)

	if result.State != StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, StateInitializedNoPRD)
	}
	if result.NextAction.Command != "hal plan" {
		t.Fatalf("nextAction.command = %q, want %q", result.NextAction.Command, "hal plan")
	}
}

func TestGet_ManualComplete_WithReports_SuggestsAuto(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)

	prd := map[string]interface{}{
		"stories": []map[string]interface{}{
			{"id": "US-001", "status": "passed"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)
	os.WriteFile(filepath.Join(reportsDir, "review-2026-03-18.md"), []byte("report"), 0644)

	result := Get(dir)

	if result.State != StateManualComplete {
		t.Fatalf("state = %q, want %q", result.State, StateManualComplete)
	}
	if result.NextAction.ID != ActionRunAuto {
		t.Fatalf("nextAction.id = %q, want %q (should suggest auto when report exists)", result.NextAction.ID, ActionRunAuto)
	}
}

func TestGet_EmptyStoriesArray(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"stories": []map[string]interface{}{},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	result := Get(dir)

	// 0 stories should be in progress (need to add stories)
	if result.State != StateManualInProgress {
		t.Fatalf("state = %q, want %q for empty stories", result.State, StateManualInProgress)
	}
	if result.Manual == nil {
		t.Fatal("manual should not be nil")
	}
	if result.Manual.TotalStories != 0 {
		t.Fatalf("totalStories = %d, want 0", result.Manual.TotalStories)
	}
}

func TestGet_UnparseablePRD(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte("not json at all"), 0644)

	result := Get(dir)

	if result.State != StateManualInProgress {
		t.Fatalf("state = %q, want %q for unparseable PRD", result.State, StateManualInProgress)
	}
}

func TestGet_GracefulWithMinimalSetup(t *testing.T) {
	// Just .hal/ dir, nothing else
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	result := Get(dir)

	if result.ContractVersion != ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, ContractVersion)
	}
	if result.State != StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, StateInitializedNoPRD)
	}
	// Should never panic on minimal setup
	if result.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}
