package loop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

func TestIsRetryable(t *testing.T) {
	r := &Runner{}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		// Nil error
		{"nil error", nil, false},

		// Transient API errors — should be retryable
		{"rate limit", fmt.Errorf("rate limit exceeded"), true},
		{"429 status", fmt.Errorf("API returned 429"), true},
		{"503 status", fmt.Errorf("API returned 503"), true},
		{"overloaded", fmt.Errorf("model is overloaded"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"i/o timeout", fmt.Errorf("i/o timeout"), true},
		{"connection timeout", fmt.Errorf("connection timeout"), true},

		// Execution timeouts — should NOT be retryable (hung commands will hang again)
		{"execution timed out 15m", fmt.Errorf("execution timed out after 15m0s"), false},
		{"execution timed out 30m", fmt.Errorf("execution timed out after 30m0s"), false},
		{"prompt timed out", fmt.Errorf("prompt timed out after 15m0s"), false},

		// Other non-retryable errors
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"file not found", fmt.Errorf("file not found: prompt.md"), false},
		{"unknown engine", fmt.Errorf("unknown engine: foo"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.isRetryable(tt.err)
			if got != tt.expected {
				t.Errorf("isRetryable(%q) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"Rate Limit exceeded", "rate limit", true},
		{"CONNECTION reset", "connection", true},
		{"hello world", "world", true},
		{"hello", "hello world", false}, // substr longer than s
		{"", "a", false},
		{"execution timed out after 15m0s", "timeout", false}, // "timeout" != "timed out"
		{"i/o timeout", "timeout", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsIgnoreCase(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestLoadPrompt_InjectsStandards(t *testing.T) {
	halDir := t.TempDir()

	// Write a prompt template with the {{STANDARDS}} placeholder
	promptContent := `# Agent Instructions

You are an autonomous coding agent.

{{STANDARDS}}

## Your Task

1. Read the PRD at ` + "`.hal/{{PRD_FILE}}`" + `
2. Read ` + "`.hal/{{PROGRESS_FILE}}`" + `
3. If needed, create the branch from ` + "`{{BASE_BRANCH}}`" + `
`
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create standards directory with some standards
	engDir := filepath.Join(halDir, template.StandardsDir, "engine")
	if err := os.MkdirAll(engDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engDir, "process-isolation.md"), []byte("# Process Isolation\n\nAlways use setsid."), 0644); err != nil {
		t.Fatal(err)
	}

	testStdDir := filepath.Join(halDir, template.StandardsDir, "testing")
	if err := os.MkdirAll(testStdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testStdDir, "table-driven.md"), []byte("# Table-Driven Tests\n\nUse t.Run subtests."), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			BaseBranch:   "develop",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Placeholder should be gone
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("{{STANDARDS}} placeholder was not replaced")
	}

	// Standards content should be present
	if !strings.Contains(prompt, "## Project Standards") {
		t.Error("missing '## Project Standards' header")
	}
	if !strings.Contains(prompt, "Process Isolation") {
		t.Error("missing engine/process-isolation standard content")
	}
	if !strings.Contains(prompt, "Table-Driven Tests") {
		t.Error("missing testing/table-driven standard content")
	}

	// Other placeholders should also be replaced
	if !strings.Contains(prompt, ".hal/prd.json") {
		t.Error("{{PRD_FILE}} was not replaced")
	}
	if !strings.Contains(prompt, ".hal/progress.txt") {
		t.Error("{{PROGRESS_FILE}} was not replaced")
	}
	if strings.Contains(prompt, "{{BASE_BRANCH}}") {
		t.Error("{{BASE_BRANCH}} placeholder was not replaced")
	}
	if !strings.Contains(prompt, "develop") {
		t.Error("base branch value was not injected")
	}
}

func TestLoadPrompt_NoStandardsGraceful(t *testing.T) {
	halDir := t.TempDir()

	// Write a prompt template with the placeholder but NO standards directory
	promptContent := "# Agent\n\n{{STANDARDS}}\n\n## Task\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Placeholder should be replaced with empty string
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("{{STANDARDS}} placeholder was not replaced when no standards exist")
	}

	// Should still have the rest of the prompt
	if !strings.Contains(prompt, "# Agent") {
		t.Error("rest of prompt is missing")
	}
	if !strings.Contains(prompt, "## Task") {
		t.Error("rest of prompt is missing")
	}
}

func TestLoadPrompt_BaseBranchFallback(t *testing.T) {
	halDir := t.TempDir()

	promptContent := "# Agent\n\nBase: {{BASE_BRANCH}}\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	if strings.Contains(prompt, "{{BASE_BRANCH}}") {
		t.Error("{{BASE_BRANCH}} placeholder was not replaced")
	}
	if !strings.Contains(prompt, "HEAD") {
		t.Error("expected fallback base branch text 'HEAD'")
	}
}

func TestLoadPrompt_OldTemplateWithoutPlaceholder(t *testing.T) {
	halDir := t.TempDir()

	// Simulate a prompt.md that hasn't been migrated (no {{STANDARDS}})
	promptContent := "# Agent\n\n## Task\n\n1. Read the PRD at `.hal/{{PRD_FILE}}`\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create standards anyway
	sDir := filepath.Join(halDir, template.StandardsDir, "config")
	if err := os.MkdirAll(sDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sDir, "init.md"), []byte("# Init\n\nBe idempotent."), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Without the placeholder, standards content won't appear — but it should not crash
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("phantom {{STANDARDS}} placeholder appeared")
	}

	// The prompt should still work, just without standards
	if !strings.Contains(prompt, "# Agent") {
		t.Error("prompt content is missing")
	}
}

// fakeEngine is a mock engine for testing the loop.
type fakeEngine struct {
	calls   int
	results []engine.Result
	prompts []string // capture prompts passed to Execute
}

func (f *fakeEngine) Name() string { return "fake" }
func (f *fakeEngine) Execute(_ context.Context, prompt string, _ *engine.Display) engine.Result {
	f.prompts = append(f.prompts, prompt)
	idx := f.calls
	f.calls++
	if idx < len(f.results) {
		return f.results[idx]
	}
	return engine.Result{Success: true}
}
func (f *fakeEngine) Prompt(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (f *fakeEngine) StreamPrompt(_ context.Context, _ string, _ *engine.Display) (string, error) {
	return "", nil
}

// setupTestHalDir creates a minimal .hal directory with prompt.md and prd.json.
func setupTestHalDir(t *testing.T, stories []engine.UserStory) string {
	t.Helper()
	halDir := t.TempDir()

	// Write prompt.md
	promptContent := "# Agent\n\n## Task\n\n1. Read `.hal/{{PRD_FILE}}`\n2. Read `.hal/{{PROGRESS_FILE}}`\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Write prd.json
	prd := map[string]interface{}{
		"project":     "test",
		"branchName":  "main",
		"userStories": stories,
	}
	data, _ := json.Marshal(prd)
	if err := os.WriteFile(filepath.Join(halDir, "prd.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	return halDir
}

func TestFalseComplete_StopsAfterMaxFalseCompletes(t *testing.T) {
	stories := []engine.UserStory{{
		ID:                 "FIX-001",
		Title:              "Fix auth",
		Description:        "Fix authentication",
		AcceptanceCriteria: []string{"auth works"},
		Priority:           1,
		Passes:             false,
	}}
	halDir := setupTestHalDir(t, stories)

	fe := &fakeEngine{
		results: []engine.Result{
			{Success: true, Complete: true},
			{Success: true, Complete: true},
			{Success: true, Complete: true},
		},
	}

	var logBuf bytes.Buffer
	runner := &Runner{
		config: Config{
			Dir:           halDir,
			PRDFile:       "prd.json",
			ProgressFile:  "progress.txt",
			MaxIterations: 5,
			Logger:        &logBuf,
			RetryDelay:    time.Millisecond,
			MaxRetries:    0,
		},
		engine:  fe,
		display: engine.NewDisplay(&logBuf),
	}

	result := runner.Run(context.Background())

	if result.Complete {
		t.Fatal("loop should not report complete when story is still pending")
	}
	if result.Success {
		t.Fatal("loop should fail after repeated false COMPLETE signals")
	}
	if result.Error == nil {
		t.Fatal("loop should return an error after repeated false COMPLETE signals")
	}
	if !strings.Contains(result.Error.Error(), "rerun `hal auto --resume`") {
		t.Fatalf("error = %q, want resume guidance", result.Error.Error())
	}
	if fe.calls != maxFalseCompletes {
		t.Fatalf("engine calls = %d, want %d", fe.calls, maxFalseCompletes)
	}
	if len(fe.prompts) != maxFalseCompletes {
		t.Fatalf("captured prompts = %d, want %d", len(fe.prompts), maxFalseCompletes)
	}
	if !strings.Contains(fe.prompts[1], "Iteration 1 Feedback") {
		t.Fatal("second prompt should contain false COMPLETE feedback")
	}
	if !strings.Contains(fe.prompts[1], "FIX-001") {
		t.Fatal("second prompt should mention the pending story ID")
	}
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "FIX-001 is still pending") {
		t.Fatal("log should contain pending story warning")
	}
}

func TestFalseCompleteInjectsFeedback(t *testing.T) {
	stories := []engine.UserStory{{
		ID:                 "FIX-001",
		Title:              "Fix auth",
		Description:        "Fix authentication",
		AcceptanceCriteria: []string{"auth works"},
		Priority:           1,
		Passes:             false,
	}}
	halDir := setupTestHalDir(t, stories)

	fe := &fakeEngine{
		results: []engine.Result{
			{Success: true, Complete: true},
			{Success: true, Complete: true},
		},
	}

	var logBuf bytes.Buffer
	runner := &Runner{
		config: Config{
			Dir:           halDir,
			PRDFile:       "prd.json",
			ProgressFile:  "progress.txt",
			MaxIterations: 5,
			Logger:        &logBuf,
			RetryDelay:    time.Millisecond,
			MaxRetries:    0,
		},
		engine:  fe,
		display: engine.NewDisplay(&logBuf),
	}

	result := runner.Run(context.Background())
	if result.Complete {
		t.Fatal("loop should not report complete when story is still pending")
	}
	if len(fe.prompts) < 2 {
		t.Fatal("expected at least 2 prompts captured")
	}
	if !strings.Contains(fe.prompts[1], "Iteration 1 Feedback") {
		t.Fatal("second prompt should contain false COMPLETE feedback")
	}
	if !strings.Contains(fe.prompts[1], "FIX-001") {
		t.Fatal("second prompt should mention the pending story ID")
	}
	if !strings.Contains(fe.prompts[1], "passes: false") {
		t.Fatal("second prompt should mention passes: false")
	}
	if !strings.Contains(fe.prompts[1], "Append `progress.txt`") {
		t.Fatal("second prompt should require progress append before COMPLETE")
	}
	if !strings.Contains(fe.prompts[1], "git status --short") {
		t.Fatal("second prompt should require a clean git status before COMPLETE")
	}
	if !strings.Contains(fe.prompts[1], "end your response normally without <promise>COMPLETE</promise>") {
		t.Fatal("second prompt should forbid COMPLETE while stories remain pending")
	}
}

func TestFalseCompleteAcceptsWhenPRDUpdated(t *testing.T) {
	stories := []engine.UserStory{
		{
			ID:       "FIX-001",
			Title:    "Fix auth",
			Priority: 1,
			Passes:   false,
		},
	}
	halDir := setupTestHalDir(t, stories)
	prdPath := filepath.Join(halDir, "prd.json")

	callCount := 0
	// First call: agent says COMPLETE but hasn't updated PRD
	// Second call: agent updates PRD (we simulate this) and says COMPLETE
	fe := &fakeEngine{
		results: []engine.Result{
			{Success: true, Complete: true},
			{Success: true, Complete: true},
		},
	}

	// Override Execute to update PRD on second call
	origExecute := fe.Execute
	fe2 := &fakeEngineWithHook{
		fakeEngine: fe,
		hook: func(prompt string) {
			callCount++
			if callCount == 2 {
				// Simulate agent updating prd.json to mark story as passing
				prd := map[string]interface{}{
					"project":    "test",
					"branchName": "main",
					"userStories": []map[string]interface{}{
						{"id": "FIX-001", "title": "Fix auth", "priority": 1, "passes": true},
					},
				}
				data, _ := json.Marshal(prd)
				os.WriteFile(prdPath, data, 0644)
			}
		},
	}
	_ = origExecute

	var logBuf bytes.Buffer
	runner := &Runner{
		config: Config{
			Dir:           halDir,
			PRDFile:       "prd.json",
			ProgressFile:  "progress.txt",
			MaxIterations: 5,
			Logger:        &logBuf,
			RetryDelay:    time.Millisecond,
			MaxRetries:    0,
		},
		engine:  fe2,
		display: engine.NewDisplay(&logBuf),
	}

	result := runner.Run(context.Background())

	// Should complete on iteration 2
	if !result.Complete {
		t.Error("loop should report complete after PRD is updated")
	}
	if result.Iterations != 2 {
		t.Errorf("expected 2 iterations, got %d", result.Iterations)
	}
}

// fakeEngineWithHook wraps fakeEngine and calls a hook before each Execute.
type fakeEngineWithHook struct {
	*fakeEngine
	hook func(prompt string)
}

func (f *fakeEngineWithHook) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	if f.hook != nil {
		f.hook(prompt)
	}
	return f.fakeEngine.Execute(ctx, prompt, display)
}
func (f *fakeEngineWithHook) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return f.fakeEngine.StreamPrompt(ctx, prompt, display)
}

func TestFalseCompleteCounterResetsWhenStoryAdvances(t *testing.T) {
	stories := []engine.UserStory{
		{ID: "FIX-001", Title: "Fix auth", Priority: 1, Passes: false},
		{ID: "FIX-002", Title: "Fix billing", Priority: 2, Passes: false},
		{ID: "FIX-003", Title: "Fix UI", Priority: 3, Passes: false},
	}
	halDir := setupTestHalDir(t, stories)
	prdPath := filepath.Join(halDir, "prd.json")

	callCount := 0
	fe := &fakeEngine{
		results: []engine.Result{
			{Success: true, Complete: true},
			{Success: true, Complete: true},
			{Success: true, Complete: true},
		},
	}
	fe2 := &fakeEngineWithHook{
		fakeEngine: fe,
		hook: func(prompt string) {
			callCount++
			if callCount == 1 {
				prd := map[string]interface{}{
					"project":    "test",
					"branchName": "main",
					"userStories": []map[string]interface{}{
						{"id": "FIX-001", "title": "Fix auth", "priority": 1, "passes": true},
						{"id": "FIX-002", "title": "Fix billing", "priority": 2, "passes": false},
						{"id": "FIX-003", "title": "Fix UI", "priority": 3, "passes": false},
					},
				}
				data, _ := json.Marshal(prd)
				os.WriteFile(prdPath, data, 0644)
			}
			if callCount == 2 {
				prd := map[string]interface{}{
					"project":    "test",
					"branchName": "main",
					"userStories": []map[string]interface{}{
						{"id": "FIX-001", "title": "Fix auth", "priority": 1, "passes": true},
						{"id": "FIX-002", "title": "Fix billing", "priority": 2, "passes": true},
						{"id": "FIX-003", "title": "Fix UI", "priority": 3, "passes": false},
					},
				}
				data, _ := json.Marshal(prd)
				os.WriteFile(prdPath, data, 0644)
			}
		},
	}

	var logBuf bytes.Buffer
	runner := &Runner{
		config: Config{
			Dir:           halDir,
			PRDFile:       "prd.json",
			ProgressFile:  "progress.txt",
			MaxIterations: 5,
			Logger:        &logBuf,
			RetryDelay:    time.Millisecond,
			MaxRetries:    0,
		},
		engine:  fe2,
		display: engine.NewDisplay(&logBuf),
	}

	result := runner.Run(context.Background())
	if result.Success {
		t.Fatal("loop should fail after repeated false COMPLETE on the same pending story")
	}
	if result.Error == nil {
		t.Fatal("loop should return an error after repeated false COMPLETE signals")
	}
	if !strings.Contains(result.Error.Error(), "FIX-003") {
		t.Fatalf("error = %q, want failure on the third pending story", result.Error.Error())
	}
	if fe.calls != 3 {
		t.Fatalf("engine calls = %d, want 3 after progress resets the false COMPLETE counter", fe.calls)
	}
}
