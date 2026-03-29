//go:build integration
// +build integration

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

type convertGranularIntegrationEngine struct {
	promptCapture *string
}

func (e *convertGranularIntegrationEngine) Name() string {
	return "convert-granular-integration"
}

func (e *convertGranularIntegrationEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (e *convertGranularIntegrationEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return e.responseForPrompt(prompt), nil
}

func (e *convertGranularIntegrationEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return e.responseForPrompt(prompt), nil
}

func (e *convertGranularIntegrationEngine) responseForPrompt(prompt string) string {
	if e.promptCapture != nil {
		*e.promptCapture = prompt
	}

	idPrefix := "US"
	if strings.Contains(prompt, "IDs are sequential (T-001, T-002, etc.)") {
		idPrefix = "T"
	}

	return fmt.Sprintf(`{
  "project": "Integration Convert Granular",
  "branchName": "hal/integration-convert-granular",
  "description": "Integration fixture output",
  "userStories": [
    {
      "id": "%s-001",
      "title": "First task",
      "description": "As a user, I want task one so that convert output is testable",
      "acceptanceCriteria": ["Criterion 1", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    },
    {
      "id": "%s-002",
      "title": "Second task",
      "description": "As a user, I want task two so that ID format is validated",
      "acceptanceCriteria": ["Criterion 2", "Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": ""
    }
  ]
}`,
		idPrefix,
		idPrefix,
	)
}

func resetConvertFlagsForIntegrationTest() {
	if flag := convertCmd.Flags().Lookup("engine"); flag != nil {
		_ = flag.Value.Set("codex")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("output"); flag != nil {
		_ = flag.Value.Set("")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("validate"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("archive"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("force"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("granular"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("branch"); flag != nil {
		_ = flag.Value.Set("")
		flag.Changed = false
	}
	if flag := convertCmd.Flags().Lookup("json"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}

	convertEngineFlag = "codex"
	convertOutputFlag = ""
	convertValidateFlag = false
	convertArchiveFlag = false
	convertForceFlag = false
	convertGranularFlag = false
	convertBranchFlag = ""
	convertJSONFlag = false
}

func TestConvertGranularWritesCanonicalPRDWithTaskIDs(t *testing.T) {
	dir := t.TempDir()
	markdownPath := filepath.Join(dir, "prd-convert-granular.md")
	markdown := "# PRD: Integration Convert Granular\n\n## Scope\n- verify granular conversion path\n"
	if err := os.WriteFile(markdownPath, []byte(markdown), 0644); err != nil {
		t.Fatalf("write markdown fixture: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	root := Root()
	origOut := root.OutOrStdout()
	origErr := root.ErrOrStderr()
	origIn := root.InOrStdin()
	t.Cleanup(func() {
		root.SetOut(origOut)
		root.SetErr(origErr)
		root.SetIn(origIn)
		root.SetArgs(nil)
	})

	resetConvertFlagsForIntegrationTest()
	t.Cleanup(resetConvertFlagsForIntegrationTest)

	var capturedPrompt string
	engineName := "integration-convert-granular"
	engine.RegisterEngine(engineName, func(cfg *engine.EngineConfig) engine.Engine {
		return &convertGranularIntegrationEngine{promptCapture: &capturedPrompt}
	})

	root.SetArgs([]string{"convert", "--granular", "--engine", engineName, filepath.Base(markdownPath)})
	if err := root.Execute(); err != nil {
		t.Fatalf("hal convert --granular failed: %v", err)
	}

	if !strings.Contains(capturedPrompt, "IDs are sequential (T-001, T-002, etc.)") {
		t.Fatalf("expected granular task-ID instruction in prompt, got: %q", capturedPrompt)
	}

	prdPath := filepath.Join(dir, template.HalDir, template.PRDFile)
	prdBytes, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatalf("read converted prd.json: %v", err)
	}

	var converted engine.PRD
	if err := json.Unmarshal(prdBytes, &converted); err != nil {
		t.Fatalf("parse converted prd.json: %v", err)
	}
	if len(converted.UserStories) == 0 {
		t.Fatalf("expected converted user stories, got none in %s", prdPath)
	}

	taskIDPattern := regexp.MustCompile(`^T-\d{3}$`)
	for _, story := range converted.UserStories {
		if !taskIDPattern.MatchString(story.ID) {
			t.Fatalf("expected granular task ID format T-XXX, got %q", story.ID)
		}
	}
}
