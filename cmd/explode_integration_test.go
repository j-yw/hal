//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

type explodeShimIntegrationEngine struct{}

func (e *explodeShimIntegrationEngine) Name() string {
	return "explode-shim-integration"
}

func (e *explodeShimIntegrationEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (e *explodeShimIntegrationEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return e.response(), nil
}

func (e *explodeShimIntegrationEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return e.response(), nil
}

func (e *explodeShimIntegrationEngine) response() string {
	return `{
  "project": "Integration Explode Shim",
  "branchName": "hal/integration-explode-shim",
  "description": "Integration fixture output",
  "userStories": [
    {
      "id": "T-001",
      "title": "Explode task",
      "description": "As a user, I want compatibility coverage so that explode stays stable",
      "acceptanceCriteria": ["Criterion 1", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}`
}

func resetExplodeFlagsForIntegrationTest() {
	if flag := explodeCmd.Flags().Lookup("branch"); flag != nil {
		_ = flag.Value.Set("")
		flag.Changed = false
	}
	if flag := explodeCmd.Flags().Lookup("engine"); flag != nil {
		_ = flag.Value.Set("codex")
		flag.Changed = false
	}
	if flag := explodeCmd.Flags().Lookup("json"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}

	explodeBranchFlag = ""
	explodeEngineFlag = "codex"
	explodeJSONFlag = false
}

func TestExplodeShimWritesCanonicalPRDAndWarns(t *testing.T) {
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "prd-explode-shim.md")
	markdown := "# PRD: Integration Explode Shim\n\n## Scope\n- verify explode compatibility path\n"
	if err := os.WriteFile(mdPath, []byte(markdown), 0644); err != nil {
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

	resetExplodeFlagsForIntegrationTest()
	t.Cleanup(resetExplodeFlagsForIntegrationTest)

	engineName := "integration-explode-shim"
	engine.RegisterEngine(engineName, func(cfg *engine.EngineConfig) engine.Engine {
		return &explodeShimIntegrationEngine{}
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"explode", "--engine", engineName, filepath.Base(mdPath)})

	if err := root.Execute(); err != nil {
		t.Fatalf("hal explode failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	if !strings.Contains(stderr.String(), explodeDeprecationWarning) {
		t.Fatalf("expected deprecation warning %q in stderr, got %q", explodeDeprecationWarning, stderr.String())
	}

	canonicalOutput := filepath.Join(template.HalDir, template.PRDFile)
	if !strings.Contains(stdout.String(), canonicalOutput) {
		t.Fatalf("expected stdout to mention canonical output %q, got %q", canonicalOutput, stdout.String())
	}

	prdPath := filepath.Join(dir, canonicalOutput)
	if _, err := os.Stat(prdPath); err != nil {
		t.Fatalf("expected generated PRD at %s: %v", prdPath, err)
	}

	legacyPath := filepath.Join(dir, template.HalDir, template.AutoPRDFile)
	if _, err := os.Stat(legacyPath); err == nil {
		t.Fatalf("expected legacy output path to remain unused, found %s", legacyPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat legacy output path %s: %v", legacyPath, err)
	}
}
