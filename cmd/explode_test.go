package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

type explodeTestEngine struct{}

func (explodeTestEngine) Name() string { return "fake" }

func (explodeTestEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (explodeTestEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (explodeTestEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func preserveExplodeFlags(t *testing.T) {
	t.Helper()
	origBranch := explodeBranchFlag
	origEngine := explodeEngineFlag
	origJSON := explodeJSONFlag
	t.Cleanup(func() {
		explodeBranchFlag = origBranch
		explodeEngineFlag = origEngine
		explodeJSONFlag = origJSON
	})
}

func chdirTempDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir temp dir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})
	return tmpDir
}

func writeMarkdownFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("# PRD\n\n## Overview"), 0644); err != nil {
		t.Fatalf("failed to write markdown fixture: %v", err)
	}
}

func writeGeneratedPRD(t *testing.T, outPath string, stories int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		t.Fatalf("mkdir for generated prd failed: %v", err)
	}

	userStories := make([]engine.UserStory, 0, stories)
	for i := 1; i <= stories; i++ {
		userStories = append(userStories, engine.UserStory{
			ID:                 fmt.Sprintf("T-%03d", i),
			Title:              "Story",
			Description:        "Description",
			AcceptanceCriteria: []string{"Typecheck passes"},
			Priority:           i,
			Passes:             false,
		})
	}

	p := engine.PRD{
		Project:     "Explode Shim",
		BranchName:  "hal/explode-shim",
		Description: "test",
		UserStories: userStories,
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal generated prd failed: %v", err)
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		t.Fatalf("write generated prd failed: %v", err)
	}
}

func extractTrailingJSON(t *testing.T, output string) string {
	t.Helper()
	start := strings.LastIndex(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end < start {
		t.Fatalf("failed to find trailing JSON object in output: %q", output)
	}
	return output[start : end+1]
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestRunExplodeWithDeps_DelegatesToConvertWithGranularCanonicalOutput(t *testing.T) {
	preserveExplodeFlags(t)
	tmpDir := chdirTempDir(t)

	mdPath := filepath.Join(tmpDir, "prd-feature.md")
	writeMarkdownFixture(t, mdPath)

	explodeBranchFlag = "hal/pinned-branch"
	explodeEngineFlag = "claude"
	explodeJSONFlag = false

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := &cobra.Command{Use: "explode"}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	called := false
	deps := explodeDeps{
		newEngine: func(name string) (engine.Engine, error) {
			if name != "claude" {
				t.Fatalf("newEngine called with %q, want %q", name, "claude")
			}
			return explodeTestEngine{}, nil
		},
		convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
			called = true
			if gotMDPath != mdPath {
				t.Fatalf("mdPath = %q, want %q", gotMDPath, mdPath)
			}
			wantOut := filepath.Join(template.HalDir, template.PRDFile)
			if gotOutPath != wantOut {
				t.Fatalf("outPath = %q, want %q", gotOutPath, wantOut)
			}
			if !opts.Granular {
				t.Fatal("opts.Granular = false, want true")
			}
			if opts.BranchName != explodeBranchFlag {
				t.Fatalf("opts.BranchName = %q, want %q", opts.BranchName, explodeBranchFlag)
			}
			writeGeneratedPRD(t, gotOutPath, 2)
			return nil
		},
		readFile: os.ReadFile,
	}

	if err := runExplodeWithDeps(cmd, []string{mdPath}, deps); err != nil {
		t.Fatalf("runExplodeWithDeps returned error: %v", err)
	}
	if !called {
		t.Fatal("convertWithEngine was not called")
	}

	if strings.TrimSpace(errOut.String()) != explodeDeprecationWarning {
		t.Fatalf("stderr warning = %q, want %q", strings.TrimSpace(errOut.String()), explodeDeprecationWarning)
	}

	if !strings.Contains(out.String(), "Path: .hal/prd.json") {
		t.Fatalf("stdout missing canonical output path: %q", out.String())
	}
	if strings.Contains(out.String(), template.AutoPRDFile) {
		t.Fatalf("stdout unexpectedly references legacy auto PRD path: %q", out.String())
	}
}

func TestRunExplodeWithDeps_JSONContractCompatibility(t *testing.T) {
	preserveExplodeFlags(t)
	tmpDir := chdirTempDir(t)

	mdPath := filepath.Join(tmpDir, "prd-feature.md")
	writeMarkdownFixture(t, mdPath)

	explodeBranchFlag = ""
	explodeEngineFlag = "codex"
	explodeJSONFlag = true

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := &cobra.Command{Use: "explode"}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	deps := explodeDeps{
		newEngine: func(name string) (engine.Engine, error) {
			if name != "codex" {
				t.Fatalf("newEngine called with %q, want %q", name, "codex")
			}
			return explodeTestEngine{}, nil
		},
		convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
			writeGeneratedPRD(t, gotOutPath, 3)
			return nil
		},
		readFile: os.ReadFile,
	}

	if err := runExplodeWithDeps(cmd, []string{mdPath}, deps); err != nil {
		t.Fatalf("runExplodeWithDeps returned error: %v", err)
	}

	if strings.TrimSpace(errOut.String()) != explodeDeprecationWarning {
		t.Fatalf("stderr warning = %q, want %q", strings.TrimSpace(errOut.String()), explodeDeprecationWarning)
	}

	jsonPayload := extractTrailingJSON(t, out.String())
	var generic map[string]any
	if err := json.Unmarshal([]byte(jsonPayload), &generic); err != nil {
		t.Fatalf("failed to unmarshal explode JSON output: %v", err)
	}

	keys := sortedKeys(generic)
	wantKeys := []string{"contractVersion", "ok", "outputPath", "summary", "taskCount"}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("json keys = %v, want %v", keys, wantKeys)
	}

	if generic["contractVersion"] != float64(1) {
		t.Fatalf("contractVersion = %v, want 1", generic["contractVersion"])
	}
	if generic["ok"] != true {
		t.Fatalf("ok = %v, want true", generic["ok"])
	}
	if generic["outputPath"] != filepath.Join(template.HalDir, template.PRDFile) {
		t.Fatalf("outputPath = %v, want %q", generic["outputPath"], filepath.Join(template.HalDir, template.PRDFile))
	}
	if generic["taskCount"] != float64(3) {
		t.Fatalf("taskCount = %v, want 3", generic["taskCount"])
	}
}
