package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/spf13/cobra"
)

func TestRunRun_DryRun_AllowsMissingGitRepoWithoutBase(t *testing.T) {
	dir := t.TempDir()

	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "prompt.md"), []byte("Base: {{BASE_BRANCH}}\n"), 0644); err != nil {
		t.Fatalf("write prompt.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "progress.txt"), []byte("## Codebase Patterns\n"), 0644); err != nil {
		t.Fatalf("write progress.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(`{
  "project": "test",
  "branchName": "hal/test",
  "description": "desc",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story",
      "description": "Do thing",
      "acceptanceCriteria": ["works"],
      "priority": 1,
      "passes": false
    }
  ]
}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
		dryRunFlag = false
		storyFlag = ""
		runBaseFlag = ""
		runIterationsFlag = 10
		engineFlag = "codex"
		maxRetries = 3
		retryDelay = 5 * time.Second
		runTimeout = 0
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	dryRunFlag = true
	storyFlag = ""
	runBaseFlag = ""
	runIterationsFlag = 10
	engineFlag = "codex"
	maxRetries = 1
	retryDelay = 10 * time.Millisecond
	runTimeout = 0

	var stderr bytes.Buffer
	if err := runRunWithWriter(nil, nil, &stderr); err != nil {
		t.Fatalf("runRunWithWriter should succeed without git repo in dry-run mode, got: %v", err)
	}

	if !strings.Contains(stderr.String(), "defaulting to current HEAD") {
		t.Fatalf("expected base branch fallback warning, got: %q", stderr.String())
	}
}

func TestRunRun_DryRun_AllowsDetachedHeadWithoutBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}

	dir := t.TempDir()
	writeFile := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	runGit("init")
	runGit("config", "user.name", "tester")
	runGit("config", "user.email", "tester@example.com")
	runGit("config", "commit.gpgsign", "false")

	writeFile(filepath.Join(dir, "README.md"), "seed\n")
	runGit("add", "README.md")
	runGit("commit", "-m", "init")
	commit := runGit("rev-parse", "HEAD")
	runGit("checkout", "--detach", commit)

	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(filepath.Join(halDir, "prompt.md"), "Base: {{BASE_BRANCH}}\n")
	writeFile(filepath.Join(halDir, "progress.txt"), "## Codebase Patterns\n")
	writeFile(filepath.Join(halDir, "prd.json"), `{
  "project": "test",
  "branchName": "hal/test",
  "description": "desc",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story",
      "description": "Do thing",
      "acceptanceCriteria": ["works"],
      "priority": 1,
      "passes": false
    }
  ]
}`)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
		dryRunFlag = false
		storyFlag = ""
		runBaseFlag = ""
		runIterationsFlag = 10
		engineFlag = "codex"
		maxRetries = 3
		retryDelay = 5 * time.Second
		runTimeout = 0
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	dryRunFlag = true
	storyFlag = ""
	runBaseFlag = ""
	runIterationsFlag = 10
	engineFlag = "codex"
	maxRetries = 1
	retryDelay = 10 * time.Millisecond
	runTimeout = 0

	if err := runRun(nil, nil); err != nil {
		t.Fatalf("runRun should succeed on detached HEAD without --base, got: %v", err)
	}
}

func TestRunRunWithWriter_IterationContract(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "run"}
		cmd.Flags().String("engine", "codex", "")
		cmd.Flags().Int("iterations", 10, "")
		cmd.Flags().String("base", "", "")
		cmd.Flags().Int("retries", 3, "")
		cmd.Flags().Duration("retry-delay", 5*time.Second, "")
		cmd.Flags().Duration("timeout", 0, "")
		cmd.Flags().Bool("dry-run", false, "")
		cmd.Flags().String("story", "", "")
		return cmd
	}

	isValidationErr := func(err error) bool {
		var exitErr *ExitCodeError
		return errors.As(err, &exitErr) && exitErr.Code == ExitCodeValidation
	}

	t.Run("positional iterations accepted", func(t *testing.T) {
		err := runRunWithWriter(newCmd(), []string{"3"}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), ".hal/ not found") {
			t.Fatalf("expected .hal missing error after parsing positional iterations, got: %v", err)
		}
	})

	t.Run("--iterations accepted", func(t *testing.T) {
		cmd := newCmd()
		if err := cmd.Flags().Set("iterations", "4"); err != nil {
			t.Fatalf("set iterations flag: %v", err)
		}

		err := runRunWithWriter(cmd, nil, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), ".hal/ not found") {
			t.Fatalf("expected .hal missing error after parsing --iterations, got: %v", err)
		}
	})

	t.Run("positional and --iterations conflict", func(t *testing.T) {
		cmd := newCmd()
		if err := cmd.Flags().Set("iterations", "4"); err != nil {
			t.Fatalf("set iterations flag: %v", err)
		}

		err := runRunWithWriter(cmd, []string{"3"}, &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if !isValidationErr(err) {
			t.Fatalf("expected validation exit code error, got: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "iterations provided both positionally and via --iterations") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("zero iterations rejected", func(t *testing.T) {
		err := runRunWithWriter(newCmd(), []string{"0"}, &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if !isValidationErr(err) {
			t.Fatalf("expected validation exit code error, got: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "iterations must be a positive integer") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("negative --iterations rejected", func(t *testing.T) {
		cmd := newCmd()
		if err := cmd.Flags().Set("iterations", "-2"); err != nil {
			t.Fatalf("set iterations flag: %v", err)
		}

		err := runRunWithWriter(cmd, nil, &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if !isValidationErr(err) {
			t.Fatalf("expected validation exit code error, got: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "iterations must be a positive integer") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("-b/--base accepted", func(t *testing.T) {
		cmd := newCmd()
		if err := cmd.Flags().Set("base", "develop"); err != nil {
			t.Fatalf("set base flag: %v", err)
		}

		err := runRunWithWriter(cmd, nil, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), ".hal/ not found") {
			t.Fatalf("expected .hal missing error after parsing --base, got: %v", err)
		}
	})

	t.Run("negative --timeout rejected", func(t *testing.T) {
		cmd := newCmd()
		if err := cmd.Flags().Set("timeout", "-1m"); err != nil {
			t.Fatalf("set timeout flag: %v", err)
		}

		err := runRunWithWriter(cmd, nil, &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if !isValidationErr(err) {
			t.Fatalf("expected validation exit code error, got: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "--timeout must be greater than or equal to 0") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestWithTimeoutOverride(t *testing.T) {
	t.Run("creates config when nil", func(t *testing.T) {
		cfg := withTimeoutOverride(nil, 30*time.Minute)
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.Timeout != 30*time.Minute {
			t.Fatalf("Timeout = %v, want %v", cfg.Timeout, 30*time.Minute)
		}
	})

	t.Run("preserves model and provider", func(t *testing.T) {
		cfg := withTimeoutOverride(&engine.EngineConfig{
			Model:    "o3",
			Provider: "openai",
			Timeout:  15 * time.Minute,
		}, 45*time.Minute)
		if cfg.Model != "o3" {
			t.Fatalf("Model = %q, want %q", cfg.Model, "o3")
		}
		if cfg.Provider != "openai" {
			t.Fatalf("Provider = %q, want %q", cfg.Provider, "openai")
		}
		if cfg.Timeout != 45*time.Minute {
			t.Fatalf("Timeout = %v, want %v", cfg.Timeout, 45*time.Minute)
		}
	})

	t.Run("ignores zero override", func(t *testing.T) {
		original := &engine.EngineConfig{Model: "o3"}
		cfg := withTimeoutOverride(original, 0)
		if cfg != original {
			t.Fatal("expected original config when override is zero")
		}
	})
}

func TestOutputRunJSON(t *testing.T) {
	tests := []struct {
		name     string
		result   loop.Result
		wantOK   bool
		wantComp bool
		wantErr  bool
	}{
		{
			name:     "success complete",
			result:   loop.Result{Success: true, Complete: true, Iterations: 5},
			wantOK:   true,
			wantComp: true,
		},
		{
			name:     "success incomplete",
			result:   loop.Result{Success: true, Complete: false, Iterations: 10},
			wantOK:   true,
			wantComp: false,
		},
		{
			name:     "failure with error",
			result:   loop.Result{Success: false, Iterations: 3, Error: errors.New("engine timeout")},
			wantOK:   false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := outputRunJSON(&buf, tt.result, "", false); err != nil {
				t.Fatalf("outputRunJSON() error = %v", err)
			}

			var jr RunResult
			if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
				t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
			}

			if jr.ContractVersion != 1 {
				t.Fatalf("contractVersion = %d, want 1", jr.ContractVersion)
			}
			if jr.OK != tt.wantOK {
				t.Fatalf("ok = %v, want %v", jr.OK, tt.wantOK)
			}
			if jr.Complete != tt.wantComp {
				t.Fatalf("complete = %v, want %v", jr.Complete, tt.wantComp)
			}
			if tt.wantErr && jr.Error == "" {
				t.Fatal("error should not be empty")
			}
			if !tt.wantErr && jr.Error != "" {
				t.Fatalf("error should be empty, got %q", jr.Error)
			}
			if jr.Iterations != tt.result.Iterations {
				t.Fatalf("iterations = %d, want %d", jr.Iterations, tt.result.Iterations)
			}
			if jr.Summary == "" {
				t.Fatal("summary should not be empty")
			}
		})
	}
}

func TestOutputRunJSONError(t *testing.T) {
	var buf bytes.Buffer
	if err := outputRunJSONError(&buf, "test error msg"); err != nil {
		t.Fatalf("outputRunJSONError() error = %v", err)
	}

	var jr RunResult
	if err := json.Unmarshal(buf.Bytes(), &jr); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if jr.OK {
		t.Fatal("ok should be false for error")
	}
	if jr.Error != "test error msg" {
		t.Fatalf("error = %q, want %q", jr.Error, "test error msg")
	}
	if jr.ContractVersion != 1 {
		t.Fatalf("contractVersion = %d, want 1", jr.ContractVersion)
	}
}
