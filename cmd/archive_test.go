package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

// writePRD writes a minimal prd.json with the given branch name into dir.
func writePRD(t *testing.T, dir, branchName string) {
	t.Helper()
	prd := engine.PRD{BranchName: branchName}
	data, err := json.Marshal(prd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, template.PRDFile), data, 0644); err != nil {
		t.Fatal(err)
	}
}

// writeFile creates a file with the given content in dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRunArchiveCreate(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, halDir string)
		nameFlag   string
		stdinInput string
		wantErr    string
		wantOutput string
	}{
		{
			name: "name flag bypasses prompt",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/my-feature")
			},
			nameFlag:   "my-feature",
			stdinInput: "",
			wantOutput: "archived",
		},
		{
			name: "prd branchName derives default shown in prompt",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/cool-feature")
			},
			nameFlag:   "",
			stdinInput: "\n",
			wantOutput: "Archive name [cool-feature]:",
		},
		{
			name: "empty input uses derived default name",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				writePRD(t, halDir, "hal/derived-name")
			},
			nameFlag:   "",
			stdinInput: "\n",
			wantOutput: "derived-name",
		},
		{
			name:       "error when halDir does not exist",
			setup:      func(t *testing.T, halDir string) {},
			nameFlag:   "test",
			stdinInput: "",
			wantErr:    ".hal/ not found",
		},
		{
			name: "error when no feature state files exist",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				// No prd.json or auto-prd.json
			},
			nameFlag:   "test",
			stdinInput: "",
			wantErr:    "no feature state to archive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, ".hal")

			if tt.setup != nil {
				// Only create halDir if setup will use it
				if tt.wantErr != ".hal/ not found" {
					os.MkdirAll(halDir, 0755)
				}
				tt.setup(t, halDir)
			}

			in := strings.NewReader(tt.stdinInput)
			var out bytes.Buffer

			err := runArchiveCreate(halDir, tt.nameFlag, in, &out)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}
		})
	}
}

func TestRunArchiveCreateWithIO_JSONMissingNameReturnsJSON(t *testing.T) {
	tmpDir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	if err := os.MkdirAll(filepath.Join(template.HalDir, "archive"), 0755); err != nil {
		t.Fatalf("mkdir .hal/archive: %v", err)
	}

	cmd := &cobra.Command{Use: "create"}
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(""))

	err = runArchiveCreateWithIO(cmd, "")
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "archive name is required with --json; pass --name/-n") {
		t.Fatalf("error %q does not contain missing-name message", err.Error())
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", out.String())
	}

	var result ArchiveCreateResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.OK {
		t.Fatalf("result.OK = true, want false")
	}
	wantErr := "archive name is required with --json; pass --name/-n"
	if result.Error != wantErr {
		t.Fatalf("result.Error = %q, want %q", result.Error, wantErr)
	}
}

func TestRunArchiveListFn(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, halDir string)
		verbose     bool
		wantErr     string
		wantOutput  []string
		wantMissing []string
	}{
		{
			name: "default output contains NAME DATE PROGRESS headers",
			setup: func(t *testing.T, halDir string) {
				archDir := filepath.Join(halDir, "archive", "2026-01-15-test-feature")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/test-feature")
			},
			verbose:     false,
			wantOutput:  []string{"NAME", "DATE", "PROGRESS"},
			wantMissing: []string{"BRANCH", "PATH"},
		},
		{
			name: "verbose output contains all column headers",
			setup: func(t *testing.T, halDir string) {
				archDir := filepath.Join(halDir, "archive", "2026-01-15-test-feature")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/test-feature")
			},
			verbose:    true,
			wantOutput: []string{"NAME", "DATE", "PROGRESS", "BRANCH", "PATH"},
		},
		{
			name: "empty archive prints no archives found",
			setup: func(t *testing.T, halDir string) {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
			},
			verbose:    false,
			wantOutput: []string{"No archives found."},
		},
		{
			name:    "error when halDir does not exist",
			setup:   func(t *testing.T, halDir string) {},
			verbose: false,
			wantErr: ".hal/ not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, ".hal")

			if tt.wantErr != ".hal/ not found" {
				os.MkdirAll(halDir, 0755)
			}
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			var out bytes.Buffer
			err := runArchiveListFn(halDir, tt.verbose, &out)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}
			for _, missing := range tt.wantMissing {
				if strings.Contains(output, missing) {
					t.Errorf("output %q should not contain %q", output, missing)
				}
			}
		})
	}
}

func TestRunArchiveListJSON(t *testing.T) {
	t.Run("missing hal dir returns JSON error payload", func(t *testing.T) {
		var out bytes.Buffer
		err := runArchiveListJSON(filepath.Join(t.TempDir(), ".hal"), &out)
		if err == nil {
			t.Fatal("expected error for missing .hal dir, got nil")
		}
		if !strings.Contains(err.Error(), ".hal/ not found") {
			t.Fatalf("error %q does not contain missing .hal message", err.Error())
		}

		if !json.Valid(out.Bytes()) {
			t.Fatalf("stdout is not valid JSON: %q", out.String())
		}

		var result map[string]interface{}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		okValue, ok := result["ok"].(bool)
		if !ok || okValue {
			t.Fatalf("result.ok = %v (present: %v), want false", result["ok"], ok)
		}

		errorValue, ok := result["error"].(string)
		if !ok || !strings.Contains(errorValue, ".hal/ not found") {
			t.Fatalf("result.error = %q, want .hal/ not found message", result["error"])
		}

		archives, ok := result["archives"].([]interface{})
		if !ok {
			t.Fatalf("result.archives is %T, want array", result["archives"])
		}
		if len(archives) != 0 {
			t.Fatalf("len(result.archives) = %d, want 0", len(archives))
		}
	})

	t.Run("success returns archive envelope JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		halDir := filepath.Join(tmpDir, ".hal")
		archiveDir := filepath.Join(halDir, "archive", "2026-01-15-test-feature")
		if err := os.MkdirAll(archiveDir, 0755); err != nil {
			t.Fatalf("mkdir archive dir: %v", err)
		}
		writePRD(t, archiveDir, "hal/test-feature")

		var out bytes.Buffer
		err := runArchiveListJSON(halDir, &out)
		if err != nil {
			t.Fatalf("runArchiveListJSON returned error: %v", err)
		}

		if !json.Valid(out.Bytes()) {
			t.Fatalf("stdout is not valid JSON: %q", out.String())
		}

		var result map[string]interface{}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("expected envelope JSON output, unmarshal error: %v", err)
		}

		okValue, ok := result["ok"].(bool)
		if !ok || !okValue {
			t.Fatalf("result.ok = %v (present: %v), want true", result["ok"], ok)
		}

		archives, ok := result["archives"].([]interface{})
		if !ok {
			t.Fatalf("result.archives is %T, want array", result["archives"])
		}
		if len(archives) != 1 {
			t.Fatalf("len(result.archives) = %d, want 1", len(archives))
		}

		first, ok := archives[0].(map[string]interface{})
		if !ok {
			t.Fatalf("result.archives[0] is %T, want object", archives[0])
		}
		if first["name"] != "2026-01-15-test-feature" {
			t.Fatalf("archive name = %v, want 2026-01-15-test-feature", first["name"])
		}
	})
}

func TestRunArchiveRestoreFn(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, halDir string) string // returns archive name
		wantErr    string
		wantOutput []string
		checkFn    func(t *testing.T, halDir string)
	}{
		{
			name: "restore moves files back and removes archive dir",
			setup: func(t *testing.T, halDir string) string {
				archName := "2026-01-15-my-feature"
				archDir := filepath.Join(halDir, "archive", archName)
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/my-feature")
				writeFile(t, archDir, template.ProgressFile, "some progress")
				return archName
			},
			wantOutput: []string{"restored"},
			checkFn: func(t *testing.T, halDir string) {
				// prd.json should be restored to halDir
				if _, err := os.Stat(filepath.Join(halDir, template.PRDFile)); os.IsNotExist(err) {
					t.Error("prd.json should exist in halDir after restore")
				}
				// progress.txt should be restored
				if _, err := os.Stat(filepath.Join(halDir, template.ProgressFile)); os.IsNotExist(err) {
					t.Error("progress.txt should exist in halDir after restore")
				}
				// archive dir should be removed
				if _, err := os.Stat(filepath.Join(halDir, "archive", "2026-01-15-my-feature")); !os.IsNotExist(err) {
					t.Error("archive directory should be removed after restore")
				}
			},
		},
		{
			name: "restore with current state auto-archives first",
			setup: func(t *testing.T, halDir string) string {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				// Current state: prd.json in halDir
				writePRD(t, halDir, "hal/current-feature")
				// Archive to restore
				archName := "2026-01-15-old-feature"
				archDir := filepath.Join(halDir, "archive", archName)
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, "hal/old-feature")
				return archName
			},
			wantOutput: []string{"auto-archiving current state", "restored"},
			checkFn: func(t *testing.T, halDir string) {
				// The old feature's prd.json should now be in halDir
				data, err := os.ReadFile(filepath.Join(halDir, template.PRDFile))
				if err != nil {
					t.Fatalf("prd.json should exist after restore: %v", err)
				}
				var prd engine.PRD
				if err := json.Unmarshal(data, &prd); err != nil {
					t.Fatalf("failed to unmarshal restored prd.json: %v", err)
				}
				if prd.BranchName != "hal/old-feature" {
					t.Errorf("restored prd.json branchName = %q, want %q", prd.BranchName, "hal/old-feature")
				}
			},
		},
		{
			name: "error when archive name does not exist",
			setup: func(t *testing.T, halDir string) string {
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				return "nonexistent-archive"
			},
			wantErr: "does not exist",
		},
		{
			name: "error when halDir does not exist",
			setup: func(t *testing.T, halDir string) string {
				return "any-name"
			},
			wantErr: ".hal/ not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, ".hal")

			if tt.wantErr != ".hal/ not found" {
				os.MkdirAll(halDir, 0755)
			}

			archName := tt.setup(t, halDir)

			var out bytes.Buffer
			err := runArchiveRestoreFn(halDir, archName, &out)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}

			if tt.checkFn != nil {
				tt.checkFn(t, halDir)
			}
		})
	}
}

func TestArchiveCLIContracts(t *testing.T) {
	assertValidationErr := func(t *testing.T, err error, contains string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		var exitErr *ExitCodeError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitCodeError, got %T (%v)", err, err)
		}
		if exitErr.Code != ExitCodeValidation {
			t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
		}
		if !strings.Contains(err.Error(), contains) {
			t.Fatalf("error %q does not contain %q", err.Error(), contains)
		}
	}

	execRoot := func(t *testing.T, dir string, stdin string, args ...string) (string, string, error) {
		t.Helper()

		origDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(origDir) })

		origOut := rootCmd.OutOrStdout()
		origErr := rootCmd.ErrOrStderr()
		origIn := rootCmd.InOrStdin()
		t.Cleanup(func() {
			rootCmd.SetOut(origOut)
			rootCmd.SetErr(origErr)
			rootCmd.SetIn(origIn)
			rootCmd.SetArgs(nil)
		})

		if flag := archiveCmd.PersistentFlags().Lookup("name"); flag != nil {
			_ = flag.Value.Set("")
			flag.Changed = false
		}
		archiveNameFlag = ""
		if flag := archiveCmd.Flags().Lookup("json"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}
		if flag := archiveCreateCmd.Flags().Lookup("json"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}
		if flag := archiveListCmd.Flags().Lookup("verbose"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}
		archiveVerboseFlag = false
		if flag := archiveListCmd.Flags().Lookup("json"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}
		if flag := archiveRestoreCmd.Flags().Lookup("json"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}

		var stdout, stderr bytes.Buffer
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		rootCmd.SetIn(strings.NewReader(stdin))
		rootCmd.SetArgs(args)

		err = rootCmd.Execute()
		return stdout.String(), stderr.String(), err
	}

	setupState := func(t *testing.T, dir string) {
		t.Helper()
		halDir := filepath.Join(dir, template.HalDir)
		if err := os.MkdirAll(filepath.Join(halDir, "archive"), 0755); err != nil {
			t.Fatalf("mkdir archive: %v", err)
		}
		writePRD(t, halDir, "hal/test-feature")
	}

	t.Run("hal archive -n works", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		stdout, _, err := execRoot(t, dir, "", "archive", "-n", "foo")
		if err != nil {
			t.Fatalf("archive command failed: %v", err)
		}
		if !strings.Contains(stdout, "archived to") {
			t.Fatalf("stdout %q does not contain archive success", stdout)
		}
	})

	t.Run("hal archive --json -n works", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		stdout, _, err := execRoot(t, dir, "", "archive", "--json", "-n", "foo")
		if err != nil {
			t.Fatalf("archive --json command failed: %v", err)
		}

		if !json.Valid([]byte(stdout)) {
			t.Fatalf("stdout %q is not valid JSON", stdout)
		}

		var result ArchiveCreateResult
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatalf("unmarshal stdout: %v", err)
		}
		if !result.OK {
			t.Fatalf("result.OK = false, want true (error=%q)", result.Error)
		}
	})

	t.Run("hal archive create -n works", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		stdout, _, err := execRoot(t, dir, "", "archive", "create", "-n", "foo")
		if err != nil {
			t.Fatalf("archive create command failed: %v", err)
		}
		if !strings.Contains(stdout, "archived to") {
			t.Fatalf("stdout %q does not contain archive success", stdout)
		}
	})

	t.Run("non-interactive no name fails", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		_, _, err := execRoot(t, dir, "", "archive")
		assertValidationErr(t, err, "archive name is required in non-interactive mode; pass --name/-n")
	})

	t.Run("archive list rejects inherited --name", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		_, _, err := execRoot(t, dir, "", "archive", "list", "-n", "x")
		assertValidationErr(t, err, "--name/-n is only valid with 'hal archive' or 'hal archive create'")
	})

	t.Run("archive restore rejects inherited --name", func(t *testing.T) {
		dir := t.TempDir()
		setupState(t, dir)

		_, _, err := execRoot(t, dir, "", "archive", "restore", "2026-01-15-foo", "-n", "x")
		assertValidationErr(t, err, "--name/-n is only valid with 'hal archive' or 'hal archive create'")
	})
}
