package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func requireRenderedJSONExitCode(t *testing.T, err error, want int) {
	t.Helper()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %T %v, want *ExitCodeError", err, err)
	}
	if exitErr.Code != want {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, want)
	}
	if exitErr.Err != nil {
		t.Fatalf("embedded error = %v, want nil after JSON was rendered", exitErr.Err)
	}
}

func TestRunRunWithWriterJSONExitStatusAndStdoutIntegrity(t *testing.T) {
	t.Run("preflight validation", func(t *testing.T) {
		chdirTemp(t)
		var out bytes.Buffer
		var errOut bytes.Buffer
		cmd := newRunSandboxTestCommand(&out, &errOut)
		if err := cmd.Flags().Set("json", "true"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		if err := cmd.Flags().Set("base", "main"); err != nil {
			t.Fatalf("set base: %v", err)
		}

		err := runRunWithWriter(cmd, nil, &errOut)
		requireRenderedJSONExitCode(t, err, ExitCodeValidation)
		assertSingleRunJSONDocument(t, out.Bytes(), false)
		if errOut.Len() != 0 {
			t.Fatalf("stderr = %q, want empty", errOut.String())
		}
	})

	t.Run("loop failure", func(t *testing.T) {
		chdirTemp(t)
		dir, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		writeRunExitStatusPRD(t, dir, false)
		var out bytes.Buffer
		var errOut bytes.Buffer
		cmd := newRunSandboxTestCommand(&out, &errOut)
		if err := cmd.Flags().Set("json", "true"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		if err := cmd.Flags().Set("base", "main"); err != nil {
			t.Fatalf("set base: %v", err)
		}

		err = runRunWithWriter(cmd, nil, &errOut)
		requireRenderedJSONExitCode(t, err, ExitCodeExpectedNonZero)
		assertSingleRunJSONDocument(t, out.Bytes(), false)
		if errOut.Len() != 0 {
			t.Fatalf("stderr = %q, want empty", errOut.String())
		}
	})

	tests := []struct {
		name     string
		complete bool
	}{
		{name: "max iteration incomplete", complete: false},
		{name: "complete", complete: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chdirTemp(t)
			dir, err := os.Getwd()
			if err != nil {
				t.Fatalf("getwd: %v", err)
			}
			writeRunExitStatusPRD(t, dir, tt.complete)
			halDir := filepath.Join(dir, ".hal")
			if err := os.WriteFile(filepath.Join(halDir, "prompt.md"), []byte("Story: {{STORY_ID}}\n"), 0o600); err != nil {
				t.Fatalf("write prompt: %v", err)
			}

			var out bytes.Buffer
			var errOut bytes.Buffer
			cmd := newRunSandboxTestCommand(&out, &errOut)
			for flag, value := range map[string]string{"json": "true", "dry-run": "true", "base": "main", "iterations": "1"} {
				if err := cmd.Flags().Set(flag, value); err != nil {
					t.Fatalf("set %s: %v", flag, err)
				}
			}

			if err := runRunWithWriter(cmd, nil, &errOut); err != nil {
				t.Fatalf("runRunWithWriter() error = %v, want zero exit", err)
			}
			result := assertSingleRunJSONDocument(t, out.Bytes(), true)
			if result.Complete != tt.complete {
				t.Fatalf("complete = %v, want %v", result.Complete, tt.complete)
			}
			if errOut.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", errOut.String())
			}
		})
	}
}

func TestRunSandboxRuntimeExecPropagatesNonzeroResult(t *testing.T) {
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{ExitCode: ExitCodeExpectedNonZero}, nil
		},
	}
	err := runSandboxRuntimeExec(context.Background(), sandboxexec.RunContext{
		Driver: driver,
	}, sandboxexec.CommandRequest{
		Command: []string{"hal", "run", "--json"},
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	requireRenderedJSONExitCode(t, err, ExitCodeExpectedNonZero)
}

func assertSingleRunJSONDocument(t *testing.T, data []byte, wantOK bool) RunResult {
	t.Helper()
	var result RunResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("stdout is not exactly one RunResult JSON document: %v\n%s", err, data)
	}
	if result.OK != wantOK {
		t.Fatalf("ok = %v, want %v", result.OK, wantOK)
	}
	return result
}

func writeRunExitStatusPRD(t *testing.T, dir string, complete bool) {
	t.Helper()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o700); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	passes := "false"
	if complete {
		passes = "true"
	}
	payload := `{
  "project": "exit status",
  "branchName": "hal/exit-status",
  "description": "verify JSON exits",
  "userStories": [{
    "id": "US-001",
    "title": "Exit status",
    "description": "verify JSON exits",
    "acceptanceCriteria": ["works"],
    "priority": 1,
    "passes": ` + passes + `
  }]
}`
	if err := os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write prd: %v", err)
	}
}

func TestOutputRunJSONFailureReturnsExpectedNonzero(t *testing.T) {
	var out bytes.Buffer
	err := outputRunJSONForCommand(nil, &out, loop.Result{Success: false, Error: errors.New("failed")}, "", false, "codex")
	requireRenderedJSONExitCode(t, err, ExitCodeExpectedNonZero)
	assertSingleRunJSONDocument(t, out.Bytes(), false)
}
