package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
)

func TestPrepareSandboxCommandContextRuntimePreservesAllowlistedFilesThenInitializes(t *testing.T) {
	projectDir := t.TempDir()
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{
		template.ConfigFile:    "engine:\n  name: pi\n",
		template.PromptFile:    "custom prompt\n",
		template.ProgressFile:  "custom progress\n",
		template.PRDFile:       `{"branchName":"hal/test"}`,
		template.AutoPRDFile:   `{"branchName":"hal/auto"}`,
		template.AutoStateFile: `{"step":"loop"}`,
	}
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(halDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(halDir, "host-secret.txt"), []byte("must not copy"), 0o600); err != nil {
		t.Fatal(err)
	}

	var copied []sandboxruntime.CopyRequest
	var execs []sandboxruntime.ExecRequest
	driver := fakeRunSandboxRuntimeDriver{
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copied = append(copied, req)
			return nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execs = append(execs, req)
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	op, err := prepareSandboxCommandContextRuntime(context.Background(), sandboxexecPrepareContext(driver), projectDir, "/workspace/repo", io.Discard)
	if err != nil {
		t.Fatalf("prepareSandboxCommandContextRuntime() error = %v", err)
	}
	if op.Phase != sandboxworkspace.MaterializationPhaseCommandConfig || !strings.Contains(op.Summary, "6") {
		t.Fatalf("operation = %#v, want command_config summary with copied count", op)
	}
	var copiedNames []string
	for _, req := range copied {
		copiedNames = append(copiedNames, filepath.Base(req.SourcePath))
		if strings.Contains(strings.Join([]string{req.DestinationPath}, " "), projectDir) {
			t.Fatalf("remote copy destination leaks host project path: %#v", req)
		}
	}
	wantNames := []string{template.ConfigFile, template.PromptFile, template.ProgressFile, template.PRDFile, template.AutoPRDFile, template.AutoStateFile}
	if !reflect.DeepEqual(copiedNames, wantNames) {
		t.Fatalf("copied names = %#v, want %#v", copiedNames, wantNames)
	}
	if len(execs) != len(wantNames)+1 {
		t.Fatalf("exec count = %d, want %d installs plus init", len(execs), len(wantNames)+1)
	}
	initReq := execs[len(execs)-1]
	if got := strings.Join(initReq.Args, " "); !strings.Contains(got, "hal init") || strings.Contains(got, "refresh-templates") {
		t.Fatalf("init args = %#v, want plain hal init", initReq.Args)
	}
	for _, req := range execs {
		joined := strings.Join(req.Args, " ")
		if strings.Contains(joined, projectDir) || strings.Contains(joined, "custom prompt") || strings.Contains(joined, "must not copy") {
			t.Fatalf("remote command leaks host path or content: %q", joined)
		}
	}
}

func TestPrepareSandboxCommandContextRuntimeRejectsSymlinkSource(t *testing.T) {
	projectDir := t.TempDir()
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(projectDir, "outside-config.yaml")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(halDir, template.ConfigFile)); err != nil {
		t.Fatal(err)
	}
	driver := fakeRunSandboxRuntimeDriver{
		copyIn: func(context.Context, sandboxruntime.CopyRequest) error {
			t.Fatal("CopyIn should not run for a symlink source")
			return nil
		},
	}
	_, err := prepareSandboxCommandContextRuntime(context.Background(), sandboxexecPrepareContext(driver), projectDir, "/workspace/repo", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v, want safe non-regular source rejection", err)
	}
}

func TestPrepareSandboxCommandContextRuntimeResetsMissingAllowlistedFiles(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, template.HalDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, template.HalDir, template.ConfigFile), []byte("engine: pi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var copied []sandboxruntime.CopyRequest
	var execs []sandboxruntime.ExecRequest
	driver := fakeRunSandboxRuntimeDriver{
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copied = append(copied, req)
			return nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execs = append(execs, req)
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	op, err := prepareSandboxCommandContextRuntime(context.Background(), sandboxexecPrepareContext(driver), projectDir, "/workspace/repo", io.Discard)
	if err != nil {
		t.Fatalf("prepareSandboxCommandContextRuntime() error = %v", err)
	}
	if !strings.Contains(op.Summary, "1 copied, 5 reset") {
		t.Fatalf("operation summary = %q, want reset count", op.Summary)
	}
	if len(copied) != 1 || filepath.Base(copied[0].SourcePath) != template.ConfigFile {
		t.Fatalf("copied = %#v, want config only", copied)
	}
	if len(execs) != len(sandboxCommandContextFiles)+1 {
		t.Fatalf("exec count = %d, want one install, five resets, and init", len(execs))
	}
	if got := strings.Join(execs[0].Args, " "); !strings.Contains(got, "mv") || !strings.Contains(got, template.ConfigFile) {
		t.Fatalf("install command = %q, want config install", got)
	}
	for i, name := range sandboxCommandContextFiles[1:] {
		joined := strings.Join(execs[i+1].Args, " ")
		if !strings.Contains(joined, "rm -f") || !strings.Contains(joined, name) {
			t.Fatalf("reset command %d = %#v, want removal for %q", i, execs[i+1].Args, name)
		}
	}
	if got := strings.Join(execs[len(execs)-1].Args, " "); !strings.Contains(got, "hal init") {
		t.Fatalf("final command = %q, want hal init", got)
	}
}

func sandboxexecPrepareContext(driver sandboxruntime.Driver) sandboxexec.PrepareContext {
	return sandboxexec.PrepareContext{
		Target: sandboxruntime.Target{Name: "bundle-target"},
		Driver: driver,
	}
}
