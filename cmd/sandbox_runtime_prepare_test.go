package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestFactorySandboxSyncEngineAuthRuntimeUsesCopyBoundary(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"token":"test-only"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(auth) error: %v", err)
	}
	var copies []sandboxruntime.CopyRequest
	var execs []sandboxruntime.ExecRequest
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copies = append(copies, req)
			return nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execs = append(execs, req)
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	target := sandboxruntime.Target{
		ID:   "container-1",
		Name: "worker-rootless",
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverRootlessPodman,
			RuntimeID: "container-1",
		},
	}

	err := factorySandboxSyncEngineAuthRuntime(context.Background(), sandboxexec.PrepareContext{
		Target: target,
		Driver: driver,
	}, factorySandboxExecutorDeps{
		engineAuthFiles: func() []factorySandboxAuthFile {
			return []factorySandboxAuthFile{{SourcePath: authPath, RemotePath: ".codex/auth.json"}}
		},
	})
	if err != nil {
		t.Fatalf("factorySandboxSyncEngineAuthRuntime() error: %v", err)
	}
	if len(copies) != 1 {
		t.Fatalf("copy calls = %d, want 1", len(copies))
	}
	if copies[0].Target.ID != target.ID || copies[0].SourcePath != authPath || !strings.HasPrefix(copies[0].DestinationPath, "/tmp/hal-auth-") {
		t.Fatalf("copy request = %#v, want runtime auth staging", copies[0])
	}
	if len(execs) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(execs))
	}
	installScript := strings.Join(execs[0].Args, " ")
	for _, want := range []string{"chmod '0600'", ".codex/auth.json", "refusing symlink destination", "rm -f"} {
		if !strings.Contains(installScript, want) {
			t.Fatalf("auth install command missing %q: %q", want, installScript)
		}
	}
	if strings.Contains(installScript, authPath) || strings.Contains(installScript, "test-only") {
		t.Fatalf("auth install command leaked host path or credential content: %q", installScript)
	}
}

func TestFactorySandboxPrepareRemoteInputsRuntimeUsesCopyBoundary(t *testing.T) {
	projectDir := t.TempDir()
	inputPath := filepath.Join(projectDir, ".hal", "prd-feature.md")
	if err := os.MkdirAll(filepath.Dir(inputPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	if err := os.WriteFile(inputPath, []byte("# Test PRD\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(PRD) error: %v", err)
	}
	var copies []sandboxruntime.CopyRequest
	var execs []sandboxruntime.ExecRequest
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copies = append(copies, req)
			return nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execs = append(execs, req)
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	record := factory.RunRecord{RepoRemote: "git@github.com:example/game.git"}

	remote, err := factorySandboxPrepareRemoteInputsRuntime(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: projectDir,
		RunRecord:  record,
		RemoteAuto: factoryRunAutoRequest{Args: []string{".hal/prd-feature.md"}},
	}, sandboxexec.PrepareContext{
		Target: sandboxruntime.Target{ID: "container-1", Name: "worker-rootless"},
		Driver: driver,
	})
	if err != nil {
		t.Fatalf("factorySandboxPrepareRemoteInputsRuntime() error: %v", err)
	}
	if len(remote.Args) != 1 || remote.Args[0] != ".hal/prd-feature.md" {
		t.Fatalf("remote args = %#v, want workspace-relative PRD path", remote.Args)
	}
	if len(execs) != 1 || !strings.Contains(strings.Join(execs[0].Args, " "), "mkdir -p") {
		t.Fatalf("input preparation execs = %#v, want mkdir", execs)
	}
	if len(copies) != 1 {
		t.Fatalf("copy calls = %d, want 1", len(copies))
	}
	wantDestination := filepath.ToSlash(filepath.Join(factorySandboxRemoteWorkspaceDir(record), ".hal", "prd-feature.md"))
	if copies[0].SourcePath != inputPath || copies[0].DestinationPath != wantDestination {
		t.Fatalf("copy request = %#v, want %q -> %q", copies[0], inputPath, wantDestination)
	}
	if copies[0].Target.ID != "container-1" {
		t.Fatalf("copy target = %#v, want selected runtime target", copies[0].Target)
	}
	if execs[0].Stdout != io.Discard || execs[0].Stderr != io.Discard {
		t.Fatalf("input preparation writers = %#v/%#v, want discard", execs[0].Stdout, execs[0].Stderr)
	}
}
