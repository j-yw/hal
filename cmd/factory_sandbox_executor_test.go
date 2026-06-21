package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestNormalizeFactorySandboxExecutorDepsFillsProductionDefaults(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{})

	checks := map[string]any{
		"defaultStore":    deps.defaultStore,
		"now":             deps.now,
		"resolveDefault":  deps.resolveDefault,
		"loadSandbox":     deps.loadSandbox,
		"provision":       deps.provision,
		"startSandbox":    deps.startSandbox,
		"resolveProvider": deps.resolveProvider,
		"runProviderExec": deps.runProviderExec,
		"bootstrap":       deps.bootstrap,
		"saveRun":         deps.saveRun,
		"appendEvent":     deps.appendEvent,
	}
	for name, fn := range checks {
		if reflect.ValueOf(fn).IsNil() {
			t.Fatalf("%s dependency was not defaulted", name)
		}
	}
}

func TestFactorySandboxConnectionMetadataFromStatePrefersTailscaleAddress(t *testing.T) {
	tests := []struct {
		name        string
		instance    *sandbox.SandboxState
		wantAddress string
		wantPublic  string
	}{
		{
			name: "tailscale ip preferred over public ip",
			instance: &sandbox.SandboxState{
				IP:                "203.0.113.42",
				TailscaleIP:       "100.64.0.9",
				TailscaleHostname: "hal-factory-dev",
				TailscaleLockdown: true,
			},
			wantAddress: "100.64.0.9",
			wantPublic:  "203.0.113.42",
		},
		{
			name: "lockdown hostname fallback without public ip",
			instance: &sandbox.SandboxState{
				TailscaleHostname: "hal-factory-dev",
				TailscaleLockdown: true,
			},
			wantAddress: "hal-factory-dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factorySandboxConnectionMetadataFromState(tt.instance)
			if got == nil {
				t.Fatal("factorySandboxConnectionMetadataFromState() = nil")
			}
			if got.Address != tt.wantAddress {
				t.Fatalf("Address = %q, want %q", got.Address, tt.wantAddress)
			}
			if got.PublicIP != tt.wantPublic {
				t.Fatalf("PublicIP = %q, want %q", got.PublicIP, tt.wantPublic)
			}
		})
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesFakeSideEffectBoundaries(t *testing.T) {
	now := time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var calls []string
	var savedRecords []factory.RunRecord
	var appendedEvent factory.EventRecord
	var gotExecArgs []string
	var gotExecInfo *sandbox.ConnectInfo
	var execCalls int

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  projectDir,
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:        "run-sandbox",
			Status:       factory.RunStatusRunning,
			ExecutorMode: factory.ExecutorModeLocal,
			RepoRemote:   "git@github.com:example/repo.git",
		},
		RemoteAuto:   factoryRunAutoRequest{Args: []string{".hal/prd.md"}},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			calls = append(calls, "store")
			return store, nil
		},
		now: func() time.Time {
			calls = append(calls, "now")
			return now
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			calls = append(calls, "load")
			if name != "factory-dev" {
				t.Fatalf("load sandbox name = %q, want factory-dev", name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatalf("provision should not be called when resolve succeeds")
			return nil, nil
		},
		startSandbox: func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error) {
			t.Fatalf("startSandbox should not be called for running target")
			return nil, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			if providerName != "daytona" {
				t.Fatalf("providerName = %q, want daytona", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, info *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			calls = append(calls, "exec")
			execCalls++
			gotExecInfo = info
			if execCalls == 2 {
				gotExecArgs = append([]string(nil), args...)
			}
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			calls = append(calls, "save")
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			calls = append(calls, "event")
			appendedEvent = *event
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}

	wantCalls := []string{"store", "now", "save", "load", "now", "save", "provider", "exec", "now", "event", "exec", "now", "event"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	if savedRecords[0].ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("saved executorMode = %q, want %q", savedRecords[0].ExecutorMode, factory.ExecutorModeSandbox)
	}
	if !savedRecords[0].UpdatedAt.Equal(now) {
		t.Fatalf("saved UpdatedAt = %s, want %s", savedRecords[0].UpdatedAt, now)
	}
	if savedRecords[1].SandboxName != "factory-dev" {
		t.Fatalf("saved sandboxName = %q, want factory-dev", savedRecords[1].SandboxName)
	}
	if savedRecords[1].Sandbox == nil {
		t.Fatalf("saved sandbox metadata = nil")
	}
	if savedRecords[1].Sandbox.Name != "factory-dev" || savedRecords[1].Sandbox.Provider != "daytona" || savedRecords[1].Sandbox.Status != sandbox.StatusRunning {
		t.Fatalf("saved sandbox metadata = %#v", savedRecords[1].Sandbox)
	}
	if savedRecords[1].Sandbox.Connection == nil || savedRecords[1].Sandbox.Connection.PublicIP != "127.0.0.1" {
		t.Fatalf("saved sandbox connection = %#v", savedRecords[1].Sandbox.Connection)
	}
	if gotExecInfo == nil || gotExecInfo.Name != "factory-dev" || gotExecInfo.IP != "127.0.0.1" {
		t.Fatalf("exec info = %#v, want factory-dev at 127.0.0.1", gotExecInfo)
	}
	if !reflect.DeepEqual(gotExecArgs, []string{"sh", "-lc", "cd '/workspace/repo' && exec 'hal' 'auto' '.hal/prd.md'"}) {
		t.Fatalf("exec args = %#v", gotExecArgs)
	}
	if appendedEvent.RunID != "run-sandbox" || appendedEvent.EventType != factory.EventTypeStepEnded || appendedEvent.Metadata["executorMode"] != factory.ExecutorModeSandbox {
		t.Fatalf("appended event = %#v", appendedEvent)
	}
	if appendedEvent.Summary != "Remote sandbox execution completed" || appendedEvent.Metadata["source"] != "remote_sandbox" {
		t.Fatalf("appended completion event = %#v", appendedEvent)
	}
}

func TestRunFactorySandboxExecutorWithDepsBootstrapsWorkspaceBeforeRemoteExecution(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var calls []string
	var bootstrapReq factory.BootstrapRequest
	var bootstrapDeps factory.BootstrapDeps
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap",
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			return fakeFactorySandboxProvider{}, nil
		},
		bootstrap: func(_ context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			calls = append(calls, "bootstrap")
			bootstrapReq = req
			bootstrapDeps = deps
			return factory.BootstrapResult{
				Timeline: []factory.BootstrapTimelineEvent{{
					Timestamp:      now,
					Step:           factory.BootstrapStepCloneRepository,
					Status:         factory.RunStatusSucceeded,
					Message:        "bootstrap step succeeded",
					CommandSummary: "git clone <redacted> /workspace/repo",
				}},
			}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			calls = append(calls, "exec")
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"provider", "bootstrap", "exec"}) {
		t.Fatalf("calls = %#v, want provider/bootstrap/exec", calls)
	}
	if bootstrapReq.RepositoryURL != "git@github.com:example/repo.git" || bootstrapReq.BaseBranch != "main" || bootstrapReq.RunBranch != "hal/feature" || bootstrapReq.WorkspaceDir != "/workspace/repo" {
		t.Fatalf("bootstrap request = %#v", bootstrapReq)
	}
	if !bootstrapReq.Options.RefreshHal {
		t.Fatalf("bootstrap refreshHal = false")
	}
	if bootstrapDeps.Executor == nil {
		t.Fatalf("bootstrap executor = nil")
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3: %#v", len(events), events)
	}
	if events[0].Metadata["phase"] != "bootstrap" || events[0].Metadata["source"] != "remote_sandbox" {
		t.Fatalf("bootstrap event metadata = %#v", events[0].Metadata)
	}
	if events[1].Summary != "Remote sandbox execution started" || events[2].Summary != "Remote sandbox execution completed" {
		t.Fatalf("remote execution events = %#v", events)
	}
	if events[0].Sequence != 1 || events[1].Sequence != 2 || events[2].Sequence != 3 {
		t.Fatalf("event sequences = %d/%d/%d, want 1/2/3", events[0].Sequence, events[1].Sequence, events[2].Sequence)
	}
}

func TestRunFactorySandboxExecutorWithDepsBootstrapsWorkspaceWithRemoteRepositoryProbes(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	var execArgs [][]string
	bootstrapCalled := false
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap-remote-probes",
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
		},
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		bootstrap: func(ctx context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			bootstrapCalled = true
			if deps.RepoExists == nil || deps.RepoRemoteURL == nil {
				t.Fatalf("bootstrap repository probes were not injected")
			}
			exists, err := deps.RepoExists(req.WorkspaceDir)
			if err != nil {
				t.Fatalf("RepoExists() error: %v", err)
			}
			if !exists {
				t.Fatalf("RepoExists() = false, want true")
			}
			remote, err := deps.RepoRemoteURL(req.WorkspaceDir)
			if err != nil {
				t.Fatalf("RepoRemoteURL() error: %v", err)
			}
			if remote != req.RepositoryURL {
				t.Fatalf("RepoRemoteURL() = %q, want %q", remote, req.RepositoryURL)
			}
			return factory.BootstrapResult{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, out io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			switch {
			case len(args) == 3 && args[0] == "sh" && args[1] == "-lc" && strings.Contains(args[2], "non_git_non_empty"):
				_, err := io.WriteString(out, "git")
				return err
			case len(args) == 6 && reflect.DeepEqual(args, []string{"git", "-C", "/workspace/repo", "remote", "get-url", "origin"}):
				_, err := io.WriteString(out, "git@github.com:example/repo.git\n")
				return err
			default:
				return nil
			}
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !bootstrapCalled {
		t.Fatalf("bootstrap was not called")
	}
	if len(execArgs) != 3 {
		t.Fatalf("exec calls = %d, want repo exists probe, remote URL probe, remote execution: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], "p='/workspace/repo'") {
		t.Fatalf("repo exists probe args = %#v", execArgs[0])
	}
	if !reflect.DeepEqual(execArgs[1], []string{"git", "-C", "/workspace/repo", "remote", "get-url", "origin"}) {
		t.Fatalf("repo remote probe args = %#v", execArgs[1])
	}
}

func TestRunFactorySandboxExecutorWithDepsDoesNotPersistUnsanitizedBootstrapStreamingOutput(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	secret := "repo-secret"
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var userOut bytes.Buffer
	var events []factory.EventRecord
	execCalls := 0
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-bootstrap-redaction",
			RepoRemote: "https://token:" + secret + "@github.com/example/repo.git",
			BaseBranch: "main",
			BranchName: "hal/feature",
		},
		RemoteOutput: &userOut,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		bootstrap: func(ctx context.Context, req factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
			step, commandResult, failure, err := factory.RunBootstrapStep(ctx, factory.BootstrapStepDeps{
				Executor: deps.Executor,
				Now:      deps.Now,
				Request:  req,
			}, factory.BootstrapStepCloneRepository, factory.BootstrapCommand{
				Name: "git",
				Args: []string{"clone", req.RepositoryURL, req.WorkspaceDir},
			})
			return factory.BootstrapResult{
				Steps:    []factory.BootstrapStepResult{step},
				Timeline: []factory.BootstrapTimelineEvent{factory.BootstrapTimelineEventFromStep(req, step, commandResult, failure)},
			}, err
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			execCalls++
			if execCalls == 1 {
				_, err := io.WriteString(out, "cloning with "+secret+"\n")
				return err
			}
			return nil
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(store factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return store.AppendEvent(event)
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !strings.Contains(userOut.String(), secret) {
		t.Fatalf("user output = %q, want raw bootstrap stream", userOut.String())
	}
	for _, event := range events {
		if strings.Contains(fmt.Sprintf("%#v", event), secret) {
			t.Fatalf("persisted event leaked bootstrap secret: %#v", event)
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsCopiesLocalMarkdownBeforeRemoteExecution(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd-feature.md"), []byte("# Feature\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var execArgs [][]string

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  projectDir,
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-copy-markdown",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{
			Args:       []string{".hal/prd-feature.md"},
			BaseBranch: "main",
		},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(execArgs) != 2 {
		t.Fatalf("exec calls = %d, want 2: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], "base64 -d > '/workspace/repo/.hal/prd-feature.md'") {
		t.Fatalf("copy exec args = %#v", execArgs[0])
	}
	wantRemote := []string{"sh", "-lc", "cd '/workspace/repo' && exec 'hal' 'auto' '.hal/prd-feature.md' '--base' 'main'"}
	if !reflect.DeepEqual(execArgs[1], wantRemote) {
		t.Fatalf("remote exec args = %#v, want %#v", execArgs[1], wantRemote)
	}
}

func TestRunFactorySandboxExecutorWithDepsCopiesAbsoluteReportToRemoteInputPath(t *testing.T) {
	projectDir := t.TempDir()
	reportPath := filepath.Join(projectDir, "analysis.md")
	if err := os.WriteFile(reportPath, []byte("# Analysis\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var execArgs [][]string

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  projectDir,
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:      "run-copy-report",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@github.com:example/repo.git",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{
			ReportPath: reportPath,
			BaseBranch: "main",
		},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if len(execArgs) != 2 {
		t.Fatalf("exec calls = %d, want 2: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], "base64 -d > '/workspace/repo/.hal/factory-inputs/analysis.md'") {
		t.Fatalf("copy exec args = %#v", execArgs[0])
	}
	wantRemote := []string{"sh", "-lc", "cd '/workspace/repo' && exec 'hal' 'auto' '--report' '.hal/factory-inputs/analysis.md' '--base' 'main'"}
	if !reflect.DeepEqual(execArgs[1], wantRemote) {
		t.Fatalf("remote exec args = %#v, want %#v", execArgs[1], wantRemote)
	}
}

func TestFactorySandboxCopyInputToRemoteSplitsLargeInputCommands(t *testing.T) {
	projectDir := t.TempDir()
	inputPath := filepath.Join(projectDir, "large.md")
	if err := os.WriteFile(inputPath, bytes.Repeat([]byte("a"), factorySandboxCopyInputChunkEncodedBytes), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	var execArgs [][]string

	remotePath, changed, err := factorySandboxCopyInputToRemote(context.Background(), projectDir, "large.md", "/workspace/repo", fakeFactorySandboxProvider{}, &sandbox.ConnectInfo{Name: "factory-dev"}, io.Discard, factorySandboxExecutorDeps{
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			execArgs = append(execArgs, append([]string(nil), args...))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("factorySandboxCopyInputToRemote() unexpected error: %v", err)
	}
	if !changed || remotePath != "large.md" {
		t.Fatalf("remotePath = %q, changed = %v, want large.md and changed", remotePath, changed)
	}
	if len(execArgs) != 2 {
		t.Fatalf("exec calls = %d, want 2: %#v", len(execArgs), execArgs)
	}
	if !strings.Contains(execArgs[0][2], "base64 -d > '/workspace/repo/large.md'") {
		t.Fatalf("first chunk command = %q, want overwrite redirect", execArgs[0][2])
	}
	if !strings.Contains(execArgs[1][2], "base64 -d >> '/workspace/repo/large.md'") {
		t.Fatalf("second chunk command = %q, want append redirect", execArgs[1][2])
	}
	for _, args := range execArgs {
		if len(args[2]) > factorySandboxCopyInputChunkEncodedBytes+512 {
			t.Fatalf("copy command length = %d, want bounded chunk command", len(args[2]))
		}
	}
}

func TestFactorySandboxRemoteAutoArgsBuildsDeterministicHalAutoCommand(t *testing.T) {
	tests := []struct {
		name string
		req  factoryRunAutoRequest
		want []string
	}{
		{
			name: "auto discovery",
			req:  factoryRunAutoRequest{},
			want: []string{"hal", "auto"},
		},
		{
			name: "markdown with base",
			req: factoryRunAutoRequest{
				Args:       []string{" .hal/prd-feature.md "},
				BaseBranch: " main ",
			},
			want: []string{"hal", "auto", ".hal/prd-feature.md", "--base", "main"},
		},
		{
			name: "report with base",
			req: factoryRunAutoRequest{
				ReportPath: " .hal/reports/analysis.md ",
				BaseBranch: " develop ",
			},
			want: []string{"hal", "auto", "--report", ".hal/reports/analysis.md", "--base", "develop"},
		},
		{
			name: "empty args are omitted",
			req: factoryRunAutoRequest{
				Args: []string{"", "  ", ".hal/prd-feature.md"},
			},
			want: []string{"hal", "auto", ".hal/prd-feature.md"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := factorySandboxRemoteAutoArgs(tt.req); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("factorySandboxRemoteAutoArgs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestFactorySandboxRemoteCommandArgsSelectsWorkspaceDirectory(t *testing.T) {
	got := factorySandboxRemoteCommandArgs(factory.RunRecord{
		RepoRemote: "git@github.com:jywlabs/hal.git",
	}, factoryRunAutoRequest{
		Args:       []string{" .hal/prd-feature.md "},
		BaseBranch: " hal/factory-remote-workspace-bootstrap ",
	})

	want := []string{"sh", "-lc", "cd '/workspace/hal' && exec 'hal' 'auto' '.hal/prd-feature.md' '--base' 'hal/factory-remote-workspace-bootstrap'"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("factorySandboxRemoteCommandArgs() = %#v, want %#v", got, want)
	}
}

func TestFactorySandboxProvisionRepoLabelStripsCredentials(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "credentialed https remote",
			remote: "https://token:secret@github.com/example/repo.git",
			want:   "github.com/example/repo",
		},
		{
			name:   "ssh scp remote",
			remote: "git@github.com:example/repo.git",
			want:   "github.com/example/repo",
		},
		{
			name:   "ssh url remote",
			remote: "ssh://git@github.com/example/repo.git",
			want:   "github.com/example/repo",
		},
		{
			name:   "fallback repository name",
			remote: "not-a-url/repo.git",
			want:   "repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factorySandboxProvisionRepoLabel(factory.RunRecord{RepoRemote: tt.remote})
			if got != tt.want {
				t.Fatalf("factorySandboxProvisionRepoLabel() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "token") || strings.Contains(got, "secret") {
				t.Fatalf("factorySandboxProvisionRepoLabel() leaked credentials: %q", got)
			}
		})
	}
}

func TestRunFactorySandboxExecutorWithDepsRequiresRemoteWorkspaceBeforeExecution(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 45, 0, 0, time.UTC)
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord
	loadCalled := false
	provisionCalled := false
	startCalled := false
	resolveProviderCalled := false
	execCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-local",
		RunRecord: factory.RunRecord{
			RunID:       "run-missing-workspace",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoPath:    "/Users/v/work/hal",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			loadCalled = true
			return nil, fs.ErrNotExist
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		startSandbox: func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error) {
			startCalled = true
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			resolveProviderCalled = true
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			execCalled = true
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	wantErr := "prepare factory sandbox inputs: sandbox workspace directory is required; configure remote.origin.url or run from a /workspace/<repo> checkout"
	if err == nil || err.Error() != wantErr {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want %q", err, wantErr)
	}
	if loadCalled || provisionCalled || startCalled || resolveProviderCalled {
		t.Fatalf("sandbox lifecycle should not run without a workspace directory: load=%t provision=%t start=%t resolveProvider=%t", loadCalled, provisionCalled, startCalled, resolveProviderCalled)
	}
	if execCalled {
		t.Fatalf("remote execution should not run without a workspace directory")
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "prepare_inputs" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.Failure == nil || failed.Failure.Message != strings.TrimPrefix(wantErr, "prepare factory sandbox inputs: ") {
		t.Fatalf("failure summary = %#v", failed.Failure)
	}
	if len(events) != 1 || events[0].Metadata["step"] != "prepare_inputs" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsSanitizedRemoteOutputEvents(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-remote",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}

	var out bytes.Buffer
	var events []factory.EventRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName:  "factory-remote",
		RunRecord:    factory.RunRecord{RunID: "run-remote-output", Status: factory.RunStatusRunning, RepoRemote: "git@github.com:example/repo.git"},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			if _, err := io.WriteString(out, "Step: run\nconnecting to 203.0."); err != nil {
				return err
			}
			_, err := io.WriteString(out, "113.42\n")
			return err
		},
		saveRun: func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if out.String() != "Step: run\nconnecting to 203.0.113.42\n" {
		t.Fatalf("remote output writer = %q", out.String())
	}
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4: %#v", len(events), events)
	}
	started, firstLine, secondLine, completed := events[0], events[1], events[2], events[3]
	if started.EventType != factory.EventTypeStepStarted || started.Summary != "Remote sandbox execution started" {
		t.Fatalf("start event = %#v", started)
	}
	if started.Metadata["source"] != "remote_sandbox" || started.Metadata["status"] != factory.RunStatusRunning {
		t.Fatalf("start event metadata = %#v", started.Metadata)
	}
	if firstLine.EventType != factory.EventTypeCommandOutputSummary || secondLine.EventType != factory.EventTypeCommandOutputSummary {
		t.Fatalf("remote event types = %q/%q, want command output summaries", firstLine.EventType, secondLine.EventType)
	}
	if firstLine.Message != "Step: run" {
		t.Fatalf("first remote message = %q", firstLine.Message)
	}
	if strings.Contains(secondLine.Message, "203.0.113.42") {
		t.Fatalf("second remote message leaked address: %q", secondLine.Message)
	}
	if !strings.Contains(secondLine.Message, "<address redacted>") {
		t.Fatalf("second remote message missing redaction marker: %q", secondLine.Message)
	}
	if secondLine.Metadata["source"] != "remote_sandbox" || secondLine.Metadata["stream"] != "remote" {
		t.Fatalf("second remote metadata = %#v", secondLine.Metadata)
	}
	if secondLine.Metadata["sandboxName"] != "factory-remote" || secondLine.Metadata["provider"] != "daytona" {
		t.Fatalf("second remote target metadata = %#v", secondLine.Metadata)
	}
	if completed.EventType != factory.EventTypeStepEnded || completed.Summary != "Remote sandbox execution completed" {
		t.Fatalf("completion event = %#v", completed)
	}
	if completed.Metadata["source"] != "remote_sandbox" || completed.Metadata["status"] != factory.RunStatusSucceeded {
		t.Fatalf("completion event metadata = %#v", completed.Metadata)
	}
}

func TestRunFactorySandboxExecutorWithDepsCanProvisionAndStartWithFakes(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	provisioned := &sandbox.SandboxState{
		Name:     "factory-new",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
	}
	started := *provisioned
	started.Status = sandbox.StatusRunning

	var provisionReq factorySandboxProvisionRequest
	startCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  "/repo",
		SandboxName: "factory-new",
		RunRecord: factory.RunRecord{
			RunID:      "run-provision",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-new" {
				t.Fatalf("load sandbox name = %q, want factory-new", name)
			}
			return nil, errFactorySandboxNotExist
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionReq = req
			return provisioned, nil
		},
		startSandbox: func(_ context.Context, instance *sandbox.SandboxState, _ io.Writer) (*sandbox.SandboxState, error) {
			startCalled = true
			if instance.Name != "factory-new" {
				t.Fatalf("start instance = %#v", instance)
			}
			return &started, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if provisionReq.ProjectDir != "/repo" || provisionReq.Name != "factory-new" || provisionReq.Repo != "github.com/example/repo" {
		t.Fatalf("provision request = %#v", provisionReq)
	}
	if provisionReq.BranchName != "" {
		t.Fatalf("provision branchName = %q, want empty", provisionReq.BranchName)
	}
	if !startCalled {
		t.Fatalf("startSandbox was not called for stopped provisioned target")
	}
}

func TestRunFactorySandboxExecutorWithDepsReturnsExplicitLoadFailure(t *testing.T) {
	loadErr := factorySandboxTestError("read sandbox \"factory-broken\": parse failed")
	provisionCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-broken",
		RunRecord:   factory.RunRecord{RunID: "run-load-failure", RepoRemote: "git@github.com:example/repo.git"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return nil, loadErr
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil || err.Error() != "load factory sandbox \"factory-broken\": read sandbox \"factory-broken\": parse failed" {
		t.Fatalf("error = %v", err)
	}
	if provisionCalled {
		t.Fatalf("provision should not be called for non-not-exist load failures")
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesDefaultResolutionWithoutExplicitTarget(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "factory-only",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	resolved := false
	var savedRecords []factory.RunRecord
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		RunRecord: factory.RunRecord{RunID: "run-default", RepoRemote: "git@github.com:example/repo.git"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatalf("loadSandbox should not be called without explicit sandbox target")
			return nil, nil
		},
		resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			resolved = true
			if !filter(target) {
				t.Fatalf("running sandbox filter rejected running target")
			}
			return target, "connecting to only active sandbox \"factory-only\"", nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !resolved {
		t.Fatalf("resolveDefault was not called")
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	if savedRecords[1].SandboxName != "factory-only" {
		t.Fatalf("saved sandboxName = %q, want factory-only", savedRecords[1].SandboxName)
	}
	if savedRecords[1].Sandbox == nil || savedRecords[1].Sandbox.Provider != "daytona" {
		t.Fatalf("saved sandbox metadata = %#v", savedRecords[1].Sandbox)
	}
}

func TestRunFactorySandboxExecutorWithDepsProvisionsWhenDefaultResolutionHasNoUsableTarget(t *testing.T) {
	resolveErr := errNoFactorySandbox
	provisioned := &sandbox.SandboxState{
		Name:     "hal-feature",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	var provisionReq factorySandboxProvisionRequest
	var savedRecords []factory.RunRecord
	loadCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: "/repo",
		RunRecord: factory.RunRecord{
			RunID:      "run-no-default",
			BranchName: "hal/feature",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			loadCalled = true
			if name != "hal-feature" {
				t.Fatalf("loadSandbox name = %q, want hal-feature", name)
			}
			return nil, errFactorySandboxNotExist
		},
		resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			if !filter(&sandbox.SandboxState{Status: sandbox.StatusRunning}) {
				t.Fatalf("running sandbox filter rejected running target")
			}
			if filter(&sandbox.SandboxState{Status: sandbox.StatusStopped}) {
				t.Fatalf("running sandbox filter accepted stopped target")
			}
			return nil, "", resolveErr
		},
		provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionReq = req
			return provisioned, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !loadCalled {
		t.Fatalf("loadSandbox was not called for derived sandbox name")
	}
	if provisionReq.Name != "hal-feature" || provisionReq.BranchName != "hal/feature" || provisionReq.ProjectDir != "/repo" || provisionReq.Repo != "github.com/example/repo" {
		t.Fatalf("provision request = %#v", provisionReq)
	}
	if len(savedRecords) < 2 || savedRecords[1].SandboxName != "hal-feature" {
		t.Fatalf("saved records = %#v", savedRecords)
	}
}

func TestRunFactorySandboxExecutorWithDepsStartsStoppedDerivedDefaultBeforeProvisioning(t *testing.T) {
	stopped := &sandbox.SandboxState{
		Name:     "hal-feature",
		Provider: "daytona",
		Status:   sandbox.StatusStopped,
	}
	started := *stopped
	started.Status = sandbox.StatusRunning
	provisionCalled := false
	startCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir: "/repo",
		RunRecord: factory.RunRecord{
			RunID:      "run-stopped-default",
			BranchName: "hal/feature",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return nil, "", errNoFactorySandbox
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "hal-feature" {
				t.Fatalf("loadSandbox name = %q, want hal-feature", name)
			}
			return stopped, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		startSandbox: func(_ context.Context, target *sandbox.SandboxState, _ io.Writer) (*sandbox.SandboxState, error) {
			startCalled = true
			if target != stopped {
				t.Fatalf("start target = %#v, want stopped sandbox", target)
			}
			return &started, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if provisionCalled {
		t.Fatalf("provision should not be called when derived stopped sandbox exists")
	}
	if !startCalled {
		t.Fatalf("startSandbox was not called for stopped default sandbox")
	}
}

func TestRunFactorySandboxExecutorWithDepsReturnsAmbiguousDefaultResolutionError(t *testing.T) {
	resolveErr := factorySandboxTestError("multiple sandboxes found: one, two")
	provisionCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		RunRecord: factory.RunRecord{
			RunID:      "run-ambiguous-default",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return nil, "", resolveErr
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want %q", resolveErr)
	}
	if err.Error() != resolveErr.Error() {
		t.Fatalf("error = %q, want %q", err.Error(), resolveErr.Error())
	}
	if provisionCalled {
		t.Fatalf("provision should not be called when default resolution is ambiguous")
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsProvisionFailure(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
	provisionErr := factorySandboxTestError("provider quota exceeded")
	store := factory.NewStore(t.TempDir())
	if err := store.AppendEvent(&factory.EventRecord{
		Sequence:  7,
		RunID:     "run-provision-failure",
		EventType: factory.EventTypeStepStarted,
		Timestamp: now.Add(-time.Minute),
		Summary:   "Existing event",
	}); err != nil {
		t.Fatalf("AppendEvent() error: %v", err)
	}
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  "/repo",
		SandboxName: "factory-new",
		RunRecord: factory.RunRecord{
			RunID:       "run-provision-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			BranchName:  "hal/factory-sandbox-executor",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return nil, errFactorySandboxNotExist
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			return nil, provisionErr
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil || err.Error() != "provision factory sandbox: provider quota exceeded" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "provision" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-new" || failed.Sandbox == nil || failed.Sandbox.Handoff != "Inspect sandbox with `hal sandbox ssh factory-new`." {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Failure == nil || failed.Failure.Category != factory.FailureCategoryPipeline || failed.Failure.Message != provisionErr.Error() {
		t.Fatalf("failed failure summary = %#v", failed.Failure)
	}
	if len(events) != 1 || events[0].Sequence != 8 || events[0].EventType != factory.EventTypeFailureClassification || events[0].Metadata["step"] != "provision" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsStartFailureWithSandboxMetadata(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 45, 0, 0, time.UTC)
	startErr := factorySandboxTestError("start failed")
	target := &sandbox.SandboxState{
		Name:     "factory-stopped",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
	}
	var savedRecords []factory.RunRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-stopped",
		RunRecord: factory.RunRecord{
			RunID:       "run-start-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		startSandbox: func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error) {
			return nil, startErr
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err == nil || err.Error() != "start factory sandbox \"factory-stopped\": start failed" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 2 {
		t.Fatalf("saved records = %d, want 2", len(savedRecords))
	}
	failed := savedRecords[1]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "start" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-stopped" || failed.Sandbox == nil || failed.Sandbox.Provider != "hetzner" || failed.Sandbox.Status != sandbox.StatusStopped {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Sandbox.SSHCommand != "hal sandbox ssh factory-stopped" {
		t.Fatalf("ssh command = %q", failed.Sandbox.SSHCommand)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsResolveProviderFailureHandoff(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	providerErr := factorySandboxTestError("unknown provider missing")
	target := &sandbox.SandboxState{
		Name:     "factory-provider",
		Provider: "missing",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName: "factory-provider",
		RunRecord: factory.RunRecord{
			RunID:       "run-provider-failure",
			Status:      factory.RunStatusRunning,
			CurrentStep: "run",
			RepoRemote:  "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			if providerName != "missing" {
				t.Fatalf("providerName = %q, want missing", providerName)
			}
			return nil, providerErr
		},
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			t.Fatalf("runProviderExec should not run when provider resolution fails")
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil || err.Error() != "resolve sandbox provider \"missing\": unknown provider missing" {
		t.Fatalf("error = %v", err)
	}
	if len(savedRecords) != 3 {
		t.Fatalf("saved records = %d, want 3", len(savedRecords))
	}
	failed := savedRecords[2]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "resolve_provider" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-provider" || failed.Sandbox == nil || failed.Sandbox.Provider != "missing" {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Failure == nil || failed.Failure.Message != providerErr.Error() || failed.Failure.SuggestedCommand != "hal sandbox ssh factory-provider" {
		t.Fatalf("failed failure summary = %#v", failed.Failure)
	}
	if len(events) != 1 || events[0].EventType != factory.EventTypeFailureClassification || events[0].Metadata["step"] != "resolve_provider" {
		t.Fatalf("failure events = %#v", events)
	}
}

func TestRunFactorySandboxExecutorWithDepsRecordsRemoteExecutionFailureHandoff(t *testing.T) {
	now := time.Date(2026, 6, 21, 11, 15, 0, 0, time.UTC)
	execErr := factorySandboxTestError("remote pipeline failed on 203.0.113.42")
	target := &sandbox.SandboxState{
		Name:     "factory-failed",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}
	var out bytes.Buffer
	var savedRecords []factory.RunRecord
	var events []factory.EventRecord

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		SandboxName:  "factory-failed",
		RunRecord:    factory.RunRecord{RunID: "run-remote-failure", Status: factory.RunStatusRunning, CurrentStep: "run", RepoRemote: "git@github.com:example/repo.git"},
		RemoteOutput: &out,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		now:          func() time.Time { return now },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			if _, err := io.WriteString(out, "remote stderr mentions 203.0.113.42\n"); err != nil {
				return err
			}
			return execErr
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			events = append(events, *event)
			return nil
		},
	})
	if err == nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want remote failure")
	}
	if strings.Contains(err.Error(), "203.0.113.42") {
		t.Fatalf("returned error leaked address: %v", err)
	}
	if !strings.Contains(err.Error(), "<address redacted>") {
		t.Fatalf("returned error missing redaction marker: %v", err)
	}
	if len(savedRecords) != 3 {
		t.Fatalf("saved records = %d, want 3", len(savedRecords))
	}
	failed := savedRecords[2]
	if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "run" {
		t.Fatalf("failed record status/step = %s/%s", failed.Status, failed.CurrentStep)
	}
	if failed.SandboxName != "factory-failed" || failed.Sandbox == nil || failed.Sandbox.Provider != "daytona" {
		t.Fatalf("failed sandbox metadata = %#v", failed.Sandbox)
	}
	if failed.Sandbox.Connection == nil || failed.Sandbox.Connection.PublicIP != "203.0.113.42" {
		t.Fatalf("failed sandbox connection = %#v", failed.Sandbox.Connection)
	}
	if failed.Failure == nil {
		t.Fatalf("failed failure summary = nil")
	}
	if failed.Failure.SuggestedCommand != "hal sandbox ssh factory-failed" {
		t.Fatalf("suggested command = %q", failed.Failure.SuggestedCommand)
	}
	if strings.Contains(failed.Failure.Message, "203.0.113.42") {
		t.Fatalf("failure message leaked address: %q", failed.Failure.Message)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3: %#v", len(events), events)
	}
	if events[1].EventType != factory.EventTypeCommandOutputSummary || strings.Contains(events[1].Message, "203.0.113.42") {
		t.Fatalf("remote output event was not sanitized: %#v", events[1])
	}
	if events[2].EventType != factory.EventTypeFailureClassification || events[2].Metadata["source"] != "remote_sandbox" {
		t.Fatalf("failure event = %#v", events[2])
	}
	if strings.Contains(events[2].Message, "203.0.113.42") {
		t.Fatalf("failure event leaked address: %q", events[2].Message)
	}
}

type factorySandboxTestError string

func (e factorySandboxTestError) Error() string { return string(e) }

const errNoFactorySandbox = factorySandboxTestError("no running sandboxes")

var errFactorySandboxNotExist = factorySandboxNotExistError("sandbox does not exist")

type factorySandboxNotExistError string

func (e factorySandboxNotExistError) Error() string { return string(e) }
func (e factorySandboxNotExistError) Unwrap() error { return fs.ErrNotExist }

type fakeFactorySandboxProvider struct{}

func (fakeFactorySandboxProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (fakeFactorySandboxProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}
