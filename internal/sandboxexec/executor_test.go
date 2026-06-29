package sandboxexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestRunInvokesInjectedPhasesAndRunner(t *testing.T) {
	stopped := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusStopped, IP: "203.0.113.42"}
	started := *stopped
	started.Status = sandbox.StatusRunning
	provider := fakeProvider{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var calls []string
	var events []Event
	var gotRunReq CommandRequest
	var gotRunContext RunContext

	result, err := Run(context.Background(), CommandRequest{
		Purpose:     "factory",
		ProjectDir:  "/repo",
		SandboxName: "factory-dev",
		Command:     []string{"hal", "auto"},
		WorkDir:     "/workspace/repo",
		Env: map[string]string{
			"GITHUB_TOKEN": "secret",
		},
		Stdout: &stdout,
		Stderr: &stderr,
	}, Dependencies{
		ResolveTarget: func(_ context.Context, req TargetRequest) (*sandbox.SandboxState, error) {
			calls = append(calls, "resolve")
			if req.Purpose != "factory" || req.ProjectDir != "/repo" || req.SandboxName != "factory-dev" {
				t.Fatalf("target request = %#v", req)
			}
			if req.Stdout != &stdout || req.Stderr != &stderr {
				t.Fatalf("target request writers were not forwarded")
			}
			return stopped, nil
		},
		StartTarget: func(_ context.Context, target *sandbox.SandboxState, stdoutWriter, stderrWriter io.Writer) (*sandbox.SandboxState, error) {
			calls = append(calls, "start")
			if target != stopped {
				t.Fatalf("start target = %#v, want stopped target", target)
			}
			if stdoutWriter != &stdout || stderrWriter != &stderr {
				t.Fatalf("start writers were not forwarded")
			}
			return &started, nil
		},
		OnTargetReady: func(_ context.Context, target *sandbox.SandboxState) error {
			calls = append(calls, "target-ready")
			if target.Status != sandbox.StatusRunning {
				t.Fatalf("target ready status = %q", target.Status)
			}
			return nil
		},
		ResolveProvider: func(_ context.Context, target *sandbox.SandboxState) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			if target.Name != "factory-dev" {
				t.Fatalf("provider target = %#v", target)
			}
			return provider, nil
		},
		OnProviderReady: func(_ context.Context, target *sandbox.SandboxState, got sandbox.Provider) error {
			calls = append(calls, "provider-ready")
			if target.Name != "factory-dev" || got != provider {
				t.Fatalf("provider ready target/provider = %#v/%#v", target, got)
			}
			return nil
		},
		PrepareWorkspace: func(_ context.Context, prep PrepareContext, req *CommandRequest) error {
			calls = append(calls, "workspace")
			if prep.Target.Name != "factory-dev" || prep.Provider != provider || prep.ConnectInfo.Name != "factory-dev" {
				t.Fatalf("workspace prep context = %#v", prep)
			}
			req.WorkDir = "/workspace/prepared"
			return nil
		},
		PrepareAuth: func(_ context.Context, prep PrepareContext, req *CommandRequest) error {
			calls = append(calls, "auth")
			if req.WorkDir != "/workspace/prepared" || prep.ProjectDir != "/repo" {
				t.Fatalf("auth prep request/context = %#v/%#v", req, prep)
			}
			return nil
		},
		PrepareCommand: func(_ context.Context, _ PrepareContext, req *CommandRequest) error {
			calls = append(calls, "command")
			req.Command = []string{"sh", "-c", "hal auto"}
			req.WorkDir = "/workspace/final"
			return nil
		},
		HandleEvent: func(_ context.Context, event Event) error {
			calls = append(calls, "event:"+string(event.Type))
			events = append(events, event)
			return nil
		},
		RunCommand: func(_ context.Context, run RunContext, req CommandRequest) error {
			calls = append(calls, "run")
			gotRunContext = run
			gotRunReq = cloneCommandRequest(req)
			if _, err := io.WriteString(req.Stdout, "stdout part"); err != nil {
				return err
			}
			if _, err := io.WriteString(req.Stdout, " finished\n"); err != nil {
				return err
			}
			_, err := io.WriteString(req.Stderr, "stderr line\n")
			return err
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if result == nil || result.Target != &started || result.Provider != provider {
		t.Fatalf("result = %#v", result)
	}
	if !reflect.DeepEqual(result.Command.Command, []string{"sh", "-c", "hal auto"}) || result.Command.WorkDir != "/workspace/final" {
		t.Fatalf("result command = %#v", result.Command)
	}
	if gotRunContext.Target != &started || gotRunContext.Provider != provider || gotRunContext.ConnectInfo.Name != "factory-dev" {
		t.Fatalf("run context = %#v", gotRunContext)
	}
	if !reflect.DeepEqual(gotRunReq.Command, []string{"sh", "-c", "hal auto"}) || gotRunReq.WorkDir != "/workspace/final" {
		t.Fatalf("run request = %#v", gotRunReq)
	}
	if gotRunReq.Env["GITHUB_TOKEN"] != "secret" {
		t.Fatalf("run env = %#v", gotRunReq.Env)
	}
	if stdout.String() != "stdout part finished\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "stderr line\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}

	wantCalls := []string{
		"resolve",
		"start",
		"target-ready",
		"provider",
		"provider-ready",
		"workspace",
		"auth",
		"command",
		"event:command_started",
		"run",
		"event:command_output",
		"event:command_output",
		"event:command_completed",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	eventTypes := make([]EventType, len(events))
	for i, event := range events {
		eventTypes[i] = event.Type
	}
	if !reflect.DeepEqual(eventTypes, []EventType{EventCommandStarted, EventCommandOutput, EventCommandOutput, EventCommandCompleted}) {
		t.Fatalf("events = %#v", events)
	}
	if events[0].SandboxName != "factory-dev" || events[0].Provider != "daytona" || !reflect.DeepEqual(events[0].Command, []string{"sh", "-c", "hal auto"}) || events[0].WorkDir != "/workspace/final" {
		t.Fatalf("start event = %#v", events[0])
	}
	if events[1].Stream != StreamStdout || events[1].Line != "stdout part finished" {
		t.Fatalf("stdout event = %#v", events[1])
	}
	if events[2].Stream != StreamStderr || events[2].Line != "stderr line" {
		t.Fatalf("stderr event = %#v", events[2])
	}
}

func TestRunUsesExistingRunningTargetWithoutStart(t *testing.T) {
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	startCalled := false

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		StartTarget: func(context.Context, *sandbox.SandboxState, io.Writer, io.Writer) (*sandbox.SandboxState, error) {
			startCalled = true
			return nil, nil
		},
		ResolveProvider: func(context.Context, *sandbox.SandboxState) (sandbox.Provider, error) {
			return fakeProvider{}, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if startCalled {
		t.Fatal("StartTarget was called for an already running target")
	}
}

func TestRunPropagatesStartFailure(t *testing.T) {
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusStopped}
	startErr := errors.New("provider start failed")

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		StartTarget: func(context.Context, *sandbox.SandboxState, io.Writer, io.Writer) (*sandbox.SandboxState, error) {
			return nil, startErr
		},
		ResolveProvider: func(context.Context, *sandbox.SandboxState) (sandbox.Provider, error) {
			t.Fatal("ResolveProvider should not run after start failure")
			return nil, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			t.Fatal("RunCommand should not run after start failure")
			return nil
		},
	})
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseStartTarget || !errors.Is(err, startErr) || phaseErr.Target != target {
		t.Fatalf("error = %#v, want start phase wrapping startErr", err)
	}
}

func TestRunPreservesInjectedProvisionPhaseError(t *testing.T) {
	provisionErr := errors.New("quota exceeded")

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-new"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return nil, &PhaseError{Phase: PhaseProvisionTarget, Err: provisionErr}
		},
		ResolveProvider: func(context.Context, *sandbox.SandboxState) (sandbox.Provider, error) {
			t.Fatal("ResolveProvider should not run after provision failure")
			return nil, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			t.Fatal("RunCommand should not run after provision failure")
			return nil
		},
	})
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseProvisionTarget || !errors.Is(err, provisionErr) {
		t.Fatalf("error = %#v, want provision phase wrapping provisionErr", err)
	}
}

func TestRunWorkspaceFailurePreventsRunner(t *testing.T) {
	workspaceErr := errors.New("bootstrap failed")
	runCalled := false

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, successfulDeps(t, Dependencies{
		PrepareWorkspace: func(context.Context, PrepareContext, *CommandRequest) error {
			return workspaceErr
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			runCalled = true
			return nil
		},
	}))
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhasePrepareWorkspace || !errors.Is(err, workspaceErr) {
		t.Fatalf("error = %#v, want workspace phase wrapping workspaceErr", err)
	}
	if runCalled {
		t.Fatal("RunCommand ran after workspace failure")
	}
}

func TestRunAuthFailurePreventsRunner(t *testing.T) {
	authErr := errors.New("auth sync failed")
	runCalled := false

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, successfulDeps(t, Dependencies{
		PrepareAuth: func(context.Context, PrepareContext, *CommandRequest) error {
			return authErr
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			runCalled = true
			return nil
		},
	}))
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhasePrepareAuth || !errors.Is(err, authErr) {
		t.Fatalf("error = %#v, want auth phase wrapping authErr", err)
	}
	if runCalled {
		t.Fatal("RunCommand ran after auth failure")
	}
}

func TestRunCommandFailureEmitsOutputAndFailureEvents(t *testing.T) {
	runErr := errors.New("remote failed")
	var events []Event
	var stdout bytes.Buffer

	_, err := Run(context.Background(), CommandRequest{
		SandboxName: "factory-dev",
		Command:     []string{"hal", "auto"},
		Stdout:      &stdout,
	}, successfulDeps(t, Dependencies{
		HandleEvent: func(_ context.Context, event Event) error {
			events = append(events, event)
			return nil
		},
		RunCommand: func(_ context.Context, _ RunContext, req CommandRequest) error {
			if _, err := io.WriteString(req.Stdout, "partial output"); err != nil {
				return err
			}
			return runErr
		},
	}))
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseRun || !errors.Is(err, runErr) {
		t.Fatalf("error = %#v, want run phase wrapping runErr", err)
	}
	if stdout.String() != "partial output" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if len(events) != 3 {
		t.Fatalf("events = %#v, want start/output/failure", events)
	}
	if events[0].Type != EventCommandStarted || events[1].Type != EventCommandOutput || events[1].Line != "partial output" || events[2].Type != EventCommandFailed {
		t.Fatalf("events = %#v", events)
	}
	if !errors.Is(events[2].Err, runErr) {
		t.Fatalf("failure event error = %v, want runErr", events[2].Err)
	}
}

func TestSandboxexecDoesNotImportCobra(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir() error: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, imported := range file.Imports {
			if strings.Trim(imported.Path.Value, `"`) == "github.com/spf13/cobra" {
				t.Fatalf("%s imports github.com/spf13/cobra", path)
			}
		}
	}
}

func successfulDeps(t *testing.T, overrides Dependencies) Dependencies {
	t.Helper()
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	deps := Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveProvider: func(context.Context, *sandbox.SandboxState) (sandbox.Provider, error) {
			return fakeProvider{}, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return nil
		},
	}
	if overrides.ResolveTarget != nil {
		deps.ResolveTarget = overrides.ResolveTarget
	}
	if overrides.StartTarget != nil {
		deps.StartTarget = overrides.StartTarget
	}
	if overrides.ResolveProvider != nil {
		deps.ResolveProvider = overrides.ResolveProvider
	}
	if overrides.PrepareWorkspace != nil {
		deps.PrepareWorkspace = overrides.PrepareWorkspace
	}
	if overrides.PrepareAuth != nil {
		deps.PrepareAuth = overrides.PrepareAuth
	}
	if overrides.PrepareCommand != nil {
		deps.PrepareCommand = overrides.PrepareCommand
	}
	if overrides.RunCommand != nil {
		deps.RunCommand = overrides.RunCommand
	}
	if overrides.HandleEvent != nil {
		deps.HandleEvent = overrides.HandleEvent
	}
	if overrides.OnTargetReady != nil {
		deps.OnTargetReady = overrides.OnTargetReady
	}
	if overrides.OnProviderReady != nil {
		deps.OnProviderReady = overrides.OnProviderReady
	}
	return deps
}

type fakeProvider struct{}

func (fakeProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (fakeProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return fmt.Errorf("not implemented")
}

func (fakeProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (fakeProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return fmt.Errorf("not implemented")
}

func (fakeProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, fmt.Errorf("not implemented")
}

func (fakeProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("not implemented")
}

func (fakeProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return fmt.Errorf("not implemented")
}
