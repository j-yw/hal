package sandboxexec

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestRunInvokesInjectedPhasesAndRunner(t *testing.T) {
	stopped := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusStopped, IP: "203.0.113.42"}
	started := *stopped
	started.Status = sandbox.StatusRunning
	driver := fakeRuntimeDriver{id: sandboxruntime.DriverSSHMachine}
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
		ResolveDriver: func(_ context.Context, target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			calls = append(calls, "driver")
			if target.Name != "factory-dev" || target.Provider != "daytona" {
				t.Fatalf("driver target = %#v", target)
			}
			return driver, nil
		},
		OnDriverReady: func(_ context.Context, target sandboxruntime.Target, got sandboxruntime.Driver) error {
			calls = append(calls, "driver-ready")
			if target.Name != "factory-dev" || got != driver {
				t.Fatalf("driver ready target/driver = %#v/%#v", target, got)
			}
			return nil
		},
		PrepareWorkspace: func(_ context.Context, prep PrepareContext, req *CommandRequest) error {
			calls = append(calls, "workspace")
			if prep.Target.Name != "factory-dev" || prep.Target.Provider != "daytona" || prep.Connection.Address != "203.0.113.42" {
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
	if result == nil || result.Target.Name != "factory-dev" || result.Target.Provider != "daytona" || result.Target.Status != sandbox.StatusRunning {
		t.Fatalf("result = %#v", result)
	}
	if !reflect.DeepEqual(result.Command.Command, []string{"sh", "-c", "hal auto"}) || result.Command.WorkDir != "/workspace/final" {
		t.Fatalf("result command = %#v", result.Command)
	}
	if result.Command.Env["GITHUB_TOKEN"] != "secret" {
		t.Fatalf("result env = %#v", result.Command.Env)
	}
	if gotRunContext.Target.Name != "factory-dev" || gotRunContext.Target.Provider != "daytona" || gotRunContext.Driver != driver || gotRunContext.Connection.Address != "203.0.113.42" {
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
		"driver",
		"driver-ready",
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

func TestRunDefaultRuntimeExecSelectsSSHMachineAndForwardsCommandFields(t *testing.T) {
	target := &sandbox.SandboxState{
		ID:          "sb-123",
		Name:        "factory-dev",
		Provider:    "daytona",
		Status:      sandbox.StatusRunning,
		IP:          "203.0.113.42",
		WorkspaceID: "workspace-456",
	}
	stdin := strings.NewReader("stdin payload\n")
	env := map[string]string{
		"HAL_FACTORY_ATTEMPT": "2",
		"GITHUB_TOKEN":        "secret",
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var resolvedTarget sandboxruntime.Target
	var gotExec sandboxruntime.ExecRequest
	var gotStdin string
	driver := &recordingRuntimeDriver{
		id: sandboxruntime.DriverSSHMachine,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Stdin != stdin {
				t.Fatalf("ExecRequest.Stdin = %#v, want original stdin reader", req.Stdin)
			}
			payload, err := io.ReadAll(req.Stdin)
			if err != nil {
				return nil, err
			}
			gotStdin = string(payload)
			gotExec = cloneExecRequest(req)
			if _, err := io.WriteString(req.Stdout, "runtime stdout\n"); err != nil {
				return nil, err
			}
			if _, err := io.WriteString(req.Stderr, "runtime stderr\n"); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	result, err := Run(context.Background(), CommandRequest{
		Purpose:     "factory",
		ProjectDir:  "/repo",
		SandboxName: "factory-dev",
		Command:     []string{"hal", "auto", "--resume"},
		WorkDir:     "/workspace/hal",
		Env:         env,
		Stdin:       stdin,
		Stdout:      &stdout,
		Stderr:      &stderr,
	}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(_ context.Context, runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedTarget = runtimeTarget
			if runtimeTarget.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("resolved runtime driver = %q, want %q", runtimeTarget.Runtime.Driver, sandboxruntime.DriverSSHMachine)
			}
			return driver, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if !driver.execCalled {
		t.Fatal("default runtime exec was not called")
	}
	if result == nil || result.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("result target = %#v, want default ssh_machine runtime", result)
	}
	if gotExec.Target.Name != "factory-dev" || gotExec.Target.Provider != "daytona" || gotExec.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine || gotExec.Target.Connection.WorkspaceID != "workspace-456" {
		t.Fatalf("exec target = %#v", gotExec.Target)
	}
	if !reflect.DeepEqual(gotExec.Args, []string{"hal", "auto", "--resume"}) {
		t.Fatalf("exec args = %#v", gotExec.Args)
	}
	if gotExec.WorkDir != "/workspace/hal" {
		t.Fatalf("exec workdir = %q", gotExec.WorkDir)
	}
	if !reflect.DeepEqual(gotExec.Env, env) {
		t.Fatalf("exec env = %#v, want %#v", gotExec.Env, env)
	}
	if gotStdin != "stdin payload\n" {
		t.Fatalf("stdin payload = %q", gotStdin)
	}
	if stdout.String() != "runtime stdout\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "runtime stderr\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if resolvedTarget.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("resolved target runtime = %#v", resolvedTarget.Runtime)
	}
}

func TestRunDefaultRuntimeExecPropagatesContextCancellation(t *testing.T) {
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	ctx, cancel := context.WithCancel(context.Background())
	driver := &recordingRuntimeDriver{
		id: sandboxruntime.DriverSSHMachine,
		exec: func(ctx context.Context, _ sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	_, err := Run(ctx, CommandRequest{
		SandboxName: "factory-dev",
		Command:     []string{"sleep", "60"},
	}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
	})
	if !driver.execCalled {
		t.Fatal("default runtime exec was not called")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want errors.Is context.Canceled", err)
	}
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseRun || phaseErr.RuntimeDriver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("phase error = %#v, want run phase with ssh_machine runtime", err)
	}
}

func TestPrepareContextUsesRuntimeBoundaryTypes(t *testing.T) {
	prepareType := reflect.TypeOf(PrepareContext{})
	providerType := reflect.TypeOf((*sandbox.Provider)(nil)).Elem()
	connectInfoType := reflect.TypeOf((*sandbox.ConnectInfo)(nil))
	for i := 0; i < prepareType.NumField(); i++ {
		field := prepareType.Field(i)
		if field.Type == providerType {
			t.Fatalf("PrepareContext.%s exposes legacy sandbox.Provider", field.Name)
		}
		if field.Type == connectInfoType {
			t.Fatalf("PrepareContext.%s exposes legacy *sandbox.ConnectInfo", field.Name)
		}
	}
	if _, ok := prepareType.FieldByName("Provider"); ok {
		t.Fatal("PrepareContext exposes legacy sandbox.Provider field")
	}
	if _, ok := prepareType.FieldByName("ConnectInfo"); ok {
		t.Fatal("PrepareContext exposes legacy sandbox.ConnectInfo field")
	}

	targetField, ok := prepareType.FieldByName("Target")
	if !ok {
		t.Fatal("PrepareContext missing Target field")
	}
	if targetField.Type != reflect.TypeOf(sandboxruntime.Target{}) {
		t.Fatalf("PrepareContext.Target type = %v, want sandboxruntime.Target", targetField.Type)
	}
	connectionField, ok := prepareType.FieldByName("Connection")
	if !ok {
		t.Fatal("PrepareContext missing Connection field")
	}
	if connectionField.Type != reflect.TypeOf(sandboxruntime.ConnectionInfo{}) {
		t.Fatalf("PrepareContext.Connection type = %v, want sandboxruntime.ConnectionInfo", connectionField.Type)
	}
}

func TestRunContextUsesRuntimeBoundaryTypes(t *testing.T) {
	runType := reflect.TypeOf(RunContext{})
	providerType := reflect.TypeOf((*sandbox.Provider)(nil)).Elem()
	connectInfoType := reflect.TypeOf((*sandbox.ConnectInfo)(nil))
	sandboxStateType := reflect.TypeOf((*sandbox.SandboxState)(nil))
	for i := 0; i < runType.NumField(); i++ {
		field := runType.Field(i)
		if field.Type == providerType {
			t.Fatalf("RunContext.%s exposes legacy sandbox.Provider", field.Name)
		}
		if field.Type == connectInfoType {
			t.Fatalf("RunContext.%s exposes legacy *sandbox.ConnectInfo", field.Name)
		}
		if field.Type == sandboxStateType {
			t.Fatalf("RunContext.%s exposes legacy *sandbox.SandboxState", field.Name)
		}
	}
	if _, ok := runType.FieldByName("Provider"); ok {
		t.Fatal("RunContext exposes legacy sandbox.Provider field")
	}
	if _, ok := runType.FieldByName("ConnectInfo"); ok {
		t.Fatal("RunContext exposes legacy sandbox.ConnectInfo field")
	}

	targetField, ok := runType.FieldByName("Target")
	if !ok {
		t.Fatal("RunContext missing Target field")
	}
	if targetField.Type != reflect.TypeOf(sandboxruntime.Target{}) {
		t.Fatalf("RunContext.Target type = %v, want sandboxruntime.Target", targetField.Type)
	}
	connectionField, ok := runType.FieldByName("Connection")
	if !ok {
		t.Fatal("RunContext missing Connection field")
	}
	if connectionField.Type != reflect.TypeOf(sandboxruntime.ConnectionInfo{}) {
		t.Fatalf("RunContext.Connection type = %v, want sandboxruntime.ConnectionInfo", connectionField.Type)
	}
	driverField, ok := runType.FieldByName("Driver")
	if !ok {
		t.Fatal("RunContext missing Driver field")
	}
	if driverField.Type != reflect.TypeOf((*sandboxruntime.Driver)(nil)).Elem() {
		t.Fatalf("RunContext.Driver type = %v, want sandboxruntime.Driver", driverField.Type)
	}
}

func TestDependenciesUseRuntimeDriverResolverTerminology(t *testing.T) {
	depsType := reflect.TypeOf(Dependencies{})
	if _, ok := depsType.FieldByName("ResolveProvider"); ok {
		t.Fatal("Dependencies exposes legacy ResolveProvider")
	}
	if _, ok := depsType.FieldByName("OnProviderReady"); ok {
		t.Fatal("Dependencies exposes legacy OnProviderReady")
	}

	resolveField, ok := depsType.FieldByName("ResolveDriver")
	if !ok {
		t.Fatal("Dependencies missing ResolveDriver")
	}
	wantResolve := reflect.TypeOf(func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
		return nil, nil
	})
	if resolveField.Type != wantResolve {
		t.Fatalf("Dependencies.ResolveDriver type = %v, want %v", resolveField.Type, wantResolve)
	}

	readyField, ok := depsType.FieldByName("OnDriverReady")
	if !ok {
		t.Fatal("Dependencies missing OnDriverReady")
	}
	wantReady := reflect.TypeOf(func(context.Context, sandboxruntime.Target, sandboxruntime.Driver) error {
		return nil
	})
	if readyField.Type != wantReady {
		t.Fatalf("Dependencies.OnDriverReady type = %v, want %v", readyField.Type, wantReady)
	}
}

func TestResultUsesRuntimeBoundaryTypes(t *testing.T) {
	resultType := reflect.TypeOf(Result{})
	providerType := reflect.TypeOf((*sandbox.Provider)(nil)).Elem()
	connectInfoType := reflect.TypeOf((*sandbox.ConnectInfo)(nil))
	sandboxStateType := reflect.TypeOf((*sandbox.SandboxState)(nil))
	for i := 0; i < resultType.NumField(); i++ {
		field := resultType.Field(i)
		if field.Type == providerType {
			t.Fatalf("Result.%s exposes legacy sandbox.Provider", field.Name)
		}
		if field.Type == connectInfoType {
			t.Fatalf("Result.%s exposes legacy *sandbox.ConnectInfo", field.Name)
		}
		if field.Type == sandboxStateType {
			t.Fatalf("Result.%s exposes legacy *sandbox.SandboxState", field.Name)
		}
	}
	if _, ok := resultType.FieldByName("Provider"); ok {
		t.Fatal("Result exposes legacy sandbox.Provider field")
	}
	if _, ok := resultType.FieldByName("ConnectInfo"); ok {
		t.Fatal("Result exposes legacy sandbox.ConnectInfo field")
	}

	targetField, ok := resultType.FieldByName("Target")
	if !ok {
		t.Fatal("Result missing Target field")
	}
	if targetField.Type != reflect.TypeOf(sandboxruntime.Target{}) {
		t.Fatalf("Result.Target type = %v, want sandboxruntime.Target", targetField.Type)
	}
	commandField, ok := resultType.FieldByName("Command")
	if !ok {
		t.Fatal("Result missing Command field")
	}
	if commandField.Type != reflect.TypeOf(CommandRequest{}) {
		t.Fatalf("Result.Command type = %v, want CommandRequest", commandField.Type)
	}
}

func TestPhaseErrorUsesRuntimeBoundaryTypes(t *testing.T) {
	phaseType := reflect.TypeOf(PhaseError{})
	providerType := reflect.TypeOf((*sandbox.Provider)(nil)).Elem()
	connectInfoType := reflect.TypeOf((*sandbox.ConnectInfo)(nil))
	for i := 0; i < phaseType.NumField(); i++ {
		field := phaseType.Field(i)
		if field.Type == providerType {
			t.Fatalf("PhaseError.%s exposes legacy sandbox.Provider", field.Name)
		}
		if field.Type == connectInfoType {
			t.Fatalf("PhaseError.%s exposes legacy *sandbox.ConnectInfo", field.Name)
		}
	}
	if _, ok := phaseType.FieldByName("Provider"); ok {
		t.Fatal("PhaseError exposes legacy sandbox.Provider field")
	}
	if _, ok := phaseType.FieldByName("ConnectInfo"); ok {
		t.Fatal("PhaseError exposes legacy sandbox.ConnectInfo field")
	}

	targetField, ok := phaseType.FieldByName("Target")
	if !ok {
		t.Fatal("PhaseError missing Target field")
	}
	if targetField.Type != reflect.TypeOf((*sandbox.SandboxState)(nil)) {
		t.Fatalf("PhaseError.Target type = %v, want *sandbox.SandboxState", targetField.Type)
	}
	driverField, ok := phaseType.FieldByName("RuntimeDriver")
	if !ok {
		t.Fatal("PhaseError missing RuntimeDriver field")
	}
	if driverField.Type.Kind() != reflect.String {
		t.Fatalf("PhaseError.RuntimeDriver type = %v, want string", driverField.Type)
	}
}

func TestPhaseNamesRemainStable(t *testing.T) {
	tests := map[Phase]string{
		PhaseResolveTarget:    "resolve_target",
		PhaseProvisionTarget:  "provision",
		PhaseStartTarget:      "start",
		PhaseResolveDriver:    "resolve_driver",
		PhasePrepareWorkspace: "prepare_workspace",
		PhasePrepareAuth:      "prepare_auth",
		PhasePrepareCommand:   "prepare_command",
		PhaseRun:              "run",
	}
	for phase, want := range tests {
		if got := string(phase); got != want {
			t.Fatalf("phase %v = %q, want %q", phase, got, want)
		}
	}
}

func TestRunPrepareContextCarriesRuntimeTargetConnection(t *testing.T) {
	target := &sandbox.SandboxState{
		ID:                "sb-123",
		Name:              "factory-dev",
		Provider:          "digitalocean",
		WorkspaceID:       "droplet-456",
		IP:                "203.0.113.42",
		TailscaleIP:       "100.64.0.7",
		TailscaleHostname: "factory-dev.tailnet.example",
		TailscaleLockdown: true,
		Status:            sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			RuntimeID:      "runtime-789",
			Image:          "ubuntu-24.04",
			WorkerID:       "worker-a",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
	}
	var got PrepareContext

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{}, nil
		},
		PrepareWorkspace: func(_ context.Context, prep PrepareContext, _ *CommandRequest) error {
			got = prep
			return nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if got.Target.ID != "sb-123" || got.Target.Name != "factory-dev" || got.Target.Provider != "digitalocean" || got.Target.Status != sandbox.StatusRunning {
		t.Fatalf("runtime target identity = %#v", got.Target)
	}
	if got.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine || got.Target.Runtime.RuntimeID != "runtime-789" || got.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("runtime metadata = %#v", got.Target.Runtime)
	}
	if got.Connection.Address != "100.64.0.7" || got.Connection.PublicIP != "203.0.113.42" || got.Connection.TailscaleHostname != "factory-dev.tailnet.example" || !got.Connection.TailscaleLockdown || got.Connection.WorkspaceID != "droplet-456" {
		t.Fatalf("runtime connection = %#v", got.Connection)
	}
	if got.Target.Connection != got.Connection {
		t.Fatalf("target connection = %#v, want %#v", got.Target.Connection, got.Connection)
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
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{}, nil
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

func TestRunAttachesCompatibilitySecurityMetadataBeforeTargetReady(t *testing.T) {
	target := &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusRunning}
	var readySecurity *sandbox.SandboxSecurity

	result, err := Run(context.Background(), CommandRequest{
		SandboxName: "factory-dev",
		Env: map[string]string{
			"GITHUB_TOKEN": "secret-value",
		},
		Security: sandbox.SecurityEvaluationRequest{
			RuntimeDriver:          sandbox.SandboxRuntimeDriverSSHMachine,
			RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
			RequestedSecretModes:   []string{sandbox.SandboxSecretModeHTTPProxy},
			CompatibilityAuthSync:  true,
		},
	}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		OnTargetReady: func(_ context.Context, ready *sandbox.SandboxState) error {
			readySecurity = ready.Security
			return nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{}, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if result == nil || result.Target.Name != "factory-dev" || result.Target.Provider != "daytona" || result.Target.Status != sandbox.StatusRunning {
		t.Fatalf("result target = %#v", result)
	}
	if target.Security == nil {
		t.Fatalf("target security = %#v", target)
	}
	if readySecurity == nil {
		t.Fatal("OnTargetReady observed nil security metadata")
	}
	if readySecurity.Network == nil || readySecurity.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("network security = %#v", readySecurity.Network)
	}
	if readySecurity.Network.PolicyEnforced == sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("compatibility path overclaimed deny-by-default enforcement: %#v", readySecurity.Network)
	}
	if readySecurity.Network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort || readySecurity.Network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("network enforcement = %#v", readySecurity.Network)
	}
	wantActive := []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}
	if readySecurity.Secrets == nil || !reflect.DeepEqual(readySecurity.Secrets.ActiveModes, wantActive) {
		t.Fatalf("active secret modes = %#v, want %#v", readySecurity.Secrets, wantActive)
	}
}

func TestRunPreservesExistingSecurityMetadataWithoutEvaluationRequest(t *testing.T) {
	existing := &sandbox.SandboxSecurity{
		Network: &sandbox.SandboxNetworkSecurity{
			PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
			PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		},
		Secrets: &sandbox.SandboxSecretSecurity{
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
		},
	}
	target := &sandbox.SandboxState{
		Name:     "microvm-dev",
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver: sandbox.SandboxRuntimeDriverMicroVM,
		},
		Security: existing,
	}

	result, err := Run(context.Background(), CommandRequest{SandboxName: "microvm-dev"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{}, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if result.Target.Name != "microvm-dev" || result.Target.Provider != "worker" {
		t.Fatalf("result target = %#v", result.Target)
	}
	if target.Security != existing {
		t.Fatalf("security metadata was replaced: got %#v want existing %#v", target.Security, existing)
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
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("ResolveDriver should not run after start failure")
			return nil, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			t.Fatal("RunCommand should not run after start failure")
			return nil
		},
	})
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseStartTarget || !errors.Is(err, startErr) {
		t.Fatalf("error = %#v, want start phase wrapping startErr", err)
	}
	if phaseErr.Target != target {
		t.Fatalf("phase target = %#v, want original target %#v", phaseErr.Target, target)
	}
	if phaseErr.RuntimeDriver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime driver = %q, want %q", phaseErr.RuntimeDriver, sandboxruntime.DriverSSHMachine)
	}
}

func TestRunPreservesInjectedProvisionPhaseError(t *testing.T) {
	provisionErr := errors.New("quota exceeded")

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-new"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return nil, &PhaseError{Phase: PhaseProvisionTarget, Err: provisionErr}
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("ResolveDriver should not run after provision failure")
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

func TestRunPhaseErrorsUseStablePhaseNames(t *testing.T) {
	tests := []struct {
		name  string
		phase Phase
		value string
		deps  func(error) Dependencies
	}{
		{
			name:  "resolve target",
			phase: PhaseResolveTarget,
			value: "resolve_target",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
						return nil, failure
					},
				})
			},
		},
		{
			name:  "start",
			phase: PhaseStartTarget,
			value: "start",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
						return &sandbox.SandboxState{Name: "factory-dev", Provider: "daytona", Status: sandbox.StatusStopped}, nil
					},
					StartTarget: func(context.Context, *sandbox.SandboxState, io.Writer, io.Writer) (*sandbox.SandboxState, error) {
						return nil, failure
					},
				})
			},
		},
		{
			name:  "resolve runtime",
			phase: PhaseResolveDriver,
			value: "resolve_driver",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
						return nil, failure
					},
				})
			},
		},
		{
			name:  "prepare workspace",
			phase: PhasePrepareWorkspace,
			value: "prepare_workspace",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					PrepareWorkspace: func(context.Context, PrepareContext, *CommandRequest) error {
						return failure
					},
				})
			},
		},
		{
			name:  "prepare auth",
			phase: PhasePrepareAuth,
			value: "prepare_auth",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					PrepareAuth: func(context.Context, PrepareContext, *CommandRequest) error {
						return failure
					},
				})
			},
		},
		{
			name:  "prepare command",
			phase: PhasePrepareCommand,
			value: "prepare_command",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					PrepareCommand: func(context.Context, PrepareContext, *CommandRequest) error {
						return failure
					},
				})
			},
		},
		{
			name:  "run",
			phase: PhaseRun,
			value: "run",
			deps: func(failure error) Dependencies {
				return successfulDeps(t, Dependencies{
					RunCommand: func(context.Context, RunContext, CommandRequest) error {
						return failure
					},
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := errors.New(tt.name + " failed")
			_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, tt.deps(failure))
			phaseErr, ok := AsPhaseError(err)
			if !ok {
				t.Fatalf("Run() error = %#v, want PhaseError", err)
			}
			if phaseErr.Phase != tt.phase || string(phaseErr.Phase) != tt.value {
				t.Fatalf("phase = %q/%q, want %q", phaseErr.Phase, string(phaseErr.Phase), tt.value)
			}
			if !errors.Is(err, failure) {
				t.Fatalf("error = %v, want to wrap %v", err, failure)
			}
		})
	}
}

func TestRunPhaseErrorCarriesSandboxTargetAndRuntimeDriver(t *testing.T) {
	runErr := errors.New("remote failed")
	target := &sandbox.SandboxState{
		ID:                "sb-123",
		Name:              "factory-dev",
		Provider:          "digitalocean",
		WorkspaceID:       "droplet-456",
		IP:                "203.0.113.42",
		TailscaleIP:       "100.64.0.7",
		TailscaleHostname: "factory-dev.tailnet.example",
		TailscaleLockdown: true,
		Status:            sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			RuntimeID:      "runtime-789",
			Image:          "ubuntu-24.04",
			WorkerID:       "worker-a",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
		Host: &sandbox.SandboxHost{
			ID: "host-123",
		},
	}

	_, err := Run(context.Background(), CommandRequest{SandboxName: "factory-dev"}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{id: "test_runtime"}, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error {
			return runErr
		},
	})
	phaseErr, ok := AsPhaseError(err)
	if !ok || phaseErr.Phase != PhaseRun || !errors.Is(err, runErr) {
		t.Fatalf("error = %#v, want run phase wrapping runErr", err)
	}
	if phaseErr.RuntimeDriver != "test_runtime" {
		t.Fatalf("runtime driver = %q, want test_runtime", phaseErr.RuntimeDriver)
	}
	if phaseErr.Target != target {
		t.Fatalf("phase target = %#v, want original target %#v", phaseErr.Target, target)
	}
	if phaseErr.Target.Host == nil || phaseErr.Target.Host.ID != "host-123" {
		t.Fatalf("phase target host = %#v, want original host metadata", phaseErr.Target.Host)
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
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRuntimeDriver{}, nil
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
	if overrides.ResolveDriver != nil {
		deps.ResolveDriver = overrides.ResolveDriver
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
	if overrides.OnDriverReady != nil {
		deps.OnDriverReady = overrides.OnDriverReady
	}
	return deps
}

type fakeRuntimeDriver struct {
	id string
}

func (f fakeRuntimeDriver) ID() string {
	if f.id != "" {
		return f.id
	}
	return sandboxruntime.DriverSSHMachine
}

func (fakeRuntimeDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRuntimeDriver) Start(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRuntimeDriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (fakeRuntimeDriver) Inspect(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRuntimeDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}

func (fakeRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (fakeRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

type recordingRuntimeDriver struct {
	id         string
	execCalled bool
	exec       func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
}

func (r *recordingRuntimeDriver) ID() string {
	if r.id != "" {
		return r.id
	}
	return sandboxruntime.DriverSSHMachine
}

func (r *recordingRuntimeDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (r *recordingRuntimeDriver) Start(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (r *recordingRuntimeDriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (r *recordingRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (r *recordingRuntimeDriver) Inspect(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (r *recordingRuntimeDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	r.execCalled = true
	if r.exec == nil {
		return &sandboxruntime.ExecResult{}, nil
	}
	return r.exec(ctx, req)
}

func (r *recordingRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (r *recordingRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func cloneExecRequest(req sandboxruntime.ExecRequest) sandboxruntime.ExecRequest {
	req.Args = append([]string(nil), req.Args...)
	if req.Env != nil {
		env := make(map[string]string, len(req.Env))
		for key, value := range req.Env {
			env[key] = value
		}
		req.Env = env
	}
	return req
}
