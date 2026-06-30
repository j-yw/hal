package rootlesspodman_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

var _ sandboxruntime.LifecycleDriver = (*rootlesspodman.Driver)(nil)

func TestLifecycleCommandsUseFakeRunnerAndSafePodmanArgs(t *testing.T) {
	const (
		containerName = "hal-dev"
		containerID   = "container-created"
		image         = "ghcr.io/acme/hal-agent:test"
		workDir       = "/workspace/project"
	)
	stdout := &bytes.Buffer{}
	env := map[string]string{"HAL_TEST": "1"}
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationCreate: {
				Stdout: containerID + "\n",
			},
			rootlesspodman.OperationInspect: {
				Stdout: `[{"Id":"container-created","Name":"hal-dev","ImageName":"ghcr.io/acme/hal-agent:test","State":{"Status":"running"}}]`,
			},
		},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		Image:           image,
		WorkDir:         workDir,
	})

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{
		Name:   containerName,
		Env:    env,
		Stdout: stdout,
	})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if created.ID != containerID || created.Name != containerName || created.Status != sandbox.StatusStopped {
		t.Fatalf("Create() target = %#v, want stopped target with podman ID/name", created)
	}
	assertRootlessRuntimeMetadata(t, created, containerID, image)

	staleMetadata := *created
	staleMetadata.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{
		Target: staleMetadata,
		Stdout: stdout,
	})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if started.Status != sandbox.StatusRunning {
		t.Fatalf("Start() status = %q, want %q", started.Status, sandbox.StatusRunning)
	}
	assertRootlessRuntimeMetadata(t, started, containerID, image)

	inspected, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: *started})
	if err != nil {
		t.Fatalf("Inspect() unexpected error: %v", err)
	}
	if inspected.Status != sandbox.StatusRunning {
		t.Fatalf("Inspect() status = %q, want %q", inspected.Status, sandbox.StatusRunning)
	}
	assertRootlessRuntimeMetadata(t, inspected, containerID, image)

	stopped, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{
		Target: *inspected,
		Stdout: stdout,
	})
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	if stopped.Status != sandbox.StatusStopped {
		t.Fatalf("Stop() status = %q, want %q", stopped.Status, sandbox.StatusStopped)
	}
	assertRootlessRuntimeMetadata(t, stopped, containerID, image)

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{
		Target: *stopped,
		Stdout: stdout,
	}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	wantOperations := []string{
		rootlesspodman.OperationCreate,
		rootlesspodman.OperationStart,
		rootlesspodman.OperationInspect,
		rootlesspodman.OperationStop,
		rootlesspodman.OperationDelete,
	}
	if got := runner.lifecycleOperations(); !reflect.DeepEqual(got, wantOperations) {
		t.Fatalf("lifecycle operations = %#v, want %#v", got, wantOperations)
	}

	wantArgsByOperation := map[string][]string{
		rootlesspodman.OperationCreate: {
			"podman", "create",
			"--pull=never",
			"--name", containerName,
			"--hostname", containerName,
			"--label", "dev.jywlabs.hal.runtime=rootless_podman",
			"--label", "dev.jywlabs.hal.sandbox.name=" + containerName,
			"--security-opt", "no-new-privileges",
			"--workdir", workDir,
			image,
			"sleep", "infinity",
		},
		rootlesspodman.OperationStart:   {"podman", "start", containerID},
		rootlesspodman.OperationInspect: {"podman", "inspect", containerID},
		rootlesspodman.OperationStop:    {"podman", "stop", containerID},
		rootlesspodman.OperationDelete:  {"podman", "rm", "--force", containerID},
	}
	for _, req := range runner.lifecycleRequests {
		if !reflect.DeepEqual(req.Args, wantArgsByOperation[req.Operation]) {
			t.Fatalf("%s args = %#v, want %#v", req.Operation, req.Args, wantArgsByOperation[req.Operation])
		}
		assertSafeLifecycleArgs(t, req.Args)
	}
	if !reflect.DeepEqual(runner.lifecycleRequests[0].Env, env) {
		t.Fatalf("Create env = %#v, want %#v", runner.lifecycleRequests[0].Env, env)
	}
}

func TestLifecycleFailuresWrapOperationWithSanitizedOutput(t *testing.T) {
	runnerErr := errors.New("podman failed token=raw-secret from /Users/alice/worktree")
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationStart: {
				ExitCode: 125,
				Stdout:   "using /Users/alice/project\n",
				Stderr:   "refusing /var/run/docker.sock token=abcd1234\n",
			},
		},
		errByOperation: map[string]error{
			rootlesspodman.OperationStart: runnerErr,
		},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{LifecycleRunner: runner})

	_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{
		Target: sandboxruntime.Target{
			ID:   "container-created",
			Name: "hal-dev",
		},
	})
	if err == nil {
		t.Fatal("Start() expected error, got nil")
	}
	if !errors.Is(err, runnerErr) {
		t.Fatalf("errors.Is(%v, runnerErr) = false, want true", err)
	}
	var opErr *rootlesspodman.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("errors.As(%T) = false, want true", opErr)
	}
	if opErr.Driver != sandboxruntime.DriverRootlessPodman || opErr.Operation != rootlesspodman.OperationStart || opErr.ExitCode != 125 {
		t.Fatalf("OperationError = %#v, want rootless start exit 125", opErr)
	}
	message := err.Error()
	for _, unsafe := range []string{"/Users/alice", "/var/run/docker.sock", "raw-secret", "abcd1234"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("error message %q contains unsafe detail %q", message, unsafe)
		}
	}
	for _, want := range []string{sandboxruntime.DriverRootlessPodman, rootlesspodman.OperationStart, "[redacted-path]", "[redacted-docker-socket]", "token=[redacted]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error message %q does not include sanitized detail %q", message, want)
		}
	}
}

func TestLifecycleRejectsMissingRunnerAndTargetReferences(t *testing.T) {
	driver := rootlesspodman.New(rootlesspodman.Options{})

	if _, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "hal-dev"}); !errors.Is(err, rootlesspodman.ErrLifecycleRunnerRequired) {
		t.Fatalf("Create() error = %v, want ErrLifecycleRunnerRequired", err)
	}

	driver = rootlesspodman.New(rootlesspodman.Options{LifecycleRunner: &fakeCommandRunner{}})
	if _, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{}); !errors.Is(err, rootlesspodman.ErrTargetRefRequired) {
		t.Fatalf("Start() error = %v, want ErrTargetRefRequired", err)
	}
}

func assertRootlessRuntimeMetadata(t *testing.T, target *sandboxruntime.Target, runtimeID, image string) {
	t.Helper()
	if target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("runtime driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverRootlessPodman)
	}
	if target.Runtime.RuntimeID != runtimeID {
		t.Fatalf("runtime ID = %q, want %q", target.Runtime.RuntimeID, runtimeID)
	}
	if target.Runtime.Image != image {
		t.Fatalf("runtime image = %q, want %q", target.Runtime.Image, image)
	}
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime isolation = %q, want %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if target.Runtime.IsolationLevel == sandbox.SandboxIsolationLevelVM {
		t.Fatalf("runtime isolation = %q, rootless Podman must not report VM isolation", target.Runtime.IsolationLevel)
	}
}

func assertSafeLifecycleArgs(t *testing.T, args []string) {
	t.Helper()
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, unsafe := range []string{"--privileged", "docker.sock", "/var/run/docker.sock", "/run/docker.sock"} {
			if strings.Contains(lower, unsafe) {
				t.Fatalf("args %#v contain unsafe lifecycle token %q", args, unsafe)
			}
		}
	}
}
