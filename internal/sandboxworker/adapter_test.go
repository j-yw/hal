package sandboxworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestClientDriverSatisfiesSandboxRuntimeDriver(t *testing.T) {
	var _ sandboxruntime.Driver = (*ClientDriver)(nil)
	var _ RuntimeDriverClient = (*Client)(nil)
}

func TestNewClientDriverRequiresDriverIDAndClient(t *testing.T) {
	if driver, err := NewClientDriver(ClientDriverOptions{Client: &recordingRuntimeDriverClient{}}); driver != nil || !errors.Is(err, ErrDriverIDRequired) {
		t.Fatalf("NewClientDriver(missing driver) = %#v, %v; want ErrDriverIDRequired", driver, err)
	}
	if driver, err := NewClientDriver(ClientDriverOptions{DriverID: "fake_runtime"}); driver != nil || !errors.Is(err, ErrWorkerClientRequired) {
		t.Fatalf("NewClientDriver(missing client) = %#v, %v; want ErrWorkerClientRequired", driver, err)
	}
}

func TestClientDriverMapsLifecycleAndInspectCallsToWorkerClient(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	env := map[string]string{"TOKEN": "raw-secret"}
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{
		Name: "adapter-dev",
		Env:  env,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	env["TOKEN"] = "changed"
	if client.createReq.Name != "adapter-dev" || client.createReq.Env["TOKEN"] != "raw-secret" {
		t.Fatalf("Create() worker request = %#v, want cloned adapter-dev env", client.createReq)
	}
	if created.Name != "adapter-dev" || created.Status != "created" || created.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Create() target = %#v, want created fake runtime target", created)
	}

	runtimeTarget := sandboxruntime.Target{
		ID:       "target-adapter-dev",
		Name:     "adapter-dev",
		Provider: "legacy-provider",
		Status:   "created",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID:      "runtime-adapter-dev",
			Image:          "image-ref",
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
		Connection: sandboxruntime.ConnectionInfo{
			Address:     "10.0.0.1",
			PublicIP:    "203.0.113.2",
			WorkspaceID: "host-sensitive-workspace",
		},
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: runtimeTarget})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if started.Status != "running" {
		t.Fatalf("Start() status = %q, want running", started.Status)
	}
	startTarget := client.lifecycleReqs[OperationStart].Target
	if startTarget.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Start() worker target runtime driver = %q, want fallback driver", startTarget.Runtime.Driver)
	}
	if startTarget.Runtime.RuntimeID != "runtime-adapter-dev" || startTarget.Runtime.WorkerID != "worker-001" {
		t.Fatalf("Start() worker target runtime metadata = %#v, want safe runtime metadata", startTarget.Runtime)
	}

	stopped, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: *started})
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if stopped.Status != "stopped" {
		t.Fatalf("Stop() status = %q, want stopped", stopped.Status)
	}

	inspected, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: *stopped})
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}
	if inspected.Status != "inspected" || inspected.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Inspect() target = %#v, want inspected fake runtime target", inspected)
	}

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *inspected}); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	wantCalls := []string{OperationCreate, OperationStart, OperationStop, OperationInspect, OperationDelete}
	if !reflect.DeepEqual(client.calls, wantCalls) {
		t.Fatalf("worker client calls = %#v, want %#v", client.calls, wantCalls)
	}
	for operation, driverID := range client.driverIDs {
		if driverID != "fake_runtime" {
			t.Fatalf("%s driverID = %q, want fake_runtime", operation, driverID)
		}
	}
}

func TestClientDriverExecForwardsToWorkerClientAndWritesBoundedOutput(t *testing.T) {
	client := &recordingRuntimeDriverClient{
		execResp: &ExecResponse{
			ExitCode: 17,
			Stdout:   workerExecOutputPayload("stdout data", MaxExecStdoutCaptureBytes, false),
			Stderr:   workerExecOutputPayload("stderr data", MaxExecStderrCaptureBytes, false),
		},
	}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	args := []string{"sh", "-lc", "cat"}
	env := map[string]string{"TOKEN": "raw-secret"}
	var stdout, stderr bytes.Buffer
	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{
			ID:     "target-dev",
			Name:   "dev",
			Status: "running",
			Runtime: sandboxruntime.RuntimeState{
				RuntimeID:      "runtime-dev",
				Image:          "image-ref",
				WorkerID:       "worker-001",
				IsolationLevel: IsolationLevelContainer,
			},
		},
		Args:    args,
		Env:     env,
		WorkDir: " /workspace/hal ",
		Stdin:   strings.NewReader("stdin data"),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	args[0] = "changed"
	env["TOKEN"] = "changed"

	if result == nil || result.ExitCode != 17 {
		t.Fatalf("Exec() result = %#v, want exit code 17", result)
	}
	if stdout.String() != "stdout data" || stderr.String() != "stderr data" {
		t.Fatalf("Exec() output = stdout %q stderr %q, want worker response output", stdout.String(), stderr.String())
	}
	if !reflect.DeepEqual(client.calls, []string{OperationExec}) {
		t.Fatalf("worker client calls = %#v, want exec call", client.calls)
	}
	if client.driverIDs[OperationExec] != "fake_runtime" {
		t.Fatalf("Exec() driverID = %q, want fake_runtime", client.driverIDs[OperationExec])
	}
	req := client.execReq
	if req.OperationID != clientDriverExecOperationID {
		t.Fatalf("Exec() operationID = %q, want %q", req.OperationID, clientDriverExecOperationID)
	}
	if req.Target.ID != "target-dev" || req.Target.Name != "dev" || req.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Exec() worker target = %#v, want converted target with fallback driver", req.Target)
	}
	if req.Target.Runtime.RuntimeID != "runtime-dev" || req.Target.Runtime.WorkerID != "worker-001" {
		t.Fatalf("Exec() worker target runtime metadata = %#v, want safe runtime metadata", req.Target.Runtime)
	}
	if !reflect.DeepEqual(req.Args, []string{"sh", "-lc", "cat"}) {
		t.Fatalf("Exec() args = %#v, want cloned args", req.Args)
	}
	if req.Env["TOKEN"] != "raw-secret" {
		t.Fatalf("Exec() env = %#v, want cloned env", req.Env)
	}
	if req.WorkDir != "/workspace/hal" {
		t.Fatalf("Exec() workdir = %q, want trimmed workdir", req.WorkDir)
	}
	if req.Stdin == nil || req.Stdin.Data != "stdin data" || req.Stdin.SizeBytes != 10 || req.Stdin.LimitBytes != MaxExecStdinBytes {
		t.Fatalf("Exec() stdin payload = %#v, want bounded stdin payload", req.Stdin)
	}
	if req.StdoutLimitBytes != MaxExecStdoutCaptureBytes || req.StderrLimitBytes != MaxExecStderrCaptureBytes {
		t.Fatalf("Exec() capture limits = stdout %d stderr %d, want worker maximums", req.StdoutLimitBytes, req.StderrLimitBytes)
	}
}

func TestClientDriverExecRejectsOversizedStdinBeforeWorkerClientDispatch(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
		Args:   []string{"cat"},
		Stdin:  strings.NewReader(strings.Repeat("x", int(MaxExecStdinBytes)+1)),
	})
	if result != nil || err == nil {
		t.Fatalf("Exec() = %#v, %v; want oversized stdin error", result, err)
	}
	assertClientDriverError(t, err, OperationExec, "fake_runtime")
	if !strings.Contains(err.Error(), "exec stdin") || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("Exec() error = %q, want sanitized stdin maximum detail", err.Error())
	}
	if len(client.calls) != 0 {
		t.Fatalf("worker client calls = %#v, want no dispatch after oversized stdin", client.calls)
	}
}

func TestClientDriverExecSurfacesCommandErrorsAndTruncation(t *testing.T) {
	t.Run("command error", func(t *testing.T) {
		client := &recordingRuntimeDriverClient{
			execResp: &ExecResponse{
				ExitCode: 126,
				Stdout:   workerExecOutputPayload("partial out", MaxExecStdoutCaptureBytes, false),
				Stderr:   workerExecOutputPayload("partial err", MaxExecStderrCaptureBytes, false),
				Error: &Error{
					Code:    ErrorCodeDriverFailed,
					Message: "exec failed token=raw-secret under /Users/alice/worktree",
				},
			},
		}
		driver, err := NewClientDriver(ClientDriverOptions{
			DriverID: "fake_runtime",
			Client:   client,
		})
		if err != nil {
			t.Fatalf("NewClientDriver() error: %v", err)
		}

		var stdout, stderr bytes.Buffer
		result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
			Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
			Args:   []string{"sh", "-lc", "exit 126"},
			Stdout: &stdout,
			Stderr: &stderr,
		})
		if result == nil || result.ExitCode != 126 || err == nil {
			t.Fatalf("Exec() = %#v, %v; want exit result with command error", result, err)
		}
		assertClientDriverError(t, err, OperationExec, "fake_runtime")
		var protocolErr *ProtocolError
		if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeDriverFailed {
			t.Fatalf("Exec() error = %T %v, want driver_failed protocol error", err, err)
		}
		if stdout.String() != "partial out" || stderr.String() != "partial err" {
			t.Fatalf("Exec() output = stdout %q stderr %q, want partial worker output", stdout.String(), stderr.String())
		}
		message := err.Error()
		for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
			if strings.Contains(message, unsafe) {
				t.Fatalf("Exec() error leaked unsafe detail %q in %q", unsafe, message)
			}
		}
		for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
			if !strings.Contains(message, want) {
				t.Fatalf("Exec() error = %q, want sanitized marker %q", message, want)
			}
		}
	})

	t.Run("truncated output", func(t *testing.T) {
		client := &recordingRuntimeDriverClient{
			execResp: &ExecResponse{
				ExitCode: 0,
				Stdout:   workerExecOutputPayload("abc", 3, true),
				Stderr:   workerExecOutputPayload("", MaxExecStderrCaptureBytes, false),
			},
		}
		driver, err := NewClientDriver(ClientDriverOptions{
			DriverID: "fake_runtime",
			Client:   client,
		})
		if err != nil {
			t.Fatalf("NewClientDriver() error: %v", err)
		}

		var stdout bytes.Buffer
		result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
			Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
			Args:   []string{"printf", "abcdef"},
			Stdout: &stdout,
		})
		if result == nil || result.ExitCode != 0 || !errors.Is(err, ErrWorkerExecOutputTruncated) {
			t.Fatalf("Exec() = %#v, %v; want exit result with truncation error", result, err)
		}
		assertClientDriverError(t, err, OperationExec, "fake_runtime")
		if stdout.String() != "abc" {
			t.Fatalf("Exec() stdout = %q, want truncated worker output", stdout.String())
		}
	})
}

func TestClientDriverExecFailuresReturnPrimarySanitizedErrors(t *testing.T) {
	unsafeDetail := "worker exec failed token=raw-secret via ssh://deploy:secret@example.test/tmp/private/worker.sock?token=raw-secret under /Users/alice/worktree and /workspace/.hal/tmp/session"
	tests := []struct {
		name          string
		client        *recordingRuntimeDriverClient
		wantWrapped   error
		wantClientErr bool
	}{
		{
			name: "worker client failure",
			client: &recordingRuntimeDriverClient{
				errByOperation: map[string]error{
					OperationExec: &ClientError{
						Operation: OperationExec,
						Code:      ErrorCodeInternal,
						Message:   unsafeDetail,
					},
				},
			},
			wantClientErr: true,
		},
		{
			name: "worker adapter failure",
			client: &recordingRuntimeDriverClient{
				errByOperation: map[string]error{
					OperationExec: errors.New(unsafeDetail),
				},
			},
		},
		{
			name: "missing worker exec response",
			client: &recordingRuntimeDriverClient{
				nilExecResp: true,
			},
			wantWrapped: ErrWorkerExecResponseRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := NewClientDriver(ClientDriverOptions{
				DriverID: "fake_runtime",
				Client:   tt.client,
			})
			if err != nil {
				t.Fatalf("NewClientDriver() error: %v", err)
			}

			result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
				Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
				Args:   []string{"sh", "-lc", "false"},
			})
			if result != nil || err == nil {
				t.Fatalf("Exec() = %#v, %v; want primary exec error", result, err)
			}
			assertClientDriverError(t, err, OperationExec, "fake_runtime")
			if tt.wantWrapped != nil && !errors.Is(err, tt.wantWrapped) {
				t.Fatalf("Exec() error = %v, want wrapped %v", err, tt.wantWrapped)
			}
			if tt.wantClientErr {
				var clientErr *ClientError
				if !errors.As(err, &clientErr) {
					t.Fatalf("Exec() error = %T %v, want wrapped worker client error", err, err)
				}
			}

			message := err.Error()
			for _, want := range []string{"fake_runtime exec failed", "exec"} {
				if !strings.Contains(message, want) {
					t.Fatalf("Exec() error = %q, want operation label %q", message, want)
				}
			}
			for _, unsafe := range []string{"raw-secret", "deploy:secret", "example.test", "/tmp/private/worker.sock", "/Users/alice", "worktree", "/workspace/.hal/tmp/session"} {
				if strings.Contains(message, unsafe) {
					t.Fatalf("Exec() error leaked unsafe detail %q in %q", unsafe, message)
				}
			}
			if tt.wantWrapped == nil {
				for _, want := range []string{"token=[redacted]", "[redacted"} {
					if !strings.Contains(message, want) {
						t.Fatalf("Exec() error = %q, want sanitized marker %q", message, want)
					}
				}
			}
		})
	}
}

func TestClientDriverDoesNotOwnRecoveryWarnings(t *testing.T) {
	source, err := os.ReadFile("adapter.go")
	if err != nil {
		t.Fatalf("ReadFile(adapter.go) error: %v", err)
	}
	for _, forbidden := range []string{
		"ArtifactWarning",
		"ArtifactMetadata",
		"EventTypeArtifactSync",
		"Warnings",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("ClientDriver source contains %q; recovery warnings belong at command boundaries", forbidden)
		}
	}
}

func TestClientDriverCopyInForwardsBoundedFileContentToWorkerClient(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	sourcePath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(sourcePath, []byte("copy payload\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error: %v", err)
	}
	target := lifecycleRuntimeTarget("fake_runtime", "dev", "running")
	target.ID = "target-dev"
	target.Runtime.RuntimeID = "runtime-dev"
	target.Runtime.WorkerID = "worker-001"

	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      sourcePath,
		DestinationPath: " /workspace/config.json ",
	}); err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}

	if !reflect.DeepEqual(client.calls, []string{OperationCopyIn}) {
		t.Fatalf("worker client calls = %#v, want copy_in call", client.calls)
	}
	if client.driverIDs[OperationCopyIn] != "fake_runtime" {
		t.Fatalf("CopyIn() driverID = %q, want fake_runtime", client.driverIDs[OperationCopyIn])
	}
	req := client.copyInReq
	if req.OperationID != clientDriverCopyInOperationID {
		t.Fatalf("CopyIn() operationID = %q, want %q", req.OperationID, clientDriverCopyInOperationID)
	}
	if req.Target.ID != "target-dev" || req.Target.Name != "dev" || req.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("CopyIn() worker target = %#v, want converted target with fallback driver", req.Target)
	}
	if req.Target.Runtime.RuntimeID != "runtime-dev" || req.Target.Runtime.WorkerID != "worker-001" {
		t.Fatalf("CopyIn() worker target runtime metadata = %#v, want safe runtime metadata", req.Target.Runtime)
	}
	if req.Source.DisplayPath != "config.json" {
		t.Fatalf("CopyIn() source displayPath = %q, want basename only", req.Source.DisplayPath)
	}
	if req.RemoteDestinationPath != "/workspace/config.json" {
		t.Fatalf("CopyIn() remote destination = %q, want trimmed remote path", req.RemoteDestinationPath)
	}
	if got := decodeWorkerCopyPayloadForTest(t, req.Payload); got != "copy payload\n" {
		t.Fatalf("CopyIn() payload = %q, want file content", got)
	}
	if req.Payload.LimitBytes != MaxCopyInPayloadBytes {
		t.Fatalf("CopyIn() payload limit = %d, want %d", req.Payload.LimitBytes, MaxCopyInPayloadBytes)
	}
}

func TestClientDriverCopyInRejectsOversizedSourceBeforeWorkerClientDispatch(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	sourcePath := filepath.Join(t.TempDir(), "oversized.bin")
	if err := os.WriteFile(sourcePath, []byte(strings.Repeat("x", int(MaxCopyInPayloadBytes)+1)), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error: %v", err)
	}
	err = driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
		SourcePath:      sourcePath,
		DestinationPath: "/workspace/oversized.bin",
	})
	if err == nil {
		t.Fatal("CopyIn() error = nil, want oversized source error")
	}
	assertClientDriverError(t, err, OperationCopyIn, "fake_runtime")
	if !strings.Contains(err.Error(), "copy_in payload") || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("CopyIn() error = %q, want sanitized copy_in maximum detail", err.Error())
	}
	if len(client.calls) != 0 {
		t.Fatalf("worker client calls = %#v, want no dispatch after oversized source", client.calls)
	}
}

func TestClientDriverCopyOutForwardsRemoteSourceAndMaterializesReturnedPayload(t *testing.T) {
	client := &recordingRuntimeDriverClient{
		copyOutResp: &CopyOutResponse{
			Payload: ptrWorkerCopyPayload("report\n", MaxCopyOutPayloadBytes),
		},
	}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	destinationPath := filepath.Join(t.TempDir(), "nested", "report.txt")
	target := lifecycleRuntimeTarget("fake_runtime", "dev", "running")
	target.ID = "target-dev"

	if err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      " /workspace/reports/report.txt ",
		DestinationPath: destinationPath,
	}); err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}

	if !reflect.DeepEqual(client.calls, []string{OperationCopyOut}) {
		t.Fatalf("worker client calls = %#v, want copy_out call", client.calls)
	}
	if client.driverIDs[OperationCopyOut] != "fake_runtime" {
		t.Fatalf("CopyOut() driverID = %q, want fake_runtime", client.driverIDs[OperationCopyOut])
	}
	req := client.copyOutReq
	if req.OperationID != clientDriverCopyOutOperationID {
		t.Fatalf("CopyOut() operationID = %q, want %q", req.OperationID, clientDriverCopyOutOperationID)
	}
	if req.Target.ID != "target-dev" || req.Target.Name != "dev" || req.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("CopyOut() worker target = %#v, want converted target with fallback driver", req.Target)
	}
	if req.RemoteSourcePath != "/workspace/reports/report.txt" {
		t.Fatalf("CopyOut() remote source = %q, want trimmed remote path", req.RemoteSourcePath)
	}
	if req.Destination.DisplayPath != "report.txt" {
		t.Fatalf("CopyOut() destination displayPath = %q, want basename only", req.Destination.DisplayPath)
	}
	if req.MaxPayloadBytes != MaxCopyOutPayloadBytes {
		t.Fatalf("CopyOut() max payload = %d, want %d", req.MaxPayloadBytes, MaxCopyOutPayloadBytes)
	}
	data, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatalf("ReadFile(destination) error: %v", err)
	}
	if string(data) != "report\n" {
		t.Fatalf("CopyOut() destination = %q, want worker payload", data)
	}
}

func TestClientDriverCopyOperationsSurfaceSanitizedWorkerErrors(t *testing.T) {
	t.Run("copy_in embedded error", func(t *testing.T) {
		client := &recordingRuntimeDriverClient{
			copyInResp: &CopyInResponse{
				Status: CopyStatusFailed,
				Error: &Error{
					Code:    ErrorCodeDriverFailed,
					Message: "copy failed token=raw-secret under /Users/alice/worktree",
				},
			},
		}
		driver, err := NewClientDriver(ClientDriverOptions{
			DriverID: "fake_runtime",
			Client:   client,
		})
		if err != nil {
			t.Fatalf("NewClientDriver() error: %v", err)
		}

		sourcePath := filepath.Join(t.TempDir(), "input.txt")
		if err := os.WriteFile(sourcePath, []byte("payload"), 0o600); err != nil {
			t.Fatalf("WriteFile(source) error: %v", err)
		}
		err = driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
			Target:          lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
			SourcePath:      sourcePath,
			DestinationPath: "/workspace/input.txt",
		})
		if err == nil {
			t.Fatal("CopyIn() error = nil, want embedded worker error")
		}
		assertClientDriverError(t, err, OperationCopyIn, "fake_runtime")
		assertSanitizedWorkerCopyError(t, err.Error())
		var protocolErr *ProtocolError
		if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeDriverFailed {
			t.Fatalf("CopyIn() error = %T %v, want driver_failed protocol error", err, err)
		}
	})

	t.Run("copy_out embedded error", func(t *testing.T) {
		client := &recordingRuntimeDriverClient{
			copyOutResp: &CopyOutResponse{
				Payload: ptrWorkerCopyPayload("partial", MaxCopyOutPayloadBytes),
				Error: &Error{
					Code:    ErrorCodeDriverFailed,
					Message: "copy failed token=raw-secret under /Users/alice/worktree",
				},
			},
		}
		driver, err := NewClientDriver(ClientDriverOptions{
			DriverID: "fake_runtime",
			Client:   client,
		})
		if err != nil {
			t.Fatalf("NewClientDriver() error: %v", err)
		}

		destinationPath := filepath.Join(t.TempDir(), "report.txt")
		err = driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
			Target:          lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
			SourcePath:      "/workspace/report.txt",
			DestinationPath: destinationPath,
		})
		if err == nil {
			t.Fatal("CopyOut() error = nil, want embedded worker error")
		}
		assertClientDriverError(t, err, OperationCopyOut, "fake_runtime")
		assertSanitizedWorkerCopyError(t, err.Error())
		var protocolErr *ProtocolError
		if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeDriverFailed {
			t.Fatalf("CopyOut() error = %T %v, want driver_failed protocol error", err, err)
		}
		if _, statErr := os.Stat(destinationPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("CopyOut() destination stat error = %v, want no partial destination", statErr)
		}
	})

	t.Run("copy_out truncated payload", func(t *testing.T) {
		client := &recordingRuntimeDriverClient{
			copyOutResp: &CopyOutResponse{
				Payload:       ptrWorkerCopyPayload("abc", MaxCopyOutPayloadBytes),
				Truncated:     true,
				LimitExceeded: true,
				Error: &Error{
					Code:    ErrorCodeDriverFailed,
					Message: "copy_out payload exceeded requested limit and was truncated",
				},
			},
		}
		driver, err := NewClientDriver(ClientDriverOptions{
			DriverID: "fake_runtime",
			Client:   client,
		})
		if err != nil {
			t.Fatalf("NewClientDriver() error: %v", err)
		}

		destinationPath := filepath.Join(t.TempDir(), "report.txt")
		err = driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
			Target:          lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
			SourcePath:      "/workspace/report.txt",
			DestinationPath: destinationPath,
		})
		if !errors.Is(err, ErrWorkerCopyOutPayloadTruncated) {
			t.Fatalf("CopyOut() error = %v, want truncation error", err)
		}
		assertClientDriverError(t, err, OperationCopyOut, "fake_runtime")
		if _, statErr := os.Stat(destinationPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("CopyOut() destination stat error = %v, want no partial destination", statErr)
		}
	})
}

func TestClientDriverPreservesContextErrorsFromWorkerClient(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.Create(canceledCtx, sandboxruntime.CreateRequest{Name: "dev"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create(canceled) error = %v, want context.Canceled", err)
	}

	timeoutCtx, timeoutCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer timeoutCancel()
	if _, err := driver.Inspect(timeoutCtx, sandboxruntime.InspectRequest{Target: sandboxruntime.Target{Name: "dev"}}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Inspect(timeout) error = %v, want context deadline", err)
	}

	if _, err := driver.Exec(canceledCtx, sandboxruntime.ExecRequest{
		Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
		Args:   []string{"true"},
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Exec(canceled) error = %v, want context.Canceled", err)
	}
}

func TestClientDriverErrorsSanitizeWorkerClientDetails(t *testing.T) {
	client := &recordingRuntimeDriverClient{
		errByOperation: map[string]error{
			OperationStart: errors.New("provider failed token=raw-secret under /Users/alice/worktree"),
		},
	}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	_, err = driver.Start(context.Background(), sandboxruntime.LifecycleRequest{
		Target: sandboxruntime.Target{
			Name:    "dev",
			Runtime: sandboxruntime.RuntimeState{Driver: "fake_runtime"},
		},
	})
	if err == nil {
		t.Fatal("Start() error = nil, want sanitized worker client error")
	}
	message := err.Error()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("Start() error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("Start() error = %q, want sanitized marker %q", message, want)
		}
	}
}

func TestClientDriverLifecycleErrorsExposeStableClassifications(t *testing.T) {
	unsafeDetail := "provider failed token=raw-secret via ssh://deploy:secret@example.test/tmp/private/worker.sock?token=raw-secret under /Users/alice/worktree and /workspace/.hal/tmp/session"
	operations := []struct {
		operation string
		call      func(*ClientDriver) error
	}{
		{
			operation: OperationCreate,
			call: func(driver *ClientDriver) error {
				_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "dev"})
				return err
			},
		},
		{
			operation: OperationStart,
			call: func(driver *ClientDriver) error {
				_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: lifecycleRuntimeTarget("fake_runtime", "dev", "created")})
				return err
			},
		},
		{
			operation: OperationInspect,
			call: func(driver *ClientDriver) error {
				_, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running")})
				return err
			},
		},
		{
			operation: OperationStop,
			call: func(driver *ClientDriver) error {
				_, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running")})
				return err
			},
		},
		{
			operation: OperationDelete,
			call: func(driver *ClientDriver) error {
				return driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: lifecycleRuntimeTarget("fake_runtime", "dev", "stopped")})
			},
		},
	}
	failures := []struct {
		name           string
		classification string
		err            func(string) error
		assertWrapped  func(*testing.T, error)
	}{
		{
			name:           "driver failure",
			classification: FailureWorkerLifecycle,
			err: func(operation string) error {
				return &ProtocolError{
					Operation: operation,
					Code:      ErrorCodeDriverFailed,
					Message:   unsafeDetail,
				}
			},
			assertWrapped: func(t *testing.T, err error) {
				t.Helper()
				var protocolErr *ProtocolError
				if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeDriverFailed {
					t.Fatalf("error = %T %v, want wrapped driver protocol error", err, err)
				}
			},
		},
		{
			name:           "runtime unavailable",
			classification: FailureRuntimeUnavailable,
			err: func(operation string) error {
				return &ProtocolError{
					Operation: operation,
					Code:      ErrorCodeDriverNotFound,
					Message:   unsafeDetail,
				}
			},
			assertWrapped: func(t *testing.T, err error) {
				t.Helper()
				var protocolErr *ProtocolError
				if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeDriverNotFound {
					t.Fatalf("error = %T %v, want wrapped driver_not_found protocol error", err, err)
				}
			},
		},
		{
			name:           "client failure",
			classification: FailureWorkerClient,
			err: func(operation string) error {
				return &ClientError{
					Operation: operation,
					Code:      ErrorCodeInternal,
					Message:   unsafeDetail,
				}
			},
			assertWrapped: func(t *testing.T, err error) {
				t.Helper()
				var clientErr *ClientError
				if !errors.As(err, &clientErr) {
					t.Fatalf("error = %T %v, want wrapped worker client error", err, err)
				}
			},
		},
	}

	for _, operation := range operations {
		for _, failure := range failures {
			t.Run(operation.operation+"/"+failure.name, func(t *testing.T) {
				client := &recordingRuntimeDriverClient{
					errByOperation: map[string]error{
						operation.operation: failure.err(operation.operation),
					},
				}
				driver, err := NewClientDriver(ClientDriverOptions{
					DriverID: "fake_runtime",
					Client:   client,
				})
				if err != nil {
					t.Fatalf("NewClientDriver() error: %v", err)
				}

				err = operation.call(driver)
				if err == nil {
					t.Fatal("lifecycle operation error = nil, want classified failure")
				}
				var driverErr *ClientDriverError
				if !errors.As(err, &driverErr) {
					t.Fatalf("error = %T, want *ClientDriverError", err)
				}
				if got := driverErr.Classification(); got != failure.classification {
					t.Fatalf("classification = %q, want %q", got, failure.classification)
				}
				failure.assertWrapped(t, err)

				message := err.Error()
				if !strings.Contains(message, failure.classification) {
					t.Fatalf("error = %q, want classification %q", message, failure.classification)
				}
				for _, unsafe := range []string{"raw-secret", "deploy:secret", "example.test", "/tmp/private/worker.sock", "/Users/alice", "worktree", "/workspace/.hal/tmp/session"} {
					if strings.Contains(message, unsafe) {
						t.Fatalf("classified error leaked unsafe detail %q in %q", unsafe, message)
					}
				}
				for _, want := range []string{"token=[redacted]", "[redacted"} {
					if !strings.Contains(message, want) {
						t.Fatalf("classified error = %q, want sanitized marker %q", message, want)
					}
				}
			})
		}
	}
}

func assertClientDriverError(t *testing.T, err error, operation, driverID string) {
	t.Helper()

	var driverErr *ClientDriverError
	if !errors.As(err, &driverErr) {
		t.Fatalf("error = %T, want *ClientDriverError", err)
	}
	if driverErr.Operation != operation || driverErr.Driver != driverID {
		t.Fatalf("ClientDriverError = %#v, want operation %q driver %q", driverErr, operation, driverID)
	}
}

type recordingRuntimeDriverClient struct {
	calls          []string
	driverIDs      map[string]string
	createReq      CreateRequest
	lifecycleReqs  map[string]LifecycleRequest
	inspectReq     InspectRequest
	execReq        ExecRequest
	execResp       *ExecResponse
	nilExecResp    bool
	copyInReq      CopyInRequest
	copyInResp     *CopyInResponse
	copyOutReq     CopyOutRequest
	copyOutResp    *CopyOutResponse
	errByOperation map[string]error
}

func (client *recordingRuntimeDriverClient) Create(ctx context.Context, driverID string, req CreateRequest) (*Target, error) {
	client.record(OperationCreate, driverID)
	client.createReq = req
	if err := client.operationError(ctx, OperationCreate); err != nil {
		return nil, err
	}
	target := lifecycleWorkerTarget(driverID, req.Name, "created")
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Start(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	client.record(OperationStart, driverID)
	client.setLifecycleReq(OperationStart, req)
	if err := client.operationError(ctx, OperationStart); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Stop(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	client.record(OperationStop, driverID)
	client.setLifecycleReq(OperationStop, req)
	if err := client.operationError(ctx, OperationStop); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Delete(ctx context.Context, driverID string, req LifecycleRequest) error {
	client.record(OperationDelete, driverID)
	client.setLifecycleReq(OperationDelete, req)
	return client.operationError(ctx, OperationDelete)
}

func (client *recordingRuntimeDriverClient) Inspect(ctx context.Context, driverID string, req InspectRequest) (*Target, error) {
	client.record(OperationInspect, driverID)
	client.inspectReq = req
	if err := client.operationError(ctx, OperationInspect); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "inspected"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Exec(ctx context.Context, driverID string, req ExecRequest) (*ExecResponse, error) {
	client.record(OperationExec, driverID)
	client.execReq = req
	if err := client.operationError(ctx, OperationExec); err != nil {
		return nil, err
	}
	if client.execResp != nil {
		resp := *client.execResp
		return &resp, nil
	}
	if client.nilExecResp {
		return nil, nil
	}
	return &ExecResponse{
		ExitCode: 0,
		Stdout:   workerExecOutputPayload("", req.StdoutLimitBytes, false),
		Stderr:   workerExecOutputPayload("", req.StderrLimitBytes, false),
	}, nil
}

func (client *recordingRuntimeDriverClient) CopyIn(ctx context.Context, driverID string, req CopyInRequest) (*CopyInResponse, error) {
	client.record(OperationCopyIn, driverID)
	client.copyInReq = req
	if err := client.operationError(ctx, OperationCopyIn); err != nil {
		return nil, err
	}
	if client.copyInResp != nil {
		resp := *client.copyInResp
		return &resp, nil
	}
	return &CopyInResponse{Status: CopyStatusCompleted}, nil
}

func (client *recordingRuntimeDriverClient) CopyOut(ctx context.Context, driverID string, req CopyOutRequest) (*CopyOutResponse, error) {
	client.record(OperationCopyOut, driverID)
	client.copyOutReq = req
	if err := client.operationError(ctx, OperationCopyOut); err != nil {
		return nil, err
	}
	if client.copyOutResp != nil {
		resp := *client.copyOutResp
		return &resp, nil
	}
	return &CopyOutResponse{
		Payload: ptrWorkerCopyPayload("", req.MaxPayloadBytes),
	}, nil
}

func (client *recordingRuntimeDriverClient) record(operation, driverID string) {
	client.calls = append(client.calls, operation)
	if client.driverIDs == nil {
		client.driverIDs = map[string]string{}
	}
	client.driverIDs[operation] = driverID
}

func (client *recordingRuntimeDriverClient) setLifecycleReq(operation string, req LifecycleRequest) {
	if client.lifecycleReqs == nil {
		client.lifecycleReqs = map[string]LifecycleRequest{}
	}
	client.lifecycleReqs[operation] = req
}

func (client *recordingRuntimeDriverClient) operationError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if client.errByOperation == nil {
		return nil
	}
	return client.errByOperation[operation]
}

func workerExecOutputPayload(data string, limit int64, truncated bool) ExecOutputPayload {
	return ExecOutputPayload{
		Data:       data,
		SizeBytes:  int64(len([]byte(data))),
		LimitBytes: limit,
		Truncated:  truncated,
	}
}

func lifecycleRuntimeTarget(driverID, name, status string) sandboxruntime.Target {
	return sandboxruntime.Target{
		Name:   name,
		Status: status,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         driverID,
			IsolationLevel: IsolationLevelHost,
		},
	}
}
