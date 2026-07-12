package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestClientStatusAndCapabilitiesOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: RuntimeDriverSSHMachine},
		&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman},
	)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
		Health: WorkerHealth{
			Status:  HealthStatusDegraded,
			Message: "warming",
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 2,
			ActiveSandboxes:        1,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if status.WorkerID != "worker-001" || status.SocketPath != socketPath {
		t.Fatalf("Status() = %#v, want configured worker and socket path", status)
	}
	if status.Health.Status != HealthStatusDegraded || status.Capacity.ActiveSandboxes != 1 {
		t.Fatalf("Status() = %#v, want configured health and capacity", status)
	}
	wantDrivers := []string{RuntimeDriverRootlessPodman, RuntimeDriverSSHMachine}
	if len(status.SupportedRuntimeDrivers) != len(wantDrivers) ||
		status.SupportedRuntimeDrivers[0] != wantDrivers[0] ||
		status.SupportedRuntimeDrivers[1] != wantDrivers[1] {
		t.Fatalf("Status() drivers = %#v, want %#v", status.SupportedRuntimeDrivers, wantDrivers)
	}

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error: %v", err)
	}
	if capabilities.WorkerID != "worker-001" {
		t.Fatalf("Capabilities() workerId = %q, want worker-001", capabilities.WorkerID)
	}
	if len(capabilities.RuntimeDrivers) != 2 {
		t.Fatalf("Capabilities() runtime drivers = %#v, want two registered drivers", capabilities.RuntimeDrivers)
	}
}

func TestClientIOMethodsRoundTripOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	driver := &recordingSocketIODriver{
		id:          "fake_runtime",
		execResult:  &sandboxruntime.ExecResult{ExitCode: 42},
		stdout:      "hello\n",
		stderr:      "warn\n",
		copyOutData: "report\n",
	}
	service := newTestWorkerIOService(t, socketPath, driver)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	execReq := *validWorkerExecRequest().Exec
	execReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	execReq.Args = []string{"sh", "-lc", "cat"}
	execReq.Env = map[string]string{"HAL_SANDBOX": "1"}
	execReq.WorkDir = " /workspace/hal "
	stdinData := string([]byte{'i', 'n', 0xff, 0x00, '\n'})
	execReq.Stdin = workerExecStdinPayload(stdinData, MaxExecStdinBytes)
	execResp, err := client.Exec(context.Background(), "fake_runtime", execReq)
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if execResp.ExitCode != 42 || execResp.Stdout.Data != "hello\n" || execResp.Stderr.Data != "warn\n" {
		t.Fatalf("Exec() response = %#v, want fake driver output over socket", execResp)
	}
	if driver.stdinData != stdinData {
		t.Fatalf("driver stdin bytes = %v, want %v", []byte(driver.stdinData), []byte(stdinData))
	}
	if driver.execReq.WorkDir != "/workspace/hal" || driver.execReq.Env["HAL_SANDBOX"] != "1" {
		t.Fatalf("driver exec request = %#v, want trimmed workdir and cloned env", driver.execReq)
	}

	copyInReq := *validWorkerCopyInRequest().CopyIn
	copyInReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyInReq.RemoteDestinationPath = " /workspace/hal/input.txt "
	copyInReq.Payload = workerCopyPayload("copy payload\n", MaxCopyInPayloadBytes)
	copyInResp, err := client.CopyIn(context.Background(), "fake_runtime", copyInReq)
	if err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}
	if copyInResp.Status != CopyStatusCompleted || copyInResp.Error != nil {
		t.Fatalf("CopyIn() response = %#v, want completed copy_in over socket", copyInResp)
	}
	if driver.copyInData != "copy payload\n" || driver.copyInReq.DestinationPath != "/workspace/hal/input.txt" {
		t.Fatalf("driver copy_in request = %#v data %q, want decoded payload and trimmed destination", driver.copyInReq, driver.copyInData)
	}

	copyOutReq := *validWorkerCopyOutRequest().CopyOut
	copyOutReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyOutReq.RemoteSourcePath = " /workspace/hal/report.txt "
	copyOutReq.MaxPayloadBytes = 64
	copyOutResp, err := client.CopyOut(context.Background(), "fake_runtime", copyOutReq)
	if err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}
	if copyOutResp.Payload == nil {
		t.Fatal("CopyOut() payload = nil, want copied payload over socket")
	}
	if got := decodeWorkerCopyPayloadForTest(t, *copyOutResp.Payload); got != "report\n" {
		t.Fatalf("CopyOut() payload = %q, want report data", got)
	}
	if copyOutResp.Truncated || copyOutResp.LimitExceeded || copyOutResp.Error != nil {
		t.Fatalf("CopyOut() metadata = %#v, want untruncated payload", copyOutResp)
	}
	if driver.copyOutReq.SourcePath != "/workspace/hal/report.txt" {
		t.Fatalf("driver copy_out source = %q, want trimmed remote source", driver.copyOutReq.SourcePath)
	}
}

func TestClientDriverRootlessLifecycleRoundTripOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	fakeDriver := &recordingRootlessE2EDriver{
		copyOutData: "artifact\n",
		execStdout:  "rootless stdout\n",
		execStderr:  "rootless stderr\n",
	}
	registry, err := NewDriverRegistry(fakeDriver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	clientDriver, err := NewClientDriver(ClientDriverOptions{
		DriverID: sandboxruntime.DriverRootlessPodman,
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	created, err := clientDriver.Create(ctx, sandboxruntime.CreateRequest{
		Name: "worker-rootless",
		Env:  map[string]string{"HAL_SANDBOX": "1"},
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	assertRootlessE2ETarget(t, OperationCreate, created, "created")

	started, err := clientDriver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	assertRootlessE2ETarget(t, OperationStart, started, "running")

	inspected, err := clientDriver.Inspect(ctx, sandboxruntime.InspectRequest{Target: *started})
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}
	assertRootlessE2ETarget(t, OperationInspect, inspected, "running")

	var stdout, stderr bytes.Buffer
	execResult, err := clientDriver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *inspected,
		Args:   []string{"sh", "-lc", "printf rootless"},
		Stdout: &stdout,
		Stderr: &stderr,
		Stdin:  strings.NewReader("stdin\n"),
	})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if execResult == nil || execResult.ExitCode != 19 {
		t.Fatalf("Exec() result = %#v, want exit code 19", execResult)
	}
	if stdout.String() != "rootless stdout\n" || stderr.String() != "rootless stderr\n" {
		t.Fatalf("Exec() output = stdout %q stderr %q, want fake rootless output", stdout.String(), stderr.String())
	}

	tempDir := t.TempDir()
	copyInSource := filepath.Join(tempDir, "input.txt")
	if err := os.WriteFile(copyInSource, []byte("copy input\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(copyInSource) error: %v", err)
	}
	if err := clientDriver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          *inspected,
		SourcePath:      copyInSource,
		DestinationPath: "/workspace/input.txt",
	}); err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}
	if fakeDriver.copyInData != "copy input\n" {
		t.Fatalf("CopyIn() driver data = %q, want copied payload", fakeDriver.copyInData)
	}

	copyOutDestination := filepath.Join(tempDir, "artifact.txt")
	if err := clientDriver.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          *inspected,
		SourcePath:      "/workspace/artifact.txt",
		DestinationPath: copyOutDestination,
	}); err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}
	copyOutData, err := os.ReadFile(copyOutDestination)
	if err != nil {
		t.Fatalf("ReadFile(copyOutDestination) error: %v", err)
	}
	if string(copyOutData) != "artifact\n" {
		t.Fatalf("CopyOut() destination = %q, want fake artifact", string(copyOutData))
	}

	stopped, err := clientDriver.Stop(ctx, sandboxruntime.LifecycleRequest{Target: *inspected})
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	assertRootlessE2ETarget(t, OperationStop, stopped, "stopped")

	if err := clientDriver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *stopped}); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	wantCalls := strings.Join([]string{
		OperationCreate,
		OperationStart,
		OperationInspect,
		OperationExec,
		OperationCopyIn,
		OperationCopyOut,
		OperationStop,
		OperationDelete,
	}, ",")
	if gotCalls := strings.Join(fakeDriver.calls, ","); gotCalls != wantCalls {
		t.Fatalf("driver calls = %q, want %q", gotCalls, wantCalls)
	}
	for _, operation := range []string{
		OperationCreate,
		OperationStart,
		OperationInspect,
		OperationExec,
		OperationCopyIn,
		OperationCopyOut,
		OperationStop,
		OperationDelete,
	} {
		assertRootlessE2ERuntime(t, operation, fakeDriver.runtimeByOperation[operation])
	}
}

func TestClientIOMethodsEnforceLimitsOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	driver := &recordingSocketIODriver{
		id:          "fake_runtime",
		execResult:  &sandboxruntime.ExecResult{ExitCode: 0},
		stdout:      "abcdef",
		stderr:      "12345",
		copyOutData: "copy-output",
	}
	service := newTestWorkerIOService(t, socketPath, driver)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	execReq := *validWorkerExecRequest().Exec
	execReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	execReq.StdoutLimitBytes = 3
	execReq.StderrLimitBytes = 2
	execResp, err := client.Exec(context.Background(), "fake_runtime", execReq)
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if execResp.Stdout.Data != "abc" || execResp.Stdout.SizeBytes != 3 || execResp.Stdout.LimitBytes != 3 || !execResp.Stdout.Truncated {
		t.Fatalf("exec stdout = %#v, want socket response truncated to 3 bytes", execResp.Stdout)
	}
	if execResp.Stderr.Data != "12" || execResp.Stderr.SizeBytes != 2 || execResp.Stderr.LimitBytes != 2 || !execResp.Stderr.Truncated {
		t.Fatalf("exec stderr = %#v, want socket response truncated to 2 bytes", execResp.Stderr)
	}

	copyOutReq := *validWorkerCopyOutRequest().CopyOut
	copyOutReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyOutReq.MaxPayloadBytes = 4
	copyOutResp, err := client.CopyOut(context.Background(), "fake_runtime", copyOutReq)
	if err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}
	if copyOutResp.Payload == nil {
		t.Fatal("CopyOut() payload = nil, want bounded payload")
	}
	if got := decodeWorkerCopyPayloadForTest(t, *copyOutResp.Payload); got != "copy" {
		t.Fatalf("CopyOut() payload = %q, want truncated copy_out payload", got)
	}
	if copyOutResp.Payload.SizeBytes != 4 || copyOutResp.Payload.LimitBytes != 4 || !copyOutResp.Truncated || !copyOutResp.LimitExceeded {
		t.Fatalf("CopyOut() response = %#v, want limit-exceeded metadata", copyOutResp)
	}
	if copyOutResp.Error == nil || copyOutResp.Error.Code != ErrorCodeDriverFailed {
		t.Fatalf("CopyOut() error = %#v, want structured payload limit error", copyOutResp.Error)
	}
}

func TestServerHandlesSingleJSONRequestResponsePerUnixConnection(t *testing.T) {
	var handled atomic.Int32
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(_ context.Context, req Request) Response {
			handled.Add(1)
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        true,
				Exec: &ExecResponse{
					Stdout: ExecOutputPayload{LimitBytes: req.Exec.StdoutLimitBytes},
					Stderr: ExecOutputPayload{LimitBytes: req.Exec.StderrLimitBytes},
				},
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	conn := dialWorkerSocket(t, socketPath)
	defer conn.Close()
	encoder := json.NewEncoder(conn)
	firstReq := validWorkerExecRequest()
	firstReq.RequestID = "req-001"
	firstReq.DriverID = "fake_runtime"
	firstReq.Exec.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	if err := encoder.Encode(firstReq); err != nil {
		t.Fatalf("Encode(first request) error: %v", err)
	}

	decoder := json.NewDecoder(conn)
	var firstResp Response
	if err := decoder.Decode(&firstResp); err != nil {
		t.Fatalf("Decode(first response) error: %v", err)
	}
	if firstResp.RequestID != "req-001" || firstResp.Operation != OperationExec || !firstResp.OK {
		t.Fatalf("first response = %#v, want only first request response", firstResp)
	}

	secondReq := firstReq
	secondReq.RequestID = "req-002"
	if err := encoder.Encode(secondReq); err != nil {
		if !isClosedSingleResponseConnectionError(err) {
			t.Fatalf("Encode(second request) error = %v, want closed single-response connection", err)
		}
	} else {
		var secondResp Response
		err = decoder.Decode(&secondResp)
		if err == nil {
			t.Fatalf("Decode(second response) error = nil with response %#v, want closed single-response connection", secondResp)
		}
		if !isClosedSingleResponseConnectionError(err) {
			t.Fatalf("Decode(second response) error = %v, want EOF or closed connection", err)
		}
	}
	if got := handled.Load(); got != 1 {
		t.Fatalf("handled requests = %d, want exactly one request per connection", got)
	}
}

func isClosedSingleResponseConnectionError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	message := err.Error()
	// Unix sockets can report ECONNRESET or EPIPE depending on whether the peer
	// closes before a buffered follow-up write reaches the server.
	return strings.Contains(message, "closed") ||
		strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "broken pipe")
}

func TestClientUsesInjectedTransportAndPropagatesContext(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(ctx context.Context, req Request) (Response, error) {
			called.Store(true)
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("transport context did not include caller deadline")
			}
			if req.ProtocolVersion != ProtocolVersion {
				t.Fatalf("request protocolVersion = %q, want %q", req.ProtocolVersion, ProtocolVersion)
			}
			if req.Operation != OperationStatus || !strings.HasPrefix(req.RequestID, OperationStatus+"-") {
				t.Fatalf("request = %#v, want status request with generated request ID", req)
			}
			status := validClientTestStatus("")
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        true,
				Status:    &status,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !called.Load() {
		t.Fatal("injected transport was not called")
	}
	if status.WorkerID != "worker-001" {
		t.Fatalf("Status() workerId = %q, want worker-001", status.WorkerID)
	}
}

func TestClientIOMethodsUseInjectedTransport(t *testing.T) {
	var operations []string
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			operations = append(operations, req.Operation)
			if req.DriverID != "fake_runtime" {
				t.Fatalf("%s driverID = %q, want fake_runtime", req.Operation, req.DriverID)
			}
			if req.ProtocolVersion != ProtocolVersion || req.RequestID == "" {
				t.Fatalf("%s request metadata = %#v, want protocol and request ID", req.Operation, req)
			}
			switch req.Operation {
			case OperationExec:
				if req.Exec == nil || req.Exec.OperationID != "exec-001" {
					t.Fatalf("exec request = %#v, want exec payload", req.Exec)
				}
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
					Exec: &ExecResponse{
						ExitCode: 7,
						Stdout: ExecOutputPayload{
							Data:       "out",
							SizeBytes:  3,
							LimitBytes: req.Exec.StdoutLimitBytes,
						},
						Stderr: ExecOutputPayload{
							Data:       "err",
							SizeBytes:  3,
							LimitBytes: req.Exec.StderrLimitBytes,
						},
					},
				}, nil
			case OperationCopyIn:
				if req.CopyIn == nil || req.CopyIn.OperationID != "copy-in-001" {
					t.Fatalf("copy_in request = %#v, want copyIn payload", req.CopyIn)
				}
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
					CopyIn:    &CopyInResponse{Status: CopyStatusCompleted},
				}, nil
			case OperationCopyOut:
				if req.CopyOut == nil || req.CopyOut.OperationID != "copy-out-001" {
					t.Fatalf("copy_out request = %#v, want copyOut payload", req.CopyOut)
				}
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
					CopyOut: &CopyOutResponse{
						Payload: ptrWorkerCopyPayload("payload", req.CopyOut.MaxPayloadBytes),
					},
				}, nil
			default:
				t.Fatalf("unexpected operation %q", req.Operation)
				return Response{}, nil
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	execReq := *validWorkerExecRequest().Exec
	execReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	execResp, err := client.Exec(context.Background(), "fake_runtime", execReq)
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if execResp.ExitCode != 7 || execResp.Stdout.Data != "out" || execResp.Stderr.Data != "err" {
		t.Fatalf("Exec() response = %#v, want bounded exec output", execResp)
	}

	copyInReq := *validWorkerCopyInRequest().CopyIn
	copyInReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyInReq.OperationID = "copy-in-001"
	copyInResp, err := client.CopyIn(context.Background(), "fake_runtime", copyInReq)
	if err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}
	if copyInResp.Status != CopyStatusCompleted {
		t.Fatalf("CopyIn() status = %q, want completed", copyInResp.Status)
	}

	copyOutReq := *validWorkerCopyOutRequest().CopyOut
	copyOutReq.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyOutReq.OperationID = "copy-out-001"
	copyOutResp, err := client.CopyOut(context.Background(), "fake_runtime", copyOutReq)
	if err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}
	if got := decodeWorkerCopyPayloadForTest(t, *copyOutResp.Payload); got != "payload" {
		t.Fatalf("CopyOut() payload = %q, want payload", got)
	}

	wantOperations := []string{OperationExec, OperationCopyIn, OperationCopyOut}
	if len(operations) != len(wantOperations) {
		t.Fatalf("operations = %#v, want %#v", operations, wantOperations)
	}
	for i, want := range wantOperations {
		if operations[i] != want {
			t.Fatalf("operations = %#v, want %#v", operations, wantOperations)
		}
	}
}

func TestClientIOMethodsValidateRequestsBeforeDispatch(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(context.Context, Request) (Response, error) {
			called.Store(true)
			return Response{}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	execReq := *validWorkerExecRequest().Exec
	execReq.Stdin = workerExecStdinPayload("oversized", MaxExecStdinBytes+1)
	execReq.Stdin.SizeBytes = MaxExecStdinBytes + 1
	if _, err := client.Exec(context.Background(), "fake_runtime", execReq); err == nil || !strings.Contains(err.Error(), "exec stdin") {
		t.Fatalf("Exec(oversized stdin) error = %v, want validation error", err)
	}

	copyInReq := *validWorkerCopyInRequest().CopyIn
	copyInReq.Payload = workerCopyPayload("payload", MaxCopyInPayloadBytes+1)
	if _, err := client.CopyIn(context.Background(), "fake_runtime", copyInReq); err == nil || !strings.Contains(err.Error(), "copy_in payload") {
		t.Fatalf("CopyIn(oversized payload) error = %v, want validation error", err)
	}

	copyOutReq := *validWorkerCopyOutRequest().CopyOut
	copyOutReq.MaxPayloadBytes = MaxCopyOutPayloadBytes + 1
	if _, err := client.CopyOut(context.Background(), "fake_runtime", copyOutReq); err == nil || !strings.Contains(err.Error(), "copy_out max payload") {
		t.Fatalf("CopyOut(oversized max) error = %v, want validation error", err)
	}

	if called.Load() {
		t.Fatal("transport was called for invalid I/O requests")
	}
}

func TestClientIOMethodsRejectResponsesAboveCallerLimits(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{
			name: "exec stdout",
			call: func(client *Client) error {
				req := *validWorkerExecRequest().Exec
				req.StdoutLimitBytes = 3
				req.StderrLimitBytes = 3
				_, err := client.Exec(context.Background(), "fake_runtime", req)
				return err
			},
		},
		{
			name: "copy_out payload",
			call: func(client *Client) error {
				req := *validWorkerCopyOutRequest().CopyOut
				req.MaxPayloadBytes = 3
				_, err := client.CopyOut(context.Background(), "fake_runtime", req)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{
				Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
					switch req.Operation {
					case OperationExec:
						return Response{
							RequestID: req.RequestID,
							Operation: req.Operation,
							OK:        true,
							Exec: &ExecResponse{
								Stdout: ExecOutputPayload{Data: "over", SizeBytes: 4, LimitBytes: 4},
								Stderr: ExecOutputPayload{Data: "ok", SizeBytes: 2, LimitBytes: 3},
							},
						}, nil
					case OperationCopyOut:
						return Response{
							RequestID: req.RequestID,
							Operation: req.Operation,
							OK:        true,
							CopyOut: &CopyOutResponse{
								Payload: ptrWorkerCopyPayload("over", 4),
							},
						}, nil
					default:
						t.Fatalf("unexpected operation %q", req.Operation)
						return Response{}, nil
					}
				}),
			})
			if err != nil {
				t.Fatalf("NewClient() error: %v", err)
			}

			err = tt.call(client)
			if err == nil {
				t.Fatal("client I/O call error = nil, want caller limit validation error")
			}
			if !strings.Contains(err.Error(), "exceeds requested limit") {
				t.Fatalf("client I/O call error = %q, want requested limit detail", err.Error())
			}
		})
	}
}

func TestClientIOMethodsSanitizeEmbeddedServiceErrors(t *testing.T) {
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			switch req.Operation {
			case OperationExec:
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
					Exec: &ExecResponse{
						Stdout: ExecOutputPayload{LimitBytes: req.Exec.StdoutLimitBytes},
						Stderr: ExecOutputPayload{LimitBytes: req.Exec.StderrLimitBytes},
						Error: &Error{
							Code:    ErrorCodeDriverFailed,
							Message: "exec failed token=raw-secret under /Users/alice/worktree",
						},
					},
				}, nil
			case OperationCopyIn:
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
					CopyIn: &CopyInResponse{
						Status: CopyStatusFailed,
						Error: &Error{
							Code:    ErrorCodeDriverFailed,
							Message: "copy failed token=raw-secret under /Users/alice/worktree",
						},
					},
				}, nil
			default:
				t.Fatalf("unexpected operation %q", req.Operation)
				return Response{}, nil
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	execReq := *validWorkerExecRequest().Exec
	execResp, err := client.Exec(context.Background(), "fake_runtime", execReq)
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	assertClientEmbeddedErrorSanitized(t, execResp.Error.Message)

	copyInReq := *validWorkerCopyInRequest().CopyIn
	copyInResp, err := client.CopyIn(context.Background(), "fake_runtime", copyInReq)
	if err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}
	assertClientEmbeddedErrorSanitized(t, copyInResp.Error.Message)
}

func TestClientReturnsCancellationAndTimeoutErrors(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(ctx context.Context, req Request) (Response, error) {
			called.Store(true)
			<-ctx.Done()
			return Response{}, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Status(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Status(canceled) error = %v, want context.Canceled", err)
	}
	if called.Load() {
		t.Fatal("transport was called for already-canceled context")
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer timeoutCancel()
	if _, err := client.Capabilities(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capabilities(timeout) error = %v, want context deadline", err)
	}
	if !called.Load() {
		t.Fatal("transport was not called before timeout")
	}
}

func TestClientRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name      string
		transport ClientTransport
		want      string
	}{
		{
			name: "invalid response operation",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{
					RequestID: req.RequestID,
					Operation: "launch",
					OK:        true,
				}, nil
			}),
			want: ErrorCodeMalformedRequest,
		},
		{
			name: "missing status payload",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
				}, nil
			}),
			want: "status payload",
		},
		{
			name: "mismatched request id",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				status := validClientTestStatus("")
				return Response{
					RequestID: "other-" + req.RequestID,
					Operation: req.Operation,
					OK:        true,
					Status:    &status,
				}, nil
			}),
			want: "requestId",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{Transport: tt.transport})
			if err != nil {
				t.Fatalf("NewClient() error: %v", err)
			}
			_, err = client.Status(context.Background())
			if err == nil {
				t.Fatal("Status() error = nil, want malformed response error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Status() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestClientRejectsMalformedJSONResponseOverUnixSocket(t *testing.T) {
	socketPath := runRawWorkerResponseSocket(t, "{not json\n")
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want malformed JSON response error")
	}
	if !strings.Contains(err.Error(), "read worker response") {
		t.Fatalf("Status() error = %q, want read response detail", err.Error())
	}
}

func TestClientReturnsProtocolErrorsWithSanitizedDetail(t *testing.T) {
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        false,
				Error: &Error{
					Code:    ErrorCodeUnsupportedOp,
					Message: "provider failed token=raw-secret from /Users/alice/worktree",
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want protocol error")
	}
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("Status() error = %T, want *ProtocolError", err)
	}
	if protocolErr.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("ProtocolError.Code = %q, want %q", protocolErr.Code, ErrorCodeUnsupportedOp)
	}
	message := err.Error()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("protocol error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("protocol error = %q, want sanitized detail %q", message, want)
		}
	}
}

func TestClientConnectionFailureIsSanitized(t *testing.T) {
	const socketPath = "/tmp/hal-worker-token=raw-secret/missing.sock"
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want connection failure")
	}
	message := err.Error()
	for _, unsafe := range []string{socketPath, "raw-secret", "hal-worker-token"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("connection error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	if !strings.Contains(message, "[redacted-path]") {
		t.Fatalf("connection error = %q, want redacted path marker", message)
	}
}

func TestNewClientRejectsInvalidConfiguration(t *testing.T) {
	if client, err := NewClient(ClientOptions{}); err == nil {
		t.Fatalf("NewClient() error = nil, want socketPath or transport error (client %#v)", client)
	}
	if client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(nil)}); err == nil {
		t.Fatalf("NewClient() error = nil, want nil transport function error (client %#v)", client)
	}
}

func validClientTestStatus(socketPath string) Status {
	return Status{
		ProtocolVersion: ProtocolVersion,
		WorkerID:        "worker-001",
		HostKind:        HostKindLocal,
		SocketPath:      socketPath,
		Health: WorkerHealth{
			Status: HealthStatusHealthy,
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 1,
		},
		Security: DefaultWorkerSecurityPolicy(),
	}
}

func assertClientEmbeddedErrorSanitized(t *testing.T, message string) {
	t.Helper()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("embedded service error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("embedded service error = %q, want sanitized marker %q", message, want)
		}
	}
}

func newTestWorkerIOService(t *testing.T, socketPath string, driver *recordingSocketIODriver) *Service {
	t.Helper()

	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	return service
}

type recordingSocketIODriver struct {
	id          string
	execResult  *sandboxruntime.ExecResult
	stdout      string
	stderr      string
	copyOutData string
	execReq     sandboxruntime.ExecRequest
	stdinData   string
	copyInReq   sandboxruntime.CopyRequest
	copyOutReq  sandboxruntime.CopyRequest
	copyInData  string
}

type recordingRootlessE2EDriver struct {
	calls              []string
	runtimeByOperation map[string]sandboxruntime.RuntimeState
	copyInData         string
	copyOutData        string
	execStdout         string
	execStderr         string
}

func (driver *recordingRootlessE2EDriver) ID() string {
	return sandboxruntime.DriverRootlessPodman
}

func (driver *recordingRootlessE2EDriver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	driver.record(OperationCreate, recordingRootlessE2ERuntime())
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := recordingRootlessE2ETarget(req.Name, "created")
	return &target, nil
}

func (driver *recordingRootlessE2EDriver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	driver.record(OperationStart, req.Target.Runtime)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (driver *recordingRootlessE2EDriver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	driver.record(OperationStop, req.Target.Runtime)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (driver *recordingRootlessE2EDriver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	driver.record(OperationDelete, req.Target.Runtime)
	return ctx.Err()
}

func (driver *recordingRootlessE2EDriver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	driver.record(OperationInspect, req.Target.Runtime)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (driver *recordingRootlessE2EDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	driver.record(OperationExec, req.Target.Runtime)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Stdout != nil && driver.execStdout != "" {
		if _, err := io.WriteString(req.Stdout, driver.execStdout); err != nil {
			return nil, err
		}
	}
	if req.Stderr != nil && driver.execStderr != "" {
		if _, err := io.WriteString(req.Stderr, driver.execStderr); err != nil {
			return nil, err
		}
	}
	return &sandboxruntime.ExecResult{ExitCode: 19}, nil
}

func (driver *recordingRootlessE2EDriver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.record(OperationCopyIn, req.Target.Runtime)
	data, err := os.ReadFile(req.SourcePath)
	if err != nil {
		return err
	}
	driver.copyInData = string(data)
	return ctx.Err()
}

func (driver *recordingRootlessE2EDriver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.record(OperationCopyOut, req.Target.Runtime)
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte(driver.copyOutData), 0o600)
}

func (driver *recordingRootlessE2EDriver) record(operation string, runtime sandboxruntime.RuntimeState) {
	driver.calls = append(driver.calls, operation)
	if driver.runtimeByOperation == nil {
		driver.runtimeByOperation = map[string]sandboxruntime.RuntimeState{}
	}
	driver.runtimeByOperation[operation] = runtime
}

func recordingRootlessE2ETarget(name, status string) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:      "target-worker-rootless",
		Name:    name,
		Status:  status,
		Runtime: recordingRootlessE2ERuntime(),
	}
}

func recordingRootlessE2ERuntime() sandboxruntime.RuntimeState {
	return sandboxruntime.RuntimeState{
		Driver:         sandboxruntime.DriverRootlessPodman,
		RuntimeID:      "ctr-worker-rootless",
		Image:          "localhost/hal-rootless:test",
		WorkerID:       "worker-001",
		IsolationLevel: IsolationLevelContainer,
	}
}

func assertRootlessE2ETarget(t *testing.T, operation string, target *sandboxruntime.Target, status string) {
	t.Helper()

	if target == nil {
		t.Fatalf("%s target = nil, want rootless target", operation)
	}
	if target.ID != "target-worker-rootless" || target.Name != "worker-rootless" || target.Status != status {
		t.Fatalf("%s target = %#v, want rootless target status %q", operation, target, status)
	}
	assertRootlessE2ERuntime(t, operation, target.Runtime)
}

func assertRootlessE2ERuntime(t *testing.T, operation string, runtime sandboxruntime.RuntimeState) {
	t.Helper()

	want := recordingRootlessE2ERuntime()
	if runtime != want {
		t.Fatalf("%s runtime = %#v, want %#v", operation, runtime, want)
	}
}

func (driver *recordingSocketIODriver) ID() string {
	return driver.id
}

func (driver *recordingSocketIODriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, ErrWorkerOperationUnsupported
}

func (driver *recordingSocketIODriver) Start(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, ErrWorkerOperationUnsupported
}

func (driver *recordingSocketIODriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, ErrWorkerOperationUnsupported
}

func (driver *recordingSocketIODriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return ErrWorkerOperationUnsupported
}

func (driver *recordingSocketIODriver) Inspect(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return nil, ErrWorkerOperationUnsupported
}

func (driver *recordingSocketIODriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	driver.execReq = req
	if req.Stdin != nil {
		data, err := io.ReadAll(req.Stdin)
		if err != nil {
			return nil, err
		}
		driver.stdinData = string(data)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Stdout != nil && driver.stdout != "" {
		if _, err := req.Stdout.Write([]byte(driver.stdout)); err != nil {
			return nil, err
		}
	}
	if req.Stderr != nil && driver.stderr != "" {
		if _, err := req.Stderr.Write([]byte(driver.stderr)); err != nil {
			return nil, err
		}
	}
	if driver.execResult != nil {
		return driver.execResult, nil
	}
	return &sandboxruntime.ExecResult{}, nil
}

func (driver *recordingSocketIODriver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.copyInReq = req
	data, err := os.ReadFile(req.SourcePath)
	if err != nil {
		return err
	}
	driver.copyInData = string(data)
	return ctx.Err()
}

func (driver *recordingSocketIODriver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.copyOutReq = req
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte(driver.copyOutData), 0o600)
}

func runRawWorkerResponseSocket(t *testing.T, payload string) string {
	t.Helper()

	socketPath := testWorkerSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix, %s) error: %v", socketPath, err)
	}
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		var req Request
		_ = json.NewDecoder(conn).Decode(&req)
		_, err = io.WriteString(conn, payload)
		errCh <- err
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("raw response socket error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("raw response socket did not stop")
		}
	})
	return socketPath
}
