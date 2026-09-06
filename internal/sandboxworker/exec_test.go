package sandboxworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerExecProtocolJSONContractPreservesRequestAndResponsePayloads(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-exec-001",
		Operation:       OperationExec,
		DriverID:        RuntimeDriverRootlessPodman,
		Exec: &ExecRequest{
			OperationID:      "exec-001",
			Target:           lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			Args:             []string{"sh", "-lc", "printf ok"},
			Env:              map[string]string{"HAL_SANDBOX": "1"},
			WorkDir:          "/workspace/hal",
			Stdin:            workerExecStdinPayload("input\n", MaxExecStdinBytes),
			StdoutLimitBytes: 128,
			StderrLimitBytes: 64,
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal(exec request) error: %v", err)
	}
	var rawReq map[string]any
	if err := json.Unmarshal(data, &rawReq); err != nil {
		t.Fatalf("Unmarshal(exec request map) error: %v", err)
	}
	if rawReq["operation"] != OperationExec {
		t.Fatalf("operation = %q, want %q", rawReq["operation"], OperationExec)
	}
	execPayload, ok := rawReq["exec"].(map[string]any)
	if !ok {
		t.Fatalf("exec payload = %#v, want object", rawReq["exec"])
	}
	assertJSONFields(t, execPayload, []string{
		"operationId",
		"target",
		"args",
		"env",
		"workDir",
		"stdin",
		"stdoutLimitBytes",
		"stderrLimitBytes",
	})
	stdinPayload, ok := execPayload["stdin"].(map[string]any)
	if !ok {
		t.Fatalf("stdin payload = %#v, want object", execPayload["stdin"])
	}
	assertJSONFields(t, stdinPayload, []string{"data", "encoding", "sizeBytes", "limitBytes"})

	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("Unmarshal(exec request) error: %v", err)
	}
	if !reflect.DeepEqual(decodedReq, req) {
		t.Fatalf("decoded request = %#v, want %#v", decodedReq, req)
	}

	resp := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-exec-001",
		Operation:       OperationExec,
		OK:              true,
		Exec: &ExecResponse{
			ExitCode: 7,
			Stdout: ExecOutputPayload{
				Data:       "out",
				SizeBytes:  3,
				LimitBytes: 128,
				Truncated:  false,
			},
			Stderr: ExecOutputPayload{
				Data:       "err",
				SizeBytes:  3,
				LimitBytes: 64,
				Truncated:  true,
			},
			Error: &Error{
				Code:    "command_failed",
				Message: "exit status 7",
			},
		},
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() unexpected error: %v", err)
	}

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal(exec response) error: %v", err)
	}
	var rawResp map[string]any
	if err := json.Unmarshal(data, &rawResp); err != nil {
		t.Fatalf("Unmarshal(exec response map) error: %v", err)
	}
	if rawResp["operation"] != OperationExec {
		t.Fatalf("response operation = %q, want %q", rawResp["operation"], OperationExec)
	}
	execResp, ok := rawResp["exec"].(map[string]any)
	if !ok {
		t.Fatalf("response exec payload = %#v, want object", rawResp["exec"])
	}
	assertJSONFields(t, execResp, []string{"exitCode", "stdout", "stderr", "error"})
	stdoutPayload, ok := execResp["stdout"].(map[string]any)
	if !ok {
		t.Fatalf("stdout payload = %#v, want object", execResp["stdout"])
	}
	assertJSONFields(t, stdoutPayload, []string{"data", "sizeBytes", "limitBytes", "truncated"})
	stderrPayload, ok := execResp["stderr"].(map[string]any)
	if !ok {
		t.Fatalf("stderr payload = %#v, want object", execResp["stderr"])
	}
	assertJSONFields(t, stderrPayload, []string{"data", "sizeBytes", "limitBytes", "truncated"})

	var decodedResp Response
	if err := json.Unmarshal(data, &decodedResp); err != nil {
		t.Fatalf("Unmarshal(exec response) error: %v", err)
	}
	if !reflect.DeepEqual(decodedResp, resp) {
		t.Fatalf("decoded response = %#v, want %#v", decodedResp, resp)
	}
}

func TestWorkerExecRequestValidationRejectsUnsafePayloads(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{
			name: "missing exec payload",
			req: Request{
				Operation: OperationExec,
				DriverID:  RuntimeDriverRootlessPodman,
			},
			want: "exec payload",
		},
		{
			name: "empty operation id",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.OperationID = " "
			}),
			want: "operation id",
		},
		{
			name: "empty args",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.Args = nil
			}),
			want: "args",
		},
		{
			name: "stdin limit exceeds maximum",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.Stdin = workerExecStdinPayload("input", MaxExecStdinBytes+1)
			}),
			want: "exceeds maximum",
		},
		{
			name: "stdin data exceeds requested limit",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.Stdin = workerExecStdinPayload("input", 4)
			}),
			want: "requested limit",
		},
		{
			name: "stdout capture limit exceeds maximum",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.StdoutLimitBytes = MaxExecStdoutCaptureBytes + 1
			}),
			want: "exec stdout capture limit exceeds maximum",
		},
		{
			name: "stderr capture limit exceeds maximum",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.StderrLimitBytes = MaxExecStderrCaptureBytes + 1
			}),
			want: "exec stderr capture limit exceeds maximum",
		},
		{
			name: "missing stdout capture limit",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.StdoutLimitBytes = 0
			}),
			want: "exec stdout capture limit is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestWorkerExecResponseValidationRejectsUnboundedOutput(t *testing.T) {
	tests := []struct {
		name string
		resp Response
		want string
	}{
		{
			name: "missing successful exec payload",
			resp: Response{
				Operation: OperationExec,
				OK:        true,
			},
			want: "exec payload",
		},
		{
			name: "stdout limit exceeds maximum",
			resp: mutateExecResponse(validWorkerExecResponse(), func(resp *ExecResponse) {
				resp.Stdout.LimitBytes = MaxExecStdoutCaptureBytes + 1
			}),
			want: "exec stdout limit exceeds maximum",
		},
		{
			name: "stderr size exceeds limit",
			resp: mutateExecResponse(validWorkerExecResponse(), func(resp *ExecResponse) {
				resp.Stderr.Data = "stderr"
				resp.Stderr.SizeBytes = 6
				resp.Stderr.LimitBytes = 5
			}),
			want: "exec stderr sizeBytes exceeds requested limit",
		},
		{
			name: "stdout size does not match payload",
			resp: mutateExecResponse(validWorkerExecResponse(), func(resp *ExecResponse) {
				resp.Stdout.Data = "stdout"
				resp.Stdout.SizeBytes = 5
			}),
			want: "does not match data size",
		},
		{
			name: "exec payload on wrong operation",
			resp: mutateExecResponse(validWorkerExecResponse(), func(resp *ExecResponse) {}),
			want: "only valid for exec",
		},
	}
	tests[len(tests)-1].resp.Operation = OperationStatus

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.resp.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestServiceExecRoutesRequestsThroughRegisteredDriver(t *testing.T) {
	driver := &recordingExecDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		result:                   &sandboxruntime.ExecResult{ExitCode: 7},
		stdout:                   "hello\n",
		stderr:                   "warn\n",
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	req := validWorkerExecRequest()
	req.DriverID = "fake_runtime"
	req.Exec.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	req.Exec.Args = []string{"sh", "-lc", "cat"}
	req.Exec.Env = map[string]string{"HAL_SANDBOX": "1"}
	req.Exec.WorkDir = " /workspace/hal "
	req.Exec.Stdin = workerExecStdinPayload("input\n", MaxExecStdinBytes)

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("exec response Validate() error: %v", err)
	}
	if !resp.OK || resp.Operation != OperationExec || resp.Exec == nil {
		t.Fatalf("exec response = %#v, want successful exec payload", resp)
	}
	if resp.Exec.ExitCode != 7 {
		t.Fatalf("exec exitCode = %d, want 7", resp.Exec.ExitCode)
	}
	if resp.Exec.Stdout.Data != "hello\n" || resp.Exec.Stdout.SizeBytes != 6 || resp.Exec.Stdout.Truncated {
		t.Fatalf("exec stdout = %#v, want captured non-truncated stdout", resp.Exec.Stdout)
	}
	if resp.Exec.Stderr.Data != "warn\n" || resp.Exec.Stderr.SizeBytes != 5 || resp.Exec.Stderr.Truncated {
		t.Fatalf("exec stderr = %#v, want captured non-truncated stderr", resp.Exec.Stderr)
	}
	if !reflect.DeepEqual(driver.calls, []string{OperationExec}) {
		t.Fatalf("driver calls = %#v, want exec call", driver.calls)
	}
	if !reflect.DeepEqual(driver.execReq.Args, []string{"sh", "-lc", "cat"}) {
		t.Fatalf("driver exec args = %#v, want protocol args", driver.execReq.Args)
	}
	if driver.execReq.Target.Name != "dev" || driver.execReq.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("driver exec target = %#v, want converted worker target", driver.execReq.Target)
	}
	if driver.execReq.Env["HAL_SANDBOX"] != "1" {
		t.Fatalf("driver exec env = %#v, want cloned env", driver.execReq.Env)
	}
	if driver.execReq.WorkDir != "/workspace/hal" {
		t.Fatalf("driver exec workdir = %q, want trimmed workdir", driver.execReq.WorkDir)
	}
	if driver.stdinData != "input\n" {
		t.Fatalf("driver stdin = %q, want request stdin", driver.stdinData)
	}
}

func workerExecStdinPayload(data string, limit int64) *ExecStdinPayload {
	return &ExecStdinPayload{
		Data:       base64.StdEncoding.EncodeToString([]byte(data)),
		Encoding:   CopyPayloadEncodingBase64,
		SizeBytes:  int64(len([]byte(data))),
		LimitBytes: limit,
	}
}

func TestServiceExecEnforcesCaptureLimitsBeforeReturningResponse(t *testing.T) {
	driver := &recordingExecDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		result:                   &sandboxruntime.ExecResult{ExitCode: 0},
		stdout:                   "abcdef",
		stderr:                   "12345",
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	req := validWorkerExecRequest()
	req.DriverID = "fake_runtime"
	req.Exec.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	req.Exec.StdoutLimitBytes = 3
	req.Exec.StderrLimitBytes = 2

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("exec response Validate() error: %v", err)
	}
	if !resp.OK || resp.Exec == nil {
		t.Fatalf("exec response = %#v, want successful bounded payload", resp)
	}
	if resp.Exec.Stdout.Data != "abc" || resp.Exec.Stdout.SizeBytes != 3 || resp.Exec.Stdout.LimitBytes != 3 || !resp.Exec.Stdout.Truncated {
		t.Fatalf("exec stdout = %#v, want truncated to 3 bytes", resp.Exec.Stdout)
	}
	if resp.Exec.Stderr.Data != "12" || resp.Exec.Stderr.SizeBytes != 2 || resp.Exec.Stderr.LimitBytes != 2 || !resp.Exec.Stderr.Truncated {
		t.Fatalf("exec stderr = %#v, want truncated to 2 bytes", resp.Exec.Stderr)
	}
}

func TestServiceExecDriverErrorsAreStructuredAndSanitized(t *testing.T) {
	driver := &recordingExecDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		result:                   &sandboxruntime.ExecResult{ExitCode: 126},
		stdout:                   "partial out",
		stderr:                   "partial err",
		err:                      errors.New("exec failed token=raw-secret under /Users/alice/worktree"),
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	req := validWorkerExecRequest()
	req.DriverID = "fake_runtime"
	req.Exec.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("exec response Validate() error: %v", err)
	}
	if !resp.OK || resp.Error != nil || resp.Exec == nil || resp.Exec.Error == nil {
		t.Fatalf("exec response = %#v, want command error inside exec payload", resp)
	}
	if resp.Exec.ExitCode != 126 {
		t.Fatalf("exec exitCode = %d, want 126", resp.Exec.ExitCode)
	}
	if resp.Exec.Error.Code != ErrorCodeDriverFailed {
		t.Fatalf("exec error code = %q, want %q", resp.Exec.Error.Code, ErrorCodeDriverFailed)
	}
	message := resp.Exec.Error.Message
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("exec error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("exec error message = %q, want sanitized marker %q", message, want)
		}
	}
}

func TestServiceExecUnsupportedUnknownDriverAndContextErrorsAreStructured(t *testing.T) {
	driver := &recordingExecDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		unsupported:              true,
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	req := validWorkerExecRequest()
	req.DriverID = "missing_runtime"
	req.Exec.Target = lifecycleWorkerTarget("missing_runtime", "dev", "running")
	unknownResp := service.HandleRequest(context.Background(), req)
	if err := unknownResp.Validate(); err != nil {
		t.Fatalf("unknown driver response Validate() error: %v", err)
	}
	if unknownResp.OK || unknownResp.Error == nil || unknownResp.Error.Code != ErrorCodeDriverNotFound {
		t.Fatalf("unknown driver response = %#v, want driver_not_found", unknownResp)
	}

	req.DriverID = "fake_runtime"
	req.Exec.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	unsupportedResp := service.HandleRequest(context.Background(), req)
	if err := unsupportedResp.Validate(); err != nil {
		t.Fatalf("unsupported response Validate() error: %v", err)
	}
	if unsupportedResp.OK || unsupportedResp.Error == nil || unsupportedResp.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("unsupported response = %#v, want unsupported_operation", unsupportedResp)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledResp := service.HandleRequest(canceledCtx, req)
	if canceledResp.OK || canceledResp.Error == nil || canceledResp.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled response = %#v, want request_canceled", canceledResp)
	}
	if !reflect.DeepEqual(driver.calls, []string{OperationExec}) {
		t.Fatalf("driver calls = %#v, want no call after canceled context", driver.calls)
	}
}

func validWorkerExecRequest() Request {
	return Request{
		Operation: OperationExec,
		DriverID:  RuntimeDriverRootlessPodman,
		Exec: &ExecRequest{
			OperationID:      "exec-001",
			Target:           lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			Args:             []string{"sh", "-lc", "printf ok"},
			StdoutLimitBytes: 128,
			StderrLimitBytes: 64,
		},
	}
}

func mutateExecRequest(req Request, mutate func(*ExecRequest)) Request {
	if req.Exec != nil && mutate != nil {
		mutate(req.Exec)
	}
	return req
}

func validWorkerExecResponse() Response {
	return Response{
		Operation: OperationExec,
		OK:        true,
		Exec: &ExecResponse{
			ExitCode: 0,
			Stdout: ExecOutputPayload{
				Data:       "out",
				SizeBytes:  3,
				LimitBytes: 128,
				Truncated:  false,
			},
			Stderr: ExecOutputPayload{
				Data:       "err",
				SizeBytes:  3,
				LimitBytes: 64,
				Truncated:  false,
			},
		},
	}
}

func mutateExecResponse(resp Response, mutate func(*ExecResponse)) Response {
	if resp.Exec != nil && mutate != nil {
		mutate(resp.Exec)
	}
	return resp
}

type recordingExecDriver struct {
	recordingLifecycleDriver
	result      *sandboxruntime.ExecResult
	stdout      string
	stderr      string
	err         error
	unsupported bool
	execReq     sandboxruntime.ExecRequest
	stdinData   string
}

func (driver *recordingExecDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	driver.calls = append(driver.calls, OperationExec)
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
	if driver.unsupported {
		return nil, ErrWorkerOperationUnsupported
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
	result := driver.result
	if result == nil && driver.err == nil {
		result = &sandboxruntime.ExecResult{}
	}
	return result, driver.err
}

func assertJSONFields(t *testing.T, payload map[string]any, fields []string) {
	t.Helper()
	for _, field := range fields {
		if _, ok := payload[field]; !ok {
			t.Fatalf("payload %#v missing JSON field %q", payload, field)
		}
	}
}
