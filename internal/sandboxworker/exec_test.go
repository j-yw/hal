package sandboxworker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWorkerExecProtocolJSONContractPreservesRequestAndResponsePayloads(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-exec-001",
		Operation:       OperationExec,
		DriverID:        RuntimeDriverRootlessPodman,
		Exec: &ExecRequest{
			OperationID: "exec-001",
			Target:      lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			Args:        []string{"sh", "-lc", "printf ok"},
			Env:         map[string]string{"HAL_SANDBOX": "1"},
			WorkDir:     "/workspace/hal",
			Stdin: &ExecStdinPayload{
				Data:       "input\n",
				SizeBytes:  6,
				LimitBytes: MaxExecStdinBytes,
			},
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
	assertJSONFields(t, stdinPayload, []string{"data", "sizeBytes", "limitBytes"})

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
				req.Stdin = &ExecStdinPayload{
					Data:       "input",
					SizeBytes:  5,
					LimitBytes: MaxExecStdinBytes + 1,
				}
			}),
			want: "exceeds maximum",
		},
		{
			name: "stdin data exceeds requested limit",
			req: mutateExecRequest(validWorkerExecRequest(), func(req *ExecRequest) {
				req.Stdin = &ExecStdinPayload{
					Data:       "input",
					SizeBytes:  5,
					LimitBytes: 4,
				}
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

func assertJSONFields(t *testing.T, payload map[string]any, fields []string) {
	t.Helper()
	for _, field := range fields {
		if _, ok := payload[field]; !ok {
			t.Fatalf("payload %#v missing JSON field %q", payload, field)
		}
	}
}
