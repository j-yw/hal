package sandboxworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerCopyProtocolJSONContractPreservesCopyInPayloads(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-copy-in-001",
		Operation:       OperationCopyIn,
		DriverID:        RuntimeDriverRootlessPodman,
		CopyIn: &CopyInRequest{
			OperationID:           "copy-in-001",
			Target:                lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			Source:                CopyPathMetadata{DisplayPath: "workspace/config.json"},
			RemoteDestinationPath: "/workspace/hal/config.json",
			Payload:               workerCopyPayload("file-content\n", MaxCopyInPayloadBytes),
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal(copy_in request) error: %v", err)
	}
	var rawReq map[string]any
	if err := json.Unmarshal(data, &rawReq); err != nil {
		t.Fatalf("Unmarshal(copy_in request map) error: %v", err)
	}
	if rawReq["operation"] != OperationCopyIn {
		t.Fatalf("operation = %q, want %q", rawReq["operation"], OperationCopyIn)
	}
	copyInPayload, ok := rawReq["copyIn"].(map[string]any)
	if !ok {
		t.Fatalf("copyIn payload = %#v, want object", rawReq["copyIn"])
	}
	assertJSONFields(t, copyInPayload, []string{
		"operationId",
		"target",
		"source",
		"remoteDestinationPath",
		"payload",
	})
	sourcePayload, ok := copyInPayload["source"].(map[string]any)
	if !ok {
		t.Fatalf("source payload = %#v, want object", copyInPayload["source"])
	}
	assertJSONFields(t, sourcePayload, []string{"displayPath"})
	filePayload, ok := copyInPayload["payload"].(map[string]any)
	if !ok {
		t.Fatalf("file payload = %#v, want object", copyInPayload["payload"])
	}
	assertJSONFields(t, filePayload, []string{"data", "encoding", "sizeBytes", "limitBytes"})

	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("Unmarshal(copy_in request) error: %v", err)
	}
	if !reflect.DeepEqual(decodedReq, req) {
		t.Fatalf("decoded request = %#v, want %#v", decodedReq, req)
	}

	resp := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-copy-in-001",
		Operation:       OperationCopyIn,
		OK:              true,
		CopyIn: &CopyInResponse{
			Status: CopyStatusFailed,
			Error: &Error{
				Code:    ErrorCodeDriverFailed,
				Message: "copy failed",
			},
		},
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() unexpected error: %v", err)
	}

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal(copy_in response) error: %v", err)
	}
	var rawResp map[string]any
	if err := json.Unmarshal(data, &rawResp); err != nil {
		t.Fatalf("Unmarshal(copy_in response map) error: %v", err)
	}
	if rawResp["operation"] != OperationCopyIn {
		t.Fatalf("response operation = %q, want %q", rawResp["operation"], OperationCopyIn)
	}
	copyInResp, ok := rawResp["copyIn"].(map[string]any)
	if !ok {
		t.Fatalf("response copyIn payload = %#v, want object", rawResp["copyIn"])
	}
	assertJSONFields(t, copyInResp, []string{"status", "error"})

	var decodedResp Response
	if err := json.Unmarshal(data, &decodedResp); err != nil {
		t.Fatalf("Unmarshal(copy_in response) error: %v", err)
	}
	if !reflect.DeepEqual(decodedResp, resp) {
		t.Fatalf("decoded response = %#v, want %#v", decodedResp, resp)
	}
}

func TestWorkerCopyProtocolJSONContractPreservesCopyOutPayloads(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-copy-out-001",
		Operation:       OperationCopyOut,
		DriverID:        RuntimeDriverRootlessPodman,
		CopyOut: &CopyOutRequest{
			OperationID:      "copy-out-001",
			Target:           lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			RemoteSourcePath: "/workspace/hal/reports/report.json",
			Destination:      CopyPathMetadata{DisplayPath: "reports/report.json"},
			MaxPayloadBytes:  4096,
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal(copy_out request) error: %v", err)
	}
	var rawReq map[string]any
	if err := json.Unmarshal(data, &rawReq); err != nil {
		t.Fatalf("Unmarshal(copy_out request map) error: %v", err)
	}
	if rawReq["operation"] != OperationCopyOut {
		t.Fatalf("operation = %q, want %q", rawReq["operation"], OperationCopyOut)
	}
	copyOutPayload, ok := rawReq["copyOut"].(map[string]any)
	if !ok {
		t.Fatalf("copyOut payload = %#v, want object", rawReq["copyOut"])
	}
	assertJSONFields(t, copyOutPayload, []string{
		"operationId",
		"target",
		"remoteSourcePath",
		"destination",
		"maxPayloadBytes",
	})
	destinationPayload, ok := copyOutPayload["destination"].(map[string]any)
	if !ok {
		t.Fatalf("destination payload = %#v, want object", copyOutPayload["destination"])
	}
	assertJSONFields(t, destinationPayload, []string{"displayPath"})

	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("Unmarshal(copy_out request) error: %v", err)
	}
	if !reflect.DeepEqual(decodedReq, req) {
		t.Fatalf("decoded request = %#v, want %#v", decodedReq, req)
	}

	resp := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-copy-out-001",
		Operation:       OperationCopyOut,
		OK:              true,
		CopyOut: &CopyOutResponse{
			Payload:       ptrWorkerCopyPayload("report\n", 4096),
			Truncated:     true,
			LimitExceeded: true,
			Error: &Error{
				Code:    ErrorCodeDriverFailed,
				Message: "payload truncated at requested limit",
			},
		},
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() unexpected error: %v", err)
	}

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal(copy_out response) error: %v", err)
	}
	var rawResp map[string]any
	if err := json.Unmarshal(data, &rawResp); err != nil {
		t.Fatalf("Unmarshal(copy_out response map) error: %v", err)
	}
	if rawResp["operation"] != OperationCopyOut {
		t.Fatalf("response operation = %q, want %q", rawResp["operation"], OperationCopyOut)
	}
	copyOutResp, ok := rawResp["copyOut"].(map[string]any)
	if !ok {
		t.Fatalf("response copyOut payload = %#v, want object", rawResp["copyOut"])
	}
	assertJSONFields(t, copyOutResp, []string{"payload", "truncated", "limitExceeded", "error"})
	filePayload, ok := copyOutResp["payload"].(map[string]any)
	if !ok {
		t.Fatalf("response file payload = %#v, want object", copyOutResp["payload"])
	}
	assertJSONFields(t, filePayload, []string{"data", "encoding", "sizeBytes", "limitBytes"})

	var decodedResp Response
	if err := json.Unmarshal(data, &decodedResp); err != nil {
		t.Fatalf("Unmarshal(copy_out response) error: %v", err)
	}
	if !reflect.DeepEqual(decodedResp, resp) {
		t.Fatalf("decoded response = %#v, want %#v", decodedResp, resp)
	}
}

func TestWorkerCopyRequestValidationRejectsUnsafePayloads(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{
			name: "missing copy_in payload",
			req: Request{
				Operation: OperationCopyIn,
				DriverID:  RuntimeDriverRootlessPodman,
			},
			want: "copyIn payload",
		},
		{
			name: "copy_in empty operation id",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.OperationID = " "
			}),
			want: "operation id",
		},
		{
			name: "copy_in missing source display path",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.Source.DisplayPath = ""
			}),
			want: "source displayPath",
		},
		{
			name: "copy_in missing remote destination path",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.RemoteDestinationPath = " "
			}),
			want: "remote destination path",
		},
		{
			name: "copy_in payload limit exceeds maximum",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.Payload = workerCopyPayload("payload", MaxCopyInPayloadBytes+1)
			}),
			want: "exceeds maximum",
		},
		{
			name: "copy_in payload exceeds requested limit",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.Payload = workerCopyPayload("payload", 6)
			}),
			want: "requested limit",
		},
		{
			name: "copy_in invalid base64 payload",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.Payload.Data = "not base64!"
			}),
			want: "not valid base64",
		},
		{
			name: "copy_in size does not match decoded payload",
			req: mutateCopyInRequest(validWorkerCopyInRequest(), func(req *CopyInRequest) {
				req.Payload = workerCopyPayload("payload", MaxCopyInPayloadBytes)
				req.Payload.SizeBytes = 3
			}),
			want: "does not match decoded data size",
		},
		{
			name: "missing copy_out payload",
			req: Request{
				Operation: OperationCopyOut,
				DriverID:  RuntimeDriverRootlessPodman,
			},
			want: "copyOut payload",
		},
		{
			name: "copy_out max payload exceeds maximum",
			req: mutateCopyOutRequest(validWorkerCopyOutRequest(), func(req *CopyOutRequest) {
				req.MaxPayloadBytes = MaxCopyOutPayloadBytes + 1
			}),
			want: "copy_out max payload exceeds maximum",
		},
		{
			name: "copy_out missing max payload",
			req: mutateCopyOutRequest(validWorkerCopyOutRequest(), func(req *CopyOutRequest) {
				req.MaxPayloadBytes = 0
			}),
			want: "copy_out max payload is required",
		},
		{
			name: "copy_out missing remote source path",
			req: mutateCopyOutRequest(validWorkerCopyOutRequest(), func(req *CopyOutRequest) {
				req.RemoteSourcePath = " "
			}),
			want: "remote source path",
		},
		{
			name: "copy_out missing destination display path",
			req: mutateCopyOutRequest(validWorkerCopyOutRequest(), func(req *CopyOutRequest) {
				req.Destination.DisplayPath = ""
			}),
			want: "destination displayPath",
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

func TestWorkerCopyResponseValidationRejectsUnsafePayloads(t *testing.T) {
	tests := []struct {
		name string
		resp Response
		want string
	}{
		{
			name: "missing successful copy_in payload",
			resp: Response{
				Operation: OperationCopyIn,
				OK:        true,
			},
			want: "copyIn payload",
		},
		{
			name: "copy_in unsupported status",
			resp: mutateCopyInResponse(validWorkerCopyInResponse(), func(resp *CopyInResponse) {
				resp.Status = "done"
			}),
			want: "status",
		},
		{
			name: "copy_in payload on wrong operation",
			resp: mutateCopyInResponse(validWorkerCopyInResponse(), func(resp *CopyInResponse) {}),
			want: "only valid for copy_in",
		},
		{
			name: "missing successful copy_out payload",
			resp: Response{
				Operation: OperationCopyOut,
				OK:        true,
				CopyOut:   &CopyOutResponse{},
			},
			want: "payload data",
		},
		{
			name: "copy_out payload limit exceeds maximum",
			resp: mutateCopyOutResponse(validWorkerCopyOutResponse(), func(resp *CopyOutResponse) {
				resp.Payload.LimitBytes = MaxCopyOutPayloadBytes + 1
			}),
			want: "exceeds maximum",
		},
		{
			name: "copy_out payload exceeds requested limit",
			resp: mutateCopyOutResponse(validWorkerCopyOutResponse(), func(resp *CopyOutResponse) {
				*resp.Payload = workerCopyPayload("payload", 6)
			}),
			want: "requested limit",
		},
		{
			name: "copy_out size does not match decoded payload",
			resp: mutateCopyOutResponse(validWorkerCopyOutResponse(), func(resp *CopyOutResponse) {
				*resp.Payload = workerCopyPayload("payload", MaxCopyOutPayloadBytes)
				resp.Payload.SizeBytes = 3
			}),
			want: "does not match decoded data size",
		},
		{
			name: "copy_out payload on wrong operation",
			resp: mutateCopyOutResponse(validWorkerCopyOutResponse(), func(resp *CopyOutResponse) {}),
			want: "only valid for copy_out",
		},
	}
	tests[2].resp.Operation = OperationStatus
	tests[2].resp.OK = false
	tests[2].resp.Error = &Error{Code: ErrorCodeDriverFailed, Message: "failed"}
	tests[7].resp.Operation = OperationStatus
	tests[7].resp.OK = false
	tests[7].resp.Error = &Error{Code: ErrorCodeDriverFailed, Message: "failed"}

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

func TestServiceCopyInRoutesRequestsThroughRegisteredDriver(t *testing.T) {
	driver := &recordingCopyDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
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

	req := validWorkerCopyInRequest()
	req.DriverID = "fake_runtime"
	req.CopyIn.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	req.CopyIn.RemoteDestinationPath = " /workspace/hal/input.txt "
	req.CopyIn.Payload = workerCopyPayload("copy payload\n", MaxCopyInPayloadBytes)

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("copy_in response Validate() error: %v", err)
	}
	if !resp.OK || resp.Operation != OperationCopyIn || resp.CopyIn == nil {
		t.Fatalf("copy_in response = %#v, want successful copy_in payload", resp)
	}
	if resp.CopyIn.Status != CopyStatusCompleted || resp.CopyIn.Error != nil {
		t.Fatalf("copy_in payload = %#v, want completed status without error", resp.CopyIn)
	}
	if !reflect.DeepEqual(driver.calls, []string{OperationCopyIn}) {
		t.Fatalf("driver calls = %#v, want copy_in call", driver.calls)
	}
	if driver.copyInReq.Target.Name != "dev" || driver.copyInReq.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("driver copy_in target = %#v, want converted worker target", driver.copyInReq.Target)
	}
	if driver.copyInReq.DestinationPath != "/workspace/hal/input.txt" {
		t.Fatalf("driver copy_in destination = %q, want trimmed remote destination", driver.copyInReq.DestinationPath)
	}
	if driver.copyInData != "copy payload\n" {
		t.Fatalf("driver copy_in source data = %q, want decoded payload", driver.copyInData)
	}
	if strings.TrimSpace(driver.copyInReq.SourcePath) == "" || driver.copyInReq.SourcePath == req.CopyIn.Source.DisplayPath {
		t.Fatalf("driver copy_in source path = %q, want staging file path", driver.copyInReq.SourcePath)
	}
}

func TestServiceCopyOutRoutesRequestsThroughRegisteredDriver(t *testing.T) {
	driver := &recordingCopyDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		copyOutData:              "report\n",
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

	req := validWorkerCopyOutRequest()
	req.DriverID = "fake_runtime"
	req.CopyOut.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	req.CopyOut.RemoteSourcePath = " /workspace/hal/report.txt "
	req.CopyOut.MaxPayloadBytes = 64

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("copy_out response Validate() error: %v", err)
	}
	if !resp.OK || resp.Operation != OperationCopyOut || resp.CopyOut == nil || resp.CopyOut.Payload == nil {
		t.Fatalf("copy_out response = %#v, want successful copy_out payload", resp)
	}
	if resp.CopyOut.Truncated || resp.CopyOut.LimitExceeded || resp.CopyOut.Error != nil {
		t.Fatalf("copy_out metadata = %#v, want untruncated payload without error", resp.CopyOut)
	}
	if got := decodeWorkerCopyPayloadForTest(t, *resp.CopyOut.Payload); got != "report\n" {
		t.Fatalf("copy_out payload = %q, want copied data", got)
	}
	if resp.CopyOut.Payload.LimitBytes != 64 || resp.CopyOut.Payload.SizeBytes != 7 {
		t.Fatalf("copy_out payload metadata = %#v, want bounded size and limit", resp.CopyOut.Payload)
	}
	if !reflect.DeepEqual(driver.calls, []string{OperationCopyOut}) {
		t.Fatalf("driver calls = %#v, want copy_out call", driver.calls)
	}
	if driver.copyOutReq.SourcePath != "/workspace/hal/report.txt" {
		t.Fatalf("driver copy_out source = %q, want trimmed remote source", driver.copyOutReq.SourcePath)
	}
	if driver.copyOutReq.Target.Name != "dev" || driver.copyOutReq.Target.Runtime.Driver != "fake_runtime" {
		t.Fatalf("driver copy_out target = %#v, want converted worker target", driver.copyOutReq.Target)
	}
}

func TestServiceCopyOutEnforcesPayloadLimitBeforeReturningResponse(t *testing.T) {
	driver := &recordingCopyDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		copyOutData:              "abcdef",
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

	req := validWorkerCopyOutRequest()
	req.DriverID = "fake_runtime"
	req.CopyOut.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	req.CopyOut.MaxPayloadBytes = 3

	resp := service.HandleRequest(context.Background(), req)
	if err := resp.Validate(); err != nil {
		t.Fatalf("copy_out response Validate() error: %v", err)
	}
	if !resp.OK || resp.CopyOut == nil || resp.CopyOut.Payload == nil {
		t.Fatalf("copy_out response = %#v, want bounded payload", resp)
	}
	if got := decodeWorkerCopyPayloadForTest(t, *resp.CopyOut.Payload); got != "abc" {
		t.Fatalf("copy_out payload = %q, want truncated data", got)
	}
	if resp.CopyOut.Payload.SizeBytes != 3 || resp.CopyOut.Payload.LimitBytes != 3 {
		t.Fatalf("copy_out payload metadata = %#v, want size and limit of 3", resp.CopyOut.Payload)
	}
	if !resp.CopyOut.Truncated || !resp.CopyOut.LimitExceeded || resp.CopyOut.Error == nil {
		t.Fatalf("copy_out limit metadata = %#v, want truncation and limit error", resp.CopyOut)
	}
}

func TestServiceCopyUnsupportedUnknownDriverAndContextErrorsAreStructured(t *testing.T) {
	driver := &recordingCopyDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		unsupportedCopyIn:        true,
		unsupportedCopyOut:       true,
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

	copyInReq := validWorkerCopyInRequest()
	copyInReq.DriverID = "missing_runtime"
	copyInReq.CopyIn.Target = lifecycleWorkerTarget("missing_runtime", "dev", "running")
	unknownResp := service.HandleRequest(context.Background(), copyInReq)
	if err := unknownResp.Validate(); err != nil {
		t.Fatalf("unknown driver response Validate() error: %v", err)
	}
	if unknownResp.OK || unknownResp.Error == nil || unknownResp.Error.Code != ErrorCodeDriverNotFound {
		t.Fatalf("unknown driver response = %#v, want driver_not_found", unknownResp)
	}

	copyInReq.DriverID = "fake_runtime"
	copyInReq.CopyIn.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	unsupportedInResp := service.HandleRequest(context.Background(), copyInReq)
	if err := unsupportedInResp.Validate(); err != nil {
		t.Fatalf("unsupported copy_in response Validate() error: %v", err)
	}
	if unsupportedInResp.OK || unsupportedInResp.Error == nil || unsupportedInResp.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("unsupported copy_in response = %#v, want unsupported_operation", unsupportedInResp)
	}

	copyOutReq := validWorkerCopyOutRequest()
	copyOutReq.DriverID = "fake_runtime"
	copyOutReq.CopyOut.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	unsupportedOutResp := service.HandleRequest(context.Background(), copyOutReq)
	if err := unsupportedOutResp.Validate(); err != nil {
		t.Fatalf("unsupported copy_out response Validate() error: %v", err)
	}
	if unsupportedOutResp.OK || unsupportedOutResp.Error == nil || unsupportedOutResp.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("unsupported copy_out response = %#v, want unsupported_operation", unsupportedOutResp)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	callsBeforeCancel := append([]string(nil), driver.calls...)
	canceledResp := service.HandleRequest(canceledCtx, copyInReq)
	if canceledResp.OK || canceledResp.Error == nil || canceledResp.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled response = %#v, want request_canceled", canceledResp)
	}
	if !reflect.DeepEqual(driver.calls, callsBeforeCancel) {
		t.Fatalf("driver calls after canceled context = %#v, want unchanged %#v", driver.calls, callsBeforeCancel)
	}
}

func TestServiceCopyDriverErrorsAreSanitized(t *testing.T) {
	driver := &recordingCopyDriver{
		recordingLifecycleDriver: recordingLifecycleDriver{id: "fake_runtime"},
		copyInErr:                errors.New("copy failed token=raw-secret under /Users/alice/worktree"),
		copyOutErr:               errors.New("copy failed token=raw-secret under /Users/alice/worktree"),
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

	copyInReq := validWorkerCopyInRequest()
	copyInReq.DriverID = "fake_runtime"
	copyInReq.CopyIn.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyInResp := service.HandleRequest(context.Background(), copyInReq)
	if err := copyInResp.Validate(); err != nil {
		t.Fatalf("copy_in error response Validate() error: %v", err)
	}
	if !copyInResp.OK || copyInResp.CopyIn == nil || copyInResp.CopyIn.Status != CopyStatusFailed || copyInResp.CopyIn.Error == nil {
		t.Fatalf("copy_in response = %#v, want failed copy_in payload error", copyInResp)
	}
	assertSanitizedWorkerCopyError(t, copyInResp.CopyIn.Error.Message)

	copyOutReq := validWorkerCopyOutRequest()
	copyOutReq.DriverID = "fake_runtime"
	copyOutReq.CopyOut.Target = lifecycleWorkerTarget("fake_runtime", "dev", "running")
	copyOutResp := service.HandleRequest(context.Background(), copyOutReq)
	if err := copyOutResp.Validate(); err != nil {
		t.Fatalf("copy_out error response Validate() error: %v", err)
	}
	if copyOutResp.OK || copyOutResp.Error == nil || copyOutResp.Error.Code != ErrorCodeDriverFailed {
		t.Fatalf("copy_out response = %#v, want top-level driver_error", copyOutResp)
	}
	assertSanitizedWorkerCopyError(t, copyOutResp.Error.Message)
}

func validWorkerCopyInRequest() Request {
	return Request{
		Operation: OperationCopyIn,
		DriverID:  RuntimeDriverRootlessPodman,
		CopyIn: &CopyInRequest{
			OperationID:           "copy-in-001",
			Target:                lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			Source:                CopyPathMetadata{DisplayPath: "workspace/input.txt"},
			RemoteDestinationPath: "/workspace/hal/input.txt",
			Payload:               workerCopyPayload("payload", MaxCopyInPayloadBytes),
		},
	}
}

func mutateCopyInRequest(req Request, mutate func(*CopyInRequest)) Request {
	if req.CopyIn != nil && mutate != nil {
		mutate(req.CopyIn)
	}
	return req
}

func validWorkerCopyOutRequest() Request {
	return Request{
		Operation: OperationCopyOut,
		DriverID:  RuntimeDriverRootlessPodman,
		CopyOut: &CopyOutRequest{
			OperationID:      "copy-out-001",
			Target:           lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "dev", "running"),
			RemoteSourcePath: "/workspace/hal/output.txt",
			Destination:      CopyPathMetadata{DisplayPath: "workspace/output.txt"},
			MaxPayloadBytes:  MaxCopyOutPayloadBytes,
		},
	}
}

func mutateCopyOutRequest(req Request, mutate func(*CopyOutRequest)) Request {
	if req.CopyOut != nil && mutate != nil {
		mutate(req.CopyOut)
	}
	return req
}

func validWorkerCopyInResponse() Response {
	return Response{
		Operation: OperationCopyIn,
		OK:        true,
		CopyIn: &CopyInResponse{
			Status: CopyStatusCompleted,
		},
	}
}

func mutateCopyInResponse(resp Response, mutate func(*CopyInResponse)) Response {
	if resp.CopyIn != nil && mutate != nil {
		mutate(resp.CopyIn)
	}
	return resp
}

func validWorkerCopyOutResponse() Response {
	return Response{
		Operation: OperationCopyOut,
		OK:        true,
		CopyOut: &CopyOutResponse{
			Payload: ptrWorkerCopyPayload("payload", MaxCopyOutPayloadBytes),
		},
	}
}

func mutateCopyOutResponse(resp Response, mutate func(*CopyOutResponse)) Response {
	if resp.CopyOut != nil && mutate != nil {
		mutate(resp.CopyOut)
	}
	return resp
}

func workerCopyPayload(data string, limit int64) CopyFilePayload {
	return CopyFilePayload{
		Data:       base64.StdEncoding.EncodeToString([]byte(data)),
		Encoding:   CopyPayloadEncodingBase64,
		SizeBytes:  int64(len([]byte(data))),
		LimitBytes: limit,
	}
}

func ptrWorkerCopyPayload(data string, limit int64) *CopyFilePayload {
	payload := workerCopyPayload(data, limit)
	return &payload
}

func decodeWorkerCopyPayloadForTest(t *testing.T, payload CopyFilePayload) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		t.Fatalf("DecodeString(copy payload) error: %v", err)
	}
	return string(data)
}

func assertSanitizedWorkerCopyError(t *testing.T, message string) {
	t.Helper()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("copy error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("copy error message = %q, want sanitized marker %q", message, want)
		}
	}
}

type recordingCopyDriver struct {
	recordingLifecycleDriver
	copyInErr          error
	copyOutErr         error
	unsupportedCopyIn  bool
	unsupportedCopyOut bool
	copyOutData        string
	copyInReq          sandboxruntime.CopyRequest
	copyOutReq         sandboxruntime.CopyRequest
	copyInData         string
}

func (driver *recordingCopyDriver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.calls = append(driver.calls, OperationCopyIn)
	driver.copyInReq = req
	data, err := os.ReadFile(req.SourcePath)
	if err != nil {
		return err
	}
	driver.copyInData = string(data)
	if err := ctx.Err(); err != nil {
		return err
	}
	if driver.unsupportedCopyIn {
		return ErrWorkerOperationUnsupported
	}
	return driver.copyInErr
}

func (driver *recordingCopyDriver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	driver.calls = append(driver.calls, OperationCopyOut)
	driver.copyOutReq = req
	if err := ctx.Err(); err != nil {
		return err
	}
	if driver.unsupportedCopyOut {
		return ErrWorkerOperationUnsupported
	}
	if driver.copyOutErr != nil {
		return driver.copyOutErr
	}
	return os.WriteFile(req.DestinationPath, []byte(driver.copyOutData), 0o600)
}
