package guestagent

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProtocolContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "version", got: string(ProtocolVersionV1), want: "guest-agent-v1"},
		{name: "readiness operation", got: string(OperationReadiness), want: "readiness"},
		{name: "exec operation", got: string(OperationExec), want: "exec"},
		{name: "copy in operation", got: string(OperationCopyIn), want: "copy_in"},
		{name: "copy out operation", got: string(OperationCopyOut), want: "copy_out"},
		{name: "literal env source", got: string(EnvironmentSourceLiteral), want: "literal"},
		{name: "secret env source", got: string(EnvironmentSourceSecret), want: "secret"},
		{name: "raw payload encoding", got: string(PayloadEncodingRaw), want: "raw"},
		{name: "base64 payload encoding", got: string(PayloadEncodingBase64), want: "base64"},
		{name: "ready status", got: string(ReadinessStatusReady), want: "ready"},
		{name: "unsupported version error", got: string(ErrorCodeUnsupportedProtocolVersion), want: "unsupported_protocol_version"},
		{name: "unknown operation error", got: string(ErrorCodeUnknownOperation), want: "unknown_operation"},
		{name: "malformed path error", got: string(ErrorCodeMalformedPath), want: "malformed_path"},
		{name: "oversized payload error", got: string(ErrorCodeOversizedPayloadMetadata), want: "oversized_payload_metadata"},
		{name: "malformed response error", got: string(ErrorCodeMalformedResponse), want: "malformed_response"},
		{name: "oversized request error", got: string(ErrorCodeOversizedRequest), want: "oversized_request"},
		{name: "oversized response error", got: string(ErrorCodeOversizedResponse), want: "oversized_response"},
		{name: "request canceled error", got: string(ErrorCodeRequestCanceled), want: "request_canceled"},
		{name: "request timeout error", got: string(ErrorCodeRequestTimeout), want: "request_timeout"},
		{name: "transport failure error", got: string(ErrorCodeTransportFailure), want: "transport_failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestProtocolDTOJSONShapes(t *testing.T) {
	readinessRequest := mustMarshalObject(t, ReadinessRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		Timing:          &TimingMetadata{TimeoutMillis: 5000},
	})
	assertExactObjectKeys(t, readinessRequest, []string{"protocolVersion", "operation", "timing"})
	assertNestedObjectKeys(t, readinessRequest, "timing", []string{"timeoutMillis"})

	readinessResponse := mustMarshalObject(t, ReadinessResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		Ready:           true,
		Status:          ReadinessStatusReady,
	})
	assertExactObjectKeys(t, readinessResponse, []string{"protocolVersion", "operation", "ready", "status"})

	execRequest := mustMarshalObject(t, ExecRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationExec,
		Args:            []string{"sh", "-lc", "printf ok"},
		Env: []EnvironmentEntry{
			{Name: "HAL_MODE", Source: EnvironmentSourceLiteral},
			{Name: "GITHUB_TOKEN", Source: EnvironmentSourceSecret},
		},
		WorkDir: "/workspace/project",
		Stdin:   &StreamMetadata{SizeBytes: 5, MaxBytes: 1024, Data: "c3RkaW4=", Encoding: PayloadEncodingBase64},
		Stdout:  StreamMetadata{MaxBytes: 2048},
		Stderr:  StreamMetadata{MaxBytes: 2048},
		Timing:  &TimingMetadata{DeadlineUnixMillis: 1893456000000},
	})
	assertExactObjectKeys(t, execRequest, []string{
		"protocolVersion", "operation", "args", "env", "workDir", "stdin", "stdout", "stderr", "timing",
	})
	assertNestedObjectKeys(t, execRequest, "stdin", []string{"sizeBytes", "maxBytes", "data", "encoding"})
	assertNestedObjectKeys(t, execRequest, "stdout", []string{"maxBytes"})
	assertNestedObjectKeys(t, execRequest, "stderr", []string{"maxBytes"})
	assertNestedObjectKeys(t, execRequest, "timing", []string{"deadlineUnixMillis"})
	envEntries, ok := execRequest["env"].([]any)
	if !ok || len(envEntries) != 2 {
		t.Fatalf("env = %#v, want two entries", execRequest["env"])
	}
	assertExactObjectKeys(t, envEntries[0], []string{"name", "source"})
	if _, ok := envEntries[0].(map[string]any)["value"]; ok {
		t.Fatalf("env entry unexpectedly exposes a value field")
	}

	execResponse := mustMarshalObject(t, ExecResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationExec,
		ExitCode:        0,
		Stdout:          StreamMetadata{SizeBytes: 2, MaxBytes: 2048, Encoding: PayloadEncodingBase64, Data: "b2s="},
		Stderr:          StreamMetadata{MaxBytes: 2048},
	})
	assertExactObjectKeys(t, execResponse, []string{"protocolVersion", "operation", "exitCode", "stdout", "stderr"})
	assertExactObjectKeys(t, execResponse["stdout"], []string{"sizeBytes", "maxBytes", "data", "encoding"})
	assertExactObjectKeys(t, execResponse["stderr"], []string{"maxBytes"})

	copyInRequest := mustMarshalObject(t, CopyInRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationCopyIn,
		DestinationPath: "/workspace/input.txt",
		Payload: PayloadMetadata{
			SizeBytes: 12,
			MaxBytes:  1024,
			Digest:    "sha256:abc123",
			Encoding:  PayloadEncodingBase64,
			Data:      "Y29weSBwYXlsb2Fk",
		},
		Timing: &TimingMetadata{TimeoutMillis: 1000},
	})
	assertExactObjectKeys(t, copyInRequest, []string{"protocolVersion", "operation", "destinationPath", "payload", "timing"})
	assertNestedObjectKeys(t, copyInRequest, "payload", []string{"sizeBytes", "maxBytes", "digest", "encoding", "data"})

	copyInResponse := mustMarshalObject(t, CopyInResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationCopyIn,
		Written:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024},
	})
	assertExactObjectKeys(t, copyInResponse, []string{"protocolVersion", "operation", "written"})

	copyOutRequest := mustMarshalObject(t, CopyOutRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationCopyOut,
		SourcePath:      "/workspace/output.txt",
		Payload:         PayloadMetadata{MaxBytes: 1024, Encoding: PayloadEncodingBase64},
	})
	assertExactObjectKeys(t, copyOutRequest, []string{"protocolVersion", "operation", "sourcePath", "payload"})

	copyOutResponse := mustMarshalObject(t, CopyOutResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationCopyOut,
		Payload:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: "Y29weSBwYXlsb2Fk"},
	})
	assertExactObjectKeys(t, copyOutResponse, []string{"protocolVersion", "operation", "payload"})
	assertNestedObjectKeys(t, copyOutResponse, "payload", []string{"sizeBytes", "maxBytes", "encoding", "data"})
}

func TestProtocolDTOsDoNotCarryRawEnvironmentValues(t *testing.T) {
	envType := reflect.TypeOf(EnvironmentEntry{})
	if _, ok := envType.FieldByName("Value"); ok {
		t.Fatalf("EnvironmentEntry must not carry raw environment values")
	}
	for i := 0; i < envType.NumField(); i++ {
		field := envType.Field(i)
		jsonName := field.Tag.Get("json")
		if jsonName == "value" || jsonName == "value,omitempty" {
			t.Fatalf("EnvironmentEntry.%s exposes raw value JSON tag %q", field.Name, jsonName)
		}
	}
}

func mustMarshalObject(t *testing.T, value any) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", encoded, err)
	}
	return out
}

func assertNestedObjectKeys(t *testing.T, object map[string]any, key string, want []string) {
	t.Helper()

	nested, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, object[key])
	}
	assertExactObjectKeys(t, nested, want)
}

func assertExactObjectKeys(t *testing.T, value any, want []string) {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	got := make(map[string]bool, len(object))
	for key := range object {
		got[key] = true
	}
	if len(got) != len(want) {
		t.Fatalf("keys = %#v, want %v", got, want)
	}
	for _, key := range want {
		if !got[key] {
			t.Fatalf("keys = %#v, missing %q", got, key)
		}
	}
}
