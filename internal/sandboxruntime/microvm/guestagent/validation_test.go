package guestagent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateProtocolRequestsAndResponsesAcceptValidContracts(t *testing.T) {
	validators := []struct {
		name string
		run  func() error
	}{
		{
			name: "readiness request",
			run: func() error {
				return ValidateReadinessRequest(ReadinessRequest{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationReadiness,
					Timing:          &TimingMetadata{TimeoutMillis: 5000},
				})
			},
		},
		{
			name: "readiness response",
			run: func() error {
				return ValidateReadinessResponse(ReadinessResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationReadiness,
					Ready:           true,
					Status:          ReadinessStatusReady,
				})
			},
		},
		{
			name: "exec request",
			run: func() error {
				return ValidateExecRequest(validExecRequest())
			},
		},
		{
			name: "exec response",
			run: func() error {
				return ValidateExecResponse(ExecResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationExec,
					ExitCode:        0,
					Stdout:          StreamMetadata{SizeBytes: 2, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: "b2s="},
					Stderr:          StreamMetadata{MaxBytes: 1024},
				})
			},
		},
		{
			name: "copy in request",
			run: func() error {
				return ValidateCopyInRequest(CopyInRequest{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyIn,
					DestinationPath: "/workspace/input.txt",
					Payload:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024, Digest: "sha256:abc123", Encoding: PayloadEncodingBase64, Data: "Y29weSBwYXlsb2Fk"},
					Timing:          &TimingMetadata{TimeoutMillis: 1000},
				})
			},
		},
		{
			name: "copy in response",
			run: func() error {
				return ValidateCopyInResponse(CopyInResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyIn,
					Written:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024},
				})
			},
		},
		{
			name: "copy out request",
			run: func() error {
				return ValidateCopyOutRequest(CopyOutRequest{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyOut,
					SourcePath:      "/workspace/output.txt",
					Payload:         PayloadMetadata{MaxBytes: 1024, Encoding: PayloadEncodingBase64},
				})
			},
		},
		{
			name: "copy out response",
			run: func() error {
				return ValidateCopyOutResponse(CopyOutResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyOut,
					Payload:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: "Y29weSBwYXlsb2Fk"},
				})
			},
		},
	}

	for _, tt := range validators {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err != nil {
				t.Fatalf("validation error: %v", err)
			}
		})
	}
}

func TestValidateProtocolRequestsRejectInvalidMetadata(t *testing.T) {
	longArgs := make([]string, MaxCommandArgs+1)
	for i := range longArgs {
		longArgs[i] = "x"
	}

	tests := []struct {
		name      string
		err       error
		wantCode  ErrorCode
		wantField string
	}{
		{
			name:      "missing protocol version",
			err:       ValidateReadinessRequest(ReadinessRequest{Operation: OperationReadiness}),
			wantCode:  ErrorCodeMissingRequiredField,
			wantField: "protocolVersion",
		},
		{
			name:      "unsupported protocol version",
			err:       ValidateReadinessRequest(ReadinessRequest{ProtocolVersion: "guest-agent-v2", Operation: OperationReadiness}),
			wantCode:  ErrorCodeUnsupportedProtocolVersion,
			wantField: "protocolVersion",
		},
		{
			name:      "unknown operation",
			err:       ValidateReadinessRequest(ReadinessRequest{ProtocolVersion: ProtocolVersionV1, Operation: "shell"}),
			wantCode:  ErrorCodeUnknownOperation,
			wantField: "operation",
		},
		{
			name:      "operation mismatch",
			err:       ValidateReadinessRequest(ReadinessRequest{ProtocolVersion: ProtocolVersionV1, Operation: OperationExec}),
			wantCode:  ErrorCodeOperationMismatch,
			wantField: "operation",
		},
		{
			name:      "missing args",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Args = nil })),
			wantCode:  ErrorCodeMissingRequiredField,
			wantField: "args",
		},
		{
			name:      "too many args",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Args = longArgs })),
			wantCode:  ErrorCodeOversizedPayloadMetadata,
			wantField: "args",
		},
		{
			name:      "malformed workdir",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.WorkDir = "../Users/alice/private" })),
			wantCode:  ErrorCodeMalformedPath,
			wantField: "workDir",
		},
		{
			name:      "dot segment workdir",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.WorkDir = "/workspace/dir/./file" })),
			wantCode:  ErrorCodeMalformedPath,
			wantField: "workDir",
		},
		{
			name: "invalid env name",
			err: ValidateExecRequest(withExecRequest(func(req *ExecRequest) {
				req.Env = []EnvironmentEntry{{Name: "TOKEN=value", Source: EnvironmentSourceLiteral}}
			})),
			wantCode:  ErrorCodeInvalidMetadata,
			wantField: "env[0].name",
		},
		{
			name:      "invalid timeout",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Timing = &TimingMetadata{TimeoutMillis: -1} })),
			wantCode:  ErrorCodeInvalidTimeout,
			wantField: "timing.timeoutMillis",
		},
		{
			name:      "invalid deadline",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Timing = &TimingMetadata{DeadlineUnixMillis: 1} })),
			wantCode:  ErrorCodeInvalidDeadline,
			wantField: "timing.deadlineUnixMillis",
		},
		{
			name: "timeout and deadline conflict",
			err: ValidateExecRequest(withExecRequest(func(req *ExecRequest) {
				req.Timing = &TimingMetadata{TimeoutMillis: 1, DeadlineUnixMillis: 1893456000000}
			})),
			wantCode:  ErrorCodeInvalidDeadline,
			wantField: "timing",
		},
		{
			name:      "missing stdout cap",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Stdout = StreamMetadata{} })),
			wantCode:  ErrorCodeMissingRequiredField,
			wantField: "stdout.maxBytes",
		},
		{
			name:      "oversized stdout cap",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Stdout = StreamMetadata{MaxBytes: MaxStreamMetadataBytes + 1} })),
			wantCode:  ErrorCodeOversizedPayloadMetadata,
			wantField: "stdout",
		},
		{
			name:      "metadata only stdin content",
			err:       ValidateExecRequest(withExecRequest(func(req *ExecRequest) { req.Stdin.Data = "" })),
			wantCode:  ErrorCodeInvalidMetadata,
			wantField: "stdin.data",
		},
		{
			name: "raw stdin content",
			err: ValidateExecRequest(withExecRequest(func(req *ExecRequest) {
				req.Stdin = &StreamMetadata{SizeBytes: 12, MaxBytes: 1024, Data: "request-body", Encoding: PayloadEncodingRaw}
			})),
			wantCode:  ErrorCodeInvalidMetadata,
			wantField: "stdin.encoding",
		},
		{
			name: "malformed copy path",
			err: ValidateCopyInRequest(CopyInRequest{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyIn,
				DestinationPath: "/workspace/../secret",
				Payload:         PayloadMetadata{SizeBytes: 1, MaxBytes: 1024},
			}),
			wantCode:  ErrorCodeMalformedPath,
			wantField: "destinationPath",
		},
		{
			name: "trailing copy path separator",
			err: ValidateCopyOutRequest(CopyOutRequest{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyOut,
				SourcePath:      "/workspace/output/",
				Payload:         PayloadMetadata{MaxBytes: 1024, Encoding: PayloadEncodingBase64},
			}),
			wantCode:  ErrorCodeMalformedPath,
			wantField: "sourcePath",
		},
		{
			name: "oversized copy payload metadata",
			err: ValidateCopyOutRequest(CopyOutRequest{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyOut,
				SourcePath:      "/workspace/output.txt",
				Payload:         PayloadMetadata{MaxBytes: MaxCopyPayloadMetadataBytes + 1},
			}),
			wantCode:  ErrorCodeOversizedPayloadMetadata,
			wantField: "payload",
		},
		{
			name: "metadata only copy payload content",
			err: ValidateCopyInRequest(CopyInRequest{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyIn,
				DestinationPath: "/workspace/input.txt",
				Payload:         PayloadMetadata{SizeBytes: 1, MaxBytes: 1024, Encoding: PayloadEncodingBase64},
			}),
			wantCode:  ErrorCodeInvalidMetadata,
			wantField: "payload.data",
		},
		{
			name: "malformed copy payload data",
			err: ValidateCopyOutResponse(CopyOutResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyOut,
				Payload:         PayloadMetadata{SizeBytes: 1, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: "not-base64"},
			}),
			wantCode:  ErrorCodeInvalidMetadata,
			wantField: "payload.data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertProtocolError(t, tt.err, tt.wantCode, tt.wantField)
		})
	}
}

func TestValidateExecRequestRejectsNonCanonicalEnvironmentSources(t *testing.T) {
	sources := []EnvironmentSource{
		" literal ",
		"\tsecret",
		"inherited\n",
		" generated",
	}
	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			err := ValidateExecRequest(withExecRequest(func(req *ExecRequest) {
				req.Env = []EnvironmentEntry{{Name: "HAL_VALUE", Source: source}}
			}))
			assertProtocolError(t, err, ErrorCodeInvalidMetadata, "env[0].source")
		})
	}
}

func TestValidateProtocolResponsesRejectStreamDataAboveDeclaredLimit(t *testing.T) {
	err := ValidateExecResponse(ExecResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationExec,
		ExitCode:        0,
		Stdout:          StreamMetadata{Data: "abcdef", MaxBytes: 5},
		Stderr:          StreamMetadata{MaxBytes: 5},
	})
	assertProtocolError(t, err, ErrorCodeOversizedPayloadMetadata, "stdout.data")
}

func TestProtocolErrorsAreRedactionSafeInStringsAndJSON(t *testing.T) {
	rawErr := errors.New(`dial https://secret.internal:8443 with Authorization: Bearer ghp_secret123 token=ghp_secret123 password=hunter2 path /Users/alice/private/key body={"token":"secret"} socket /var/run/docker.sock 127.0.0.1:8080`)
	protocolErr := NewProtocolError(ErrorCodeInvalidMetadata, OperationExec, "args[0]", rawErr)

	encoded, err := json.Marshal(protocolErr)
	if err != nil {
		t.Fatalf("Marshal(ProtocolError) error: %v", err)
	}
	combined := strings.ToLower(protocolErr.Error() + " " + string(encoded))
	for _, forbidden := range []string{
		"secret.internal",
		"8443",
		"authorization",
		"bearer",
		"ghp_secret123",
		"hunter2",
		"/users/alice",
		"/var/run/docker.sock",
		"127.0.0.1",
		"8080",
		`"token":"secret"`,
	} {
		if strings.Contains(combined, strings.ToLower(forbidden)) {
			t.Fatalf("protocol error leaked %q in %s", forbidden, combined)
		}
	}
	assertContains(t, combined, "invalid_metadata")
	assertContains(t, combined, "args[0]")
}

func TestValidationErrorsDoNotLeakRejectedRequestValues(t *testing.T) {
	request := withExecRequest(func(req *ExecRequest) {
		req.Args = []string{"sh", "-lc", "cat /Users/alice/private token=ghp_secret123"}
		req.Env = []EnvironmentEntry{{Name: "TOKEN=value", Source: EnvironmentSourceLiteral}}
		req.WorkDir = "../Users/alice/private"
	})

	err := ValidateExecRequest(request)
	assertProtocolError(t, err, ErrorCodeInvalidMetadata, "env[0].name")
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(validation error) error: %v", marshalErr)
	}
	combined := strings.ToLower(err.Error() + " " + string(encoded))
	for _, forbidden := range []string{
		"/users/alice",
		"ghp_secret123",
		"token=value",
		"cat /users",
	} {
		if strings.Contains(combined, strings.ToLower(forbidden)) {
			t.Fatalf("validation error leaked %q in %s", forbidden, combined)
		}
	}
}

func validExecRequest() ExecRequest {
	return ExecRequest{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationExec,
		Args:            []string{"sh", "-lc", "printf ok"},
		Env:             []EnvironmentEntry{{Name: "HAL_MODE", Source: EnvironmentSourceLiteral}},
		WorkDir:         "/workspace/project",
		Stdin:           &StreamMetadata{SizeBytes: 4, MaxBytes: 1024, Data: "c3RkaQ==", Encoding: PayloadEncodingBase64},
		Stdout:          StreamMetadata{MaxBytes: 1024},
		Stderr:          StreamMetadata{MaxBytes: 1024},
		Timing:          &TimingMetadata{TimeoutMillis: 5000},
	}
}

func withExecRequest(mutator func(*ExecRequest)) ExecRequest {
	req := validExecRequest()
	mutator(&req)
	return req
}

func assertProtocolError(t *testing.T, err error, wantCode ErrorCode, wantField string) {
	t.Helper()

	if err == nil {
		t.Fatalf("validation error = nil, want code %q", wantCode)
	}
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("validation error type = %T, want *ProtocolError", err)
	}
	if protocolErr.Code != wantCode {
		t.Fatalf("error code = %q, want %q; error=%v", protocolErr.Code, wantCode, err)
	}
	if protocolErr.Field != wantField {
		t.Fatalf("error field = %q, want %q; error=%v", protocolErr.Field, wantField, err)
	}
}

func assertContains(t *testing.T, value, want string) {
	t.Helper()

	if !strings.Contains(value, want) {
		t.Fatalf("%q does not contain %q", value, want)
	}
}
