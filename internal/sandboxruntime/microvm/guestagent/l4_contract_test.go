package guestagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestL4ProtocolAdditiveErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		got  ErrorCode
		want string
	}{
		{name: "malformed request", got: ErrorCodeMalformedRequest, want: "malformed_request"},
		{name: "server not ready", got: ErrorCodeServerNotReady, want: "server_not_ready"},
		{name: "server busy", got: ErrorCodeServerBusy, want: "server_busy"},
		{name: "environment unavailable", got: ErrorCodeEnvironmentUnavailable, want: "environment_unavailable"},
		{name: "execution failed", got: ErrorCodeExecutionFailed, want: "execution_failed"},
		{name: "copy failed", got: ErrorCodeCopyFailed, want: "copy_failed"},
		{name: "digest mismatch", got: ErrorCodeDigestMismatch, want: "digest_mismatch"},
		{name: "resource changed", got: ErrorCodeResourceChanged, want: "resource_changed"},
		{name: "durability uncertain", got: ErrorCodeDurabilityUncertain, want: "durability_uncertain"},
		{name: "backend unavailable", got: ErrorCodeBackendUnavailable, want: "backend_unavailable"},
		{name: "unsupported platform", got: ErrorCodeUnsupportedPlatform, want: "unsupported_platform"},
		{name: "internal failure", got: ErrorCodeInternalFailure, want: "internal_failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.got); got != tt.want {
				t.Fatalf("error code = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestL4ErrorResponseExactJSONShape(t *testing.T) {
	tests := []struct {
		name      string
		response  ErrorResponse
		wantJSON  string
		wantValid bool
	}{
		{
			name: "known operation",
			response: ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationExec,
				Error: &ProtocolError{
					Code:      ErrorCodeExecutionFailed,
					Operation: OperationExec,
					Field:     "exec",
					Message:   "guest command execution failed",
				},
			},
			wantJSON:  `{"protocolVersion":"guest-agent-v1","operation":"exec","error":{"code":"execution_failed","operation":"exec","field":"exec","message":"guest command execution failed"}}`,
			wantValid: true,
		},
		{
			name: "malformed header omits operation",
			response: ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Error: &ProtocolError{
					Code:    ErrorCodeMalformedRequest,
					Field:   "request",
					Message: "guest agent request is malformed",
				},
			},
			wantJSON:  `{"protocolVersion":"guest-agent-v1","error":{"code":"malformed_request","field":"request","message":"guest agent request is malformed"}}`,
			wantValid: true,
		},
		{
			name: "nil error is invalid",
			response: ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
			},
			wantJSON:  `{"protocolVersion":"guest-agent-v1","error":null}`,
			wantValid: false,
		},
		{
			name: "padded operations are invalid",
			response: ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       " exec ",
				Error: &ProtocolError{
					Code:      ErrorCodeExecutionFailed,
					Operation: " exec ",
				},
			},
			wantJSON:  `{"protocolVersion":"guest-agent-v1","operation":" exec ","error":{"code":"execution_failed","operation":"exec"}}`,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}
			if got := string(encoded); got != tt.wantJSON {
				t.Fatalf("Marshal() = %s, want %s", got, tt.wantJSON)
			}
			err = ValidateErrorResponse(tt.response)
			if tt.wantValid && err != nil {
				t.Fatalf("ValidateErrorResponse() error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Fatal("ValidateErrorResponse() error = nil, want validation failure")
			}
		})
	}
}

func TestL4ReadinessResponseValidatesPresentStatus(t *testing.T) {
	tests := []struct {
		name    string
		ready   bool
		status  ReadinessStatus
		wantErr bool
	}{
		{name: "ready", ready: true, status: ReadinessStatusReady},
		{name: "not ready", ready: false, status: ReadinessStatusNotReady},
		{name: "true not ready contradiction", ready: true, status: ReadinessStatusNotReady, wantErr: true},
		{name: "false ready contradiction", ready: false, status: ReadinessStatusReady, wantErr: true},
		{name: "padded ready", ready: false, status: " ready ", wantErr: true},
		{name: "padded not ready", ready: false, status: " not_ready ", wantErr: true},
		{name: "unsupported status", status: "starting", wantErr: true},
		{name: "v1 ready response omits status", ready: true},
		{name: "v1 not-ready response omits status", ready: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReadinessResponse(ReadinessResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationReadiness,
				Ready:           tt.ready,
				Status:          tt.status,
			})
			if tt.wantErr && !l4ProtocolErrorCode(err, ErrorCodeInvalidMetadata) {
				t.Fatalf("ValidateReadinessResponse() error = %v, want %s", err, ErrorCodeInvalidMetadata)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateReadinessResponse() error: %v", err)
			}
		})
	}
}

func TestL4ExecResponseRequiresDeclaredOutputData(t *testing.T) {
	tests := []struct {
		name      string
		response  ExecResponse
		wantField string
	}{
		{
			name: "stdout",
			response: ExecResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationExec,
				Stdout:          StreamMetadata{SizeBytes: 2, MaxBytes: 1024, Encoding: PayloadEncodingBase64},
				Stderr:          StreamMetadata{MaxBytes: 1024},
			},
			wantField: "stdout.data",
		},
		{
			name: "stderr",
			response: ExecResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationExec,
				Stdout:          StreamMetadata{MaxBytes: 1024},
				Stderr:          StreamMetadata{SizeBytes: 3, MaxBytes: 1024, Encoding: PayloadEncodingBase64},
			},
			wantField: "stderr.data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExecResponse(tt.response)
			var protocolErr *ProtocolError
			if !errors.As(err, &protocolErr) ||
				protocolErr.Code != ErrorCodeInvalidMetadata ||
				protocolErr.Field != tt.wantField {
				t.Fatalf("ValidateExecResponse() error = %v, want %s at %s", err, ErrorCodeInvalidMetadata, tt.wantField)
			}
		})
	}
}

func TestL4ClientStrictlyRejectsMalformedResponseObjects(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "unknown top level field",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready","extra":true}`,
		},
		{
			name:     "duplicate top level field",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"ready":false,"status":"ready"}`,
		},
		{
			name:     "unknown nested error field",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"server_not_ready","operation":"readiness","extra":"unsafe"}}`,
		},
		{
			name:     "duplicate nested error field",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"server_not_ready","code":"internal_failure","operation":"readiness"}}`,
		},
		{
			name:     "noncanonical case alias",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"Ready":false,"status":"ready"}`,
		},
		{
			name:     "trailing document",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"} {}`,
		},
		{
			name:     "array root",
			response: `[]`,
		},
		{
			name:     "null root",
			response: `null`,
		},
		{
			name:     "string root",
			response: `"response"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := l4ReadinessClient(t, []byte(tt.response))
			_, err := client.Readiness(context.Background(), ReadinessRequest{})
			if !l4ProtocolErrorCode(err, ErrorCodeMalformedResponse) {
				t.Fatalf("Readiness() error = %v, want %s", err, ErrorCodeMalformedResponse)
			}
		})
	}
}

func TestL4ClientRejectsNullResponseScalars(t *testing.T) {
	tests := []struct {
		name     string
		response string
		call     func(*Client) error
	}{
		{
			name:     "readiness value",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":null,"status":"not_ready"}`,
			call: func(client *Client) error {
				_, err := client.Readiness(context.Background(), ReadinessRequest{})
				return err
			},
		},
		{
			name:     "exec exit code",
			response: `{"protocolVersion":"guest-agent-v1","operation":"exec","exitCode":null,"stdout":{"maxBytes":1024},"stderr":{"maxBytes":1024}}`,
			call: func(client *Client) error {
				_, err := client.Exec(context.Background(), validExecRequest())
				return err
			},
		},
		{
			name:     "stream truncated",
			response: `{"protocolVersion":"guest-agent-v1","operation":"exec","exitCode":0,"stdout":{"maxBytes":1024,"truncated":null},"stderr":{"maxBytes":1024}}`,
			call: func(client *Client) error {
				_, err := client.Exec(context.Background(), validExecRequest())
				return err
			},
		},
		{
			name:     "copy size",
			response: `{"protocolVersion":"guest-agent-v1","operation":"copy_in","written":{"sizeBytes":null,"maxBytes":1024}}`,
			call: func(client *Client) error {
				_, err := client.CopyIn(context.Background(), CopyInRequest{
					DestinationPath: "/workspace/input",
					Payload: PayloadMetadata{
						MaxBytes: 1024,
						Encoding: PayloadEncodingBase64,
					},
				})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := l4ReadinessClient(t, []byte(tt.response))
			if err := tt.call(client); !l4ProtocolErrorCode(err, ErrorCodeMalformedResponse) {
				t.Fatalf("client call error = %v, want %s", err, ErrorCodeMalformedResponse)
			}
		})
	}
}

func TestL4ClientRejectsPaddedPayloadEncoding(t *testing.T) {
	for _, encoding := range []string{" raw ", " base64 ", " chunked "} {
		t.Run(encoding, func(t *testing.T) {
			response := `{"protocolVersion":"guest-agent-v1","operation":"exec","exitCode":0,` +
				`"stdout":{"maxBytes":1024,"encoding":` + fmt.Sprintf("%q", encoding) + `},` +
				`"stderr":{"maxBytes":1024}}`
			client := l4ReadinessClient(t, []byte(response))
			_, err := client.Exec(context.Background(), validExecRequest())
			if !l4ProtocolErrorCode(err, ErrorCodeInvalidMetadata) {
				t.Fatalf("Exec() error = %v, want %s", err, ErrorCodeInvalidMetadata)
			}
		})
	}
}

func TestL4ClientRejectsNonCanonicalBase64Data(t *testing.T) {
	for _, data := range []string{"Z\nA==", "ZE=="} {
		t.Run(fmt.Sprintf("%q", data), func(t *testing.T) {
			response := `{"protocolVersion":"guest-agent-v1","operation":"exec","exitCode":0,` +
				`"stdout":{"sizeBytes":1,"maxBytes":1024,"encoding":"base64","data":` +
				fmt.Sprintf("%q", data) + `},"stderr":{"maxBytes":1024}}`
			client := l4ReadinessClient(t, []byte(response))
			_, err := client.Exec(context.Background(), validExecRequest())
			if !l4ProtocolErrorCode(err, ErrorCodeInvalidMetadata) {
				t.Fatalf("Exec() error = %v, want %s", err, ErrorCodeInvalidMetadata)
			}
		})
	}
}

func TestL4ClientRejectsPaddedProtocolVersion(t *testing.T) {
	client := l4ReadinessClient(
		t,
		[]byte(`{"protocolVersion":" guest-agent-v1 ","operation":"readiness","ready":true,"status":"ready"}`),
	)
	_, err := client.Readiness(context.Background(), ReadinessRequest{})
	if !l4ProtocolErrorCode(err, ErrorCodeUnsupportedProtocolVersion) {
		t.Fatalf("Readiness() error = %v, want %s", err, ErrorCodeUnsupportedProtocolVersion)
	}
}

func TestL4ClientAcceptsGenericKnownOperationError(t *testing.T) {
	encoded, err := json.Marshal(ErrorResponse{
		ProtocolVersion: ProtocolVersionV1,
		Operation:       OperationReadiness,
		Error: &ProtocolError{
			Code:      ErrorCodeServerNotReady,
			Operation: OperationReadiness,
			Field:     "server",
			Message:   "guest agent server is not ready",
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	client := l4ReadinessClient(t, encoded)
	_, err = client.Readiness(context.Background(), ReadinessRequest{})
	if !l4ProtocolErrorCode(err, ErrorCodeServerNotReady) {
		t.Fatalf("Readiness() error = %v, want %s", err, ErrorCodeServerNotReady)
	}
}

func TestL4ClientPreservesOperationlessGenericErrorCode(t *testing.T) {
	tests := []ErrorCode{
		ErrorCodeMalformedRequest,
		ErrorCodeOversizedRequest,
		ErrorCodeMissingRequiredField,
		ErrorCodeUnsupportedProtocolVersion,
		ErrorCodeUnknownOperation,
		ErrorCodeInternalFailure,
	}
	for _, code := range tests {
		t.Run(string(code), func(t *testing.T) {
			encoded, err := json.Marshal(ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Error: &ProtocolError{
					Code:  code,
					Field: "request",
				},
			})
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			client := l4ReadinessClient(t, encoded)
			_, err = client.Readiness(context.Background(), ReadinessRequest{})
			if !l4ProtocolErrorCode(err, code) {
				t.Fatalf("Readiness() error = %v, want %s", err, code)
			}
		})
	}
}

func TestL4ClientRejectsOperationlessMutationOutcomeError(t *testing.T) {
	tests := []ErrorCode{
		ErrorCodeMalformedPath,
		ErrorCodeInvalidTimeout,
		ErrorCodeInvalidDeadline,
		ErrorCodeOversizedPayloadMetadata,
		ErrorCodeInvalidMetadata,
		ErrorCodeOversizedResponse,
		ErrorCodeRequestCanceled,
		ErrorCodeRequestTimeout,
		ErrorCodeServerNotReady,
		ErrorCodeServerBusy,
		ErrorCodeEnvironmentUnavailable,
		ErrorCodeExecutionFailed,
		ErrorCodeCopyFailed,
		ErrorCodeDigestMismatch,
		ErrorCodeResourceChanged,
		ErrorCodeDurabilityUncertain,
		ErrorCodeBackendUnavailable,
		ErrorCodeUnsupportedPlatform,
	}
	for _, code := range tests {
		t.Run(string(code), func(t *testing.T) {
			encoded, err := json.Marshal(ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Error: &ProtocolError{
					Code:  code,
					Field: "copy",
				},
			})
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			client := l4ReadinessClient(t, encoded)
			_, err = client.CopyIn(context.Background(), CopyInRequest{
				DestinationPath: "/workspace/input",
				Payload: PayloadMetadata{
					MaxBytes: 1024,
					Encoding: PayloadEncodingBase64,
				},
			})
			if !l4ProtocolErrorCode(err, ErrorCodeMalformedResponse) {
				t.Fatalf("CopyIn() error = %v, want %s", err, ErrorCodeMalformedResponse)
			}
		})
	}
}

func TestL4ClientRejectsInvalidGenericErrorEnvelope(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "nested operation does not match envelope",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"server_not_ready","operation":"copy_in"}}`,
		},
		{
			name:     "known operation has unsupported error code",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"future_error","operation":"readiness"}}`,
		},
		{
			name:     "known operation has missing error code",
			response: `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"operation":"readiness"}}`,
		},
		{
			name:     "operationless error has unsupported code",
			response: `{"protocolVersion":"guest-agent-v1","error":{"code":"future_error","field":"request"}}`,
		},
		{
			name:     "operationless error has missing code",
			response: `{"protocolVersion":"guest-agent-v1","error":{"field":"request"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := l4ReadinessClient(t, []byte(tt.response))
			_, err := client.Readiness(context.Background(), ReadinessRequest{})
			if !l4ProtocolErrorCode(err, ErrorCodeMalformedResponse) {
				t.Fatalf("Readiness() error = %v, want %s", err, ErrorCodeMalformedResponse)
			}
		})
	}
}

func l4ReadinessClient(t *testing.T, response []byte) *Client {
	t.Helper()

	client, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
			return TransportResponse{Encoded: response}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	return client
}

func l4ProtocolErrorCode(err error, want ErrorCode) bool {
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == want
}
