package guestagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientUsesFakeTransportForReadinessExecAndCopyRequests(t *testing.T) {
	var operations []Operation
	client, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(_ context.Context, request TransportRequest) (TransportResponse, error) {
			operations = append(operations, request.Operation)
			if request.ProtocolVersion != ProtocolVersionV1 {
				t.Fatalf("transport protocolVersion = %q, want %q", request.ProtocolVersion, ProtocolVersionV1)
			}
			if request.MaxResponseBytes != DefaultMaxEncodedResponseBytes {
				t.Fatalf("transport maxResponseBytes = %d, want default", request.MaxResponseBytes)
			}
			switch request.Operation {
			case OperationReadiness:
				var decoded ReadinessRequest
				decodeClientRequest(t, request.Encoded, &decoded)
				if decoded.ProtocolVersion != ProtocolVersionV1 || decoded.Operation != OperationReadiness {
					t.Fatalf("readiness request = %#v, want v1 readiness", decoded)
				}
				return encodeClientResponse(t, ReadinessResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationReadiness,
					Ready:           true,
					Status:          ReadinessStatusReady,
				}), nil
			case OperationExec:
				var decoded ExecRequest
				decodeClientRequest(t, request.Encoded, &decoded)
				if got := strings.Join(decoded.Args, " "); got != "sh -lc printf ok" {
					t.Fatalf("exec args = %q, want command metadata", got)
				}
				if decoded.WorkDir != "/workspace/project" || decoded.Stdout.MaxBytes != 1024 || decoded.Stderr.MaxBytes != 1024 {
					t.Fatalf("exec request = %#v, want bounded metadata", decoded)
				}
				if decoded.Stdin == nil || decoded.Stdin.Encoding != PayloadEncodingBase64 || decoded.Stdin.Data == "" {
					t.Fatalf("exec stdin = %#v, want bounded base64 content", decoded.Stdin)
				}
				return encodeClientResponse(t, ExecResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationExec,
					ExitCode:        7,
					Stdout:          StreamMetadata{SizeBytes: 2, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: base64.StdEncoding.EncodeToString([]byte("ok"))},
					Stderr:          StreamMetadata{SizeBytes: 3, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: base64.StdEncoding.EncodeToString([]byte("err"))},
				}), nil
			case OperationCopyIn:
				var decoded CopyInRequest
				decodeClientRequest(t, request.Encoded, &decoded)
				if decoded.DestinationPath != "/workspace/input.txt" || decoded.Payload.SizeBytes != 12 || decoded.Payload.Data == "" || decoded.Payload.Encoding != PayloadEncodingBase64 {
					t.Fatalf("copy_in request = %#v, want guest destination and payload content", decoded)
				}
				return encodeClientResponse(t, CopyInResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyIn,
					Written:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024, Encoding: PayloadEncodingBase64},
				}), nil
			case OperationCopyOut:
				var decoded CopyOutRequest
				decodeClientRequest(t, request.Encoded, &decoded)
				if decoded.SourcePath != "/workspace/output.txt" || decoded.Payload.MaxBytes != 2048 {
					t.Fatalf("copy_out request = %#v, want guest source and payload limit", decoded)
				}
				return encodeClientResponse(t, CopyOutResponse{
					ProtocolVersion: ProtocolVersionV1,
					Operation:       OperationCopyOut,
					Payload:         PayloadMetadata{SizeBytes: 18, MaxBytes: 2048, Encoding: PayloadEncodingBase64, Data: base64.StdEncoding.EncodeToString([]byte("copy-out-payload!!"))},
				}), nil
			default:
				t.Fatalf("unexpected operation %q", request.Operation)
				return TransportResponse{}, nil
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	readiness, err := client.Readiness(context.Background(), ReadinessRequest{Timing: &TimingMetadata{TimeoutMillis: 5000}})
	if err != nil {
		t.Fatalf("Readiness() error: %v", err)
	}
	if !readiness.Ready || readiness.Status != ReadinessStatusReady {
		t.Fatalf("Readiness() = %#v, want ready response", readiness)
	}

	execResponse, err := client.Exec(context.Background(), validExecRequest())
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if execResponse.ExitCode != 7 || execResponse.Stdout.SizeBytes != 2 || execResponse.Stderr.SizeBytes != 3 {
		t.Fatalf("Exec() response = %#v, want fake exec result", execResponse)
	}

	copyInResponse, err := client.CopyIn(context.Background(), CopyInRequest{
		DestinationPath: "/workspace/input.txt",
		Payload:         PayloadMetadata{SizeBytes: 12, MaxBytes: 1024, Encoding: PayloadEncodingBase64, Data: base64.StdEncoding.EncodeToString([]byte("copy payload"))},
	})
	if err != nil {
		t.Fatalf("CopyIn() error: %v", err)
	}
	if copyInResponse.Written.SizeBytes != 12 {
		t.Fatalf("CopyIn() response = %#v, want written metadata", copyInResponse)
	}

	copyOutResponse, err := client.CopyOut(context.Background(), CopyOutRequest{
		SourcePath: "/workspace/output.txt",
		Payload:    PayloadMetadata{MaxBytes: 2048, Encoding: PayloadEncodingBase64},
	})
	if err != nil {
		t.Fatalf("CopyOut() error: %v", err)
	}
	if copyOutResponse.Payload.SizeBytes != 18 {
		t.Fatalf("CopyOut() response = %#v, want payload metadata", copyOutResponse)
	}

	want := []Operation{OperationReadiness, OperationExec, OperationCopyIn, OperationCopyOut}
	if len(operations) != len(want) {
		t.Fatalf("operations = %#v, want %#v", operations, want)
	}
	for i := range want {
		if operations[i] != want[i] {
			t.Fatalf("operations = %#v, want %#v", operations, want)
		}
	}
}

func TestClientHonorsContextCancellationAndRequestDeadlines(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(ctx context.Context, _ TransportRequest) (TransportResponse, error) {
			called.Store(true)
			<-ctx.Done()
			return TransportResponse{}, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Readiness(canceledCtx, ReadinessRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Readiness(canceled) error = %v, want context.Canceled", err)
	}
	if called.Load() {
		t.Fatal("transport was called for already-canceled context")
	}

	if _, err := client.Readiness(context.Background(), ReadinessRequest{
		Timing: &TimingMetadata{TimeoutMillis: 1},
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Readiness(timeout) error = %v, want context deadline", err)
	}
	if !called.Load() {
		t.Fatal("transport was not called before request timeout")
	}

	deadlineClient, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(ctx context.Context, _ TransportRequest) (TransportResponse, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("transport context did not include request deadline")
			}
			if time.Until(deadline) > time.Second {
				t.Fatalf("transport deadline = %s, want request timeout deadline", deadline)
			}
			return encodeClientResponse(t, ReadinessResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationReadiness,
				Ready:           true,
				Status:          ReadinessStatusReady,
			}), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient(deadline) error: %v", err)
	}
	if _, err := deadlineClient.Readiness(context.Background(), ReadinessRequest{
		Timing: &TimingMetadata{TimeoutMillis: 500},
	}); err != nil {
		t.Fatalf("Readiness(deadline) error: %v", err)
	}
}

func TestClientCopyInPublishedOutcomeOutranksLateContext(t *testing.T) {
	payload := []byte("published payload")
	request := CopyInRequest{
		DestinationPath: "/workspace/published.txt",
		Payload: PayloadMetadata{
			SizeBytes: int64(len(payload)),
			MaxBytes:  1024,
			Encoding:  PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(payload),
		},
	}

	tests := []struct {
		name     string
		response TransportResponse
		wantCode ErrorCode
	}{
		{
			name: "published success",
			response: encodeClientResponse(t, CopyInResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyIn,
				Written: PayloadMetadata{
					SizeBytes: int64(len(payload)),
					MaxBytes:  1024,
					Encoding:  PayloadEncodingBase64,
				},
			}),
		},
		{
			name: "published durability uncertain",
			response: encodeClientResponse(t, ErrorResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyIn,
				Error: &ProtocolError{
					Code:      ErrorCodeDurabilityUncertain,
					Operation: OperationCopyIn,
					Field:     "copy",
					Message:   "copy publication durability is uncertain",
				},
			}),
			wantCode: ErrorCodeDurabilityUncertain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			client, err := NewClient(ClientOptions{
				Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
					cancel()
					return tt.response, nil
				}),
			})
			if err != nil {
				t.Fatalf("NewClient() error: %v", err)
			}

			response, err := client.CopyIn(ctx, request)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("CopyIn() error = %v, want published success", err)
				}
				if response == nil || response.Written.SizeBytes != int64(len(payload)) {
					t.Fatalf("CopyIn() response = %#v, want published metadata", response)
				}
				return
			}
			if !clientProtocolErrorCode(err, tt.wantCode) {
				t.Fatalf("CopyIn() error = %v, want %s", err, tt.wantCode)
			}
		})
	}
}

func TestClientEnforcesEncodedRequestAndResponseLimits(t *testing.T) {
	var called atomic.Bool
	requestLimitClient, err := NewClient(ClientOptions{
		MaxRequestBytes: 64,
		Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
			called.Store(true)
			return TransportResponse{}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient(request limit) error: %v", err)
	}
	if _, err := requestLimitClient.Exec(context.Background(), validExecRequest()); !clientProtocolErrorCode(err, ErrorCodeOversizedRequest) {
		t.Fatalf("Exec(oversized request) error = %v, want %s", err, ErrorCodeOversizedRequest)
	}
	if called.Load() {
		t.Fatal("transport was called for oversized encoded request")
	}

	responseLimitClient, err := NewClient(ClientOptions{
		MaxResponseBytes: 32,
		Transport: TransportFunc(func(_ context.Context, request TransportRequest) (TransportResponse, error) {
			if request.MaxResponseBytes != 32 {
				t.Fatalf("MaxResponseBytes = %d, want configured response limit", request.MaxResponseBytes)
			}
			return TransportResponse{Encoded: []byte(strings.Repeat("x", 33))}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient(response limit) error: %v", err)
	}
	if _, err := responseLimitClient.Readiness(context.Background(), ReadinessRequest{}); !clientProtocolErrorCode(err, ErrorCodeOversizedResponse) {
		t.Fatalf("Readiness(oversized response) error = %v, want %s", err, ErrorCodeOversizedResponse)
	}
}

func TestClientRejectsMalformedAndMismatchedResponses(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantCode ErrorCode
	}{
		{
			name:     "malformed json",
			response: []byte("{not-json\n"),
			wantCode: ErrorCodeMalformedResponse,
		},
		{
			name: "unsupported response version",
			response: encodedGuestAgentResponseForTest(ReadinessResponse{
				ProtocolVersion: "guest-agent-v2",
				Operation:       OperationReadiness,
				Ready:           true,
				Status:          ReadinessStatusReady,
			}),
			wantCode: ErrorCodeUnsupportedProtocolVersion,
		},
		{
			name: "operation mismatch",
			response: encodedGuestAgentResponseForTest(CopyInResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationCopyIn,
				Written:         PayloadMetadata{SizeBytes: 1, MaxBytes: 1},
			}),
			wantCode: ErrorCodeOperationMismatch,
		},
		{
			name: "missing required response field",
			response: encodedGuestAgentResponseForTest(ReadinessResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationReadiness,
				Status:          "launching",
			}),
			wantCode: ErrorCodeInvalidMetadata,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{
				Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
					return TransportResponse{Encoded: tt.response}, nil
				}),
			})
			if err != nil {
				t.Fatalf("NewClient() error: %v", err)
			}
			if _, err := client.Readiness(context.Background(), ReadinessRequest{}); !clientProtocolErrorCode(err, tt.wantCode) {
				t.Fatalf("Readiness() error = %v, want code %s", err, tt.wantCode)
			}
		})
	}
}

func TestClientReturnsRedactionSafePublicErrors(t *testing.T) {
	client, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
			return TransportResponse{}, fmt.Errorf(`dial unix /Users/alice/private/agent.sock for args "sh -lc curl https://secret.internal/path" Authorization: Bearer ghp_secret123 token=ghp_secret123 password=hunter2 body={"token":"secret"} socket /var/run/docker.sock 127.0.0.1:8080`)
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	req := validExecRequest()
	req.Args = []string{"sh", "-lc", "curl https://secret.internal/path token=ghp_secret123"}
	req.Env = []EnvironmentEntry{{Name: "GITHUB_TOKEN", Source: EnvironmentSourceSecret}}
	_, err = client.Exec(context.Background(), req)
	if err == nil {
		t.Fatal("Exec() error = nil, want transport error")
	}
	combined := strings.ToLower(err.Error())
	for _, forbidden := range []string{
		"/users/alice",
		"agent.sock",
		"secret.internal",
		"authorization",
		"bearer",
		"ghp_secret123",
		"hunter2",
		`"token":"secret"`,
		"/var/run/docker.sock",
		"127.0.0.1",
		"8080",
		"curl https://secret",
	} {
		if strings.Contains(combined, strings.ToLower(forbidden)) {
			t.Fatalf("client error leaked %q in %q", forbidden, combined)
		}
	}
	for _, want := range []string{"transport_failure", "[redacted"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("client error = %q, want %q", combined, want)
		}
	}
}

func TestClientSanitizesGuestProtocolErrorResponses(t *testing.T) {
	client, err := NewClient(ClientOptions{
		Transport: TransportFunc(func(context.Context, TransportRequest) (TransportResponse, error) {
			return encodeClientResponse(t, ReadinessResponse{
				ProtocolVersion: ProtocolVersionV1,
				Operation:       OperationReadiness,
				Error: NewProtocolError(
					ErrorCodeInvalidMetadata,
					OperationReadiness,
					"status",
					fmt.Errorf(`guest failed at https://secret.internal/path token=ghp_secret123 under /Users/alice/private body={"token":"secret"}`),
				),
			}), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Readiness(context.Background(), ReadinessRequest{})
	if !clientProtocolErrorCode(err, ErrorCodeInvalidMetadata) {
		t.Fatalf("Readiness() error = %v, want %s", err, ErrorCodeInvalidMetadata)
	}
	combined := strings.ToLower(err.Error())
	for _, forbidden := range []string{"secret.internal", "ghp_secret123", "/users/alice", `"token":"secret"`} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("guest protocol error leaked %q in %q", forbidden, combined)
		}
	}
}

func TestNewClientRejectsMissingTransport(t *testing.T) {
	if client, err := NewClient(ClientOptions{}); err == nil {
		t.Fatalf("NewClient() error = nil with client %#v, want missing transport error", client)
	}
	if client, err := NewClient(ClientOptions{Transport: TransportFunc(nil)}); err == nil {
		t.Fatalf("NewClient(nil func) error = nil with client %#v, want missing transport error", client)
	}
}

func decodeClientRequest(t *testing.T, encoded []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(encoded, out); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", encoded, err)
	}
}

func encodeClientResponse(t *testing.T, value any) TransportResponse {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	return TransportResponse{Encoded: encoded}
}

func encodedGuestAgentResponseForTest(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(strings.TrimSpace(err.Error()))
	}
	return encoded
}

func clientProtocolErrorCode(err error, want ErrorCode) bool {
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == want
}
