package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestGuestAgentTransportSatisfiesFirecrackerGuestTransport(t *testing.T) {
	var _ firecracker.GuestTransport = (*GuestAgentTransport)(nil)

	client := &recordingGuestAgentClient{
		execResponse: &guestagent.ExecResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationExec,
			ExitCode:        9,
			Stdout:          guestagent.StreamMetadata{MaxBytes: DefaultGuestAgentExecStdoutLimitBytes},
			Stderr:          guestagent.StreamMetadata{MaxBytes: DefaultGuestAgentExecStderrLimitBytes},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})

	result, err := transport.Exec(context.Background(), validGuestAgentTransportExecRequest())
	if err != nil {
		t.Fatalf("Exec() error = %v, want nil", err)
	}
	if result == nil || result.ExitCode != 9 {
		t.Fatalf("Exec() result = %#v, want exit code 9", result)
	}
}

func TestGuestAgentTransportExecDelegatesBoundedProtocolRequestAndPropagatesOutput(t *testing.T) {
	client := &recordingGuestAgentClient{
		execResponse: &guestagent.ExecResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationExec,
			ExitCode:        23,
			Stdout:          guestagent.StreamMetadata{Data: base64.StdEncoding.EncodeToString([]byte("guest stdout\n")), SizeBytes: 13, MaxBytes: 32, Encoding: guestagent.PayloadEncodingBase64},
			Stderr:          guestagent.StreamMetadata{Data: base64.StdEncoding.EncodeToString([]byte("guest stderr\n")), SizeBytes: 13, MaxBytes: 16, Encoding: guestagent.PayloadEncodingBase64},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:               client,
		ExecStdinLimitBytes:  8,
		ExecStdoutLimitBytes: 32,
		ExecStderrLimitBytes: 16,
		Timing:               &guestagent.TimingMetadata{TimeoutMillis: 2500},
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	req := validGuestAgentTransportExecRequest()
	req.Stdout = stdout
	req.Stderr = stderr
	req.Stdin = strings.NewReader("stdin")
	req.Env = map[string]string{
		"SAFE":         "value",
		"GITHUB_TOKEN": "ghp_secret_not_sent",
	}

	result, err := transport.Exec(context.Background(), req)
	if err != nil {
		t.Fatalf("Exec() error = %v, want nil", err)
	}
	if result == nil || result.ExitCode != 23 {
		t.Fatalf("Exec() result = %#v, want exit code 23", result)
	}
	if stdout.String() != "guest stdout\n" || stderr.String() != "guest stderr\n" {
		t.Fatalf("output stdout=%q stderr=%q, want guest-agent streams", stdout.String(), stderr.String())
	}
	if client.execCalls != 1 {
		t.Fatalf("guest-agent Exec calls = %d, want 1", client.execCalls)
	}

	got := client.execRequest
	if got.ProtocolVersion != guestagent.ProtocolVersionV1 || got.Operation != guestagent.OperationExec {
		t.Fatalf("protocol request header = %#v, want v1 exec", got)
	}
	if !reflect.DeepEqual(got.Args, req.Args) {
		t.Fatalf("exec args = %#v, want %#v", got.Args, req.Args)
	}
	if got.WorkDir != "/workspace/project" {
		t.Fatalf("workDir = %q, want guest workdir", got.WorkDir)
	}
	if got.Stdin == nil || got.Stdin.MaxBytes != 8 || got.Stdin.SizeBytes != 5 || got.Stdin.Encoding != guestagent.PayloadEncodingBase64 {
		t.Fatalf("stdin metadata = %#v, want bounded base64 stdin payload", got.Stdin)
	}
	stdin, err := base64.StdEncoding.DecodeString(got.Stdin.Data)
	if err != nil {
		t.Fatalf("stdin payload is not base64: %v", err)
	}
	if string(stdin) != "stdin" {
		t.Fatalf("stdin payload = %q, want request stdin bytes", string(stdin))
	}
	if got.Stdout.MaxBytes != 32 || got.Stderr.MaxBytes != 16 {
		t.Fatalf("output limits = stdout %d stderr %d, want configured limits", got.Stdout.MaxBytes, got.Stderr.MaxBytes)
	}
	if got.Timing == nil || got.Timing.TimeoutMillis != 2500 {
		t.Fatalf("timing = %#v, want cloned timeout", got.Timing)
	}
	wantEnv := []guestagent.EnvironmentEntry{
		{Name: "GITHUB_TOKEN", Source: guestagent.EnvironmentSourceSecret},
		{Name: "SAFE", Source: guestagent.EnvironmentSourceLiteral},
	}
	if !reflect.DeepEqual(got.Env, wantEnv) {
		t.Fatalf("env metadata = %#v, want names and safe sources only", got.Env)
	}
}

func TestGuestAgentTransportCopyInSendsBoundedHostSourceBytes(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "input.txt")
	payload := []byte("copy-in payload\n")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(source) error: %v", err)
	}
	client := &recordingGuestAgentClient{
		copyInResponse: &guestagent.CopyInResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyIn,
			Written:         guestagent.PayloadMetadata{SizeBytes: int64(len(payload)), MaxBytes: 64, Digest: guestAgentTransportDigest(payload), Encoding: guestagent.PayloadEncodingBase64},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:                  client,
		CopyInPayloadLimitBytes: 64,
	})

	err := transport.CopyIn(context.Background(), firecracker.GuestCopyRequest{
		Target:          sandboxruntime.Target{ID: "fc-alpha"},
		SourcePath:      sourcePath,
		DestinationPath: "/workspace/input.txt",
	})
	if err != nil {
		t.Fatalf("CopyIn() error = %v, want nil", err)
	}
	if client.copyInCalls != 1 {
		t.Fatalf("guest-agent CopyIn calls = %d, want 1", client.copyInCalls)
	}
	got := client.copyInRequest
	if got.ProtocolVersion != guestagent.ProtocolVersionV1 || got.Operation != guestagent.OperationCopyIn {
		t.Fatalf("copy_in header = %#v, want v1 copy_in", got)
	}
	if got.DestinationPath != "/workspace/input.txt" {
		t.Fatalf("copy_in destination = %q, want guest destination", got.DestinationPath)
	}
	if got.Payload.MaxBytes != 64 || got.Payload.SizeBytes != int64(len(payload)) || got.Payload.Encoding != guestagent.PayloadEncodingBase64 || got.Payload.Digest != guestAgentTransportDigest(payload) {
		t.Fatalf("copy_in payload metadata = %#v, want configured base64 payload", got.Payload)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Payload.Data)
	if err != nil {
		t.Fatalf("copy_in payload data is not base64: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("copy_in payload = %q, want host source bytes", string(decoded))
	}
}

func TestGuestAgentTransportCopyInPreservesPublishedDurabilityUncertainOutcome(t *testing.T) {
	for _, tt := range []struct {
		name     string
		asResult bool
	}{
		{name: "client error"},
		{name: "response error", asResult: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sourcePath := filepath.Join(t.TempDir(), "input.txt")
			if err := os.WriteFile(sourcePath, []byte("published payload"), 0o600); err != nil {
				t.Fatalf("WriteFile(source) error: %v", err)
			}
			protocolError := &guestagent.ProtocolError{
				Code:      guestagent.ErrorCodeDurabilityUncertain,
				Operation: guestagent.OperationCopyIn,
				Field:     "copy",
				Message:   "copy publication durability is uncertain",
				Err:       errors.New("fsync /Users/alice/private/token-ghp_secret.txt endpoint=unix:///tmp/guest.sock"),
			}
			client := validRecordingGuestAgentClient()
			if tt.asResult {
				client.copyInResponse = &guestagent.CopyInResponse{
					ProtocolVersion: guestagent.ProtocolVersionV1,
					Operation:       guestagent.OperationCopyIn,
					Error:           protocolError,
				}
			} else {
				client.copyInErr = protocolError
			}
			transport := NewGuestAgentTransport(GuestAgentTransportOptions{
				Client:                  client,
				CopyInPayloadLimitBytes: 64,
			})

			err := transport.CopyIn(context.Background(), firecracker.GuestCopyRequest{
				SourcePath:      sourcePath,
				DestinationPath: "/workspace/input.txt",
			})
			requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeDurabilityUncertain)

			var publicationError interface {
				CopyPublicationDurabilityUncertain() bool
			}
			if !errors.As(err, &publicationError) || !publicationError.CopyPublicationDurabilityUncertain() {
				t.Fatalf("CopyIn() error = %v, want machine-readable uncertain publication outcome", err)
			}
			assertGuestAgentTransportErrorDoesNotLeak(t, err,
				"/Users/alice",
				"ghp_secret",
				"unix://",
				"/tmp",
				"guest.sock",
			)
		})
	}
}

func TestGuestAgentTransportCopyOutWritesBoundedGuestPayloadBytes(t *testing.T) {
	destinationPath := filepath.Join(t.TempDir(), "nested", "output.txt")
	payload := []byte("copy-out payload\n")
	client := &recordingGuestAgentClient{
		copyOutResponse: &guestagent.CopyOutResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyOut,
			Payload:         guestAgentTransportPayloadFromBytes(payload, 96),
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:                   client,
		CopyOutPayloadLimitBytes: 96,
	})

	err := transport.CopyOut(context.Background(), firecracker.GuestCopyRequest{
		Target:          sandboxruntime.Target{ID: "fc-alpha"},
		SourcePath:      "/workspace/output.txt",
		DestinationPath: destinationPath,
	})
	if err != nil {
		t.Fatalf("CopyOut() error = %v, want nil", err)
	}
	if client.copyOutCalls != 1 {
		t.Fatalf("guest-agent CopyOut calls = %d, want 1", client.copyOutCalls)
	}
	got := client.copyOutRequest
	if got.ProtocolVersion != guestagent.ProtocolVersionV1 || got.Operation != guestagent.OperationCopyOut {
		t.Fatalf("copy_out header = %#v, want v1 copy_out", got)
	}
	if got.SourcePath != "/workspace/output.txt" {
		t.Fatalf("copy_out source = %q, want guest source", got.SourcePath)
	}
	if got.Payload.MaxBytes != 96 || got.Payload.Encoding != guestagent.PayloadEncodingBase64 || got.Payload.Data != "" {
		t.Fatalf("copy_out payload metadata = %#v, want configured base64 payload request without data", got.Payload)
	}
	written, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatalf("ReadFile(copy_out destination) error: %v", err)
	}
	if !bytes.Equal(written, payload) {
		t.Fatalf("copy_out destination = %q, want guest payload bytes", string(written))
	}
}

func TestGuestAgentTransportExecRejectsOutputAboveConfiguredLimitsBeforeWriting(t *testing.T) {
	client := &recordingGuestAgentClient{
		execResponse: &guestagent.ExecResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationExec,
			ExitCode:        0,
			Stdout:          guestagent.StreamMetadata{Data: base64.StdEncoding.EncodeToString([]byte("abcdef")), SizeBytes: 6, MaxBytes: 6, Encoding: guestagent.PayloadEncodingBase64},
			Stderr:          guestagent.StreamMetadata{MaxBytes: 5},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:               client,
		ExecStdoutLimitBytes: 5,
		ExecStderrLimitBytes: 5,
	})
	stdout := &bytes.Buffer{}
	req := validGuestAgentTransportExecRequest()
	req.Stdout = stdout

	result, err := transport.Exec(context.Background(), req)
	if result == nil || result.ExitCode != 0 {
		t.Fatalf("Exec() result = %#v, want bounded result even on response error", result)
	}
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeOversizedPayloadMetadata)
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want no data written after limit violation", stdout.String())
	}
}

func TestGuestAgentTransportExecRejectsOversizedStdinBeforeDispatch(t *testing.T) {
	client := validRecordingGuestAgentClient()
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:              client,
		ExecStdinLimitBytes: 8,
	})
	req := validGuestAgentTransportExecRequest()
	req.Stdin = strings.NewReader("123456789")

	result, err := transport.Exec(context.Background(), req)
	if result != nil {
		t.Fatalf("Exec() result = %#v, want nil before dispatch", result)
	}
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeOversizedPayloadMetadata)
	if client.execCalls != 0 {
		t.Fatalf("guest-agent Exec calls = %d, want no dispatch for oversized stdin", client.execCalls)
	}
	assertGuestAgentTransportErrorDoesNotLeak(t, err, "123456789")
}

func TestGuestAgentTransportCopyInRejectsUnsafeOrOversizedSourceBeforeDispatch(t *testing.T) {
	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing-token-ghp_secret.txt")
	directoryPath := filepath.Join(tempDir, "directory")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatalf("Mkdir(directory) error: %v", err)
	}
	oversizedPath := filepath.Join(tempDir, "oversized.txt")
	if err := os.WriteFile(oversizedPath, []byte("123456789"), 0o600); err != nil {
		t.Fatalf("WriteFile(oversized) error: %v", err)
	}

	tests := []struct {
		name       string
		sourcePath string
		wantCode   guestagent.ErrorCode
	}{
		{name: "missing", sourcePath: missingPath, wantCode: guestagent.ErrorCodeMalformedPath},
		{name: "directory", sourcePath: directoryPath, wantCode: guestagent.ErrorCodeMalformedPath},
		{name: "too large", sourcePath: oversizedPath, wantCode: guestagent.ErrorCodeOversizedPayloadMetadata},
		{name: "relative", sourcePath: "relative/token-ghp_secret.txt", wantCode: guestagent.ErrorCodeMalformedPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := validRecordingGuestAgentClient()
			transport := NewGuestAgentTransport(GuestAgentTransportOptions{
				Client:                  client,
				CopyInPayloadLimitBytes: 8,
			})
			err := transport.CopyIn(context.Background(), firecracker.GuestCopyRequest{
				SourcePath:      tt.sourcePath,
				DestinationPath: "/workspace/input.txt",
			})
			requireGuestAgentProtocolErrorCode(t, err, tt.wantCode)
			if client.copyInCalls != 0 {
				t.Fatalf("guest-agent CopyIn calls = %d, want no dispatch for invalid source", client.copyInCalls)
			}
			assertGuestAgentTransportErrorDoesNotLeak(t, err, tt.sourcePath, "ghp_secret", "123456789")
		})
	}
}

func TestGuestAgentTransportCopyOutRejectsUnsafeDestinationBeforeDispatch(t *testing.T) {
	client := validRecordingGuestAgentClient()
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})

	err := transport.CopyOut(context.Background(), firecracker.GuestCopyRequest{
		SourcePath:      "/workspace/output.txt",
		DestinationPath: "relative/output-token-ghp_secret.txt",
	})
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeMalformedPath)
	if client.copyOutCalls != 0 {
		t.Fatalf("guest-agent CopyOut calls = %d, want no dispatch for unsafe destination", client.copyOutCalls)
	}
	assertGuestAgentTransportErrorDoesNotLeak(t, err, "relative/output-token-ghp_secret.txt", "ghp_secret")
}

func TestGuestAgentTransportCopyOutRejectsMalformedPayloadBeforeWritingDestination(t *testing.T) {
	destinationPath := filepath.Join(t.TempDir(), "output-token-ghp_secret.txt")
	client := validRecordingGuestAgentClient()
	client.copyOutResponse = &guestagent.CopyOutResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		Payload:         guestagent.PayloadMetadata{SizeBytes: 4, MaxBytes: 64, Encoding: guestagent.PayloadEncodingBase64},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:                   client,
		CopyOutPayloadLimitBytes: 64,
	})

	err := transport.CopyOut(context.Background(), firecracker.GuestCopyRequest{
		SourcePath:      "/workspace/output.txt",
		DestinationPath: destinationPath,
	})
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeInvalidMetadata)
	if client.copyOutCalls != 1 {
		t.Fatalf("guest-agent CopyOut calls = %d, want one dispatch before malformed response", client.copyOutCalls)
	}
	if _, statErr := os.Stat(destinationPath); !os.IsNotExist(statErr) {
		t.Fatalf("copy_out destination stat error = %v, want no destination written", statErr)
	}
	assertGuestAgentTransportErrorDoesNotLeak(t, err, destinationPath, "ghp_secret")
}

func TestGuestAgentTransportRejectsMalformedGuestPathsBeforeDispatch(t *testing.T) {
	tests := []struct {
		name      string
		run       func(*GuestAgentTransport) error
		callCount func(*recordingGuestAgentClient) int
		wantCode  guestagent.ErrorCode
	}{
		{
			name: "empty exec workdir",
			run: func(transport *GuestAgentTransport) error {
				req := validGuestAgentTransportExecRequest()
				req.WorkDir = ""
				_, err := transport.Exec(context.Background(), req)
				return err
			},
			callCount: func(client *recordingGuestAgentClient) int { return client.execCalls },
			wantCode:  guestagent.ErrorCodeMissingRequiredField,
		},
		{
			name: "unsafe copy in destination",
			run: func(transport *GuestAgentTransport) error {
				return transport.CopyIn(context.Background(), firecracker.GuestCopyRequest{
					SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
					DestinationPath: "/workspace/../secret-token-ghp_secret.txt",
				})
			},
			callCount: func(client *recordingGuestAgentClient) int { return client.copyInCalls },
			wantCode:  guestagent.ErrorCodeMalformedPath,
		},
		{
			name: "url copy out source",
			run: func(transport *GuestAgentTransport) error {
				return transport.CopyOut(context.Background(), firecracker.GuestCopyRequest{
					SourcePath:      "https://secret.internal/private-output.sock",
					DestinationPath: "/Users/alice/private/output-token-ghp_secret.txt",
				})
			},
			callCount: func(client *recordingGuestAgentClient) int { return client.copyOutCalls },
			wantCode:  guestagent.ErrorCodeMalformedPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := validRecordingGuestAgentClient()
			transport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})
			err := tt.run(transport)
			requireGuestAgentProtocolErrorCode(t, err, tt.wantCode)
			if got := tt.callCount(client); got != 0 {
				t.Fatalf("client calls = %d, want no dispatch before validation succeeds", got)
			}
			assertGuestAgentTransportErrorDoesNotLeak(t, err,
				"/Users/alice",
				"ghp_secret",
				"secret.internal",
				"private-output.sock",
				"secret-token-ghp_secret.txt",
			)
		})
	}
}

func TestGuestAgentTransportPropagatesContextCancellationToClient(t *testing.T) {
	client := validRecordingGuestAgentClient()
	client.exec = func(ctx context.Context, _ guestagent.ExecRequest) (*guestagent.ExecResponse, error) {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("client context error = %v, want context.Canceled", ctx.Err())
		}
		return nil, ctx.Err()
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.Exec(ctx, validGuestAgentTransportExecRequest())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exec(canceled) error = %v, want context.Canceled", err)
	}
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeRequestCanceled)
	if client.execCalls != 1 {
		t.Fatalf("guest-agent Exec calls = %d, want canceled context propagated into client", client.execCalls)
	}
}

func TestGuestAgentTransportErrorsAreRedactionSafe(t *testing.T) {
	client := validRecordingGuestAgentClient()
	client.execErr = fmt.Errorf(`dial unix /Users/alice/private/agent.sock at https://secret.internal:9443/path Authorization: Bearer ghp_secret token=ghp_secret password=hunter2 body={"token":"secret"} socket /var/run/docker.sock payload=guest-body-secret`)
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})
	req := validGuestAgentTransportExecRequest()
	req.Env = map[string]string{"SECRET_TOKEN": "ghp_secret", "SAFE": "value"}
	req.Stdin = strings.NewReader("guest-body-secret")

	_, err := transport.Exec(context.Background(), req)
	requireGuestAgentProtocolErrorCode(t, err, guestagent.ErrorCodeTransportFailure)
	assertGuestAgentTransportErrorDoesNotLeak(t, err,
		"/Users/alice",
		"agent.sock",
		"secret.internal",
		"9443",
		"authorization",
		"bearer",
		"ghp_secret",
		"hunter2",
		`"token":"secret"`,
		"/var/run/docker.sock",
		"guest-body-secret",
	)
}

func validGuestAgentTransportExecRequest() firecracker.GuestExecRequest {
	return firecracker.GuestExecRequest{
		Target:  sandboxruntime.Target{ID: "fc-alpha", Name: "firecracker-alpha"},
		Args:    []string{"sh", "-lc", "printf ok"},
		WorkDir: "/workspace/project",
	}
}

func validRecordingGuestAgentClient() *recordingGuestAgentClient {
	return &recordingGuestAgentClient{
		execResponse: &guestagent.ExecResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationExec,
			ExitCode:        0,
			Stdout:          guestagent.StreamMetadata{MaxBytes: DefaultGuestAgentExecStdoutLimitBytes},
			Stderr:          guestagent.StreamMetadata{MaxBytes: DefaultGuestAgentExecStderrLimitBytes},
		},
		copyInResponse: &guestagent.CopyInResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyIn,
			Written:         guestagent.PayloadMetadata{MaxBytes: DefaultGuestAgentCopyPayloadLimitBytes, Encoding: guestagent.PayloadEncodingRaw},
		},
		copyOutResponse: &guestagent.CopyOutResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyOut,
			Payload:         guestagent.PayloadMetadata{MaxBytes: DefaultGuestAgentCopyPayloadLimitBytes, Encoding: guestagent.PayloadEncodingBase64},
		},
	}
}

type recordingGuestAgentClient struct {
	execCalls       int
	copyInCalls     int
	copyOutCalls    int
	execRequest     guestagent.ExecRequest
	copyInRequest   guestagent.CopyInRequest
	copyOutRequest  guestagent.CopyOutRequest
	execResponse    *guestagent.ExecResponse
	copyInResponse  *guestagent.CopyInResponse
	copyOutResponse *guestagent.CopyOutResponse
	execErr         error
	copyInErr       error
	copyOutErr      error
	exec            func(context.Context, guestagent.ExecRequest) (*guestagent.ExecResponse, error)
	copyIn          func(context.Context, guestagent.CopyInRequest) (*guestagent.CopyInResponse, error)
	copyOut         func(context.Context, guestagent.CopyOutRequest) (*guestagent.CopyOutResponse, error)
}

func (client *recordingGuestAgentClient) Exec(ctx context.Context, req guestagent.ExecRequest) (*guestagent.ExecResponse, error) {
	client.execCalls++
	client.execRequest = req
	if client.exec != nil {
		return client.exec(ctx, req)
	}
	if client.execErr != nil {
		return nil, client.execErr
	}
	return client.execResponse, nil
}

func (client *recordingGuestAgentClient) CopyIn(ctx context.Context, req guestagent.CopyInRequest) (*guestagent.CopyInResponse, error) {
	client.copyInCalls++
	client.copyInRequest = req
	if client.copyIn != nil {
		return client.copyIn(ctx, req)
	}
	if client.copyInErr != nil {
		return nil, client.copyInErr
	}
	return client.copyInResponse, nil
}

func (client *recordingGuestAgentClient) CopyOut(ctx context.Context, req guestagent.CopyOutRequest) (*guestagent.CopyOutResponse, error) {
	client.copyOutCalls++
	client.copyOutRequest = req
	if client.copyOut != nil {
		return client.copyOut(ctx, req)
	}
	if client.copyOutErr != nil {
		return nil, client.copyOutErr
	}
	return client.copyOutResponse, nil
}

func requireGuestAgentProtocolErrorCode(t *testing.T, err error, want guestagent.ErrorCode) {
	t.Helper()
	var protocolErr *guestagent.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("error = %v, want guest-agent protocol error code %s", err, want)
	}
	if protocolErr.Code != want {
		t.Fatalf("protocol error code = %s, want %s; error=%v", protocolErr.Code, want, err)
	}
}

func assertGuestAgentTransportErrorDoesNotLeak(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	combined := strings.ToLower(fmt.Sprint(err))
	for _, fragment := range forbidden {
		if strings.Contains(combined, strings.ToLower(fragment)) {
			t.Fatalf("error leaked %q in %q", fragment, combined)
		}
	}
}
