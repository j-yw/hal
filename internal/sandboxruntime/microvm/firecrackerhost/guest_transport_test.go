package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			Stdout:          guestagent.StreamMetadata{Data: "guest stdout\n", SizeBytes: 13, MaxBytes: 32},
			Stderr:          guestagent.StreamMetadata{Data: "guest stderr\n", SizeBytes: 13, MaxBytes: 16},
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
	if got.Stdin == nil || got.Stdin.MaxBytes != 8 {
		t.Fatalf("stdin metadata = %#v, want bounded stdin metadata", got.Stdin)
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

func TestGuestAgentTransportCopyInDelegatesGuestDestinationOnly(t *testing.T) {
	client := &recordingGuestAgentClient{
		copyInResponse: &guestagent.CopyInResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyIn,
			Written:         guestagent.PayloadMetadata{SizeBytes: 12, MaxBytes: 64, Encoding: guestagent.PayloadEncodingRaw},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:                  client,
		CopyInPayloadLimitBytes: 64,
	})

	err := transport.CopyIn(context.Background(), firecracker.GuestCopyRequest{
		Target:          sandboxruntime.Target{ID: "fc-alpha"},
		SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
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
	if got.Payload.MaxBytes != 64 || got.Payload.Encoding != guestagent.PayloadEncodingRaw {
		t.Fatalf("copy_in payload metadata = %#v, want configured raw payload limit", got.Payload)
	}
}

func TestGuestAgentTransportCopyOutDelegatesGuestSourceOnly(t *testing.T) {
	client := &recordingGuestAgentClient{
		copyOutResponse: &guestagent.CopyOutResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationCopyOut,
			Payload:         guestagent.PayloadMetadata{SizeBytes: 18, MaxBytes: 96, Encoding: guestagent.PayloadEncodingRaw},
		},
	}
	transport := NewGuestAgentTransport(GuestAgentTransportOptions{
		Client:                   client,
		CopyOutPayloadLimitBytes: 96,
	})

	err := transport.CopyOut(context.Background(), firecracker.GuestCopyRequest{
		Target:          sandboxruntime.Target{ID: "fc-alpha"},
		SourcePath:      "/workspace/output.txt",
		DestinationPath: "/Users/alice/private/output-token-ghp_secret.txt",
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
	if got.Payload.MaxBytes != 96 || got.Payload.Encoding != guestagent.PayloadEncodingRaw {
		t.Fatalf("copy_out payload metadata = %#v, want configured raw payload limit", got.Payload)
	}
}

func TestGuestAgentTransportExecRejectsOutputAboveConfiguredLimitsBeforeWriting(t *testing.T) {
	client := &recordingGuestAgentClient{
		execResponse: &guestagent.ExecResponse{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationExec,
			ExitCode:        0,
			Stdout:          guestagent.StreamMetadata{Data: "abcdef", SizeBytes: 6, MaxBytes: 6},
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
			Payload:         guestagent.PayloadMetadata{MaxBytes: DefaultGuestAgentCopyPayloadLimitBytes, Encoding: guestagent.PayloadEncodingRaw},
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
