package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const (
	DefaultGuestAgentExecStdinLimitBytes   int64 = 512 << 10
	DefaultGuestAgentExecStdoutLimitBytes  int64 = 256 << 10
	DefaultGuestAgentExecStderrLimitBytes  int64 = 256 << 10
	DefaultGuestAgentCopyPayloadLimitBytes int64 = 512 << 10
)

var errGuestAgentClientRequired = errors.New("guest agent client is required")

// GuestAgentClient is the host-side protocol client boundary used by the
// Firecracker guest transport adapter.
type GuestAgentClient interface {
	Exec(context.Context, guestagent.ExecRequest) (*guestagent.ExecResponse, error)
	CopyIn(context.Context, guestagent.CopyInRequest) (*guestagent.CopyInResponse, error)
	CopyOut(context.Context, guestagent.CopyOutRequest) (*guestagent.CopyOutResponse, error)
}

// GuestAgentTransportOptions configures the Firecracker guest-agent transport
// adapter. Limit fields default to conservative bounded values when omitted.
type GuestAgentTransportOptions struct {
	Client                   GuestAgentClient
	ExecStdinLimitBytes      int64
	ExecStdoutLimitBytes     int64
	ExecStderrLimitBytes     int64
	CopyInPayloadLimitBytes  int64
	CopyOutPayloadLimitBytes int64
	Timing                   *guestagent.TimingMetadata
}

// GuestAgentTransport adapts Firecracker guest exec and copy requests onto the
// versioned guest-agent protocol client.
type GuestAgentTransport struct {
	client                   GuestAgentClient
	execStdinLimitBytes      int64
	execStdoutLimitBytes     int64
	execStderrLimitBytes     int64
	copyInPayloadLimitBytes  int64
	copyOutPayloadLimitBytes int64
	timing                   *guestagent.TimingMetadata
}

var _ firecracker.GuestTransport = (*GuestAgentTransport)(nil)

// NewGuestAgentTransport constructs a Firecracker guest transport over an
// injected guest-agent client. A nil client makes operations fail with a
// redaction-safe protocol error.
func NewGuestAgentTransport(options GuestAgentTransportOptions) *GuestAgentTransport {
	return &GuestAgentTransport{
		client:                   options.Client,
		execStdinLimitBytes:      guestAgentTransportLimit(options.ExecStdinLimitBytes, DefaultGuestAgentExecStdinLimitBytes, guestagent.MaxStreamMetadataBytes),
		execStdoutLimitBytes:     guestAgentTransportLimit(options.ExecStdoutLimitBytes, DefaultGuestAgentExecStdoutLimitBytes, guestagent.MaxStreamMetadataBytes),
		execStderrLimitBytes:     guestAgentTransportLimit(options.ExecStderrLimitBytes, DefaultGuestAgentExecStderrLimitBytes, guestagent.MaxStreamMetadataBytes),
		copyInPayloadLimitBytes:  guestAgentTransportLimit(options.CopyInPayloadLimitBytes, DefaultGuestAgentCopyPayloadLimitBytes, guestagent.MaxCopyPayloadMetadataBytes),
		copyOutPayloadLimitBytes: guestAgentTransportLimit(options.CopyOutPayloadLimitBytes, DefaultGuestAgentCopyPayloadLimitBytes, guestagent.MaxCopyPayloadMetadataBytes),
		timing:                   cloneGuestAgentTransportTiming(options.Timing),
	}
}

// Exec translates a Firecracker guest exec request to the guest-agent exec
// protocol and writes bounded captured stdout/stderr to the supplied writers.
func (transport *GuestAgentTransport) Exec(ctx context.Context, req firecracker.GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	client, err := transport.clientFor(guestagent.OperationExec)
	if err != nil {
		return nil, err
	}
	protocolReq, err := transport.execRequest(req)
	if err != nil {
		return nil, err
	}
	response, err := client.Exec(nonNilContext(ctx), protocolReq)
	if err != nil {
		return nil, guestAgentTransportClientError(ctx, guestagent.OperationExec, err)
	}
	if response == nil {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedResponse, guestagent.OperationExec, "response", errors.New("guest agent returned no exec response"))
	}

	result := &sandboxruntime.ExecResult{ExitCode: response.ExitCode}
	if response.Error != nil {
		return result, response.Error
	}
	if err := guestagent.ValidateExecResponse(*response); err != nil {
		return result, err
	}
	if err := validateGuestAgentTransportStreamLimit(guestagent.OperationExec, "stdout", response.Stdout, transport.execStdoutLimit()); err != nil {
		return result, err
	}
	if err := validateGuestAgentTransportStreamLimit(guestagent.OperationExec, "stderr", response.Stderr, transport.execStderrLimit()); err != nil {
		return result, err
	}
	if err := writeGuestAgentTransportOutput(req.Stdout, "stdout", response.Stdout.Data); err != nil {
		return result, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationExec, "stdout", err)
	}
	if err := writeGuestAgentTransportOutput(req.Stderr, "stderr", response.Stderr.Data); err != nil {
		return result, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationExec, "stderr", err)
	}
	return result, nil
}

// CopyIn translates a Firecracker copy-in request to the guest-agent copy-in
// protocol. Host-local source paths are intentionally not sent to the guest.
func (transport *GuestAgentTransport) CopyIn(ctx context.Context, req firecracker.GuestCopyRequest) error {
	client, err := transport.clientFor(guestagent.OperationCopyIn)
	if err != nil {
		return err
	}
	protocolReq := guestagent.CopyInRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyIn,
		DestinationPath: req.DestinationPath,
		Payload: guestagent.PayloadMetadata{
			MaxBytes: transport.copyInPayloadLimit(),
			Encoding: guestagent.PayloadEncodingRaw,
		},
		Timing: transport.timingMetadata(),
	}
	if err := guestagent.ValidateCopyInRequest(protocolReq); err != nil {
		return err
	}
	response, err := client.CopyIn(nonNilContext(ctx), protocolReq)
	if err != nil {
		return guestAgentTransportClientError(ctx, guestagent.OperationCopyIn, err)
	}
	if response == nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedResponse, guestagent.OperationCopyIn, "response", errors.New("guest agent returned no copy_in response"))
	}
	if response.Error != nil {
		return response.Error
	}
	if err := guestagent.ValidateCopyInResponse(*response); err != nil {
		return err
	}
	return validateGuestAgentTransportPayloadLimit(guestagent.OperationCopyIn, "written", response.Written, transport.copyInPayloadLimit())
}

// CopyOut translates a Firecracker copy-out request to the guest-agent copy-out
// protocol. Host-local destination paths are intentionally not sent to the
// guest.
func (transport *GuestAgentTransport) CopyOut(ctx context.Context, req firecracker.GuestCopyRequest) error {
	client, err := transport.clientFor(guestagent.OperationCopyOut)
	if err != nil {
		return err
	}
	protocolReq := guestagent.CopyOutRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		SourcePath:      req.SourcePath,
		Payload: guestagent.PayloadMetadata{
			MaxBytes: transport.copyOutPayloadLimit(),
			Encoding: guestagent.PayloadEncodingRaw,
		},
		Timing: transport.timingMetadata(),
	}
	if err := guestagent.ValidateCopyOutRequest(protocolReq); err != nil {
		return err
	}
	response, err := client.CopyOut(nonNilContext(ctx), protocolReq)
	if err != nil {
		return guestAgentTransportClientError(ctx, guestagent.OperationCopyOut, err)
	}
	if response == nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedResponse, guestagent.OperationCopyOut, "response", errors.New("guest agent returned no copy_out response"))
	}
	if response.Error != nil {
		return response.Error
	}
	if err := guestagent.ValidateCopyOutResponse(*response); err != nil {
		return err
	}
	return validateGuestAgentTransportPayloadLimit(guestagent.OperationCopyOut, "payload", response.Payload, transport.copyOutPayloadLimit())
}

func (transport *GuestAgentTransport) execRequest(req firecracker.GuestExecRequest) (guestagent.ExecRequest, error) {
	protocolReq := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            append([]string(nil), req.Args...),
		Env:             guestAgentTransportEnvironment(req.Env),
		WorkDir:         req.WorkDir,
		Stdout: guestagent.StreamMetadata{
			MaxBytes: transport.execStdoutLimit(),
		},
		Stderr: guestagent.StreamMetadata{
			MaxBytes: transport.execStderrLimit(),
		},
		Timing: transport.timingMetadata(),
	}
	if req.Stdin != nil {
		protocolReq.Stdin = &guestagent.StreamMetadata{
			MaxBytes: transport.execStdinLimit(),
		}
	}
	if err := guestagent.ValidateExecRequest(protocolReq); err != nil {
		return guestagent.ExecRequest{}, err
	}
	return protocolReq, nil
}

func (transport *GuestAgentTransport) clientFor(operation guestagent.Operation) (GuestAgentClient, error) {
	if transport == nil || transport.client == nil {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, operation, "client", errGuestAgentClientRequired)
	}
	return transport.client, nil
}

func guestAgentTransportEnvironment(env map[string]string) []guestagent.EnvironmentEntry {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]guestagent.EnvironmentEntry, 0, len(keys))
	for _, key := range keys {
		source := guestagent.EnvironmentSourceLiteral
		if guestAgentTransportSecretEnvName(key) {
			source = guestagent.EnvironmentSourceSecret
		}
		entries = append(entries, guestagent.EnvironmentEntry{
			Name:   key,
			Source: source,
		})
	}
	return entries
}

func guestAgentTransportSecretEnvName(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "CREDENTIAL", "AUTHORIZATION", "COOKIE"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func validateGuestAgentTransportStreamLimit(operation guestagent.Operation, field string, metadata guestagent.StreamMetadata, limit int64) error {
	if metadata.MaxBytes > limit || metadata.SizeBytes > limit || int64(len(metadata.Data)) > limit {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeOversizedPayloadMetadata, operation, field, errors.New("guest agent stream exceeds configured limit"))
	}
	return nil
}

func validateGuestAgentTransportPayloadLimit(operation guestagent.Operation, field string, metadata guestagent.PayloadMetadata, limit int64) error {
	if metadata.MaxBytes > limit || metadata.SizeBytes > limit {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeOversizedPayloadMetadata, operation, field, errors.New("guest agent payload exceeds configured limit"))
	}
	return nil
}

func writeGuestAgentTransportOutput(writer io.Writer, stream, data string) error {
	if writer == nil || data == "" {
		return nil
	}
	if _, err := io.WriteString(writer, data); err != nil {
		return fmt.Errorf("write exec %s: %w", stream, err)
	}
	return nil
}

func guestAgentTransportClientError(ctx context.Context, operation guestagent.Operation, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := nonNilContext(ctx).Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return guestAgentTransportContextError(operation, ctxErr)
	}
	if errors.Is(err, context.Canceled) {
		return guestAgentTransportContextError(operation, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return guestAgentTransportContextError(operation, context.DeadlineExceeded)
	}
	return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, operation, "transport", err)
}

func guestAgentTransportContextError(operation guestagent.Operation, err error) error {
	code := guestagent.ErrorCodeRequestCanceled
	message := "guest agent request canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = guestagent.ErrorCodeRequestTimeout
		message = "guest agent request timed out"
	}
	return &guestagent.ProtocolError{
		Code:      code,
		Operation: operation,
		Field:     "context",
		Message:   message,
		Err:       err,
	}
}

func guestAgentTransportProtocolError(code guestagent.ErrorCode, operation guestagent.Operation, field string, err error) error {
	return guestagent.NewProtocolError(code, operation, field, err)
}

func (transport *GuestAgentTransport) execStdinLimit() int64 {
	if transport == nil || transport.execStdinLimitBytes <= 0 {
		return DefaultGuestAgentExecStdinLimitBytes
	}
	return transport.execStdinLimitBytes
}

func (transport *GuestAgentTransport) execStdoutLimit() int64 {
	if transport == nil || transport.execStdoutLimitBytes <= 0 {
		return DefaultGuestAgentExecStdoutLimitBytes
	}
	return transport.execStdoutLimitBytes
}

func (transport *GuestAgentTransport) execStderrLimit() int64 {
	if transport == nil || transport.execStderrLimitBytes <= 0 {
		return DefaultGuestAgentExecStderrLimitBytes
	}
	return transport.execStderrLimitBytes
}

func (transport *GuestAgentTransport) copyInPayloadLimit() int64 {
	if transport == nil || transport.copyInPayloadLimitBytes <= 0 {
		return DefaultGuestAgentCopyPayloadLimitBytes
	}
	return transport.copyInPayloadLimitBytes
}

func (transport *GuestAgentTransport) copyOutPayloadLimit() int64 {
	if transport == nil || transport.copyOutPayloadLimitBytes <= 0 {
		return DefaultGuestAgentCopyPayloadLimitBytes
	}
	return transport.copyOutPayloadLimitBytes
}

func (transport *GuestAgentTransport) timingMetadata() *guestagent.TimingMetadata {
	if transport == nil {
		return nil
	}
	return cloneGuestAgentTransportTiming(transport.timing)
}

func cloneGuestAgentTransportTiming(timing *guestagent.TimingMetadata) *guestagent.TimingMetadata {
	if timing == nil {
		return nil
	}
	copied := *timing
	return &copied
}

func guestAgentTransportLimit(value, fallback, maximum int64) int64 {
	if value <= 0 {
		return fallback
	}
	if maximum > 0 && value > maximum {
		return maximum
	}
	return value
}
