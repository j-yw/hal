package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

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
var _ firecracker.GuestCopyPublicationError = (*guestAgentCopyPublicationError)(nil)

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
	if err := writeGuestAgentTransportOutput(req.Stdout, "stdout", response.Stdout); err != nil {
		return result, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationExec, "stdout", err)
	}
	if err := writeGuestAgentTransportOutput(req.Stderr, "stderr", response.Stderr); err != nil {
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
			Encoding: guestagent.PayloadEncodingBase64,
		},
		Timing: transport.timingMetadata(),
	}
	if err := guestagent.ValidateCopyInRequest(protocolReq); err != nil {
		return err
	}
	payload, err := readGuestAgentTransportCopyInPayload(req.SourcePath, transport.copyInPayloadLimit())
	if err != nil {
		return err
	}
	protocolReq.Payload = payload
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
		if publicationError := guestAgentCopyPublicationErrorFromClient(guestagent.OperationCopyIn, response.Error); publicationError != nil {
			return publicationError
		}
		return response.Error
	}
	if err := guestagent.ValidateCopyInResponse(*response); err != nil {
		return err
	}
	if err := validateGuestAgentTransportPayloadLimit(guestagent.OperationCopyIn, "written", response.Written, transport.copyInPayloadLimit()); err != nil {
		return err
	}
	if response.Written.SizeBytes != protocolReq.Payload.SizeBytes {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationCopyIn, "written.sizeBytes", errors.New("guest agent copy_in acknowledgement size mismatch"))
	}
	if response.Written.Digest == "" || response.Written.Digest != protocolReq.Payload.Digest {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationCopyIn, "written.digest", errors.New("guest agent copy_in acknowledgement digest mismatch"))
	}
	if response.Written.Encoding != guestagent.PayloadEncodingBase64 {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationCopyIn, "written.encoding", errors.New("guest agent copy_in acknowledgement encoding mismatch"))
	}
	return nil
}

// CopyOut translates a Firecracker copy-out request to the guest-agent copy-out
// protocol. Host-local destination paths are intentionally not sent to the
// guest.
func (transport *GuestAgentTransport) CopyOut(ctx context.Context, req firecracker.GuestCopyRequest) error {
	client, err := transport.clientFor(guestagent.OperationCopyOut)
	if err != nil {
		return err
	}
	destinationPath, err := validateGuestAgentTransportHostPath(guestagent.OperationCopyOut, "destinationPath", req.DestinationPath)
	if err != nil {
		return err
	}
	protocolReq := guestagent.CopyOutRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		SourcePath:      req.SourcePath,
		Payload: guestagent.PayloadMetadata{
			MaxBytes: transport.copyOutPayloadLimit(),
			Encoding: guestagent.PayloadEncodingBase64,
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
	if err := validateGuestAgentTransportPayloadLimit(guestagent.OperationCopyOut, "payload", response.Payload, transport.copyOutPayloadLimit()); err != nil {
		return err
	}
	data, err := decodeGuestAgentTransportPayload(guestagent.OperationCopyOut, "payload", response.Payload, transport.copyOutPayloadLimit())
	if err != nil {
		return err
	}
	return writeGuestAgentTransportCopyOutDestination(destinationPath, data)
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
		stdin, err := readGuestAgentTransportBounded(req.Stdin, transport.execStdinLimit(), guestagent.OperationExec, "stdin", "read exec stdin")
		if err != nil {
			return guestagent.ExecRequest{}, err
		}
		protocolReq.Stdin = &guestagent.StreamMetadata{
			SizeBytes: int64(len(stdin)),
			MaxBytes:  transport.execStdinLimit(),
			Data:      base64.StdEncoding.EncodeToString(stdin),
			Encoding:  guestagent.PayloadEncodingBase64,
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

func readGuestAgentTransportCopyInPayload(sourcePath string, limit int64) (guestagent.PayloadMetadata, error) {
	sourcePath, err := validateGuestAgentTransportHostPath(guestagent.OperationCopyIn, "sourcePath", sourcePath)
	if err != nil {
		return guestagent.PayloadMetadata{}, err
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		code := guestagent.ErrorCodeTransportFailure
		if os.IsNotExist(err) {
			code = guestagent.ErrorCodeMalformedPath
		}
		return guestagent.PayloadMetadata{}, guestAgentTransportProtocolError(code, guestagent.OperationCopyIn, "sourcePath", errors.New("copy_in source is unavailable"))
	}
	if !info.Mode().IsRegular() {
		return guestagent.PayloadMetadata{}, guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedPath, guestagent.OperationCopyIn, "sourcePath", errors.New("copy_in source must be a regular file"))
	}
	if info.Size() > limit {
		return guestagent.PayloadMetadata{}, guestAgentTransportProtocolError(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyIn, "payload", errors.New("copy_in source exceeds configured payload limit"))
	}

	file, err := os.Open(sourcePath)
	if err != nil {
		return guestagent.PayloadMetadata{}, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyIn, "sourcePath", errors.New("copy_in source is unreadable"))
	}
	defer file.Close()

	data, err := readGuestAgentTransportBounded(file, limit, guestagent.OperationCopyIn, "payload", "read copy_in source")
	if err != nil {
		return guestagent.PayloadMetadata{}, err
	}
	return guestAgentTransportPayloadFromBytes(data, limit), nil
}

func readGuestAgentTransportBounded(reader io.Reader, limit int64, operation guestagent.Operation, field, action string) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, operation, field, fmt.Errorf("%s failed", action))
	}
	if int64(len(data)) > limit {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeOversizedPayloadMetadata, operation, field, errors.New("payload exceeds configured byte limit"))
	}
	return data, nil
}

func validateGuestAgentTransportHostPath(operation guestagent.Operation, field, value string) (string, error) {
	path := strings.TrimSpace(value)
	if path == "" {
		return "", guestAgentTransportProtocolError(guestagent.ErrorCodeMissingRequiredField, operation, field, errors.New("host path is required"))
	}
	if !utf8.ValidString(path) ||
		containsGuestAgentTransportControl(path) ||
		strings.Contains(path, "://") ||
		strings.Contains(path, "\\") ||
		!filepath.IsAbs(path) ||
		path == string(filepath.Separator) ||
		filepath.Clean(path) != path ||
		containsGuestAgentTransportParentSegment(path) {
		return "", guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedPath, operation, field, errors.New("host path is unsafe"))
	}
	return path, nil
}

func containsGuestAgentTransportParentSegment(path string) bool {
	for _, segment := range strings.Split(path, string(filepath.Separator)) {
		if segment == ".." {
			return true
		}
	}
	return false
}

func containsGuestAgentTransportControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func guestAgentTransportPayloadFromBytes(data []byte, limit int64) guestagent.PayloadMetadata {
	sum := sha256.Sum256(data)
	return guestagent.PayloadMetadata{
		SizeBytes: int64(len(data)),
		MaxBytes:  limit,
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Encoding:  guestagent.PayloadEncodingBase64,
		Data:      base64.StdEncoding.EncodeToString(data),
	}
}

func decodeGuestAgentTransportPayload(operation guestagent.Operation, field string, payload guestagent.PayloadMetadata, limit int64) ([]byte, error) {
	if payload.Encoding != guestagent.PayloadEncodingBase64 {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".encoding", errors.New("guest agent payload encoding is unsupported"))
	}
	if payload.Data == "" && payload.SizeBytes > 0 {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".data", errors.New("guest agent payload data is missing"))
	}
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".data", errors.New("guest agent payload data is malformed"))
	}
	if int64(len(data)) != payload.SizeBytes {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".sizeBytes", errors.New("guest agent payload size mismatch"))
	}
	if int64(len(data)) > limit {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeOversizedPayloadMetadata, operation, field, errors.New("guest agent payload exceeds configured limit"))
	}
	if payload.Digest != "" && !strings.EqualFold(payload.Digest, guestAgentTransportDigest(data)) {
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".digest", errors.New("guest agent payload digest mismatch"))
	}
	return data, nil
}

func decodeGuestAgentTransportStream(operation guestagent.Operation, field string, stream guestagent.StreamMetadata) ([]byte, error) {
	switch stream.Encoding {
	case "", guestagent.PayloadEncodingRaw:
		return []byte(stream.Data), nil
	case guestagent.PayloadEncodingBase64:
		data, err := base64.StdEncoding.DecodeString(stream.Data)
		if err != nil {
			return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".data", errors.New("guest agent stream data is malformed"))
		}
		return data, nil
	default:
		return nil, guestAgentTransportProtocolError(guestagent.ErrorCodeInvalidMetadata, operation, field+".encoding", errors.New("guest agent stream encoding is unsupported"))
	}
}

func guestAgentTransportDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateGuestAgentTransportStreamLimit(operation guestagent.Operation, field string, metadata guestagent.StreamMetadata, limit int64) error {
	dataSize := int64(0)
	if metadata.Data != "" {
		data, err := decodeGuestAgentTransportStream(operation, field, metadata)
		if err != nil {
			return err
		}
		dataSize = int64(len(data))
	}
	if metadata.MaxBytes > limit || metadata.SizeBytes > limit || dataSize > limit {
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

func writeGuestAgentTransportOutput(writer io.Writer, stream string, metadata guestagent.StreamMetadata) error {
	if writer == nil || metadata.Data == "" {
		return nil
	}
	data, err := decodeGuestAgentTransportStream(guestagent.OperationExec, stream, metadata)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write exec %s: %w", stream, err)
	}
	return nil
}

func writeGuestAgentTransportCopyOutDestination(destinationPath string, data []byte) error {
	if err := validateGuestAgentTransportCopyOutDestination(destinationPath); err != nil {
		return err
	}
	destinationDir := filepath.Dir(destinationPath)
	tmp, err := os.CreateTemp(destinationDir, "."+filepath.Base(destinationPath)+".tmp-*")
	if err != nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("prepare copy_out destination"))
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", fmt.Errorf("write copy_out destination: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", fmt.Errorf("write copy_out destination: %w", err))
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("write copy_out destination"))
	}
	if err := os.Rename(tmpPath, destinationPath); err != nil {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("write copy_out destination"))
	}
	removeTmp = false
	return nil
}

func validateGuestAgentTransportCopyOutDestination(destinationPath string) error {
	destinationDir := filepath.Dir(destinationPath)
	if info, err := os.Lstat(destinationDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedPath, guestagent.OperationCopyOut, "destinationPath", errors.New("copy_out destination directory is unsafe"))
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(destinationDir, 0o700); err != nil {
			return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("prepare copy_out destination"))
		}
	} else {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("prepare copy_out destination"))
	}
	if info, err := os.Lstat(destinationPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return guestAgentTransportProtocolError(guestagent.ErrorCodeMalformedPath, guestagent.OperationCopyOut, "destinationPath", errors.New("copy_out destination is unsafe"))
		}
	} else if !os.IsNotExist(err) {
		return guestAgentTransportProtocolError(guestagent.ErrorCodeTransportFailure, guestagent.OperationCopyOut, "destinationPath", errors.New("prepare copy_out destination"))
	}
	return nil
}

func guestAgentTransportClientError(ctx context.Context, operation guestagent.Operation, err error) error {
	if err == nil {
		return nil
	}
	if publicationError := guestAgentCopyPublicationErrorFromClient(operation, err); publicationError != nil {
		return publicationError
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

type guestAgentCopyPublicationError struct {
	protocolError *guestagent.ProtocolError
}

func (err *guestAgentCopyPublicationError) Error() string {
	if err == nil || err.protocolError == nil {
		return ""
	}
	return err.protocolError.Error()
}

func (err *guestAgentCopyPublicationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.protocolError
}

func (*guestAgentCopyPublicationError) CopyPublicationDurabilityUncertain() bool {
	return true
}

func guestAgentCopyPublicationErrorFromClient(operation guestagent.Operation, err error) error {
	if operation != guestagent.OperationCopyIn {
		return nil
	}
	protocolError, ok := err.(*guestagent.ProtocolError)
	if !ok ||
		protocolError == nil ||
		protocolError.Code != guestagent.ErrorCodeDurabilityUncertain ||
		protocolError.Operation != guestagent.OperationCopyIn {
		return nil
	}
	return &guestAgentCopyPublicationError{
		protocolError: &guestagent.ProtocolError{
			Code:      guestagent.ErrorCodeDurabilityUncertain,
			Operation: guestagent.OperationCopyIn,
			Field:     "copy",
			Message:   "copy publication durability is uncertain",
			Err:       guestagent.ErrProtocolValidation,
		},
	}
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
