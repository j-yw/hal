package sandboxworker

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ExecRequest describes a bounded command execution request over the worker
// protocol.
type ExecRequest struct {
	OperationID      string            `json:"operationId"`
	Target           Target            `json:"target"`
	Args             []string          `json:"args"`
	Env              map[string]string `json:"env,omitempty"`
	WorkDir          string            `json:"workDir,omitempty"`
	Stdin            *ExecStdinPayload `json:"stdin,omitempty"`
	StdoutLimitBytes int64             `json:"stdoutLimitBytes"`
	StderrLimitBytes int64             `json:"stderrLimitBytes"`
}

// ExecStdinPayload carries optional bounded stdin content for an exec request.
type ExecStdinPayload struct {
	Data       string `json:"data"`
	Encoding   string `json:"encoding"`
	SizeBytes  int64  `json:"sizeBytes"`
	LimitBytes int64  `json:"limitBytes"`
}

// ExecResponse describes bounded command output and exit metadata returned by
// the worker protocol.
type ExecResponse struct {
	ExitCode int               `json:"exitCode"`
	Stdout   ExecOutputPayload `json:"stdout"`
	Stderr   ExecOutputPayload `json:"stderr"`
	Error    *Error            `json:"error,omitempty"`
}

// ExecOutputPayload carries one bounded captured output stream.
type ExecOutputPayload struct {
	Data       string `json:"data"`
	SizeBytes  int64  `json:"sizeBytes"`
	LimitBytes int64  `json:"limitBytes"`
	Truncated  bool   `json:"truncated"`
}

// Validate checks exec request metadata and bounded payload limits.
func (req ExecRequest) Validate() error {
	if err := validateWorkerIOOperationID(req.OperationID); err != nil {
		return err
	}
	if err := validateWorkerIOTarget(req.Target); err != nil {
		return err
	}
	if len(req.Args) == 0 || strings.TrimSpace(req.Args[0]) == "" {
		return workerIOValidationError("exec request args are required")
	}
	if req.Stdin != nil {
		if err := req.Stdin.Validate(); err != nil {
			return fmt.Errorf("exec request stdin: %w", err)
		}
	}
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    "exec stdout capture limit",
		Value:    req.StdoutLimitBytes,
		Maximum:  MaxExecStdoutCaptureBytes,
		Required: true,
	}); err != nil {
		return err
	}
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    "exec stderr capture limit",
		Value:    req.StderrLimitBytes,
		Maximum:  MaxExecStderrCaptureBytes,
		Required: true,
	}); err != nil {
		return err
	}
	return nil
}

// Validate checks bounded stdin payload metadata.
func (payload ExecStdinPayload) Validate() error {
	if strings.TrimSpace(payload.Encoding) == "" {
		return workerIOValidationError("exec stdin encoding is required")
	}
	if payload.Encoding != CopyPayloadEncodingBase64 {
		return workerIOValidationError("exec stdin encoding %q is unsupported", payload.Encoding)
	}
	if err := validateWorkerIOPayload(workerIOPayloadValidation{
		Field:           "exec stdin",
		SizeBytes:       payload.SizeBytes,
		LimitBytes:      payload.LimitBytes,
		MaximumBytes:    MaxExecStdinBytes,
		PayloadRequired: true,
	}); err != nil {
		return err
	}
	if len(payload.Data) > maxBase64EncodedPayloadLength(payload.LimitBytes) {
		return workerIOValidationError("exec stdin data exceeds encoded limit for %d bytes", payload.LimitBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return workerIOValidationError("exec stdin data is not valid %s", CopyPayloadEncodingBase64)
	}
	if int64(len(decoded)) != payload.SizeBytes {
		return workerIOValidationError("exec stdin sizeBytes %d does not match decoded data size %d bytes", payload.SizeBytes, len(decoded))
	}
	return nil
}

// Validate checks exec response output and optional command error metadata.
func (resp ExecResponse) Validate() error {
	if err := resp.Stdout.Validate(MaxExecStdoutCaptureBytes, "exec stdout"); err != nil {
		return err
	}
	if err := resp.Stderr.Validate(MaxExecStderrCaptureBytes, "exec stderr"); err != nil {
		return err
	}
	if resp.Error != nil {
		if err := resp.Error.Validate(); err != nil {
			return fmt.Errorf("exec response error: %w", err)
		}
	}
	return nil
}

// Validate checks one bounded exec output stream.
func (payload ExecOutputPayload) Validate(maximumBytes int64, field string) error {
	field = workerIOValidationField(field, "exec output")
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    field + " limit",
		Value:    payload.LimitBytes,
		Maximum:  maximumBytes,
		Required: true,
	}); err != nil {
		return err
	}
	if err := validateWorkerIOPayload(workerIOPayloadValidation{
		Field:        field,
		SizeBytes:    payload.SizeBytes,
		LimitBytes:   payload.LimitBytes,
		MaximumBytes: maximumBytes,
	}); err != nil {
		return err
	}
	return validatePayloadSizeMatchesData(field, payload.SizeBytes, payload.Data)
}

func validatePayloadSizeMatchesData(field string, sizeBytes int64, data string) error {
	actualSize := int64(len([]byte(data)))
	if actualSize != sizeBytes {
		return workerIOValidationError("%s sizeBytes %d does not match data size %d bytes", field, sizeBytes, actualSize)
	}
	return nil
}
