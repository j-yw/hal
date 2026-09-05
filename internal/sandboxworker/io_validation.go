package sandboxworker

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// Worker I/O payloads are intentionally bounded below the default socket
	// request/response caps so protocol handlers can reject unsafe requests
	// before dispatch.
	MaxExecStdinBytes         int64 = 512 << 10
	MaxExecStdoutCaptureBytes int64 = 256 << 10
	MaxExecStderrCaptureBytes int64 = 256 << 10
	MaxCopyInPayloadBytes     int64 = 512 << 10
	MaxCopyOutPayloadBytes    int64 = 512 << 10
)

type workerIOLimitValidation struct {
	Field    string
	Value    int64
	Maximum  int64
	Required bool
}

type workerIOPayloadValidation struct {
	Field           string
	SizeBytes       int64
	LimitBytes      int64
	MaximumBytes    int64
	PayloadRequired bool
}

func validateWorkerIOOperationID(operationID string) error {
	if strings.TrimSpace(operationID) == "" {
		return workerIOValidationError("worker io operation id is required")
	}
	return nil
}

func validateWorkerIOTarget(target Target) error {
	if err := target.Validate(); err != nil {
		return workerIOValidationError("worker io target: %v", err)
	}
	return nil
}

func validateWorkerIOLimit(validation workerIOLimitValidation) error {
	field := workerIOValidationField(validation.Field, "worker io limit")
	if validation.Maximum <= 0 {
		return workerIOValidationError("%s maximum must be positive", field)
	}
	if validation.Value < 0 {
		return workerIOValidationError("%s must be non-negative", field)
	}
	if validation.Required && validation.Value == 0 {
		return workerIOValidationError("%s is required", field)
	}
	if validation.Value > validation.Maximum {
		return workerIOValidationError("%s exceeds maximum of %d bytes", field, validation.Maximum)
	}
	return nil
}

func validateWorkerIOPayload(validation workerIOPayloadValidation) error {
	field := workerIOValidationField(validation.Field, "worker io payload")
	if validation.MaximumBytes <= 0 {
		return workerIOValidationError("%s maximum must be positive", field)
	}
	if validation.SizeBytes < 0 {
		return workerIOValidationError("%s sizeBytes must be non-negative", field)
	}
	limitRequired := validation.PayloadRequired || validation.SizeBytes > 0
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    field + " limit",
		Value:    validation.LimitBytes,
		Maximum:  validation.MaximumBytes,
		Required: limitRequired,
	}); err != nil {
		return err
	}
	if validation.PayloadRequired && validation.SizeBytes == 0 {
		return workerIOValidationError("%s sizeBytes is required", field)
	}
	if validation.SizeBytes > validation.MaximumBytes {
		return workerIOValidationError("%s sizeBytes exceeds maximum of %d bytes", field, validation.MaximumBytes)
	}
	if validation.LimitBytes > 0 && validation.SizeBytes > validation.LimitBytes {
		return workerIOValidationError("%s sizeBytes exceeds requested limit of %d bytes", field, validation.LimitBytes)
	}
	return nil
}

func workerIOValidationField(field, fallback string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return fallback
	}
	return field
}

func workerIOValidationError(format string, args ...any) error {
	return errors.New(sanitizeProtocolErrorDetail(fmt.Sprintf(format, args...)))
}
