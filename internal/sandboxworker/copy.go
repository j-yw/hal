package sandboxworker

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	CopyPayloadEncodingBase64 = "base64"

	CopyStatusCompleted = "completed"
	CopyStatusFailed    = "failed"
)

// CopyInRequest describes a bounded file copy into a worker target.
type CopyInRequest struct {
	OperationID           string           `json:"operationId"`
	Target                Target           `json:"target"`
	Source                CopyPathMetadata `json:"source"`
	RemoteDestinationPath string           `json:"remoteDestinationPath"`
	Payload               CopyFilePayload  `json:"payload"`
}

// CopyInResponse describes copy-in completion metadata.
type CopyInResponse struct {
	Status string `json:"status"`
	Error  *Error `json:"error,omitempty"`
}

// CopyOutRequest describes a bounded file copy out of a worker target.
type CopyOutRequest struct {
	OperationID      string           `json:"operationId"`
	Target           Target           `json:"target"`
	RemoteSourcePath string           `json:"remoteSourcePath"`
	Destination      CopyPathMetadata `json:"destination"`
	MaxPayloadBytes  int64            `json:"maxPayloadBytes"`
}

// CopyOutResponse carries bounded file content copied out of a worker target.
type CopyOutResponse struct {
	Payload       *CopyFilePayload `json:"payload,omitempty"`
	Truncated     bool             `json:"truncated"`
	LimitExceeded bool             `json:"limitExceeded"`
	Error         *Error           `json:"error,omitempty"`
}

// CopyPathMetadata carries caller-safe display path metadata. It must not be
// used as a host or remote filesystem path by protocol handlers.
type CopyPathMetadata struct {
	DisplayPath string `json:"displayPath"`
}

// CopyFilePayload carries bounded file bytes encoded for JSON transport.
type CopyFilePayload struct {
	Data       string `json:"data"`
	Encoding   string `json:"encoding"`
	SizeBytes  int64  `json:"sizeBytes"`
	LimitBytes int64  `json:"limitBytes"`
}

// Validate checks copy-in request metadata and bounded payload limits.
func (req CopyInRequest) Validate() error {
	if err := validateWorkerIOOperationID(req.OperationID); err != nil {
		return err
	}
	if err := validateWorkerIOTarget(req.Target); err != nil {
		return err
	}
	if err := req.Source.Validate("copy_in source"); err != nil {
		return err
	}
	if strings.TrimSpace(req.RemoteDestinationPath) == "" {
		return workerIOValidationError("copy_in remote destination path is required")
	}
	if err := req.Payload.Validate(MaxCopyInPayloadBytes, "copy_in payload", true); err != nil {
		return err
	}
	return nil
}

// Validate checks copy-in completion metadata.
func (resp CopyInResponse) Validate() error {
	if !validCopyStatus(resp.Status) {
		return fmt.Errorf("copy_in response status %q is unsupported", resp.Status)
	}
	if resp.Error != nil {
		if err := resp.Error.Validate(); err != nil {
			return fmt.Errorf("copy_in response error: %w", err)
		}
	}
	return nil
}

// Validate checks copy-out request metadata and caller payload limit.
func (req CopyOutRequest) Validate() error {
	if err := validateWorkerIOOperationID(req.OperationID); err != nil {
		return err
	}
	if err := validateWorkerIOTarget(req.Target); err != nil {
		return err
	}
	if strings.TrimSpace(req.RemoteSourcePath) == "" {
		return workerIOValidationError("copy_out remote source path is required")
	}
	if err := req.Destination.Validate("copy_out destination"); err != nil {
		return err
	}
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    "copy_out max payload",
		Value:    req.MaxPayloadBytes,
		Maximum:  MaxCopyOutPayloadBytes,
		Required: true,
	}); err != nil {
		return err
	}
	return nil
}

// Validate checks copy-out response payload metadata and optional error data.
func (resp CopyOutResponse) Validate() error {
	if resp.Payload != nil {
		if err := resp.Payload.Validate(MaxCopyOutPayloadBytes, "copy_out payload", false); err != nil {
			return err
		}
	}
	if resp.Error != nil {
		if err := resp.Error.Validate(); err != nil {
			return fmt.Errorf("copy_out response error: %w", err)
		}
	}
	return nil
}

// Validate checks caller-safe path display metadata.
func (metadata CopyPathMetadata) Validate(field string) error {
	field = workerIOValidationField(field, "copy path metadata")
	if strings.TrimSpace(metadata.DisplayPath) == "" {
		return workerIOValidationError("%s displayPath is required", field)
	}
	return nil
}

// Validate checks bounded JSON file payload metadata and encoded content.
func (payload CopyFilePayload) Validate(maximumBytes int64, field string, payloadRequired bool) error {
	field = workerIOValidationField(field, "copy payload")
	if strings.TrimSpace(payload.Encoding) == "" {
		return workerIOValidationError("%s encoding is required", field)
	}
	if payload.Encoding != CopyPayloadEncodingBase64 {
		return workerIOValidationError("%s encoding %q is unsupported", field, payload.Encoding)
	}
	if err := validateWorkerIOLimit(workerIOLimitValidation{
		Field:    field + " limit",
		Value:    payload.LimitBytes,
		Maximum:  maximumBytes,
		Required: true,
	}); err != nil {
		return err
	}
	if err := validateWorkerIOPayload(workerIOPayloadValidation{
		Field:           field,
		SizeBytes:       payload.SizeBytes,
		LimitBytes:      payload.LimitBytes,
		MaximumBytes:    maximumBytes,
		PayloadRequired: payloadRequired,
	}); err != nil {
		return err
	}
	if len(payload.Data) > maxBase64EncodedPayloadLength(payload.LimitBytes) {
		return workerIOValidationError("%s data exceeds encoded limit for %d bytes", field, payload.LimitBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return workerIOValidationError("%s data is not valid %s", field, CopyPayloadEncodingBase64)
	}
	if int64(len(decoded)) != payload.SizeBytes {
		return workerIOValidationError("%s sizeBytes %d does not match decoded data size %d bytes", field, payload.SizeBytes, len(decoded))
	}
	return nil
}

func maxBase64EncodedPayloadLength(limitBytes int64) int {
	if limitBytes <= 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if limitBytes > int64(maxInt/4*3) {
		return maxInt
	}
	return base64.StdEncoding.EncodedLen(int(limitBytes))
}

func validCopyStatus(status string) bool {
	switch status {
	case CopyStatusCompleted, CopyStatusFailed:
		return true
	default:
		return false
	}
}
