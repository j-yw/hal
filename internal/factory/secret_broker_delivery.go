package factory

import (
	"errors"
	"fmt"
	"strings"
)

// Secret broker delivery mode validation sentinels.
var (
	ErrInvalidSecretBrokerDeliveryMode     = errors.New("invalid factory secret delivery mode")
	ErrUnsupportedSecretBrokerDeliveryMode = errors.New("unsupported factory secret delivery mode")
)

// SecretBrokerDeliveryModeValidationRequest captures requested and
// active/effective delivery mode metadata. These fields are safe mode
// identifiers only; they do not carry secret values or delivery payloads.
type SecretBrokerDeliveryModeValidationRequest struct {
	RequestedModes []string
	ActiveModes    []string
}

// SecretBrokerDeliveryModeMetadata is the durable, redaction-safe result of
// delivery mode validation.
type SecretBrokerDeliveryModeMetadata struct {
	RequestedModes []string `json:"requestedModes,omitempty"`
	ActiveModes    []string `json:"activeModes,omitempty"`
}

// SupportedSecretBrokerDeliveryModes returns the exact delivery metadata modes
// currently recognized by the factory secret broker foundation.
func SupportedSecretBrokerDeliveryModes() []string {
	return []string{
		SecretBrokerDeliveryModeEnv,
		SecretBrokerDeliveryModeFileTmpfs,
		SecretBrokerDeliveryModeSSHAgent,
		SecretBrokerDeliveryModeHTTPProxy,
		SecretBrokerDeliveryModeLegacyAuthSync,
	}
}

// ValidateSecretBrokerDeliveryModes validates secret delivery metadata without
// implementing or invoking any delivery mechanism.
func ValidateSecretBrokerDeliveryModes(request SecretBrokerDeliveryModeValidationRequest) (SecretBrokerDeliveryModeMetadata, error) {
	requested, err := normalizeSecretBrokerDeliveryModes("requestedModes", request.RequestedModes)
	if err != nil {
		return SecretBrokerDeliveryModeMetadata{}, err
	}
	active, err := normalizeSecretBrokerDeliveryModes("activeModes", request.ActiveModes)
	if err != nil {
		return SecretBrokerDeliveryModeMetadata{}, err
	}
	return SecretBrokerDeliveryModeMetadata{
		RequestedModes: requested,
		ActiveModes:    active,
	}, nil
}

type secretBrokerDeliveryModeValidationCode string

const (
	secretBrokerDeliveryModeValidationCodeEmpty       secretBrokerDeliveryModeValidationCode = "empty_mode"
	secretBrokerDeliveryModeValidationCodeUnsupported secretBrokerDeliveryModeValidationCode = "unsupported_mode"
)

// SecretBrokerDeliveryModeValidationError identifies invalid metadata by safe
// field and index only. It intentionally omits the rejected value.
type SecretBrokerDeliveryModeValidationError struct {
	Field string
	Index int
	Code  string
}

func (e SecretBrokerDeliveryModeValidationError) Error() string {
	location := strings.TrimSpace(e.Field)
	if location == "" {
		location = "modes"
	}
	if e.Index >= 0 {
		location = fmt.Sprintf("%s[%d]", location, e.Index)
	}

	switch secretBrokerDeliveryModeValidationCode(e.Code) {
	case secretBrokerDeliveryModeValidationCodeEmpty:
		return fmt.Sprintf("invalid factory secret delivery mode at %s: mode is required", location)
	case secretBrokerDeliveryModeValidationCodeUnsupported:
		return fmt.Sprintf("unsupported factory secret delivery mode at %s", location)
	default:
		return fmt.Sprintf("invalid factory secret delivery mode at %s", location)
	}
}

func (e SecretBrokerDeliveryModeValidationError) Unwrap() error {
	switch secretBrokerDeliveryModeValidationCode(e.Code) {
	case secretBrokerDeliveryModeValidationCodeUnsupported:
		return ErrUnsupportedSecretBrokerDeliveryMode
	default:
		return ErrInvalidSecretBrokerDeliveryMode
	}
}

func normalizeSecretBrokerDeliveryModes(field string, modes []string) ([]string, error) {
	if len(modes) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(modes))
	for i, mode := range modes {
		normalized, err := normalizeSecretBrokerDeliveryMode(field, i, mode)
		if err != nil {
			return nil, err
		}
		if !containsSecretBrokerDeliveryMode(out, normalized) {
			out = append(out, normalized)
		}
	}
	return out, nil
}

func normalizeSecretBrokerDeliveryMode(field string, index int, mode string) (string, error) {
	normalized := strings.TrimSpace(mode)
	if normalized == "" {
		return "", SecretBrokerDeliveryModeValidationError{
			Field: field,
			Index: index,
			Code:  string(secretBrokerDeliveryModeValidationCodeEmpty),
		}
	}
	for _, supported := range SupportedSecretBrokerDeliveryModes() {
		if normalized == supported {
			return normalized, nil
		}
	}
	return "", SecretBrokerDeliveryModeValidationError{
		Field: field,
		Index: index,
		Code:  string(secretBrokerDeliveryModeValidationCodeUnsupported),
	}
}

func containsSecretBrokerDeliveryMode(modes []string, mode string) bool {
	for _, existing := range modes {
		if existing == mode {
			return true
		}
	}
	return false
}

func cloneSecretBrokerDeliveryModeMetadata(metadata *SecretBrokerDeliveryModeMetadata) *SecretBrokerDeliveryModeMetadata {
	if metadata == nil {
		return nil
	}
	return &SecretBrokerDeliveryModeMetadata{
		RequestedModes: append([]string(nil), metadata.RequestedModes...),
		ActiveModes:    append([]string(nil), metadata.ActiveModes...),
	}
}
