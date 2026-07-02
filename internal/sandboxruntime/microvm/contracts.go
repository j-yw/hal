package microvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	DriverID = "microvm"

	DefaultCPUCount     = 2
	DefaultMemoryMiB    = 2048
	DefaultDiskSizeMiB  = 10240
	DefaultGuestWorkDir = "/workspace"
)

const (
	NetworkModeNoLiveNetworking NetworkMode = "no_live_networking"
	DefaultNetworkMode          NetworkMode = NetworkModeNoLiveNetworking
)

const (
	ErrorCodeUnavailableCapability ErrorCode = "unavailable_capability"
	ErrorCodeInvalidConfig         ErrorCode = "invalid_config"
	ErrorCodeBackendNotConfigured  ErrorCode = "backend_not_configured"
	ErrorCodeTargetRequired        ErrorCode = "target_required"
	ErrorCodeTargetNameRequired    ErrorCode = "target_name_required"
)

var (
	ErrUnavailableCapability = errors.New("microvm capability unavailable")
	ErrInvalidConfig         = errors.New("microvm config is invalid")
	ErrBackendNotConfigured  = errors.New("microvm backend is not configured")
	ErrTargetRequired        = errors.New("microvm target is required")
	ErrTargetNameRequired    = errors.New("microvm target name is required")
)

var (
	endpointURLPattern       = regexp.MustCompile(`(?i)\b(?:https?|ssh|tcp|udp|grpc|unix)://[^\s'"<>]+`)
	hostPathPattern          = regexp.MustCompile(`(?i)(?:/private)?/(?:Users|home|tmp|var|opt|etc|run|usr/local|Volumes)/[^\s:'",]+`)
	secretAssignmentPattern  = regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key|credential|authorization)=\S+`)
	commonSecretValuePattern = regexp.MustCompile(`(?i)(^|[\s"'=:/])([A-Za-z0-9._-]*(?:secret|hunter2|ghp_[A-Za-z0-9_]*|sk-[A-Za-z0-9_-]+)[A-Za-z0-9._-]*)`)
	ipEndpointPattern        = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	hostEndpointPattern      = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9.-]*\.(?:test|local|internal|example|com|net|org|io|dev)(?::\d+)?\b`)
	backendDetailPattern     = regexp.MustCompile(`(?i)\b(?:firecracker-go-sdk|github\.com/firecracker-microvm/[^\s]+|cloud-hypervisor-sdk|provider internals?)\b`)
)

const maxOperationErrorDetailBytes = 512

// NetworkMode names the requested guest networking contract without implying
// that a backend has enabled live networking.
type NetworkMode string

// ErrorCode is the stable public classification for microVM operation errors.
type ErrorCode string

// Config contains backend-neutral microVM runtime configuration. Path fields
// are host-local inputs and must not be copied into public error strings.
type Config struct {
	KernelImagePath string      `json:"kernelImagePath,omitempty"`
	RootfsPath      string      `json:"rootfsPath,omitempty"`
	InitrdPath      string      `json:"initrdPath,omitempty"`
	JailerPath      string      `json:"jailerPath,omitempty"`
	HypervisorPath  string      `json:"hypervisorPath,omitempty"`
	CPUCount        int         `json:"cpuCount,omitempty"`
	MemoryMiB       int         `json:"memoryMiB,omitempty"`
	DiskSizeMiB     int         `json:"diskSizeMiB,omitempty"`
	GuestWorkDir    string      `json:"guestWorkDir,omitempty"`
	NetworkMode     NetworkMode `json:"networkMode,omitempty"`
	ImageLabel      string      `json:"imageLabel,omitempty"`
	ImageDigest     string      `json:"imageDigest,omitempty"`
	TemplateLabel   string      `json:"templateLabel,omitempty"`
	TemplateDigest  string      `json:"templateDigest,omitempty"`
}

// Options groups backend-neutral microVM runtime options.
type Options struct {
	Config Config `json:"config,omitempty"`
}

// OperationError is the public error shape shared by future microVM backends.
// Message is always sanitized before display or JSON encoding; Err is preserved
// only for errors.Is/As.
type OperationError struct {
	Code      ErrorCode `json:"code"`
	Operation string    `json:"operation,omitempty"`
	Field     string    `json:"field,omitempty"`
	Message   string    `json:"message,omitempty"`
	Err       error     `json:"-"`
}

// DefaultConfig returns conservative fake-safe defaults for microVM backends.
func DefaultConfig() Config {
	return Config{
		CPUCount:     DefaultCPUCount,
		MemoryMiB:    DefaultMemoryMiB,
		DiskSizeMiB:  DefaultDiskSizeMiB,
		GuestWorkDir: DefaultGuestWorkDir,
		NetworkMode:  DefaultNetworkMode,
	}
}

// ApplyDefaults fills omitted defaultable config fields while preserving all
// explicit backend and image/template metadata.
func ApplyDefaults(config Config) Config {
	defaults := DefaultConfig()
	if config.CPUCount <= 0 {
		config.CPUCount = defaults.CPUCount
	}
	if config.MemoryMiB <= 0 {
		config.MemoryMiB = defaults.MemoryMiB
	}
	if config.DiskSizeMiB <= 0 {
		config.DiskSizeMiB = defaults.DiskSizeMiB
	}
	if strings.TrimSpace(config.GuestWorkDir) == "" {
		config.GuestWorkDir = defaults.GuestWorkDir
	}
	if strings.TrimSpace(string(config.NetworkMode)) == "" {
		config.NetworkMode = defaults.NetworkMode
	}
	return config
}

// EffectiveConfig returns Options.Config with defaultable values populated.
func (opts Options) EffectiveConfig() Config {
	return ApplyDefaults(opts.Config)
}

func NewOperationError(code ErrorCode, operation string, err error) *OperationError {
	return &OperationError{
		Code:      normalizeErrorCode(code),
		Operation: sanitizeIdentifier(operation),
		Message:   sanitizeOperationDetail(errorDetail(err)),
		Err:       err,
	}
}

func NewUnavailableCapabilityError(operation string, err error) *OperationError {
	if err == nil {
		err = ErrUnavailableCapability
	}
	return NewOperationError(ErrorCodeUnavailableCapability, operation, err)
}

func NewInvalidConfigError(operation string, err error) *OperationError {
	if err == nil {
		err = ErrInvalidConfig
	}
	return NewOperationError(ErrorCodeInvalidConfig, operation, err)
}

func NewBackendNotConfiguredError(operation string) *OperationError {
	return NewOperationError(ErrorCodeBackendNotConfigured, operation, ErrBackendNotConfigured)
}

func NewTargetRequiredError(operation string) *OperationError {
	return NewOperationError(ErrorCodeTargetRequired, operation, ErrTargetRequired)
}

func NewTargetNameRequiredError(operation string) *OperationError {
	return NewOperationError(ErrorCodeTargetNameRequired, operation, ErrTargetNameRequired)
}

func (err *OperationError) Error() string {
	if err == nil {
		return ""
	}
	code := normalizeErrorCode(err.Code)
	operation := sanitizeIdentifier(err.Operation)
	message := fmt.Sprintf("%s operation failed (%s)", DriverID, code)
	if operation != "" {
		message = fmt.Sprintf("%s %s failed (%s)", DriverID, operation, code)
	}
	if detail := err.safeMessage(); detail != "" {
		message += ": " + detail
	}
	return message
}

func (err *OperationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (err *OperationError) MarshalJSON() ([]byte, error) {
	if err == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Code      ErrorCode `json:"code"`
		Operation string    `json:"operation,omitempty"`
		Field     string    `json:"field,omitempty"`
		Message   string    `json:"message,omitempty"`
	}{
		Code:      normalizeErrorCode(err.Code),
		Operation: sanitizeIdentifier(err.Operation),
		Field:     sanitizeIdentifier(err.Field),
		Message:   err.safeMessage(),
	})
}

func (err *OperationError) safeMessage() string {
	if err == nil {
		return ""
	}
	if strings.TrimSpace(err.Message) != "" {
		return sanitizeOperationDetail(err.Message)
	}
	return sanitizeOperationDetail(errorDetail(err.Err))
}

func normalizeErrorCode(code ErrorCode) ErrorCode {
	switch code {
	case ErrorCodeUnavailableCapability,
		ErrorCodeInvalidConfig,
		ErrorCodeBackendNotConfigured,
		ErrorCodeTargetRequired,
		ErrorCodeTargetNameRequired:
		return code
	default:
		return ErrorCodeInvalidConfig
	}
}

func errorDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sanitizeOperationDetail(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	detail = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, detail)
	detail = strings.Join(strings.Fields(detail), " ")
	detail = endpointURLPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = hostPathPattern.ReplaceAllString(detail, "[redacted-path]")
	detail = secretAssignmentPattern.ReplaceAllString(detail, "$1=[redacted]")
	detail = commonSecretValuePattern.ReplaceAllString(detail, "$1[redacted]")
	detail = ipEndpointPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = hostEndpointPattern.ReplaceAllString(detail, "[redacted-endpoint]")
	detail = backendDetailPattern.ReplaceAllString(detail, "[redacted-backend-detail]")
	if len(detail) > maxOperationErrorDetailBytes {
		detail = strings.TrimSpace(detail[:maxOperationErrorDetailBytes]) + "..."
	}
	return detail
}

func sanitizeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(unicode.ToLower(r))
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			builder.WriteRune(r)
		default:
			return ""
		}
	}
	value = builder.String()
	if value == "" {
		return ""
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
