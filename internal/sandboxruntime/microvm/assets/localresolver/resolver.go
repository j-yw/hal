package localresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

const (
	ErrorCodeInvalidRequest      ErrorCode = "invalid_request"
	ErrorCodeUnsafePath          ErrorCode = "unsafe_path"
	ErrorCodeFileUnavailable     ErrorCode = "file_unavailable"
	ErrorCodeSymlinkRejected     ErrorCode = "symlink_rejected"
	ErrorCodeUnsupportedFileType ErrorCode = "unsupported_file_type"
)

var (
	ErrInvalidRequest      = errors.New("local asset request is invalid")
	ErrUnsafePath          = errors.New("local asset path is unsafe")
	ErrFileUnavailable     = errors.New("local asset file is unavailable")
	ErrSymlinkRejected     = errors.New("local asset symlink is rejected")
	ErrUnsupportedFileType = errors.New("local asset file type is unsupported")
)

// ErrorCode identifies a sanitized local asset resolver failure.
type ErrorCode string

// ResolveRequest describes explicit local launch assets to verify and lock.
type ResolveRequest struct {
	ID                 assets.SafeID      `json:"id,omitempty"`
	Labels             []assets.SafeLabel `json:"labels,omitempty"`
	Assets             []AssetRequest     `json:"assets,omitempty"`
	LockedAtUnixMillis int64              `json:"lockedAtUnixMillis,omitempty"`
}

// AssetRequest is one explicit local file input plus US-001 launch metadata.
type AssetRequest struct {
	ID          assets.SafeID               `json:"id"`
	Role        assets.AssetRole            `json:"role"`
	Kind        assets.AssetKind            `json:"kind"`
	Path        string                      `json:"path"`
	Labels      []assets.SafeLabel          `json:"labels,omitempty"`
	InitConfig  *assets.InitConfigMetadata  `json:"initConfig,omitempty"`
	AgentConfig *assets.AgentConfigMetadata `json:"agentConfig,omitempty"`
	Resources   []assets.ResourceMetadata   `json:"resources,omitempty"`
}

// Error is the public resolver error shape. It never includes rejected path
// values, URL-looking input, token-looking input, or host filesystem details.
type Error struct {
	Code    ErrorCode        `json:"code"`
	Field   string           `json:"field,omitempty"`
	Role    assets.AssetRole `json:"role,omitempty"`
	Message string           `json:"message,omitempty"`
	Err     error            `json:"-"`
}

// Resolve verifies explicit local launch asset files and returns a US-001
// immutable descriptor locked by SHA-256 digests.
func Resolve(request ResolveRequest) (assets.LaunchDescriptor, error) {
	if request.LockedAtUnixMillis < 0 {
		return assets.LaunchDescriptor{}, newResolverError(
			ErrorCodeInvalidRequest,
			"lockedAtUnixMillis",
			"",
			"lock timestamp must be non-negative",
			ErrInvalidRequest,
		)
	}

	descriptor := assets.LaunchDescriptor{
		ID:     request.ID,
		Labels: copySafeLabels(request.Labels),
	}
	if request.Assets != nil {
		descriptor.Assets = make([]assets.LaunchAsset, 0, len(request.Assets))
	}

	for i, input := range request.Assets {
		resolved, err := resolveAsset(i, input, request.LockedAtUnixMillis)
		if err != nil {
			return assets.LaunchDescriptor{}, err
		}
		descriptor.Assets = append(descriptor.Assets, resolved)
	}

	result := assets.ValidateAndNormalizeLaunchDescriptor(descriptor)
	if !result.Valid {
		return assets.LaunchDescriptor{}, newResolverError(
			ErrorCodeInvalidRequest,
			"assets",
			"",
			"launch asset descriptor is invalid",
			assets.ValidationErrors(result.Errors),
		)
	}
	return *result.Normalized, nil
}

func resolveAsset(index int, input AssetRequest, lockedAtUnixMillis int64) (assets.LaunchAsset, error) {
	role := normalizeRole(input.Role)
	kind := normalizeKind(input.Kind)
	fieldPrefix := assetField(index)

	if role == "" {
		return assets.LaunchAsset{}, newResolverError(ErrorCodeInvalidRequest, fieldPrefix+".role", "", "asset role is required", ErrInvalidRequest)
	}
	if kind == "" {
		return assets.LaunchAsset{}, newResolverError(ErrorCodeInvalidRequest, fieldPrefix+".kind", role, "asset kind is required", ErrInvalidRequest)
	}
	if expected, ok := expectedKindForRole(role); !ok {
		return assets.LaunchAsset{}, newResolverError(ErrorCodeInvalidRequest, fieldPrefix+".role", "", "asset role is unsupported", ErrInvalidRequest)
	} else if kind != expected {
		return assets.LaunchAsset{}, newResolverError(ErrorCodeInvalidRequest, fieldPrefix+".kind", role, "asset kind does not match role", ErrInvalidRequest)
	}

	path, err := validateLocalHostPath(input.Path, fieldPrefix+".path", role)
	if err != nil {
		return assets.LaunchAsset{}, err
	}

	digestValue, sizeBytes, err := digestReadableRegularFile(path, fieldPrefix+".path", role)
	if err != nil {
		return assets.LaunchAsset{}, err
	}

	return assets.LaunchAsset{
		ID:     input.ID,
		Role:   role,
		Kind:   kind,
		Labels: copySafeLabels(input.Labels),
		Source: assets.AssetSource{
			Type: assets.SourceTypeLocalFile,
			HostPath: &assets.HostPathMetadata{
				Path: path,
				Role: assets.HostPathRoleResolvedLocalAsset,
			},
		},
		Lock: assets.LockMetadata{
			Digest: assets.DigestMetadata{
				Algorithm: assets.DigestAlgorithmSHA256,
				Value:     digestValue,
			},
			SizeBytes:          sizeBytes,
			LockedAtUnixMillis: lockedAtUnixMillis,
		},
		InitConfig:  copyInitConfig(input.InitConfig),
		AgentConfig: copyAgentConfig(input.AgentConfig),
		Resources:   copyResourceMetadata(input.Resources),
	}, nil
}

func validateLocalHostPath(raw string, field string, role assets.AssetRole) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", newResolverError(ErrorCodeUnsafePath, field, role, "asset path is required", ErrUnsafePath)
	}
	if raw != strings.TrimSpace(raw) ||
		containsControl(raw) ||
		rawLooksLikeURL(raw) ||
		looksSecretLike(raw) ||
		containsUnsafePathCharacter(raw) ||
		!filepath.IsAbs(raw) ||
		filepath.Clean(raw) != raw {
		return "", newResolverError(ErrorCodeUnsafePath, field, role, "asset path must be an absolute clean host path", ErrUnsafePath)
	}
	return raw, nil
}

func digestReadableRegularFile(path string, field string, role assets.AssetRole) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, newResolverError(ErrorCodeFileUnavailable, field, role, "asset file is not available", ErrFileUnavailable)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", 0, newResolverError(ErrorCodeSymlinkRejected, field, role, "asset file must not be a symlink", ErrSymlinkRejected)
	}
	if !info.Mode().IsRegular() {
		return "", 0, newResolverError(ErrorCodeUnsupportedFileType, field, role, "asset file must be a regular file", ErrUnsupportedFileType)
	}

	file, err := os.Open(path)
	if err != nil {
		return "", 0, newResolverError(ErrorCodeFileUnavailable, field, role, "asset file is not readable", ErrFileUnavailable)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return "", 0, newResolverError(ErrorCodeFileUnavailable, field, role, "asset file is not readable", ErrFileUnavailable)
	}
	if !openedInfo.Mode().IsRegular() {
		return "", 0, newResolverError(ErrorCodeUnsupportedFileType, field, role, "asset file must be a regular file", ErrUnsupportedFileType)
	}

	hash := sha256.New()
	sizeBytes, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, newResolverError(ErrorCodeFileUnavailable, field, role, "asset file could not be read", ErrFileUnavailable)
	}
	return hex.EncodeToString(hash.Sum(nil)), sizeBytes, nil
}

func expectedKindForRole(role assets.AssetRole) (assets.AssetKind, bool) {
	switch role {
	case assets.AssetRoleKernel:
		return assets.AssetKindKernelImage, true
	case assets.AssetRoleRootfs:
		return assets.AssetKindRootfsImage, true
	case assets.AssetRoleInitrd:
		return assets.AssetKindInitrdImage, true
	case assets.AssetRoleGuestInitConfig:
		return assets.AssetKindGuestConfig, true
	case assets.AssetRoleGuestAgentConfig:
		return assets.AssetKindAgentConfig, true
	default:
		return "", false
	}
}

func normalizeRole(role assets.AssetRole) assets.AssetRole {
	return assets.AssetRole(strings.ToLower(strings.TrimSpace(string(role))))
}

func normalizeKind(kind assets.AssetKind) assets.AssetKind {
	return assets.AssetKind(strings.ToLower(strings.TrimSpace(string(kind))))
}

func containsControl(value string) bool {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func rawLooksLikeURL(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") {
		return true
	}
	for _, prefix := range []string{
		"http:",
		"https:",
		"ssh:",
		"tcp:",
		"udp:",
		"grpc:",
		"file:",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func looksSecretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"authorization",
		"bearer",
		"token",
		"secret",
		"credential",
		"password",
		"api_key",
		"apikey",
		"access_key",
		"private_key",
		"ghp_",
		"github_pat_",
		"sk-",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsUnsafePathCharacter(value string) bool {
	for _, r := range value {
		switch r {
		case '\\', '"', '\'', '`', '<', '>', '|', '&', ';', '$', '{', '}', '[', ']', '(', ')':
			return true
		}
	}
	return false
}

func copySafeLabels(in []assets.SafeLabel) []assets.SafeLabel {
	if in == nil {
		return nil
	}
	out := make([]assets.SafeLabel, len(in))
	copy(out, in)
	return out
}

func copyInitConfig(in *assets.InitConfigMetadata) *assets.InitConfigMetadata {
	if in == nil {
		return nil
	}
	return &assets.InitConfigMetadata{
		Format:     in.Format,
		EntryPoint: in.EntryPoint,
		Labels:     copySafeLabels(in.Labels),
	}
}

func copyAgentConfig(in *assets.AgentConfigMetadata) *assets.AgentConfigMetadata {
	if in == nil {
		return nil
	}
	return &assets.AgentConfigMetadata{
		Protocol: in.Protocol,
		Version:  in.Version,
		Features: copySafeLabels(in.Features),
	}
}

func copyResourceMetadata(in []assets.ResourceMetadata) []assets.ResourceMetadata {
	if in == nil {
		return nil
	}
	out := make([]assets.ResourceMetadata, len(in))
	for i, resource := range in {
		out[i] = assets.ResourceMetadata{
			ID:        resource.ID,
			Kind:      resource.Kind,
			SizeBytes: resource.SizeBytes,
			Labels:    copySafeLabels(resource.Labels),
		}
	}
	return out
}

func assetField(index int) string {
	return fmt.Sprintf("assets[%d]", index)
}

func newResolverError(code ErrorCode, field string, role assets.AssetRole, message string, cause error) *Error {
	return &Error{
		Code:    normalizeErrorCode(code),
		Field:   sanitizeField(field),
		Role:    sanitizeRole(role),
		Message: sanitizeMessage(message),
		Err:     cause,
	}
}

func normalizeErrorCode(code ErrorCode) ErrorCode {
	switch code {
	case ErrorCodeInvalidRequest,
		ErrorCodeUnsafePath,
		ErrorCodeFileUnavailable,
		ErrorCodeSymlinkRejected,
		ErrorCodeUnsupportedFileType:
		return code
	default:
		return ErrorCodeInvalidRequest
	}
}

func sanitizeField(field string) string {
	field = strings.TrimSpace(field)
	if field == "" || containsControl(field) || looksSecretLike(field) || rawLooksLikeURL(field) {
		return ""
	}
	for _, r := range field {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '[' || r == ']':
		default:
			return ""
		}
	}
	return field
}

func sanitizeRole(role assets.AssetRole) assets.AssetRole {
	if _, ok := expectedKindForRole(role); ok {
		return role
	}
	return ""
}

func sanitizeMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" || containsControl(message) || looksSecretLike(message) || rawLooksLikeURL(message) {
		return ""
	}
	return message
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	message := "local asset resolver failed (" + string(normalizeErrorCode(err.Code)) + ")"
	if field := sanitizeField(err.Field); field != "" {
		message += " field=" + field
	}
	if role := sanitizeRole(err.Role); role != "" {
		message += " role=" + string(role)
	}
	if detail := sanitizeMessage(err.Message); detail != "" {
		message += ": " + detail
	}
	return message
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (err *Error) MarshalJSON() ([]byte, error) {
	if err == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Code    ErrorCode        `json:"code"`
		Field   string           `json:"field,omitempty"`
		Role    assets.AssetRole `json:"role,omitempty"`
		Message string           `json:"message,omitempty"`
	}{
		Code:    normalizeErrorCode(err.Code),
		Field:   sanitizeField(err.Field),
		Role:    sanitizeRole(err.Role),
		Message: sanitizeMessage(err.Message),
	})
}
