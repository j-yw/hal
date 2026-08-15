package guestagent

import (
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

func ValidateReadinessRequest(request ReadinessRequest) error {
	if err := validateHeader(request.ProtocolVersion, request.Operation, OperationReadiness); err != nil {
		return err
	}
	if err := validateIsolationProofRequest(request.Operation, request.IsolationProof); err != nil {
		return err
	}
	return validateTiming(request.Operation, request.Timing)
}

func ValidateReadinessResponse(response ReadinessResponse) error {
	if err := validateHeader(response.ProtocolVersion, response.Operation, OperationReadiness); err != nil {
		return err
	}
	if response.Status != "" {
		if !validReadinessStatus(response.Status) {
			return newValidationError(ErrorCodeInvalidMetadata, response.Operation, "status", "readiness status is unsupported")
		}
		if response.Ready != (response.Status == ReadinessStatusReady) {
			return newValidationError(ErrorCodeInvalidMetadata, response.Operation, "status", "readiness status contradicts ready")
		}
	} else if response.IsolationProof != nil {
		return newValidationError(ErrorCodeMissingRequiredField, response.Operation, "status", "proof-bearing readiness status is required")
	}
	if err := validateIsolationProof(response.Operation, response.IsolationProof); err != nil {
		return err
	}
	if response.IsolationProof != nil && response.IsolationProof.Status == IsolationProofStatusVerified && !response.Ready {
		return newValidationError(ErrorCodeInvalidMetadata, response.Operation, "isolationProof.status", "verified isolation proof requires ready response")
	}
	return nil
}

// ValidateReadinessResponseForRequest additionally requires an exact proof
// binding when the readiness request selected the optional L7 proof lane.
func ValidateReadinessResponseForRequest(response ReadinessResponse, request ReadinessRequest) error {
	if err := ValidateReadinessRequest(request); err != nil {
		return err
	}
	if err := ValidateReadinessResponse(response); err != nil {
		return err
	}
	if request.IsolationProof == nil {
		return nil
	}
	proof := response.IsolationProof
	if proof == nil {
		return newValidationError(ErrorCodeMissingRequiredField, OperationReadiness, "isolationProof", "isolation proof is required")
	}
	if proof.Generation != request.IsolationProof.Generation {
		return newValidationError(ErrorCodeInvalidMetadata, OperationReadiness, "isolationProof.generation", "isolation proof generation does not match request")
	}
	if proof.RuntimeGeneration != request.IsolationProof.RuntimeGeneration {
		return newValidationError(ErrorCodeInvalidMetadata, OperationReadiness, "isolationProof.runtimeGeneration", "isolation proof runtime generation does not match request")
	}
	if proof.Status != IsolationProofStatusVerified || !verifiedProcessIsolationProof(*proof) {
		return newValidationError(ErrorCodeInvalidMetadata, OperationReadiness, "isolationProof.status", "isolation proof is not verified")
	}
	if request.IsolationProof.RequireNetworkProof && !verifiedNetworkIsolationProof(proof.Network) {
		return newValidationError(ErrorCodeInvalidMetadata, OperationReadiness, "isolationProof.network", "network isolation proof is not verified")
	}
	return nil
}

func validateIsolationProofRequest(operation Operation, request *IsolationProofRequest) error {
	if request == nil {
		return nil
	}
	if request.Generation == "" {
		return newValidationError(ErrorCodeMissingRequiredField, operation, "isolationProof.generation", "isolation proof generation is required")
	}
	if len(request.Generation) > MaxIsolationProofGenerationBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "isolationProof.generation", "isolation proof generation exceeds protocol limit")
	}
	if !validIsolationGeneration(request.Generation, false) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.generation", "isolation proof generation is invalid")
	}
	if len(request.RuntimeGeneration) > MaxIsolationProofGenerationBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "isolationProof.runtimeGeneration", "isolation proof runtime generation exceeds protocol limit")
	}
	if !validIsolationGeneration(request.RuntimeGeneration, true) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.runtimeGeneration", "isolation proof runtime generation is invalid")
	}
	return nil
}

func validateIsolationProof(operation Operation, proof *IsolationProof) error {
	if proof == nil {
		return nil
	}
	if proof.Generation == "" {
		return newValidationError(ErrorCodeMissingRequiredField, operation, "isolationProof.generation", "isolation proof generation is required")
	}
	if len(proof.Generation) > MaxIsolationProofGenerationBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "isolationProof.generation", "isolation proof generation exceeds protocol limit")
	}
	if !validIsolationGeneration(proof.Generation, false) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.generation", "isolation proof generation is invalid")
	}
	if len(proof.RuntimeGeneration) > MaxIsolationProofGenerationBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "isolationProof.runtimeGeneration", "isolation proof runtime generation exceeds protocol limit")
	}
	if !validIsolationGeneration(proof.RuntimeGeneration, true) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.runtimeGeneration", "isolation proof runtime generation is invalid")
	}
	if !validIsolationProofStatus(proof.Status) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.status", "isolation proof status is unsupported")
	}
	if proof.Status == IsolationProofStatusVerified && !verifiedProcessIsolationProof(*proof) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof", "verified isolation proof is incomplete")
	}
	if proof.Status != IsolationProofStatusVerified &&
		(proof.RestrictedIdentity || proof.CapabilitiesCleared || proof.NoNewPrivileges || proof.SupplementaryGroupsCleared || proof.RawPacketSocketDenied) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof", "unverified isolation proof contains partial claims")
	}
	if proof.Network != nil {
		if !validIsolationProofStatus(proof.Network.Status) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.network.status", "network isolation proof status is unsupported")
		}
		if proof.Network.Status == IsolationProofStatusVerified && !verifiedNetworkIsolationProof(proof.Network) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.network", "verified network isolation proof is incomplete")
		}
		if proof.Network.Status != IsolationProofStatusVerified &&
			(proof.Network.SingleInterface || proof.Network.StaticRoutes || proof.Network.ProxyReachable) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, "isolationProof.network", "unverified network isolation proof contains partial claims")
		}
	}
	return nil
}

func verifiedProcessIsolationProof(proof IsolationProof) bool {
	return proof.RestrictedIdentity && proof.CapabilitiesCleared && proof.NoNewPrivileges &&
		proof.SupplementaryGroupsCleared && proof.RawPacketSocketDenied
}

func verifiedNetworkIsolationProof(proof *NetworkIsolationProof) bool {
	return proof != nil && proof.Status == IsolationProofStatusVerified &&
		proof.SingleInterface && proof.StaticRoutes && proof.ProxyReachable
}

func validIsolationProofStatus(status IsolationProofStatus) bool {
	switch status {
	case IsolationProofStatusVerified, IsolationProofStatusUnavailable, IsolationProofStatusFailed:
		return true
	default:
		return false
	}
}

func validIsolationGeneration(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if value != strings.TrimSpace(value) || len(value) > MaxIsolationProofGenerationBytes {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '-', char == '_', char == '.', char == ':':
		default:
			return false
		}
	}
	return true
}

// ValidateErrorResponse validates the generic v1 error response envelope.
func ValidateErrorResponse(response ErrorResponse) error {
	if strings.TrimSpace(string(response.ProtocolVersion)) == "" {
		return newValidationError(ErrorCodeMissingRequiredField, response.Operation, "protocolVersion", "protocol version is required")
	}
	if response.ProtocolVersion != ProtocolVersionV1 {
		return newValidationError(ErrorCodeUnsupportedProtocolVersion, response.Operation, "protocolVersion", "protocol version is unsupported")
	}
	if response.Operation != "" && !validOperation(response.Operation) {
		return newValidationError(ErrorCodeUnknownOperation, "", "operation", "operation is unsupported")
	}
	if response.Error == nil {
		return newValidationError(ErrorCodeMissingRequiredField, response.Operation, "error", "error is required")
	}
	if normalizeErrorCode(response.Error.Code) != response.Error.Code {
		return newValidationError(ErrorCodeInvalidMetadata, response.Operation, "error.code", "error code is unsupported")
	}
	if response.Operation != "" && response.Error.Operation != "" && response.Error.Operation != response.Operation {
		return newValidationError(ErrorCodeOperationMismatch, response.Operation, "error.operation", "error operation does not match envelope")
	}
	if response.Operation == "" && response.Error.Operation != "" {
		return newValidationError(ErrorCodeOperationMismatch, "", "error.operation", "error operation requires an envelope operation")
	}
	return nil
}

func ValidateExecRequest(request ExecRequest) error {
	if err := validateHeader(request.ProtocolVersion, request.Operation, OperationExec); err != nil {
		return err
	}
	if err := validateCommandArgs(request.Operation, request.Args); err != nil {
		return err
	}
	if err := validateEnvironment(request.Operation, request.Env); err != nil {
		return err
	}
	if err := validateGuestPath(request.Operation, "workDir", request.WorkDir); err != nil {
		return err
	}
	if request.Stdin != nil {
		if err := validateStreamMetadata(request.Operation, "stdin", *request.Stdin, true); err != nil {
			return err
		}
		if err := validateRequiredBase64StreamData(request.Operation, "stdin", *request.Stdin); err != nil {
			return err
		}
	}
	if request.Stdout.Data != "" {
		return newValidationError(ErrorCodeInvalidMetadata, request.Operation, "stdout.data", "stream data is not accepted in request metadata")
	}
	if err := validateStreamMetadata(request.Operation, "stdout", request.Stdout, true); err != nil {
		return err
	}
	if request.Stderr.Data != "" {
		return newValidationError(ErrorCodeInvalidMetadata, request.Operation, "stderr.data", "stream data is not accepted in request metadata")
	}
	if err := validateStreamMetadata(request.Operation, "stderr", request.Stderr, true); err != nil {
		return err
	}
	return validateTiming(request.Operation, request.Timing)
}

func ValidateExecResponse(response ExecResponse) error {
	if err := validateHeader(response.ProtocolVersion, response.Operation, OperationExec); err != nil {
		return err
	}
	if response.ExitCode < 0 {
		return newValidationError(ErrorCodeInvalidMetadata, response.Operation, "exitCode", "exit code must be non-negative")
	}
	if err := validateStreamMetadata(response.Operation, "stdout", response.Stdout, true); err != nil {
		return err
	}
	if err := validateRequiredBase64StreamData(response.Operation, "stdout", response.Stdout); err != nil {
		return err
	}
	if err := validateStreamMetadata(response.Operation, "stderr", response.Stderr, true); err != nil {
		return err
	}
	return validateRequiredBase64StreamData(response.Operation, "stderr", response.Stderr)
}

func ValidateCopyInRequest(request CopyInRequest) error {
	if err := validateHeader(request.ProtocolVersion, request.Operation, OperationCopyIn); err != nil {
		return err
	}
	if err := validateGuestPath(request.Operation, "destinationPath", request.DestinationPath); err != nil {
		return err
	}
	if err := validatePayloadMetadata(request.Operation, "payload", request.Payload, true); err != nil {
		return err
	}
	if err := validatePayloadBase64Encoding(request.Operation, "payload", request.Payload); err != nil {
		return err
	}
	if err := validateRequiredPayloadData(request.Operation, "payload", request.Payload); err != nil {
		return err
	}
	return validateTiming(request.Operation, request.Timing)
}

func ValidateCopyInResponse(response CopyInResponse) error {
	if err := validateHeader(response.ProtocolVersion, response.Operation, OperationCopyIn); err != nil {
		return err
	}
	if err := validatePayloadMetadata(response.Operation, "written", response.Written, true); err != nil {
		return err
	}
	return validateNoPayloadData(response.Operation, "written", response.Written)
}

func ValidateCopyOutRequest(request CopyOutRequest) error {
	if err := validateHeader(request.ProtocolVersion, request.Operation, OperationCopyOut); err != nil {
		return err
	}
	if err := validateGuestPath(request.Operation, "sourcePath", request.SourcePath); err != nil {
		return err
	}
	if err := validatePayloadMetadata(request.Operation, "payload", request.Payload, true); err != nil {
		return err
	}
	if err := validatePayloadBase64Encoding(request.Operation, "payload", request.Payload); err != nil {
		return err
	}
	if err := validateNoPayloadData(request.Operation, "payload", request.Payload); err != nil {
		return err
	}
	return validateTiming(request.Operation, request.Timing)
}

func ValidateCopyOutResponse(response CopyOutResponse) error {
	if err := validateHeader(response.ProtocolVersion, response.Operation, OperationCopyOut); err != nil {
		return err
	}
	if err := validatePayloadMetadata(response.Operation, "payload", response.Payload, true); err != nil {
		return err
	}
	if err := validatePayloadBase64Encoding(response.Operation, "payload", response.Payload); err != nil {
		return err
	}
	return validateRequiredPayloadData(response.Operation, "payload", response.Payload)
}

func validateHeader(version ProtocolVersion, operation Operation, want Operation) error {
	if strings.TrimSpace(string(version)) == "" {
		return newValidationError(ErrorCodeMissingRequiredField, want, "protocolVersion", "protocol version is required")
	}
	if version != ProtocolVersionV1 {
		return newValidationError(ErrorCodeUnsupportedProtocolVersion, want, "protocolVersion", "protocol version is unsupported")
	}
	if strings.TrimSpace(string(operation)) == "" {
		return newValidationError(ErrorCodeMissingRequiredField, want, "operation", "operation is required")
	}
	if !validOperation(operation) {
		return newValidationError(ErrorCodeUnknownOperation, "", "operation", "operation is unsupported")
	}
	if operation != want {
		return newValidationError(ErrorCodeOperationMismatch, operation, "operation", "operation does not match DTO type")
	}
	return nil
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationReadiness, OperationExec, OperationCopyIn, OperationCopyOut:
		return true
	default:
		return false
	}
}

func validateTiming(operation Operation, timing *TimingMetadata) error {
	if timing == nil {
		return nil
	}
	if timing.TimeoutMillis < 0 {
		return newValidationError(ErrorCodeInvalidTimeout, operation, "timing.timeoutMillis", "timeout must be positive")
	}
	if timing.TimeoutMillis > MaxTimeoutMillis {
		return newValidationError(ErrorCodeInvalidTimeout, operation, "timing.timeoutMillis", "timeout exceeds protocol limit")
	}
	if timing.DeadlineUnixMillis < 0 {
		return newValidationError(ErrorCodeInvalidDeadline, operation, "timing.deadlineUnixMillis", "deadline must be positive")
	}
	if timing.DeadlineUnixMillis > 0 && timing.DeadlineUnixMillis < MinDeadlineUnixMillis {
		return newValidationError(ErrorCodeInvalidDeadline, operation, "timing.deadlineUnixMillis", "deadline is outside supported range")
	}
	if timing.DeadlineUnixMillis > MaxDeadlineUnixMillis {
		return newValidationError(ErrorCodeInvalidDeadline, operation, "timing.deadlineUnixMillis", "deadline exceeds supported range")
	}
	if timing.TimeoutMillis > 0 && timing.DeadlineUnixMillis > 0 {
		return newValidationError(ErrorCodeInvalidDeadline, operation, "timing", "timeout and deadline are mutually exclusive")
	}
	return nil
}

func validateCommandArgs(operation Operation, args []string) error {
	if len(args) == 0 {
		return newValidationError(ErrorCodeMissingRequiredField, operation, "args", "command args are required")
	}
	if len(args) > MaxCommandArgs {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "args", "command args exceed protocol limit")
	}
	for i, arg := range args {
		field := fmt.Sprintf("args[%d]", i)
		if i == 0 && strings.TrimSpace(arg) == "" {
			return newValidationError(ErrorCodeMissingRequiredField, operation, field, "command executable is required")
		}
		if containsControl(arg) || !utf8.ValidString(arg) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, field, "command arg contains invalid characters")
		}
		if len(arg) > MaxCommandArgBytes {
			return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field, "command arg exceeds protocol limit")
		}
	}
	return nil
}

func validateEnvironment(operation Operation, entries []EnvironmentEntry) error {
	if len(entries) > MaxEnvironmentEntries {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, "env", "environment metadata exceeds protocol limit")
	}
	for i, entry := range entries {
		nameField := fmt.Sprintf("env[%d].name", i)
		if !validEnvironmentName(entry.Name) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, nameField, "environment name is invalid")
		}
		if entry.Source != "" && !validEnvironmentSource(entry.Source) {
			return newValidationError(ErrorCodeInvalidMetadata, operation, fmt.Sprintf("env[%d].source", i), "environment source is unsupported")
		}
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || len(name) > 128 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func validEnvironmentSource(source EnvironmentSource) bool {
	switch source {
	case EnvironmentSourceLiteral,
		EnvironmentSourceSecret,
		EnvironmentSourceInherited,
		EnvironmentSourceGenerated:
		return true
	default:
		return false
	}
}

func validateGuestPath(operation Operation, field, value string) error {
	if strings.TrimSpace(value) == "" {
		return newValidationError(ErrorCodeMissingRequiredField, operation, field, "guest path is required")
	}
	if value != strings.TrimSpace(value) ||
		len(value) > MaxGuestPathBytes ||
		containsControl(value) ||
		!utf8.ValidString(value) ||
		!strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") ||
		strings.Contains(value, "://") ||
		strings.Contains(value, "//") ||
		path.Clean(value) != value ||
		containsParentPathSegment(value) {
		return newValidationError(ErrorCodeMalformedPath, operation, field, "guest path must be absolute and normalized")
	}
	return nil
}

func containsParentPathSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func validateStreamMetadata(operation Operation, field string, metadata StreamMetadata, requireMax bool) error {
	if metadata.SizeBytes < 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".sizeBytes", "stream size must be non-negative")
	}
	if metadata.MaxBytes < 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".maxBytes", "stream limit must be non-negative")
	}
	if requireMax && metadata.MaxBytes == 0 {
		return newValidationError(ErrorCodeMissingRequiredField, operation, field+".maxBytes", "stream byte limit is required")
	}
	if metadata.SizeBytes > MaxStreamMetadataBytes || metadata.MaxBytes > MaxStreamMetadataBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field, "stream metadata exceeds protocol limit")
	}
	if metadata.MaxBytes > 0 && metadata.SizeBytes > metadata.MaxBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field+".sizeBytes", "stream size exceeds declared limit")
	}
	if metadata.Data != "" {
		return validateEncodedData(operation, field, metadata.Data, metadata.Encoding, metadata.SizeBytes, metadata.MaxBytes, MaxStreamMetadataBytes, "stream")
	}
	if metadata.Encoding != "" && !validPayloadEncoding(metadata.Encoding) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", "stream encoding is unsupported")
	}
	return nil
}

func validatePayloadMetadata(operation Operation, field string, metadata PayloadMetadata, requireMax bool) error {
	if metadata.SizeBytes < 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".sizeBytes", "payload size must be non-negative")
	}
	if metadata.MaxBytes < 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".maxBytes", "payload limit must be non-negative")
	}
	if requireMax && metadata.MaxBytes == 0 {
		return newValidationError(ErrorCodeMissingRequiredField, operation, field+".maxBytes", "payload byte limit is required")
	}
	if metadata.SizeBytes > MaxCopyPayloadMetadataBytes || metadata.MaxBytes > MaxCopyPayloadMetadataBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field, "payload metadata exceeds protocol limit")
	}
	if metadata.MaxBytes > 0 && metadata.SizeBytes > metadata.MaxBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field+".sizeBytes", "payload size exceeds declared limit")
	}
	if metadata.Digest != "" && !validPayloadDigest(metadata.Digest) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".digest", "payload digest is invalid")
	}
	if metadata.Encoding != "" && !validPayloadEncoding(metadata.Encoding) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", "payload encoding is unsupported")
	}
	if metadata.Data != "" {
		if metadata.Encoding != PayloadEncodingBase64 {
			return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", "payload data must be base64 encoded")
		}
		return validateEncodedData(operation, field, metadata.Data, metadata.Encoding, metadata.SizeBytes, metadata.MaxBytes, MaxCopyPayloadMetadataBytes, "payload")
	}
	return nil
}

func validateRequiredBase64StreamData(operation Operation, field string, metadata StreamMetadata) error {
	if metadata.Data == "" && metadata.SizeBytes > 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", "stream data is required for declared content")
	}
	if metadata.Data != "" && metadata.Encoding != PayloadEncodingBase64 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", "stream data must be base64 encoded")
	}
	return nil
}

func validatePayloadBase64Encoding(operation Operation, field string, metadata PayloadMetadata) error {
	if metadata.Encoding != PayloadEncodingBase64 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", "payload encoding must be base64")
	}
	return nil
}

func validateRequiredPayloadData(operation Operation, field string, metadata PayloadMetadata) error {
	if metadata.Data == "" && metadata.SizeBytes > 0 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", "payload data is required for declared content")
	}
	return nil
}

func validateNoPayloadData(operation Operation, field string, metadata PayloadMetadata) error {
	if metadata.Data != "" {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", "payload data is not accepted for this message")
	}
	return nil
}

func validateEncodedData(operation Operation, field, data string, encoding PayloadEncoding, sizeBytes, maxBytes, maximumBytes int64, kind string) error {
	if !utf8.ValidString(data) {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", kind+" data contains invalid characters")
	}
	decodedSize := int64(len(data))
	switch encoding {
	case "", PayloadEncodingRaw:
	case PayloadEncodingBase64:
		if len(data) > maxBase64EncodedPayloadLength(maxBytes, maximumBytes) {
			return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field+".data", kind+" data exceeds encoded limit")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(data)
		if err != nil {
			return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", kind+" data is not valid base64")
		}
		if base64.StdEncoding.EncodeToString(decoded) != data {
			return newValidationError(ErrorCodeInvalidMetadata, operation, field+".data", kind+" data is not valid base64")
		}
		decodedSize = int64(len(decoded))
	default:
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".encoding", kind+" data encoding is unsupported")
	}
	if decodedSize > maximumBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field+".data", kind+" data exceeds protocol limit")
	}
	if maxBytes > 0 && decodedSize > maxBytes {
		return newValidationError(ErrorCodeOversizedPayloadMetadata, operation, field+".data", kind+" data exceeds declared limit")
	}
	if sizeBytes > 0 && decodedSize != sizeBytes {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".sizeBytes", kind+" size does not match decoded data")
	}
	if sizeBytes == 0 && decodedSize > 0 && encoding == PayloadEncodingBase64 {
		return newValidationError(ErrorCodeInvalidMetadata, operation, field+".sizeBytes", kind+" size is required for encoded data")
	}
	return nil
}

func maxBase64EncodedPayloadLength(limitBytes, maximumBytes int64) int {
	if limitBytes <= 0 || limitBytes > maximumBytes {
		limitBytes = maximumBytes
	}
	maxInt := int(^uint(0) >> 1)
	if limitBytes > int64(maxInt/4*3) {
		return maxInt
	}
	return base64.StdEncoding.EncodedLen(int(limitBytes))
}

func validPayloadDigest(digest string) bool {
	if digest != strings.TrimSpace(digest) || len(digest) > 128 || containsControl(digest) {
		return false
	}
	for _, r := range digest {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == ':' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func validPayloadEncoding(encoding PayloadEncoding) bool {
	switch encoding {
	case PayloadEncodingRaw, PayloadEncodingBase64, PayloadEncodingChunked:
		return true
	default:
		return false
	}
}

func validReadinessStatus(status ReadinessStatus) bool {
	switch status {
	case ReadinessStatusReady, ReadinessStatusNotReady:
		return true
	default:
		return false
	}
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
