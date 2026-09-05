package v2control

import (
	"reflect"
	"testing"
)

func TestProtocolVersionIsExact(t *testing.T) {
	if ProtocolVersion != "guest-agent-v2" {
		t.Fatalf("ProtocolVersion = %q", ProtocolVersion)
	}
}

func TestOperationCatalogAndSafeUnknownClassification(t *testing.T) {
	known := []struct {
		operation Operation
		token     string
	}{
		{OperationReadiness, "readiness"},
		{OperationCredentialPrepare, "credential_prepare"},
		{OperationCredentialRenew, "credential_renew"},
		{OperationCredentialRevoke, "credential_revoke"},
		{OperationExec, "exec"},
	}
	for _, test := range known {
		if string(test.operation) != test.token {
			t.Fatalf("operation constant = %q, want %q", test.operation, test.token)
		}
		parsed, err := ParseOperationToken(test.token)
		if err != nil {
			t.Fatalf("ParseOperationToken(%q): %v", test.token, err)
		}
		if got, err := EncodeOperationToken(parsed); err != nil || got != test.token {
			t.Fatalf("EncodeOperationToken(%q) = %q, %v", test.token, got, err)
		}
		if got, ok := KnownOperation(parsed); !ok || got != test.operation {
			t.Fatalf("KnownOperation(%q) = %q, %t", test.token, got, ok)
		}
		fromCatalog, err := OperationTokenFor(test.operation)
		if err != nil || !reflect.DeepEqual(parsed, fromCatalog) {
			t.Fatalf("OperationTokenFor(%q) = %#v, %v", test.operation, fromCatalog, err)
		}
	}

	unknown, err := ParseOperationToken("future_operation_2")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := KnownOperation(unknown); ok || got != "" {
		t.Fatalf("unknown classified as known: %q, %t", got, ok)
	}
	if got, err := EncodeOperationToken(unknown); err != nil || got != "future_operation_2" {
		t.Fatalf("unknown token = %q, %v", got, err)
	}

	for _, operation := range []Operation{"", "readiness_2", "unknown"} {
		if _, err := OperationTokenFor(operation); err == nil {
			t.Errorf("OperationTokenFor(%q) succeeded", operation)
		}
	}
	for _, token := range []string{
		"", "Readiness", "_readiness", "1readiness", "credential-renew",
		"credential.renew", "credential/renew", "credential renew", "éxec",
		"a\n", string(make([]byte, 65)),
	} {
		if _, err := ParseOperationToken(token); err == nil {
			t.Errorf("ParseOperationToken(%q) succeeded", token)
		}
	}
	if _, err := EncodeOperationToken(OperationToken{}); err == nil {
		t.Error("zero OperationToken encoded")
	}
}

func TestErrorCodeCatalogAndMessagesAreExact(t *testing.T) {
	tests := []struct {
		code    ErrorCode
		token   string
		message string
	}{
		{ErrorCodeMalformedRequest, "malformed_request", "credential request is malformed"},
		{ErrorCodeUnknownOperation, "unknown_operation", "credential operation is unsupported"},
		{ErrorCodeRequestConflict, "request_conflict", "credential request conflicts with prior state"},
		{ErrorCodeIdentityMismatch, "identity_mismatch", "credential identity does not match"},
		{ErrorCodeRevisionStale, "revision_stale", "credential revision is stale"},
		{ErrorCodeExpired, "expired", "credential request is expired"},
		{ErrorCodeResourceLimit, "resource_limit", "credential request exceeds a fixed limit"},
		{ErrorCodePrepareFailed, "prepare_failed", "credential preparation failed"},
		{ErrorCodeRenewFailed, "renew_failed", "credential renewal failed"},
		{ErrorCodeRevokeFailed, "revoke_failed", "credential revocation failed"},
		{ErrorCodeExecFailed, "exec_failed", "credential execution failed"},
		{ErrorCodeHelperUnavailable, "helper_unavailable", "credential helper is unavailable"},
		{ErrorCodeCleanupIncomplete, "cleanup_incomplete", "credential cleanup is incomplete"},
	}
	for _, test := range tests {
		if string(test.code) != test.token {
			t.Fatalf("error code constant = %q, want %q", test.code, test.token)
		}
		if got, err := EncodeErrorCode(test.code); err != nil || got != test.token {
			t.Errorf("EncodeErrorCode(%q) = %q, %v", test.code, got, err)
		}
		if got, err := ParseErrorCode(test.token); err != nil || got != test.code {
			t.Errorf("ParseErrorCode(%q) = %q, %v", test.token, got, err)
		}
		if got, err := ErrorCodeMessage(test.code); err != nil || got != test.message {
			t.Errorf("ErrorCodeMessage(%q) = %q, %v", test.code, got, err)
		}
	}
	for _, token := range []string{"", "Malformed_request", "malformed-request", "unknown", "cleanup_incomplete_2"} {
		if _, err := ParseErrorCode(token); err == nil {
			t.Errorf("ParseErrorCode(%q) succeeded", token)
		}
	}
	for _, code := range []ErrorCode{"", "cleanup_incomplete_2", "unknown"} {
		if _, err := EncodeErrorCode(code); err == nil {
			t.Errorf("EncodeErrorCode(%q) succeeded", code)
		}
		if _, err := ErrorCodeMessage(code); err == nil {
			t.Errorf("ErrorCodeMessage(%q) succeeded", code)
		}
	}
}

func TestOperationErrorMatrixEveryEdge(t *testing.T) {
	allCodes := []ErrorCode{
		ErrorCodeMalformedRequest, ErrorCodeUnknownOperation,
		ErrorCodeRequestConflict, ErrorCodeIdentityMismatch,
		ErrorCodeRevisionStale, ErrorCodeExpired, ErrorCodeResourceLimit,
		ErrorCodePrepareFailed, ErrorCodeRenewFailed, ErrorCodeRevokeFailed,
		ErrorCodeExecFailed, ErrorCodeHelperUnavailable,
		ErrorCodeCleanupIncomplete,
	}
	allowed := map[Operation][]ErrorCode{
		OperationReadiness: {
			ErrorCodeMalformedRequest, ErrorCodeRequestConflict,
			ErrorCodeIdentityMismatch, ErrorCodeHelperUnavailable,
		},
		OperationCredentialPrepare: {
			ErrorCodeMalformedRequest, ErrorCodeRequestConflict,
			ErrorCodeIdentityMismatch, ErrorCodeRevisionStale, ErrorCodeExpired,
			ErrorCodeResourceLimit, ErrorCodePrepareFailed,
			ErrorCodeHelperUnavailable, ErrorCodeCleanupIncomplete,
		},
		OperationCredentialRenew: {
			ErrorCodeMalformedRequest, ErrorCodeRequestConflict,
			ErrorCodeIdentityMismatch, ErrorCodeRevisionStale, ErrorCodeExpired,
			ErrorCodeRenewFailed, ErrorCodeHelperUnavailable,
		},
		OperationCredentialRevoke: {
			ErrorCodeMalformedRequest, ErrorCodeRequestConflict,
			ErrorCodeIdentityMismatch, ErrorCodeRevisionStale,
			ErrorCodeRevokeFailed, ErrorCodeHelperUnavailable,
			ErrorCodeCleanupIncomplete,
		},
		OperationExec: {
			ErrorCodeMalformedRequest, ErrorCodeRequestConflict,
			ErrorCodeIdentityMismatch, ErrorCodeRevisionStale, ErrorCodeExpired,
			ErrorCodeResourceLimit, ErrorCodeExecFailed, ErrorCodeHelperUnavailable,
		},
	}
	for operation, operationAllowed := range allowed {
		token, err := OperationTokenFor(operation)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range allCodes {
			want := containsErrorCode(operationAllowed, code)
			got := ValidateOperationErrorCode(token, code) == nil
			if got != want {
				t.Errorf("operation %q, code %q: valid=%t, want %t", operation, code, got, want)
			}
		}
	}

	unknown, err := ParseOperationToken("future_operation")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range allCodes {
		want := code == ErrorCodeUnknownOperation
		got := ValidateOperationErrorCode(unknown, code) == nil
		if got != want {
			t.Errorf("unknown operation, code %q: valid=%t, want %t", code, got, want)
		}
	}
	if ValidateOperationErrorCode(OperationToken{}, ErrorCodeMalformedRequest) == nil {
		t.Error("zero operation token accepted")
	}
	if ValidateOperationErrorCode(unknown, ErrorCode("cleanup_incomplete_2")) == nil {
		t.Error("unknown error code accepted")
	}
}

func containsErrorCode(codes []ErrorCode, target ErrorCode) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
