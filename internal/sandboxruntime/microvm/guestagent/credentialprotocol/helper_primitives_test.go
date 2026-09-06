package credentialprotocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBodyTokenExactGrammarBoundsAndPrefix(t *testing.T) {
	t.Parallel()

	valid := []string{
		"a", "Z", "0", "a.-_:Z9", strings.Repeat("a", MaxBodyTokenBytes),
	}
	for _, token := range valid {
		encoded, err := EncodeBodyToken(token)
		if err != nil {
			t.Fatalf("EncodeBodyToken(%q) error = %v", token, err)
		}
		if len(encoded) != 2+len(token) || int(encoded[0])<<8|int(encoded[1]) != len(token) {
			t.Fatalf("EncodeBodyToken(%q) = %x", token, encoded)
		}
		decoded, err := DecodeBodyToken(encoded)
		if err != nil || decoded != token {
			t.Fatalf("DecodeBodyToken(%q) = %q, %v", token, decoded, err)
		}
		withTail := append(cloneBytes(encoded), 0xaa)
		prefix, consumed, err := DecodeBodyTokenPrefix(withTail)
		if err != nil || prefix != token || consumed != len(encoded) {
			t.Fatalf("DecodeBodyTokenPrefix(%q) = %q, %d, %v", token, prefix, consumed, err)
		}
		if _, err := DecodeBodyToken(withTail); !errors.Is(err, ErrBodyTokenTrailingData) {
			t.Fatalf("DecodeBodyToken(trailing) error = %v, want ErrBodyTokenTrailingData", err)
		}
	}

	invalid := []string{"", strings.Repeat("a", MaxBodyTokenBytes+1), "-first", "_first", ".first", ":first", "a/b", "a b", "a\x00b", "a邻"}
	for _, token := range invalid {
		if _, err := EncodeBodyToken(token); !errors.Is(err, ErrInvalidBodyToken) {
			t.Fatalf("EncodeBodyToken(%q) error = %v, want ErrInvalidBodyToken", token, err)
		}
	}

	malformed := [][]byte{
		nil, {0}, {0, 0}, {0, 2, 'a'}, {0, 1, '-'}, {0, MaxBodyTokenBytes + 1},
	}
	for _, encoded := range malformed {
		if _, _, err := DecodeBodyTokenPrefix(encoded); err == nil {
			t.Fatalf("DecodeBodyTokenPrefix(%x) unexpectedly succeeded", encoded)
		}
	}
}

func TestBodyTokenDecodeDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeBodyToken("alpha")
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := DecodeBodyTokenPrefix(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for index := 2; index < len(encoded); index++ {
		encoded[index] = 'x'
	}
	if decoded != "alpha" {
		t.Fatalf("decoded token changed through input mutation: %q", decoded)
	}
}

func TestOptionalRelativePathCanonicalEncodingAndBounds(t *testing.T) {
	t.Parallel()

	valid := []string{
		"", "a", "dir/file", "space allowed/file:name", strings.Repeat("a", MaxRelativePathComponentBytes),
		strings.Repeat("a", 255) + "/" + strings.Repeat("b", 255),
	}
	for _, path := range valid {
		encoded, err := EncodeOptionalRelativePath(path)
		if err != nil {
			t.Fatalf("EncodeOptionalRelativePath(%q) error = %v", path, err)
		}
		decoded, err := DecodeOptionalRelativePath(encoded)
		if err != nil || decoded != path {
			t.Fatalf("DecodeOptionalRelativePath(%q) = %q, %v", path, decoded, err)
		}
		withTail := append(cloneBytes(encoded), 0xbb)
		prefix, consumed, err := DecodeOptionalRelativePathPrefix(withTail)
		if err != nil || prefix != path || consumed != len(encoded) {
			t.Fatalf("DecodeOptionalRelativePathPrefix(%q) = %q, %d, %v", path, prefix, consumed, err)
		}
		if _, err := DecodeOptionalRelativePath(withTail); !errors.Is(err, ErrRelativePathTrailingData) {
			t.Fatalf("DecodeOptionalRelativePath(trailing) error = %v, want ErrRelativePathTrailingData", err)
		}
	}

	maxPath := strings.Repeat("a", 255)
	for len(maxPath)+1+255 <= MaxRelativePathBytes {
		maxPath += "/" + strings.Repeat("b", 255)
	}
	if len(maxPath) > MaxRelativePathBytes {
		t.Fatalf("test path length = %d", len(maxPath))
	}
	if _, err := EncodeOptionalRelativePath(maxPath); err != nil {
		t.Fatalf("EncodeOptionalRelativePath(large canonical) error = %v", err)
	}
	exactMaxPath := strings.Repeat("a/", 15) + strings.Repeat("b", 255)
	for len(exactMaxPath) < MaxRelativePathBytes {
		remaining := MaxRelativePathBytes - len(exactMaxPath)
		componentLength := remaining - 1
		if componentLength > MaxRelativePathComponentBytes {
			componentLength = MaxRelativePathComponentBytes
		}
		exactMaxPath += "/" + strings.Repeat("c", componentLength)
	}
	if len(exactMaxPath) != MaxRelativePathBytes {
		t.Fatalf("exact maximum path fixture length = %d", len(exactMaxPath))
	}
	if _, err := EncodeOptionalRelativePath(exactMaxPath); err != nil {
		t.Fatalf("EncodeOptionalRelativePath(exact max) error = %v", err)
	}

	invalid := []string{
		"/absolute", "trailing/", "a//b", ".", "..", "a/./b", "a/../b", `a\b`, "a\x00b", "a\x1fb", "a\x7fb", "a邻b",
		strings.Repeat("a", MaxRelativePathComponentBytes+1), strings.Repeat("a", MaxRelativePathBytes+1),
	}
	for _, path := range invalid {
		if _, err := EncodeOptionalRelativePath(path); !errors.Is(err, ErrInvalidRelativePath) {
			t.Fatalf("EncodeOptionalRelativePath(%q) error = %v, want ErrInvalidRelativePath", path, err)
		}
	}

	malformed := [][]byte{nil, {0}, {0, 2, 'a'}, {0, 1, '/'}, {0, 2, '.', '.'}}
	for _, encoded := range malformed {
		if _, _, err := DecodeOptionalRelativePathPrefix(encoded); err == nil {
			t.Fatalf("DecodeOptionalRelativePathPrefix(%x) unexpectedly succeeded", encoded)
		}
	}
}

func TestHelperPrimitiveErrorsDoNotEchoRejectedInput(t *testing.T) {
	t.Parallel()

	seed := "credential-value-never-echoed/host/private/path"
	checks := []error{}
	if _, err := EncodeBodyToken(seed); err != nil {
		checks = append(checks, err)
	}
	if _, err := EncodeOptionalRelativePath("../" + seed); err != nil {
		checks = append(checks, err)
	}
	if len(checks) != 2 {
		t.Fatalf("rejected error count = %d, want 2", len(checks))
	}
	for _, err := range checks {
		if strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), "private/path") {
			t.Fatalf("error leaked rejected input: %q", err)
		}
	}
}

func TestOptionalRelativePathDecodeDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeOptionalRelativePath("dir/file")
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := DecodeOptionalRelativePathPrefix(encoded)
	if err != nil {
		t.Fatal(err)
	}
	copy(encoded[2:], bytes.Repeat([]byte{'x'}, len(encoded)-2))
	if decoded != "dir/file" {
		t.Fatalf("decoded path changed through input mutation: %q", decoded)
	}
}

func TestHelperNumericCatalogsAreExactClosedAndSanitized(t *testing.T) {
	t.Parallel()

	testClosedCatalog(t, "revoke", []catalogCase[RevokeReason]{
		{RevokeReasonRequested, 1, "requested"}, {RevokeReasonExpired, 2, "expired"},
		{RevokeReasonSessionLoss, 3, "session_loss"}, {RevokeReasonSourceRevoked, 4, "source_revoked"},
		{RevokeReasonWorkerCancel, 5, "worker_cancel"}, {RevokeReasonDaemonShutdown, 6, "daemon_shutdown"},
	}, ValidateRevokeReason, func(value RevokeReason) string { return value.String() }, ErrUnknownRevokeReason)

	testClosedCatalog(t, "disposition", []catalogCase[ResponseDisposition]{
		{ResponseDispositionAccepted, 1, "accepted"}, {ResponseDispositionRejected, 2, "rejected"},
		{ResponseDispositionCleanupComplete, 3, "cleanup_complete"}, {ResponseDispositionCleanupRetry, 4, "cleanup_retry"},
		{ResponseDispositionStopVMRequired, 5, "stop_vm_required"},
	}, ValidateResponseDisposition, func(value ResponseDisposition) string { return value.String() }, ErrUnknownResponseDisposition)

	testClosedCatalog(t, "failure", []catalogCase[FailureCode]{
		{FailureCodeNone, 0, "none"}, {FailureCodeMalformed, 1, "malformed"},
		{FailureCodeIdentityMismatch, 2, "identity_mismatch"}, {FailureCodeRevisionStale, 3, "revision_stale"},
		{FailureCodeExpired, 4, "expired"}, {FailureCodeResourceLimit, 5, "resource_limit"},
		{FailureCodePrepareFailed, 6, "prepare_failed"}, {FailureCodeRenewFailed, 7, "renew_failed"},
		{FailureCodeRevokeFailed, 8, "revoke_failed"}, {FailureCodeExecFailed, 9, "exec_failed"},
		{FailureCodeCleanupIncomplete, 10, "cleanup_incomplete"}, {FailureCodeHelperUnavailable, 11, "helper_unavailable"},
	}, ValidateFailureCode, func(value FailureCode) string { return value.String() }, ErrUnknownFailureCode)

	testClosedCatalog(t, "event", []catalogCase[EventCode]{
		{EventCodeExpired, 1, "expired"}, {EventCodeSessionLoss, 2, "session_loss"},
		{EventCodeSourceRevoked, 3, "source_revoked"}, {EventCodeCleanupRequired, 4, "cleanup_required"},
	}, ValidateEventCode, func(value EventCode) string { return value.String() }, ErrUnknownEventCode)

	testClosedCatalog(t, "close", []catalogCase[CloseReason]{
		{CloseReasonNormal, 1, "normal"}, {CloseReasonProtocolError, 2, "protocol_error"},
		{CloseReasonIdentityDrift, 3, "identity_drift"}, {CloseReasonExpired, 4, "expired"},
		{CloseReasonHelperLoss, 5, "helper_loss"}, {CloseReasonShutdown, 6, "shutdown"},
	}, ValidateCloseReason, func(value CloseReason) string { return value.String() }, ErrUnknownCloseReason)
}

type catalogCase[T ~uint8] struct {
	value T
	wire  uint8
	name  string
}

func testClosedCatalog[T ~uint8](
	t *testing.T,
	name string,
	cases []catalogCase[T],
	validate func(T) error,
	stringify func(T) string,
	wantUnknown error,
) {
	t.Helper()
	known := make(map[uint8]bool, len(cases))
	for _, test := range cases {
		known[test.wire] = true
		if uint8(test.value) != test.wire || stringify(test.value) != test.name {
			t.Errorf("%s catalog value = %d/%q, want %d/%q", name, test.value, stringify(test.value), test.wire, test.name)
		}
		if err := validate(test.value); err != nil {
			t.Errorf("validate %s %d error = %v", name, test.wire, err)
		}
	}
	for value := 0; value <= 0xff; value++ {
		if known[uint8(value)] {
			continue
		}
		if err := validate(T(value)); !errors.Is(err, wantUnknown) {
			t.Errorf("validate unknown %s %d error = %v, want %v", name, value, err, wantUnknown)
		}
		if got := stringify(T(value)); got != "unknown" {
			t.Errorf("unknown %s %d String() = %q, want unknown", name, value, got)
		}
	}
}
