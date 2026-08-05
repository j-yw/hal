package v2control

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const (
	failurePrefix = `{"protocolVersion":"guest-agent-v2","operation":"readiness","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","ok":false,"error":`
	failureVector = failurePrefix + `{"code":"helper_unavailable","message":"credential helper is unavailable"}}`
)

func TestFailureResponseExactVectorsForEveryOperationAndSafeUnknown(t *testing.T) {
	tests := []struct {
		operation string
		code      ErrorCode
		message   string
	}{
		{"readiness", ErrorCodeHelperUnavailable, "credential helper is unavailable"},
		{"credential_prepare", ErrorCodePrepareFailed, "credential preparation failed"},
		{"credential_renew", ErrorCodeRenewFailed, "credential renewal failed"},
		{"credential_revoke", ErrorCodeRevokeFailed, "credential revocation failed"},
		{"exec", ErrorCodeExecFailed, "credential execution failed"},
		{"future_operation", ErrorCodeUnknownOperation, "credential operation is unsupported"},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			operation, err := ParseOperationToken(test.operation)
			if err != nil {
				t.Fatal(err)
			}
			controlError, err := NewControlError(operation, test.code)
			if err != nil {
				t.Fatal(err)
			}
			response, err := NewFailureResponse(testRequestID(t), testIdentityDigest(), controlError)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := EncodeFailureResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"protocolVersion":"guest-agent-v2","operation":"` + test.operation +
				`","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","ok":false,"error":{"code":"` +
				string(test.code) + `","message":"` + test.message + `"}}`
			if string(wire) != want {
				t.Fatalf("wire = %s\nwant = %s", wire, want)
			}
			decoded, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), wire)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.OperationToken() != operation || decoded.RequestID() != testRequestID(t) ||
				decoded.IdentityDigest() != testIdentityDigest() || decoded.ControlError().Code() != test.code {
				t.Fatalf("decoded correlation/error changed: %#v", decoded)
			}
		})
	}
}

func TestFailureResponseMalformedFieldIsClosedAndCanonical(t *testing.T) {
	operation, _ := OperationTokenFor(OperationReadiness)
	controlError, err := newMalformedControlErrorForField(operation, schemaFieldBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewFailureResponse(testRequestID(t), testIdentityDigest(), controlError)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeFailureResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(failureVector,
		`{"code":"helper_unavailable","message":"credential helper is unavailable"}`,
		`{"code":"malformed_request","field":"body","message":"credential request is malformed"}`, 1)
	if string(wire) != want {
		t.Fatalf("wire = %s\nwant = %s", wire, want)
	}
	decoded, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if field, ok := decoded.ControlError().Field(); !ok || field != "body" {
		t.Fatalf("decoded field = %q, %t", field, ok)
	}

	for _, field := range []string{"", "Body", "error.code", "privateValue", "body.value"} {
		unsafe := strings.Replace(want, `"field":"body"`, `"field":"`+field+`"`, 1)
		assertInvalidFailureJSON(t, operation, unsafe)
	}
	fieldOnOtherCode := strings.Replace(failureVector,
		`"code":"helper_unavailable"`, `"code":"helper_unavailable","field":"body"`, 1)
	assertInvalidFailureJSON(t, operation, fieldOnOtherCode)
}

func TestFailureResponseConstructionEnforcesEveryMatrixEdge(t *testing.T) {
	allCodes := []ErrorCode{
		ErrorCodeMalformedRequest, ErrorCodeUnknownOperation, ErrorCodeRequestConflict,
		ErrorCodeIdentityMismatch, ErrorCodeRevisionStale, ErrorCodeExpired,
		ErrorCodeResourceLimit, ErrorCodePrepareFailed, ErrorCodeRenewFailed,
		ErrorCodeRevokeFailed, ErrorCodeExecFailed, ErrorCodeHelperUnavailable,
		ErrorCodeCleanupIncomplete,
	}
	operations := []string{
		"readiness", "credential_prepare", "credential_renew", "credential_revoke", "exec", "future_operation",
	}
	for _, operationValue := range operations {
		operation, err := ParseOperationToken(operationValue)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range allCodes {
			controlError, controlErr := NewControlError(operation, code)
			response, responseErr := NewFailureResponse(testRequestID(t), testIdentityDigest(), controlError)
			if (controlErr == nil) != (responseErr == nil) {
				t.Errorf("operation=%s code=%s controlErr=%v response=%#v responseErr=%v", operationValue, code, controlErr, response, responseErr)
			}
		}
	}

	operation, _ := OperationTokenFor(OperationReadiness)
	controlError, _ := NewControlError(operation, ErrorCodeHelperUnavailable)
	if _, err := NewFailureResponse(RequestID{}, testIdentityDigest(), controlError); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("zero request ID error = %v", err)
	}
	if _, err := NewFailureResponse(testRequestID(t), testIdentityDigest(), ControlError{}); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("zero control error = %v", err)
	}
	if err := ValidateFailureResponse(FailureResponse{}); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("zero response validation error = %v", err)
	}
	if _, err := EncodeFailureResponse(FailureResponse{}); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("zero response encode error = %v", err)
	}
}

func TestFailureResponseRejectsEveryRootAndErrorFieldMutation(t *testing.T) {
	operation, _ := OperationTokenFor(OperationReadiness)
	rootFields := []string{
		`"protocolVersion":"guest-agent-v2"`,
		`"operation":"readiness"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`,
		`"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
		`"ok":false`,
	}
	errorFields := []string{
		`"code":"helper_unavailable"`,
		`"message":"credential helper is unavailable"`,
	}
	for _, field := range append(rootFields, errorFields...) {
		field := field
		t.Run(field, func(t *testing.T) {
			assertInvalidFailureJSON(t, operation, replaceFieldWithNull(t, failureVector, field))
			assertInvalidFailureJSON(t, operation, duplicateReadinessField(t, failureVector, field))
			assertInvalidFailureJSON(t, operation, caseAliasReadinessField(t, failureVector, field))
		})
	}
	errorMember := `"error":{"code":"helper_unavailable","message":"credential helper is unavailable"}`
	assertInvalidFailureJSON(t, operation, replaceOnce(t, failureVector, errorMember, errorMember+","+errorMember))
	assertInvalidFailureJSON(t, operation, replaceOnce(t, failureVector, `"error"`, `"Error"`))
	fieldVector := strings.Replace(failureVector,
		`{"code":"helper_unavailable","message":"credential helper is unavailable"}`,
		`{"code":"malformed_request","field":"body","message":"credential request is malformed"}`, 1)
	fieldMember := `"field":"body"`
	assertInvalidFailureJSON(t, operation, replaceFieldWithNull(t, fieldVector, fieldMember))
	assertInvalidFailureJSON(t, operation, duplicateReadinessField(t, fieldVector, fieldMember))
	assertInvalidFailureJSON(t, operation, caseAliasReadinessField(t, fieldVector, fieldMember))
	for _, wire := range []string{
		strings.Replace(failureVector, `"protocolVersion":"guest-agent-v2",`, "", 1),
		strings.Replace(failureVector, `"operation":"readiness",`, "", 1),
		strings.Replace(failureVector, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA",`, "", 1),
		strings.Replace(failureVector, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",`, "", 1),
		strings.Replace(failureVector, `"ok":false,`, "", 1),
		strings.Replace(failureVector, `,"error":{"code":"helper_unavailable","message":"credential helper is unavailable"}`, "", 1),
		strings.Replace(failureVector, `"code":"helper_unavailable",`, "", 1),
		strings.Replace(failureVector, `,"message":"credential helper is unavailable"`, "", 1),
		strings.Replace(failureVector, `"ok":false`, `"ok":true`, 1),
		strings.Replace(failureVector, `"ok":false`, `"ok":0`, 1),
		strings.Replace(failureVector, `"ok":false`, `"ok":false,"body":{}`, 1),
		strings.Replace(failureVector, `"error":{`, `"error":null,"discard":{`, 1),
		strings.Replace(failureVector, `"protocolVersion":"guest-agent-v2"`, `"unknown":0,"protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(failureVector, `"code":"helper_unavailable"`, `"unknown":0,"code":"helper_unavailable"`, 1),
		strings.Replace(failureVector, `"protocolVersion":"guest-agent-v2","operation":"readiness"`, `"operation":"readiness","protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(failureVector, `"code":"helper_unavailable","message":"credential helper is unavailable"`, `"message":"credential helper is unavailable","code":"helper_unavailable"`, 1),
		" " + failureVector,
		failureVector + "\n",
		failureVector + `{}`,
		`null`,
	} {
		assertInvalidFailureJSON(t, operation, wire)
	}
	invalidUTF8 := append([]byte(failureVector), 0xff)
	if _, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), invalidUTF8); !errors.Is(err, ErrInvalidFailureResponseJSON) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestFailureResponseRejectsEveryFieldOrderPermutation(t *testing.T) {
	operation, _ := OperationTokenFor(OperationReadiness)
	rootFields := []string{
		`"protocolVersion":"guest-agent-v2"`,
		`"operation":"readiness"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`,
		`"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
		`"ok":false`,
		`"error":{"code":"helper_unavailable","message":"credential helper is unavailable"}`,
	}
	canonicalRoot := strings.Join(rootFields, ",")
	for _, permutation := range failurePermutations(rootFields) {
		joined := strings.Join(permutation, ",")
		if joined == canonicalRoot {
			continue
		}
		assertInvalidFailureJSON(t, operation, "{"+joined+"}")
	}

	errorFields := []string{
		`"code":"malformed_request"`,
		`"field":"body"`,
		`"message":"credential request is malformed"`,
	}
	canonicalError := strings.Join(errorFields, ",")
	for _, permutation := range failurePermutations(errorFields) {
		joined := strings.Join(permutation, ",")
		wire := failurePrefix + "{" + joined + "}}"
		if joined == canonicalError {
			if _, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), []byte(wire)); err != nil {
				t.Fatalf("canonical field order failed: %v", err)
			}
			continue
		}
		assertInvalidFailureJSON(t, operation, wire)
	}
}

func TestFailureResponseRejectsCodeMessageAndOperationNearMisses(t *testing.T) {
	readiness, _ := OperationTokenFor(OperationReadiness)
	for _, wire := range []string{
		strings.Replace(failureVector, `"guest-agent-v2"`, `"guest-agent-v02"`, 1),
		strings.Replace(failureVector, `"operation":"readiness"`, `"operation":"Readiness"`, 1),
		strings.Replace(failureVector, `"operation":"readiness"`, `"operation":"credential-readiness"`, 1),
		strings.Replace(failureVector, `"code":"helper_unavailable"`, `"code":"Helper_unavailable"`, 1),
		strings.Replace(failureVector, `"code":"helper_unavailable"`, `"code":"helper-unavailable"`, 1),
		strings.Replace(failureVector, `"message":"credential helper is unavailable"`, `"message":"credential helper unavailable"`, 1),
		strings.Replace(failureVector, `"message":"credential helper is unavailable"`, `"message":"credential helper is unavailable "`, 1),
		strings.Replace(failureVector, `"code":"helper_unavailable","message":"credential helper is unavailable"`, `"code":"exec_failed","message":"credential execution failed"`, 1),
		strings.Replace(failureVector, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`, `"requestId":"AAAAAAAAAAAAAAAAAAAAAA"`, 1),
		strings.Replace(failureVector, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA="`, 1),
		strings.Replace(failureVector, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`, 1),
	} {
		assertInvalidFailureJSON(t, readiness, wire)
	}

	unknown, _ := ParseOperationToken("future_operation")
	unknownWire := strings.Replace(failureVector, `"operation":"readiness"`, `"operation":"future_operation"`, 1)
	assertInvalidFailureJSON(t, unknown, unknownWire)
	unknownWire = strings.Replace(unknownWire,
		`"code":"helper_unavailable","message":"credential helper is unavailable"`,
		`"code":"unknown_operation","message":"credential operation is unsupported"`, 1)
	if _, err := DecodeFailureResponse(unknown, testRequestID(t), testIdentityDigest(), []byte(unknownWire)); err != nil {
		t.Fatalf("canonical safe unknown rejected: %v", err)
	}
	for _, unsafe := range []string{"", "Readiness", "_future", "1future", "future-operation", strings.Repeat("a", 65)} {
		wire := strings.Replace(unknownWire, `"operation":"future_operation"`, `"operation":"`+unsafe+`"`, 1)
		if response, err := DecodeFailureResponse(unknown, testRequestID(t), testIdentityDigest(), []byte(wire)); !errors.Is(err, ErrInvalidFailureResponseJSON) || response != (FailureResponse{}) {
			t.Errorf("unsafe operation %q response=%#v error=%v", unsafe, response, err)
		}
	}
}

func TestFailureResponseMandatoryCorrelation(t *testing.T) {
	readiness, _ := OperationTokenFor(OperationReadiness)
	execOperation, _ := OperationTokenFor(OperationExec)
	if _, err := DecodeFailureResponse(execOperation, testRequestID(t), testIdentityDigest(), []byte(failureVector)); !errors.Is(err, ErrFailureCorrelationMismatch) {
		t.Fatalf("operation mismatch error = %v", err)
	}
	requestBytes := testRequestID(t).Bytes()
	requestBytes[0]++
	otherRequestID, _ := NewRequestID(requestBytes)
	if _, err := DecodeFailureResponse(readiness, otherRequestID, testIdentityDigest(), []byte(failureVector)); !errors.Is(err, ErrFailureCorrelationMismatch) {
		t.Fatalf("request ID mismatch error = %v", err)
	}
	digestBytes := testIdentityDigest().Bytes()
	digestBytes[0]++
	if _, err := DecodeFailureResponse(readiness, testRequestID(t), NewIdentityDigest(digestBytes), []byte(failureVector)); !errors.Is(err, ErrFailureCorrelationMismatch) {
		t.Fatalf("identity mismatch error = %v", err)
	}
	if _, err := DecodeFailureResponse(OperationToken{}, testRequestID(t), testIdentityDigest(), []byte(failureVector)); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("invalid expected operation error = %v", err)
	}
	if _, err := DecodeFailureResponse(readiness, RequestID{}, testIdentityDigest(), []byte(failureVector)); !errors.Is(err, ErrInvalidFailureResponse) {
		t.Fatalf("invalid expected request ID error = %v", err)
	}
}

func TestFailureResponseJSONSizeDepthAndCanonicalBounds(t *testing.T) {
	if maxFailureJSONBytes != session.MaxControlPlaintextBytes {
		t.Fatalf("failure bound = %d, session bound = %d", maxFailureJSONBytes, session.MaxControlPlaintextBytes)
	}
	readiness, _ := OperationTokenFor(OperationReadiness)
	atBound := make([]byte, maxFailureJSONBytes)
	copy(atBound, failureVector)
	for index := len(failureVector); index < len(atBound); index++ {
		atBound[index] = ' '
	}
	if !validFailureJSONInput(atBound) {
		t.Fatal("exact maximum valid JSON failed preflight")
	}
	if _, err := DecodeFailureResponse(readiness, testRequestID(t), testIdentityDigest(), atBound); !errors.Is(err, ErrInvalidFailureResponseJSON) {
		t.Fatalf("noncanonical exact maximum error = %v", err)
	}
	plusOne := append(append([]byte(nil), atBound...), ' ')
	if validFailureJSONInput(plusOne) {
		t.Fatal("maximum plus one passed preflight")
	}
	if _, err := DecodeFailureResponse(readiness, testRequestID(t), testIdentityDigest(), plusOne); !errors.Is(err, ErrInvalidFailureResponseJSON) {
		t.Fatalf("maximum plus one error = %v", err)
	}
	if !validFailureJSONInput([]byte(`[[[]]]`)) || validFailureJSONInput([]byte(`[[[[]]]]`)) {
		t.Fatal("failure JSON depth bound changed")
	}
	deep := strings.Replace(failureVector, `"error":{`, `"error":{"unknown":[[[[[]]]]],`, 1)
	assertInvalidFailureJSON(t, readiness, deep)
}

func TestFailureResponseSerializationAndErrorsStayOpaque(t *testing.T) {
	operation, _ := OperationTokenFor(OperationReadiness)
	controlError, _ := NewControlError(operation, ErrorCodeHelperUnavailable)
	response, _ := NewFailureResponse(testRequestID(t), testIdentityDigest(), controlError)
	if _, err := json.Marshal(response); !errors.Is(err, ErrFailureSerialization) {
		t.Fatalf("generic marshal error = %v", err)
	}
	if _, err := response.MarshalText(); !errors.Is(err, ErrFailureSerialization) {
		t.Fatalf("generic text marshal error = %v", err)
	}
	before := response
	if err := json.Unmarshal([]byte(failureVector), &response); !errors.Is(err, ErrFailureSerialization) {
		t.Fatalf("generic unmarshal error = %v", err)
	}
	if response.state != before.state {
		t.Fatal("failed generic decode changed response")
	}
	if err := response.UnmarshalText([]byte(failureVector)); !errors.Is(err, ErrFailureSerialization) {
		t.Fatalf("generic text unmarshal error = %v", err)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%x", "%q"} {
		if got := fmt.Sprintf(format, response); got != "<v2control.FailureResponse>" {
			t.Errorf("format %q = %q", format, got)
		}
	}

	secret := "secret://host.example/token-value"
	unsafeWire := strings.Replace(failureVector, "credential helper is unavailable", secret, 1)
	_, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), []byte(unsafeWire))
	if !errors.Is(err, ErrInvalidFailureResponseJSON) || strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
		t.Fatalf("unsafe decode error = %v", err)
	}

	typ := reflect.TypeOf(FailureResponse{})
	for index := 0; index < typ.NumField(); index++ {
		if typ.Field(index).IsExported() {
			t.Errorf("FailureResponse field %q is exported", typ.Field(index).Name)
		}
	}
}

func assertInvalidFailureJSON(t *testing.T, operation OperationToken, wire string) {
	t.Helper()
	if _, err := DecodeFailureResponse(operation, testRequestID(t), testIdentityDigest(), []byte(wire)); !errors.Is(err, ErrInvalidFailureResponseJSON) {
		t.Fatalf("wire unexpectedly accepted or wrong error: %v\n%s", err, wire)
	}
}

func failurePermutations(values []string) [][]string {
	working := append([]string(nil), values...)
	permutations := make([][]string, 0)
	var visit func(int)
	visit = func(index int) {
		if index == len(working) {
			permutations = append(permutations, append([]string(nil), working...))
			return
		}
		for candidate := index; candidate < len(working); candidate++ {
			working[index], working[candidate] = working[candidate], working[index]
			visit(index + 1)
			working[index], working[candidate] = working[candidate], working[index]
		}
	}
	visit(0)
	return permutations
}
