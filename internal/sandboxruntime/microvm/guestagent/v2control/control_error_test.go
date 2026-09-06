package v2control

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestControlErrorExactMessageAndCanonicalJSON(t *testing.T) {
	operation, err := OperationTokenFor(OperationCredentialPrepare)
	if err != nil {
		t.Fatal(err)
	}
	controlError, err := NewControlError(operation, ErrorCodePrepareFailed)
	if err != nil {
		t.Fatal(err)
	}
	if controlError.Code() != ErrorCodePrepareFailed || controlError.Message() != "credential preparation failed" {
		t.Fatalf("unexpected error: code=%q message=%q", controlError.Code(), controlError.Message())
	}
	if field, ok := controlError.Field(); ok || field != "" {
		t.Fatalf("unexpected field %q, %t", field, ok)
	}
	if got := controlError.Error(); got != controlError.Message() {
		t.Fatalf("Error() = %q", got)
	}
	wire, err := json.Marshal(controlError)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(wire), `{"code":"prepare_failed","message":"credential preparation failed"}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
	if err := ValidateControlError(controlError); err != nil {
		t.Fatalf("ValidateControlError: %v", err)
	}
}

func TestControlErrorStaticFieldIsPrivateAndMalformedOnly(t *testing.T) {
	fields := []struct {
		field schemaField
		path  string
	}{
		{schemaFieldProtocolVersion, "protocolVersion"},
		{schemaFieldOperation, "operation"},
		{schemaFieldRequestID, "requestId"},
		{schemaFieldIdentityDigest, "identityDigest"},
		{schemaFieldBody, "body"},
	}
	for index, test := range fields {
		if test.field != schemaField(index+1) {
			t.Fatalf("schema field %q numeric value = %d", test.path, test.field)
		}
		if got, ok := schemaFieldString(test.field); !ok || got != test.path {
			t.Fatalf("schemaFieldString(%d) = %q, %t", test.field, got, ok)
		}
	}
	for _, field := range []schemaField{0, schemaFieldBody + 1, 255} {
		if got, ok := schemaFieldString(field); ok || got != "" {
			t.Fatalf("unknown schema field %d = %q, %t", field, got, ok)
		}
	}

	operation, err := OperationTokenFor(OperationReadiness)
	if err != nil {
		t.Fatal(err)
	}
	controlError, err := newMalformedControlErrorForField(operation, schemaFieldProtocolVersion)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := controlError.Field(); !ok || got != "protocolVersion" {
		t.Fatalf("Field = %q, %t", got, ok)
	}
	wire, err := json.Marshal(controlError)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(wire), `{"code":"malformed_request","field":"protocolVersion","message":"credential request is malformed"}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}

	invalid := controlError
	invalid.code = ErrorCodeRequestConflict
	if ValidateControlError(invalid) == nil {
		t.Error("non-malformed error carried a field")
	}
	invalid = controlError
	invalid.field = schemaField(255)
	if ValidateControlError(invalid) == nil {
		t.Error("unknown static schema field accepted")
	}
}

func TestControlErrorConstructionEnforcesOperationMatrix(t *testing.T) {
	readiness, _ := OperationTokenFor(OperationReadiness)
	if _, err := NewControlError(readiness, ErrorCodeExecFailed); err == nil {
		t.Error("readiness accepted exec_failed")
	}
	if _, err := NewControlError(readiness, ErrorCodeUnknownOperation); err == nil {
		t.Error("known operation accepted unknown_operation")
	}
	unknown, _ := ParseOperationToken("future_operation")
	if _, err := NewControlError(unknown, ErrorCodeUnknownOperation); err != nil {
		t.Fatalf("safe unknown rejected unknown_operation: %v", err)
	}
	if _, err := NewControlError(unknown, ErrorCodeMalformedRequest); err == nil {
		t.Error("safe unknown accepted malformed_request")
	}
	if _, err := newMalformedControlErrorForField(unknown, schemaFieldOperation); err == nil {
		t.Error("safe unknown accepted field-bearing malformed_request")
	}
}

func TestControlErrorFormattingCannotIncludeDynamicInput(t *testing.T) {
	unknown, err := ParseOperationToken("attacker_supplied_but_safe")
	if err != nil {
		t.Fatal(err)
	}
	controlError, err := NewControlError(unknown, ErrorCodeUnknownOperation)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		got := fmt.Sprintf(format, controlError)
		if strings.Contains(got, "attacker") {
			t.Fatalf("format %q leaked operation token: %q", format, got)
		}
		if got != "credential operation is unsupported" {
			t.Fatalf("format %q = %q", format, got)
		}
	}
	methods := []string{
		"Code", "Error", "Field", "Format", "GoString", "MarshalJSON", "Message",
	}
	assertPublicMethods(t, reflect.TypeOf(ControlError{}), methods)
	assertPublicMethods(t, reflect.TypeOf(&ControlError{}), methods)
}
