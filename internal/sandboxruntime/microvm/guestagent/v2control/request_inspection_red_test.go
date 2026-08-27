package v2control

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestL8D6GuestV2RequestInspectorFreezesBodylessCanonicalDispatch(t *testing.T) {
	readinessWire, err := EncodeReadinessRequest(testReadinessRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectCredentialRequestRoot(readinessWire)
	if err != nil {
		t.Fatalf("InspectCredentialRequestRoot(readiness) error = %v", err)
	}
	operation, known := inspected.KnownOperation()
	if !known || operation != OperationReadiness || inspected.RequestID() != testReadinessRequest(t).RequestID() || inspected.IdentityDigest() != testReadinessRequest(t).IdentityDigest() {
		t.Fatal("readiness inspection did not preserve exact bodyless correlation")
	}

	unknownWire := []byte(`{"protocolVersion":"guest-agent-v2","operation":"future_operation","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","body":{"uninterpreted":[1,true,"value"]}}`)
	unknown, err := InspectCredentialRequestRoot(unknownWire)
	if err != nil {
		t.Fatalf("InspectCredentialRequestRoot(unknown) error = %v", err)
	}
	if _, known := unknown.KnownOperation(); known {
		t.Fatal("safe unknown operation was classified as known")
	}
	encodedOperation, err := EncodeOperationToken(unknown.OperationToken())
	if err != nil || encodedOperation != "future_operation" {
		t.Fatalf("unknown operation = %q, %v", encodedOperation, err)
	}
}

func TestL8D6GuestV2InitialPrepareDerivesIdentityOnlyFromSessionAndBody(t *testing.T) {
	expected := testCredentialPrepareRequest(t)
	wire, err := EncodeCredentialPrepareRequest(expected)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInitialCredentialPrepareRequest(expected.state.identity.SessionID(), wire)
	if err != nil {
		t.Fatalf("DecodeInitialCredentialPrepareRequest() error = %v", err)
	}
	if !reflect.DeepEqual(decoded.Identity(), expected.Identity()) || decoded.IdentityDigest() != expected.IdentityDigest() {
		t.Fatal("initial prepare did not derive the exact authenticated session identity")
	}

	otherSession := expected.state.identity.SessionID()
	otherSession[0] ^= 0xff
	if _, err := DecodeInitialCredentialPrepareRequest(otherSession, wire); !errors.Is(err, ErrInvalidCredentialPrepareRequestJSON) {
		t.Fatalf("cross-session initial prepare error = %v", err)
	}
}

func TestL8D6GuestV2InspectedRequestDeniesGenericSerialization(t *testing.T) {
	request := InspectedRequest{}
	if _, err := json.Marshal(request); !errors.Is(err, ErrCredentialRequestInspectionSerialization) {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	fields := reflect.VisibleFields(reflect.TypeOf(request))
	if len(fields) != 1 || fields[0].Name != "state" || fields[0].Type != reflect.TypeOf((*inspectedRequestState)(nil)) {
		t.Fatalf("InspectedRequest fields = %#v, want one private owned state pointer", fields)
	}
}

func TestL8D6GuestV2RequestInspectorRejectsInvalidOrDuplicateBodyJSON(t *testing.T) {
	for _, wire := range [][]byte{
		[]byte(`{"protocolVersion":"guest-agent-v2","operation":"future_operation","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","body":{"value":"\q"}}`),
		[]byte(`{"protocolVersion":"guest-agent-v2","operation":"future_operation","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","body":{"value":1,"value":2}}`),
	} {
		if _, err := InspectCredentialRequestRoot(wire); !errors.Is(err, ErrInvalidCredentialRequestRootJSON) {
			t.Fatalf("InspectCredentialRequestRoot(%s) error = %v, want invalid JSON", wire, err)
		}
	}
}
