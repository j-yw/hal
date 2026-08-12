package v2control

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

const (
	testPriorRevision = uint64(8)
	testRenewExpiry   = int64(1700000600123456789)
	testSessionExpiry = int64(1700001200123456789)
	testRootExpiry    = int64(1700001800123456789)
)

func TestCredentialRenewCanonicalVectorsAndAccessors(t *testing.T) {
	request := testCredentialRenewRequest(t)
	sessionDigest, err := GuestCredentialSessionIdentityDigest(testSessionIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	jobDigest, err := JobIdentityDigest(validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if request.IdentityDigest().Bytes() != sessionDigest || sessionDigest == jobDigest {
		t.Fatal("renew envelope digest must be the session-bound identity digest, not the bare job digest")
	}
	wire, err := EncodeCredentialRenewRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	identityJSON, err := MarshalJobIdentity(validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"guest-agent-v2","operation":"credential_renew","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","body":{"identity":` + string(identityJSON) + `,"revision":9,"expiresAtUnixNano":1700000600123456789,"priorProofId":"active-proof-8"}}`
	if string(wire) != want {
		t.Fatalf("renew request:\n got %s\nwant %s", wire, want)
	}
	decoded, err := DecodeCredentialRenewRequest(testSessionIdentity(t), testPriorRevision, testSessionExpiry, testRootExpiry, wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Revision() != 9 || decoded.ExpiresAtUnixNano() != testRenewExpiry || decoded.PriorProofID() != "active-proof-8" || decoded.RequestID() != request.RequestID() || decoded.IdentityDigest() != request.IdentityDigest() {
		t.Fatal("renew request accessors changed")
	}
	assertJobIdentityEqual(t, decoded.Identity(), validChildIdentity(t))

	response, err := NewCredentialRenewSuccessResponse(request, "active-proof-9")
	if err != nil {
		t.Fatal(err)
	}
	responseWire, err := EncodeCredentialRenewSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	wantResponse := `{"protocolVersion":"guest-agent-v2","operation":"credential_renew","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","ok":true,"body":{"revision":9,"expiresAtUnixNano":1700000600123456789,"replacementActiveProofId":"active-proof-9"}}`
	if string(responseWire) != wantResponse {
		t.Fatalf("renew success:\n got %s\nwant %s", responseWire, wantResponse)
	}
	decodedResponse, err := DecodeCredentialRenewSuccessResponse(request, responseWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedResponse.Revision() != 9 || decodedResponse.ExpiresAtUnixNano() != testRenewExpiry || decodedResponse.ReplacementActiveProofID() != "active-proof-9" {
		t.Fatal("renew success accessors changed")
	}
}

func TestCredentialRenewCallerStateRules(t *testing.T) {
	identity := testSessionIdentity(t)
	requestID := testLifecycleRequestID(t)
	tests := []struct {
		name                   string
		prior                  uint64
		expires, session, root int64
	}{
		{"zero prior", 0, testRenewExpiry, testSessionExpiry, testRootExpiry},
		{"revision overflow", math.MaxUint64, testRenewExpiry, testSessionExpiry, testRootExpiry},
		{"zero expiry", testPriorRevision, 0, testSessionExpiry, testRootExpiry},
		{"negative expiry", testPriorRevision, -1, testSessionExpiry, testRootExpiry},
		{"at identity issue time", testPriorRevision, 1700000000123456789, testSessionExpiry, testRootExpiry},
		{"before identity issue time", testPriorRevision, 1700000000123456788, testSessionExpiry, testRootExpiry},
		{"zero session horizon", testPriorRevision, testRenewExpiry, 0, testRootExpiry},
		{"zero root horizon", testPriorRevision, testRenewExpiry, testSessionExpiry, 0},
		{"past session horizon", testPriorRevision, testSessionExpiry + 1, testSessionExpiry, testRootExpiry},
		{"past root horizon", testPriorRevision, testRootExpiry + 1, testRootExpiry + 2, testRootExpiry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCredentialRenewRequest(requestID, identity, test.prior, test.expires, test.session, test.root, "active-proof-8"); !errors.Is(err, ErrInvalidCredentialRenewRequest) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := NewCredentialRenewRequest(requestID, identity, testPriorRevision, testSessionExpiry, testSessionExpiry, testRootExpiry, "active-proof-8"); err != nil {
		t.Fatalf("exact session horizon rejected: %v", err)
	}
	if _, err := NewCredentialRenewRequest(requestID, identity, testPriorRevision, testRootExpiry, testRootExpiry+1, testRootExpiry, "active-proof-8"); err != nil {
		t.Fatalf("exact root horizon rejected: %v", err)
	}
	if _, err := NewCredentialRenewRequest(requestID, identity, testPriorRevision, testSessionExpiry, testSessionExpiry, testSessionExpiry, "active-proof-8"); err != nil {
		t.Fatalf("expiry equal to both horizons rejected: %v", err)
	}
	if _, err := NewCredentialRenewRequest(requestID, identity, testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, strings.Repeat("a", 128)); err != nil {
		t.Fatalf("exact safe-ID bound rejected: %v", err)
	}
	if _, err := NewCredentialRenewRequest(requestID, identity, testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, strings.Repeat("a", 129)); !errors.Is(err, ErrInvalidCredentialRenewRequest) {
		t.Fatalf("safe-ID bound plus one error = %v", err)
	}
}

func TestCredentialRevokeCatalogVectorsAndAccessors(t *testing.T) {
	wants := []CredentialRevokeReason{
		CredentialRevokeReasonRequested, CredentialRevokeReasonExpired,
		CredentialRevokeReasonSessionLoss, CredentialRevokeReasonSourceRevoked,
		CredentialRevokeReasonWorkerCancel, CredentialRevokeReasonDaemonShutdown,
	}
	for _, reason := range wants {
		if _, err := NewCredentialRevokeRequest(testLifecycleRequestID(t), testSessionIdentity(t), 9, reason); err != nil {
			t.Errorf("reason %q rejected: %v", reason, err)
		}
	}
	for _, reason := range []CredentialRevokeReason{"", "Requested", "source-revoked", "unknown"} {
		if _, err := NewCredentialRevokeRequest(testLifecycleRequestID(t), testSessionIdentity(t), 9, reason); !errors.Is(err, ErrInvalidCredentialRevokeRequest) {
			t.Errorf("reason %q error = %v", reason, err)
		}
	}
	request := testCredentialRevokeRequest(t)
	wire, err := EncodeCredentialRevokeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	identityJSON, _ := MarshalJobIdentity(validChildIdentity(t))
	want := `{"protocolVersion":"guest-agent-v2","operation":"credential_revoke","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","body":{"identity":` + string(identityJSON) + `,"revision":9,"reason":"source_revoked"}}`
	if string(wire) != want {
		t.Fatalf("revoke request:\n got %s\nwant %s", wire, want)
	}
	decoded, err := DecodeCredentialRevokeRequest(testSessionIdentity(t), 9, wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Revision() != 9 || decoded.Reason() != CredentialRevokeReasonSourceRevoked || decoded.RequestID() != request.RequestID() || decoded.IdentityDigest() != request.IdentityDigest() {
		t.Fatal("revoke request accessors changed")
	}
	assertJobIdentityEqual(t, decoded.Identity(), validChildIdentity(t))

	response, err := NewCredentialRevokeSuccessResponse(request, "cleanup-proof-9")
	if err != nil {
		t.Fatal(err)
	}
	responseWire, err := EncodeCredentialRevokeSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	wantResponse := `{"protocolVersion":"guest-agent-v2","operation":"credential_revoke","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","ok":true,"body":{"revision":9,"cleanupProofId":"cleanup-proof-9","authorityAbsent":true,"resourcesAbsent":true,"cleanupDisposition":"cleanup_complete"}}`
	if string(responseWire) != wantResponse {
		t.Fatalf("revoke success:\n got %s\nwant %s", responseWire, wantResponse)
	}
	decodedResponse, err := DecodeCredentialRevokeSuccessResponse(request, responseWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedResponse.Revision() != 9 || decodedResponse.CleanupProofID() != "cleanup-proof-9" || !decodedResponse.AuthorityAbsent() || !decodedResponse.ResourcesAbsent() || decodedResponse.CleanupDisposition() != CredentialCleanupDispositionComplete {
		t.Fatal("revoke success accessors changed")
	}
}

func TestCredentialLifecycleStrictCanonicalJSONAndCorrelation(t *testing.T) {
	renew := testCredentialRenewRequest(t)
	renewWire, _ := EncodeCredentialRenewRequest(renew)
	revoke := testCredentialRevokeRequest(t)
	revokeWire, _ := EncodeCredentialRevokeRequest(revoke)
	renewSuccess, _ := NewCredentialRenewSuccessResponse(renew, "active-proof-9")
	renewSuccessWire, _ := EncodeCredentialRenewSuccessResponse(renewSuccess)
	revokeSuccess, _ := NewCredentialRevokeSuccessResponse(revoke, "cleanup-proof-9")
	revokeSuccessWire, _ := EncodeCredentialRevokeSuccessResponse(revokeSuccess)

	requestCases := []struct {
		name string
		wire []byte
		run  func([]byte) error
	}{
		{"renew unknown root", replaceBytes(renewWire, `"body":`, `"unknown":0,"body":`), decodeRenewForTest},
		{"renew unknown body", replaceBytes(renewWire, `"revision":9`, `"unknown":0,"revision":9`), decodeRenewForTest},
		{"renew duplicate", replaceBytes(renewWire, `"revision":9`, `"revision":9,"revision":9`), decodeRenewForTest},
		{"renew case alias", replaceBytes(renewWire, `"priorProofId"`, `"PriorProofId"`), decodeRenewForTest},
		{"renew null", replaceBytes(renewWire, `"priorProofId":"active-proof-8"`, `"priorProofId":null`), decodeRenewForTest},
		{"renew omitted", replaceBytes(renewWire, `,"priorProofId":"active-proof-8"`, ``), decodeRenewForTest},
		{"renew numeric decimal", replaceBytes(renewWire, `"revision":9`, `"revision":9.0`), decodeRenewForTest},
		{"renew numeric exponent", replaceBytes(renewWire, `"expiresAtUnixNano":1700000600123456789`, `"expiresAtUnixNano":1700000600123456789e0`), decodeRenewForTest},
		{"renew overflow", replaceBytes(renewWire, `"revision":9`, `"revision":18446744073709551616`), decodeRenewForTest},
		{"renew reordered", replaceBytes(renewWire, `"protocolVersion":"guest-agent-v2","operation":"credential_renew"`, `"operation":"credential_renew","protocolVersion":"guest-agent-v2"`), decodeRenewForTest},
		{"renew alternate union", replaceBytes(renewWire, `"priorProofId":"active-proof-8"`, `"reason":"requested"`), decodeRenewForTest},
		{"renew trailing", append(append([]byte(nil), renewWire...), '\n'), decodeRenewForTest},
		{"revoke null", replaceBytes(revokeWire, `"reason":"source_revoked"`, `"reason":null`), decodeRevokeForTest},
		{"revoke omitted", replaceBytes(revokeWire, `,"reason":"source_revoked"`, ``), decodeRevokeForTest},
		{"revoke alternate union", replaceBytes(revokeWire, `"reason":"source_revoked"`, `"priorProofId":"active-proof-8"`), decodeRevokeForTest},
	}
	for _, test := range requestCases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(test.wire); err == nil {
				t.Fatal("invalid request succeeded")
			}
		})
	}

	for _, test := range []struct {
		name string
		wire []byte
		run  func([]byte) error
	}{
		{"renew false", replaceBytes(renewSuccessWire, `"ok":true`, `"ok":false`), decodeRenewSuccessForTest},
		{"renew body null", replaceBytes(renewSuccessWire, `"body":{`, `"body":null,"discard":{`), decodeRenewSuccessForTest},
		{"renew omitted proof", replaceBytes(renewSuccessWire, `,"replacementActiveProofId":"active-proof-9"`, ``), decodeRenewSuccessForTest},
		{"renew alternate body", replaceBytes(renewSuccessWire, `"replacementActiveProofId":"active-proof-9"`, `"cleanupProofId":"cleanup-proof-9"`), decodeRenewSuccessForTest},
		{"revoke authority false", replaceBytes(revokeSuccessWire, `"authorityAbsent":true`, `"authorityAbsent":false`), decodeRevokeSuccessForTest},
		{"revoke resources false", replaceBytes(revokeSuccessWire, `"resourcesAbsent":true`, `"resourcesAbsent":false`), decodeRevokeSuccessForTest},
		{"revoke disposition", replaceBytes(revokeSuccessWire, `"cleanup_complete"`, `"cleanup_incomplete"`), decodeRevokeSuccessForTest},
		{"revoke alternate body", replaceBytes(revokeSuccessWire, `"cleanupProofId":"cleanup-proof-9"`, `"replacementActiveProofId":"active-proof-9"`), decodeRevokeSuccessForTest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(test.wire); err == nil {
				t.Fatal("invalid success succeeded")
			}
		})
	}

	otherID := testRequestIDWithFirstByte(t, 2)
	otherRenew, _ := NewCredentialRenewRequest(otherID, testSessionIdentity(t), testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, "active-proof-8")
	if _, err := DecodeCredentialRenewSuccessResponse(otherRenew, renewSuccessWire); !errors.Is(err, ErrCredentialRenewCorrelationMismatch) {
		t.Fatalf("renew correlation error = %v", err)
	}
	otherRevoke, _ := NewCredentialRevokeRequest(otherID, testSessionIdentity(t), 9, CredentialRevokeReasonSourceRevoked)
	if _, err := DecodeCredentialRevokeSuccessResponse(otherRevoke, revokeSuccessWire); !errors.Is(err, ErrCredentialRevokeCorrelationMismatch) {
		t.Fatalf("revoke correlation error = %v", err)
	}
	otherIdentity := otherLifecycleSessionIdentity(t)
	otherIdentityRenew, _ := NewCredentialRenewRequest(renew.RequestID(), otherIdentity, testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, "active-proof-8")
	if _, err := DecodeCredentialRenewSuccessResponse(otherIdentityRenew, renewSuccessWire); !errors.Is(err, ErrCredentialRenewCorrelationMismatch) {
		t.Fatalf("renew session/identity correlation error = %v", err)
	}
	if _, err := DecodeCredentialRenewRequest(otherIdentity, testPriorRevision, testSessionExpiry, testRootExpiry, renewWire); !errors.Is(err, ErrInvalidCredentialRenewRequestJSON) {
		t.Fatalf("renew request session/identity error = %v", err)
	}
	otherRevisionRenew, _ := NewCredentialRenewRequest(renew.RequestID(), testSessionIdentity(t), testPriorRevision+1, testRenewExpiry, testSessionExpiry, testRootExpiry, "active-proof-9")
	if _, err := DecodeCredentialRenewSuccessResponse(otherRevisionRenew, renewSuccessWire); !errors.Is(err, ErrCredentialRenewCorrelationMismatch) {
		t.Fatalf("renew revision correlation error = %v", err)
	}
	otherRevisionRevoke, _ := NewCredentialRevokeRequest(revoke.RequestID(), testSessionIdentity(t), 10, CredentialRevokeReasonSourceRevoked)
	if _, err := DecodeCredentialRevokeSuccessResponse(otherRevisionRevoke, revokeSuccessWire); !errors.Is(err, ErrCredentialRevokeCorrelationMismatch) {
		t.Fatalf("revoke revision correlation error = %v", err)
	}
}

func TestCredentialLifecycleBoundsPrivateAbsenceAndSafeErrors(t *testing.T) {
	if maxCredentialLifecycleJSONBytes != 2*1024*1024 || maxCredentialLifecycleJSONDepth != 5 || maxCredentialLifecycleJSONTokens != 512 || maxCredentialLifecycleJSONStringBytes != 128 {
		t.Fatal("lifecycle bounds changed")
	}
	if !validCredentialLifecycleJSONInput([]byte(`[[[[[]]]]]`)) || validCredentialLifecycleJSONInput([]byte(`[[[[[[]]]]]]`)) {
		t.Fatal("depth boundary changed")
	}
	if !validCredentialLifecycleJSONInput([]byte(`"`+strings.Repeat("a", 128)+`"`)) || validCredentialLifecycleJSONInput([]byte(`"`+strings.Repeat("a", 129)+`"`)) {
		t.Fatal("string boundary changed")
	}
	atBound := make([]byte, maxCredentialLifecycleJSONBytes)
	copy(atBound, `null`)
	for index := 4; index < len(atBound); index++ {
		atBound[index] = ' '
	}
	if !validCredentialLifecycleJSONInput(atBound) || validCredentialLifecycleJSONInput(append(atBound, ' ')) {
		t.Fatal("byte boundary changed")
	}
	var tokenBuilder strings.Builder
	tokenBuilder.WriteByte('[')
	for index := 0; index < 510; index++ {
		if index > 0 {
			tokenBuilder.WriteByte(',')
		}
		tokenBuilder.WriteByte('0')
	}
	tokenBuilder.WriteByte(']')
	if !validCredentialLifecycleJSONInput([]byte(tokenBuilder.String())) {
		t.Fatal("token maximum rejected")
	}
	tokenBuilder.WriteString(" ")
	plusOne := strings.Replace(tokenBuilder.String(), "]", ",0]", 1)
	if validCredentialLifecycleJSONInput([]byte(plusOne)) {
		t.Fatal("token maximum plus one accepted")
	}

	for _, wire := range lifecycleCanonicalWires(t) {
		if strings.Contains(string(wire), "privateRecordCount") || strings.Contains(string(wire), "privateAggregateBytes") || strings.Contains(string(wire), "privateAggregateSha256") {
			t.Fatalf("private field leaked: %s", wire)
		}
	}
	for _, err := range []error{ErrInvalidCredentialRenewRequest, ErrInvalidCredentialRenewRequestJSON, ErrInvalidCredentialRenewSuccess, ErrInvalidCredentialRenewSuccessJSON, ErrCredentialRenewCorrelationMismatch, ErrInvalidCredentialRevokeRequest, ErrInvalidCredentialRevokeRequestJSON, ErrInvalidCredentialRevokeSuccess, ErrInvalidCredentialRevokeSuccessJSON, ErrCredentialRevokeCorrelationMismatch, ErrCredentialLifecycleSerialization} {
		for _, secret := range []string{"active-proof-8", "cleanup-proof-9", "example.invalid", "/private"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked %q: %v", secret, err)
			}
		}
	}
}

func TestCredentialLifecycleGenericSerializationAndFormattingDenied(t *testing.T) {
	renewRequest := testCredentialRenewRequest(t)
	revokeRequest := testCredentialRevokeRequest(t)
	values := []any{renewRequest, &renewRequest, revokeRequest, &revokeRequest}
	renewSuccess, _ := NewCredentialRenewSuccessResponse(testCredentialRenewRequest(t), "active-proof-9")
	revokeSuccess, _ := NewCredentialRevokeSuccessResponse(testCredentialRevokeRequest(t), "cleanup-proof-9")
	values = append(values, renewSuccess, &renewSuccess, revokeSuccess, &revokeSuccess)
	for _, value := range values {
		if _, err := json.Marshal(value); !errors.Is(err, ErrCredentialLifecycleSerialization) {
			t.Errorf("%T JSON error = %v", value, err)
		}
		if marshaler := value.(encoding.TextMarshaler); func() error { _, err := marshaler.MarshalText(); return err }() != ErrCredentialLifecycleSerialization {
			t.Errorf("%T text serialization was not denied", value)
		}
		if marshaler := value.(encoding.BinaryMarshaler); func() error { _, err := marshaler.MarshalBinary(); return err }() != ErrCredentialLifecycleSerialization {
			t.Errorf("%T binary serialization was not denied", value)
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%x", "%q"} {
			if got := fmt.Sprintf(format, value); !strings.HasPrefix(got, "<v2control.Credential") {
				t.Errorf("%T format %s = %q", value, format, got)
			}
		}
	}

	renew := testCredentialRenewRequest(t)
	before := renew
	if err := json.Unmarshal([]byte(`{}`), &renew); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renew, before) {
		t.Fatal("renew denied JSON unmarshal mutated receiver")
	}
	if err := renew.UnmarshalText([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renew, before) {
		t.Fatal("renew denied text unmarshal mutated receiver")
	}
	if err := renew.UnmarshalBinary([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renew, before) {
		t.Fatal("renew denied binary unmarshal mutated receiver")
	}
	revoke := testCredentialRevokeRequest(t)
	revokeBefore := revoke
	if err := json.Unmarshal([]byte(`{}`), &revoke); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revoke, revokeBefore) {
		t.Fatal("revoke denied JSON unmarshal mutated receiver")
	}
	if err := revoke.UnmarshalText([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revoke, revokeBefore) {
		t.Fatal("revoke denied text unmarshal mutated receiver")
	}
	if err := revoke.UnmarshalBinary([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revoke, revokeBefore) {
		t.Fatal("revoke denied binary unmarshal mutated receiver")
	}
	renewResponse := renewSuccess
	renewResponseBefore := renewResponse
	if err := json.Unmarshal([]byte(`{}`), &renewResponse); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renewResponse, renewResponseBefore) {
		t.Fatal("renew success denied JSON unmarshal mutated receiver")
	}
	if err := renewResponse.UnmarshalText([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renewResponse, renewResponseBefore) {
		t.Fatal("renew success denied text unmarshal mutated receiver")
	}
	if err := renewResponse.UnmarshalBinary([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(renewResponse, renewResponseBefore) {
		t.Fatal("renew success denied binary unmarshal mutated receiver")
	}
	revokeResponse := revokeSuccess
	revokeResponseBefore := revokeResponse
	if err := json.Unmarshal([]byte(`{}`), &revokeResponse); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revokeResponse, revokeResponseBefore) {
		t.Fatal("revoke success denied JSON unmarshal mutated receiver")
	}
	if err := revokeResponse.UnmarshalText([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revokeResponse, revokeResponseBefore) {
		t.Fatal("revoke success denied text unmarshal mutated receiver")
	}
	if err := revokeResponse.UnmarshalBinary([]byte("secret")); !errors.Is(err, ErrCredentialLifecycleSerialization) || !reflect.DeepEqual(revokeResponse, revokeResponseBefore) {
		t.Fatal("revoke success denied binary unmarshal mutated receiver")
	}
}

func testCredentialRenewRequest(t *testing.T) CredentialRenewRequest {
	t.Helper()
	request, err := NewCredentialRenewRequest(testLifecycleRequestID(t), testSessionIdentity(t), testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, "active-proof-8")
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testCredentialRevokeRequest(t *testing.T) CredentialRevokeRequest {
	t.Helper()
	request, err := NewCredentialRevokeRequest(testLifecycleRequestID(t), testSessionIdentity(t), 9, CredentialRevokeReasonSourceRevoked)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testSessionIdentity(t *testing.T) GuestCredentialSessionIdentity {
	t.Helper()
	identity, err := NewGuestCredentialSessionIdentity(sequentialSessionID(), validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func otherLifecycleSessionIdentity(t *testing.T) GuestCredentialSessionIdentity {
	t.Helper()
	sessionID := filledSessionID(33)
	root := validRootIdentity()
	root.GuestSessionGeneration = sessionGeneration(sessionID)
	jobIdentity, err := JobIdentityFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewGuestCredentialSessionIdentity(sessionID, jobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testLifecycleRequestID(t *testing.T) RequestID { return testRequestIDWithFirstByte(t, 1) }

func testRequestIDWithFirstByte(t *testing.T, first byte) RequestID {
	t.Helper()
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	raw[0] = first
	id, err := NewRequestID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func decodeRenewForTest(wire []byte) error {
	_, err := DecodeCredentialRenewRequest(mustTestSessionIdentity(), testPriorRevision, testSessionExpiry, testRootExpiry, wire)
	return err
}

func decodeRevokeForTest(wire []byte) error {
	_, err := DecodeCredentialRevokeRequest(mustTestSessionIdentity(), 9, wire)
	return err
}

func decodeRenewSuccessForTest(wire []byte) error {
	_, err := DecodeCredentialRenewSuccessResponse(mustTestRenewRequest(), wire)
	return err
}

func decodeRevokeSuccessForTest(wire []byte) error {
	_, err := DecodeCredentialRevokeSuccessResponse(mustTestRevokeRequest(), wire)
	return err
}

func mustTestSessionIdentity() GuestCredentialSessionIdentity {
	identity, _ := NewGuestCredentialSessionIdentity(sequentialSessionID(), mustValidChildIdentity())
	return identity
}

func mustValidChildIdentity() JobIdentity {
	identity, _ := JobIdentityFromRoot(validRootIdentity())
	return identity
}

func mustTestRenewRequest() CredentialRenewRequest {
	request, _ := NewCredentialRenewRequest(mustTestRequestID(), mustTestSessionIdentity(), testPriorRevision, testRenewExpiry, testSessionExpiry, testRootExpiry, "active-proof-8")
	return request
}

func mustTestRevokeRequest() CredentialRevokeRequest {
	request, _ := NewCredentialRevokeRequest(mustTestRequestID(), mustTestSessionIdentity(), 9, CredentialRevokeReasonSourceRevoked)
	return request
}

func mustTestRequestID() RequestID {
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	id, _ := NewRequestID(raw)
	return id
}

func lifecycleCanonicalWires(t *testing.T) [][]byte {
	t.Helper()
	renew := testCredentialRenewRequest(t)
	revoke := testCredentialRevokeRequest(t)
	renewSuccess, _ := NewCredentialRenewSuccessResponse(renew, "active-proof-9")
	revokeSuccess, _ := NewCredentialRevokeSuccessResponse(revoke, "cleanup-proof-9")
	a, _ := EncodeCredentialRenewRequest(renew)
	b, _ := EncodeCredentialRenewSuccessResponse(renewSuccess)
	c, _ := EncodeCredentialRevokeRequest(revoke)
	d, _ := EncodeCredentialRevokeSuccessResponse(revokeSuccess)
	return [][]byte{a, b, c, d}
}

func replaceBytes(wire []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(wire), old, replacement, 1))
}
