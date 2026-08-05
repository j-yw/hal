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
	readinessRequestVector = `{"protocolVersion":"guest-agent-v2","operation":"readiness","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","body":{"requiredCapabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"],"expectedServiceUID":998,"expectedServiceGID":998,"expectedWorkloadUID":1000,"expectedWorkloadGID":1000,"helperProtocol":"guest-helper-v1"}}`
	readinessSuccessVector = `{"protocolVersion":"guest-agent-v2","operation":"readiness","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","ok":true,"body":{"capabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"],"serviceUID":998,"serviceGID":998,"workloadUID":1000,"workloadGID":1000,"helperProtocol":"guest-helper-v1","guestSessionGeneration":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","helperGeneration":"helper-generation-1"}}`
)

func TestReadinessRequestExactVectorAndDefensiveCapabilities(t *testing.T) {
	request := testReadinessRequest(t)
	wire, err := EncodeReadinessRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) != readinessRequestVector {
		t.Fatalf("request wire = %s", wire)
	}
	decoded, err := DecodeReadinessRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID() != request.RequestID() || decoded.IdentityDigest() != request.IdentityDigest() {
		t.Fatal("decoded request correlation changed")
	}
	assertReadinessRequestMetadata(t, decoded)
	capabilities := decoded.RequiredCapabilities()
	capabilities[0] = "changed"
	if got := decoded.RequiredCapabilities()[0]; got != "credential_lifecycle" {
		t.Fatalf("capability alias escaped: %q", got)
	}
}

func TestReadinessSuccessExactVectorAndCorrelationSafeBuilder(t *testing.T) {
	request := testReadinessRequest(t)
	response, err := NewReadinessSuccessResponse(request, "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeReadinessSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) != readinessSuccessVector {
		t.Fatalf("success wire = %s", wire)
	}
	decoded, err := DecodeReadinessSuccessResponse(request, wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID() != request.RequestID() || decoded.IdentityDigest() != request.IdentityDigest() {
		t.Fatal("decoded success correlation changed")
	}
	if decoded.GuestSessionGeneration() != EncodeIdentityDigest(request.IdentityDigest()) {
		t.Fatalf("session generation = %q", decoded.GuestSessionGeneration())
	}
	if decoded.HelperGeneration() != "helper-generation-1" {
		t.Fatalf("helper generation = %q", decoded.HelperGeneration())
	}
	assertReadinessSuccessMetadata(t, decoded)
	capabilities := decoded.Capabilities()
	capabilities[0] = "changed"
	if got := decoded.Capabilities()[0]; got != "credential_lifecycle" {
		t.Fatalf("capability alias escaped: %q", got)
	}
}

func TestReadinessRequestAcceptsEverySessionIDRepresentationValue(t *testing.T) {
	requestID := testRequestID(t)
	request, err := NewReadinessRequest(requestID, NewIdentityDigest([32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeReadinessRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReadinessRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.IdentityDigest().Bytes() != [32]byte{} {
		t.Fatal("zero session ID representation was not preserved")
	}
	response, err := NewReadinessSuccessResponse(decoded, "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	if response.GuestSessionGeneration() != strings.Repeat("A", 43) {
		t.Fatalf("zero generation = %q", response.GuestSessionGeneration())
	}
}

func TestReadinessRequestRejectsEveryFieldMutation(t *testing.T) {
	tests := []struct {
		name string
		wire string
	}{
		{"protocol version", replaceOnce(t, readinessRequestVector, `"guest-agent-v2"`, `"guest-agent-v1"`)},
		{"operation", replaceOnce(t, readinessRequestVector, `"operation":"readiness"`, `"operation":"exec"`)},
		{"operation case alias", replaceOnce(t, readinessRequestVector, `"operation":"readiness"`, `"operation":"Readiness"`)},
		{"request ID zero", replaceOnce(t, readinessRequestVector, `"AQIDBAUGBwgJCgsMDQ4PEA"`, `"AAAAAAAAAAAAAAAAAAAAAA"`)},
		{"request ID padding", replaceOnce(t, readinessRequestVector, `"AQIDBAUGBwgJCgsMDQ4PEA"`, `"AQIDBAUGBwgJCgsMDQ4PEA="`)},
		{"identity digest padding", replaceOnce(t, readinessRequestVector, `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`)},
		{"capability credential lifecycle", replaceOnce(t, readinessRequestVector, `"credential_lifecycle"`, `"credential-lifecycle"`)},
		{"capability exec binding", replaceOnce(t, readinessRequestVector, `"credential_exec_binding"`, `"credential-exec-binding"`)},
		{"capability exact PID", replaceOnce(t, readinessRequestVector, `"helper_exact_pid"`, `"helper_exact_Pid"`)},
		{"capability file", replaceOnce(t, readinessRequestVector, `"file_tmpfs"`, `"file-tmpfs"`)},
		{"capability SSH", replaceOnce(t, readinessRequestVector, `"ssh_agent"`, `"ssh-agent"`)},
		{"capability order", replaceOnce(t, readinessRequestVector, `"credential_lifecycle","credential_exec_binding"`, `"credential_exec_binding","credential_lifecycle"`)},
		{"service UID", replaceOnce(t, readinessRequestVector, `"expectedServiceUID":998`, `"expectedServiceUID":999`)},
		{"service GID", replaceOnce(t, readinessRequestVector, `"expectedServiceGID":998`, `"expectedServiceGID":999`)},
		{"workload UID", replaceOnce(t, readinessRequestVector, `"expectedWorkloadUID":1000`, `"expectedWorkloadUID":1001`)},
		{"workload GID", replaceOnce(t, readinessRequestVector, `"expectedWorkloadGID":1000`, `"expectedWorkloadGID":1001`)},
		{"helper protocol", replaceOnce(t, readinessRequestVector, `"guest-helper-v1"`, `"guest-helper-v2"`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeReadinessRequest([]byte(test.wire)); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReadinessSuccessRejectsEveryFieldMutation(t *testing.T) {
	request := testReadinessRequest(t)
	tests := []struct {
		name string
		wire string
	}{
		{"protocol version", replaceOnce(t, readinessSuccessVector, `"guest-agent-v2"`, `"guest-agent-v1"`)},
		{"operation", replaceOnce(t, readinessSuccessVector, `"operation":"readiness"`, `"operation":"exec"`)},
		{"request ID", replaceOnce(t, readinessSuccessVector, `"AQIDBAUGBwgJCgsMDQ4PEA"`, `"AAAAAAAAAAAAAAAAAAAAAA"`)},
		{"identity digest", replaceOnce(t, readinessSuccessVector, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`)},
		{"ok false", replaceOnce(t, readinessSuccessVector, `"ok":true`, `"ok":false`)},
		{"capability credential lifecycle", replaceOnce(t, readinessSuccessVector, `"credential_lifecycle"`, `"credential-lifecycle"`)},
		{"capability exec binding", replaceOnce(t, readinessSuccessVector, `"credential_exec_binding"`, `"credential-exec-binding"`)},
		{"capability exact PID", replaceOnce(t, readinessSuccessVector, `"helper_exact_pid"`, `"helper_exact_Pid"`)},
		{"capability file", replaceOnce(t, readinessSuccessVector, `"file_tmpfs"`, `"file-tmpfs"`)},
		{"capability SSH", replaceOnce(t, readinessSuccessVector, `"ssh_agent"`, `"ssh-agent"`)},
		{"capability order", replaceOnce(t, readinessSuccessVector, `"credential_lifecycle","credential_exec_binding"`, `"credential_exec_binding","credential_lifecycle"`)},
		{"service UID", replaceOnce(t, readinessSuccessVector, `"serviceUID":998`, `"serviceUID":999`)},
		{"service GID", replaceOnce(t, readinessSuccessVector, `"serviceGID":998`, `"serviceGID":999`)},
		{"workload UID", replaceOnce(t, readinessSuccessVector, `"workloadUID":1000`, `"workloadUID":1001`)},
		{"workload GID", replaceOnce(t, readinessSuccessVector, `"workloadGID":1000`, `"workloadGID":1001`)},
		{"helper protocol", replaceOnce(t, readinessSuccessVector, `"guest-helper-v1"`, `"guest-helper-v2"`)},
		{"session generation", replaceOnce(t, readinessSuccessVector, `"guestSessionGeneration":"AAE`, `"guestSessionGeneration":"AQE`)},
		{"helper generation empty", replaceOnce(t, readinessSuccessVector, `"helperGeneration":"helper-generation-1"`, `"helperGeneration":""`)},
		{"helper generation unsafe", replaceOnce(t, readinessSuccessVector, `"helper-generation-1"`, `"helper/generation/secret"`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeReadinessSuccessResponse(request, []byte(test.wire)); !errors.Is(err, ErrInvalidReadinessSuccessJSON) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReadinessRequestStrictJSONNegatives(t *testing.T) {
	omissions := []string{
		strings.Replace(readinessRequestVector, `"protocolVersion":"guest-agent-v2",`, "", 1),
		strings.Replace(readinessRequestVector, `"operation":"readiness",`, "", 1),
		strings.Replace(readinessRequestVector, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA",`, "", 1),
		strings.Replace(readinessRequestVector, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",`, "", 1),
		omitReadinessRootBody(t, readinessRequestVector),
		strings.Replace(readinessRequestVector, `"requiredCapabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"],`, "", 1),
		strings.Replace(readinessRequestVector, `"expectedServiceUID":998,`, "", 1),
		strings.Replace(readinessRequestVector, `"expectedServiceGID":998,`, "", 1),
		strings.Replace(readinessRequestVector, `"expectedWorkloadUID":1000,`, "", 1),
		strings.Replace(readinessRequestVector, `"expectedWorkloadGID":1000,`, "", 1),
		strings.Replace(readinessRequestVector, `,"helperProtocol":"guest-helper-v1"`, "", 1),
	}
	for index, wire := range omissions {
		if _, err := DecodeReadinessRequest([]byte(wire)); err == nil {
			t.Errorf("omission %d succeeded", index)
		}
	}

	tests := []string{
		" " + readinessRequestVector,
		readinessRequestVector + "\n",
		readinessRequestVector + `{}`,
		`null`,
		strings.Replace(readinessRequestVector, `"body":{`, `"body":null,"discard":{`, 1),
		strings.Replace(readinessRequestVector, `"protocolVersion"`, `"ProtocolVersion"`, 1),
		strings.Replace(readinessRequestVector, `"helperProtocol"`, `"HelperProtocol"`, 1),
		strings.Replace(readinessRequestVector, `"body":{`, `"unknown":0,"body":{`, 1),
		strings.Replace(readinessRequestVector, `"helperProtocol":`, `"unknown":0,"helperProtocol":`, 1),
		strings.Replace(readinessRequestVector, `"protocolVersion":"guest-agent-v2"`, `"protocolVersion":"guest-agent-v2","protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(readinessRequestVector, `"helperProtocol":"guest-helper-v1"`, `"helperProtocol":"guest-helper-v1","helperProtocol":"guest-helper-v1"`, 1),
		strings.Replace(readinessRequestVector, `"expectedServiceUID":998`, `"expectedServiceUID":9.98e2`, 1),
		strings.Replace(readinessRequestVector, `"expectedServiceGID":998`, `"expectedServiceGID":998.0`, 1),
		strings.Replace(readinessRequestVector, `"expectedWorkloadUID":1000`, `"expectedWorkloadUID":1e3`, 1),
		strings.Replace(readinessRequestVector, `"expectedWorkloadGID":1000`, `"expectedWorkloadGID":1.000e3`, 1),
		strings.Replace(readinessRequestVector, `"body":{`, `"body":{"unknown":[[[[[]]]]],`, 1),
		strings.Replace(readinessRequestVector, `"protocolVersion":"guest-agent-v2","operation":"readiness"`, `"operation":"readiness","protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(readinessRequestVector, `"expectedServiceUID":998,"expectedServiceGID":998`, `"expectedServiceGID":998,"expectedServiceUID":998`, 1),
	}
	for index, wire := range tests {
		t.Run(fmt.Sprintf("strict-%d", index), func(t *testing.T) {
			if _, err := DecodeReadinessRequest([]byte(wire)); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	invalidUTF8 := append([]byte(readinessRequestVector), 0xff)
	if _, err := DecodeReadinessRequest(invalidUTF8); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestReadinessRequestRejectsNullDuplicateAndCaseAliasForEveryField(t *testing.T) {
	fields := []string{
		`"protocolVersion":"guest-agent-v2"`,
		`"operation":"readiness"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`,
		`"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
		`"requiredCapabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"]`,
		`"expectedServiceUID":998`,
		`"expectedServiceGID":998`,
		`"expectedWorkloadUID":1000`,
		`"expectedWorkloadGID":1000`,
		`"helperProtocol":"guest-helper-v1"`,
	}
	for _, field := range fields {
		field := field
		t.Run(field, func(t *testing.T) {
			assertInvalidReadinessRequestJSON(t, replaceFieldWithNull(t, readinessRequestVector, field))
			assertInvalidReadinessRequestJSON(t, duplicateReadinessField(t, readinessRequestVector, field))
			assertInvalidReadinessRequestJSON(t, caseAliasReadinessField(t, readinessRequestVector, field))
		})
	}
	assertInvalidReadinessRequestJSON(t, replaceReadinessRootBodyWithNull(t, readinessRequestVector))
	assertInvalidReadinessRequestJSON(t, duplicateReadinessRootBody(t, readinessRequestVector))
	assertInvalidReadinessRequestJSON(t, strings.Replace(readinessRequestVector, `"body"`, `"Body"`, 1))
}

func TestReadinessJSONSizeAndDepthBoundsMatchSessionAuthority(t *testing.T) {
	if maxReadinessJSONBytes != session.MaxControlPlaintextBytes {
		t.Fatalf("readiness JSON bound = %d, session control bound = %d", maxReadinessJSONBytes, session.MaxControlPlaintextBytes)
	}
	atBound := make([]byte, maxReadinessJSONBytes)
	copy(atBound, readinessRequestVector)
	for index := len(readinessRequestVector); index < len(atBound); index++ {
		atBound[index] = ' '
	}
	if !validReadinessJSONInput(atBound) {
		t.Fatal("exact maximum canonical-prefix JSON failed syntax/size preflight")
	}
	if _, err := DecodeReadinessRequest(atBound); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
		t.Fatalf("noncompact exact maximum error = %v", err)
	}
	plusOne := append(append([]byte(nil), atBound...), ' ')
	if validReadinessJSONInput(plusOne) {
		t.Fatal("maximum plus one passed syntax/size preflight")
	}
	if _, err := DecodeReadinessRequest(plusOne); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
		t.Fatalf("maximum plus one error = %v", err)
	}

	if !validReadinessJSONInput([]byte(`[[[]]]`)) {
		t.Fatal("depth at maximum failed preflight")
	}
	if validReadinessJSONInput([]byte(`[[[[]]]]`)) {
		t.Fatal("depth maximum plus one passed preflight")
	}
	if !validReadinessJSONInput([]byte(readinessRequestVector)) ||
		!validReadinessJSONInput([]byte(readinessSuccessVector)) {
		t.Fatal("canonical readiness envelope exceeded depth bound")
	}
	duplicate := duplicateReadinessField(t, readinessRequestVector, `"protocolVersion":"guest-agent-v2"`)
	if validReadinessJSONInput([]byte(duplicate)) {
		t.Fatal("duplicate key reached concrete unmarshal")
	}
}

func TestReadinessSuccessStrictJSONNegativesAndCorrelation(t *testing.T) {
	request := testReadinessRequest(t)
	omissions := []string{
		strings.Replace(readinessSuccessVector, `"protocolVersion":"guest-agent-v2",`, "", 1),
		strings.Replace(readinessSuccessVector, `"operation":"readiness",`, "", 1),
		strings.Replace(readinessSuccessVector, `"requestId":"AQIDBAUGBwgJCgsMDQ4PEA",`, "", 1),
		strings.Replace(readinessSuccessVector, `"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",`, "", 1),
		strings.Replace(readinessSuccessVector, `"ok":true,`, "", 1),
		omitReadinessRootBody(t, readinessSuccessVector),
		strings.Replace(readinessSuccessVector, `"capabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"],`, "", 1),
		strings.Replace(readinessSuccessVector, `"serviceUID":998,`, "", 1),
		strings.Replace(readinessSuccessVector, `"serviceGID":998,`, "", 1),
		strings.Replace(readinessSuccessVector, `"workloadUID":1000,`, "", 1),
		strings.Replace(readinessSuccessVector, `"workloadGID":1000,`, "", 1),
		strings.Replace(readinessSuccessVector, `"helperProtocol":"guest-helper-v1",`, "", 1),
		strings.Replace(readinessSuccessVector, `"guestSessionGeneration":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",`, "", 1),
		strings.Replace(readinessSuccessVector, `,"helperGeneration":"helper-generation-1"`, "", 1),
	}
	for index, wire := range omissions {
		if _, err := DecodeReadinessSuccessResponse(request, []byte(wire)); err == nil {
			t.Errorf("omission %d succeeded", index)
		}
	}

	for index, wire := range []string{
		" " + readinessSuccessVector,
		readinessSuccessVector + "\n",
		readinessSuccessVector + `{}`,
		`null`,
		strings.Replace(readinessSuccessVector, `"body":{`, `"body":null,"discard":{`, 1),
		strings.Replace(readinessSuccessVector, `"ok"`, `"Ok"`, 1),
		strings.Replace(readinessSuccessVector, `"helperGeneration"`, `"HelperGeneration"`, 1),
		strings.Replace(readinessSuccessVector, `"ok":true`, `"unknown":0,"ok":true`, 1),
		strings.Replace(readinessSuccessVector, `"helperGeneration":`, `"unknown":0,"helperGeneration":`, 1),
		strings.Replace(readinessSuccessVector, `"ok":true`, `"ok":true,"ok":true`, 1),
		strings.Replace(readinessSuccessVector, `"helperGeneration":"helper-generation-1"`, `"helperGeneration":"helper-generation-1","helperGeneration":"helper-generation-1"`, 1),
		strings.Replace(readinessSuccessVector, `"serviceUID":998`, `"serviceUID":9.98e2`, 1),
		strings.Replace(readinessSuccessVector, `"body":{`, `"body":{"unknown":[[[[[]]]]],`, 1),
		strings.Replace(readinessSuccessVector, `"protocolVersion":"guest-agent-v2","operation":"readiness"`, `"operation":"readiness","protocolVersion":"guest-agent-v2"`, 1),
		strings.Replace(readinessSuccessVector, `"serviceUID":998,"serviceGID":998`, `"serviceGID":998,"serviceUID":998`, 1),
	} {
		t.Run(fmt.Sprintf("strict-%d", index), func(t *testing.T) {
			if _, err := DecodeReadinessSuccessResponse(request, []byte(wire)); !errors.Is(err, ErrInvalidReadinessSuccessJSON) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	invalidUTF8 := append([]byte(readinessSuccessVector), 0xff)
	if _, err := DecodeReadinessSuccessResponse(request, invalidUTF8); !errors.Is(err, ErrInvalidReadinessSuccessJSON) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}

	otherIDBytes := request.RequestID().Bytes()
	otherIDBytes[0]++
	otherID, err := NewRequestID(otherIDBytes)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := NewReadinessRequest(otherID, request.IdentityDigest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReadinessSuccessResponse(otherRequest, []byte(readinessSuccessVector)); !errors.Is(err, ErrReadinessCorrelationMismatch) {
		t.Fatalf("request-ID mismatch error = %v", err)
	}
	digestBytes := request.IdentityDigest().Bytes()
	digestBytes[0]++
	otherRequest, err = NewReadinessRequest(request.RequestID(), NewIdentityDigest(digestBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReadinessSuccessResponse(otherRequest, []byte(readinessSuccessVector)); !errors.Is(err, ErrReadinessCorrelationMismatch) {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestReadinessSuccessRejectsNullDuplicateAndCaseAliasForEveryField(t *testing.T) {
	request := testReadinessRequest(t)
	fields := []string{
		`"protocolVersion":"guest-agent-v2"`,
		`"operation":"readiness"`,
		`"requestId":"AQIDBAUGBwgJCgsMDQ4PEA"`,
		`"identityDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
		`"ok":true`,
		`"capabilities":["credential_lifecycle","credential_exec_binding","helper_exact_pid","file_tmpfs","ssh_agent"]`,
		`"serviceUID":998`,
		`"serviceGID":998`,
		`"workloadUID":1000`,
		`"workloadGID":1000`,
		`"helperProtocol":"guest-helper-v1"`,
		`"guestSessionGeneration":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
		`"helperGeneration":"helper-generation-1"`,
	}
	for _, field := range fields {
		field := field
		t.Run(field, func(t *testing.T) {
			assertInvalidReadinessSuccessJSON(t, request, replaceFieldWithNull(t, readinessSuccessVector, field))
			assertInvalidReadinessSuccessJSON(t, request, duplicateReadinessField(t, readinessSuccessVector, field))
			assertInvalidReadinessSuccessJSON(t, request, caseAliasReadinessField(t, readinessSuccessVector, field))
		})
	}
	assertInvalidReadinessSuccessJSON(t, request, replaceReadinessRootBodyWithNull(t, readinessSuccessVector))
	assertInvalidReadinessSuccessJSON(t, request, duplicateReadinessRootBody(t, readinessSuccessVector))
	assertInvalidReadinessSuccessJSON(t, request, strings.Replace(readinessSuccessVector, `"body"`, `"Body"`, 1))
}

func TestReadinessConstructionRejectsInvalidValuesAndZeroStates(t *testing.T) {
	if _, err := NewReadinessRequest(RequestID{}, NewIdentityDigest([32]byte{})); !errors.Is(err, ErrInvalidReadinessRequest) {
		t.Fatalf("zero request ID error = %v", err)
	}
	if _, err := EncodeReadinessRequest(ReadinessRequest{}); !errors.Is(err, ErrInvalidReadinessRequest) {
		t.Fatalf("zero request error = %v", err)
	}
	request := testReadinessRequest(t)
	for _, helperGeneration := range []string{"", " helper", "helper/secret", strings.Repeat("a", 129)} {
		if _, err := NewReadinessSuccessResponse(request, helperGeneration); !errors.Is(err, ErrInvalidReadinessSuccess) {
			t.Errorf("helper %q error = %v", helperGeneration, err)
		}
	}
	if _, err := NewReadinessSuccessResponse(ReadinessRequest{}, "helper-generation-1"); !errors.Is(err, ErrInvalidReadinessSuccess) {
		t.Fatalf("zero request response error = %v", err)
	}
	if _, err := EncodeReadinessSuccessResponse(ReadinessSuccessResponse{}); !errors.Is(err, ErrInvalidReadinessSuccess) {
		t.Fatalf("zero success error = %v", err)
	}
}

func TestReadinessValuesDenyGenericSerializationAndFormatSafely(t *testing.T) {
	request := testReadinessRequest(t)
	response, err := NewReadinessSuccessResponse(request, "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range []struct {
		value       interface{ MarshalText() ([]byte, error) }
		placeholder string
	}{
		{request, "<v2control.ReadinessRequest>"},
		{response, "<v2control.ReadinessSuccessResponse>"},
	} {
		if _, err := json.Marshal(test.value); !errors.Is(err, ErrReadinessSerialization) {
			t.Errorf("value %d JSON error = %v", name, err)
		}
		if _, err := test.value.MarshalText(); !errors.Is(err, ErrReadinessSerialization) {
			t.Errorf("value %d text error = %v", name, err)
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%x", "%q"} {
			if got := fmt.Sprintf(format, test.value); got != test.placeholder {
				t.Errorf("value %d format %q = %q", name, format, got)
			}
		}
	}

	requestBefore := request
	if err := json.Unmarshal([]byte(readinessRequestVector), &request); !errors.Is(err, ErrReadinessSerialization) {
		t.Fatalf("generic request decode error = %v", err)
	}
	if request.state != requestBefore.state {
		t.Fatal("failed generic request decode changed value")
	}
	if err := request.UnmarshalText([]byte(readinessRequestVector)); !errors.Is(err, ErrReadinessSerialization) {
		t.Fatalf("generic request text decode error = %v", err)
	}
	if request.state != requestBefore.state {
		t.Fatal("failed generic request text decode changed value")
	}

	responseBefore := response
	if err := json.Unmarshal([]byte(readinessSuccessVector), &response); !errors.Is(err, ErrReadinessSerialization) {
		t.Fatalf("generic success decode error = %v", err)
	}
	if response.state != responseBefore.state {
		t.Fatal("failed generic success decode changed value")
	}
	if err := response.UnmarshalText([]byte(readinessSuccessVector)); !errors.Is(err, ErrReadinessSerialization) {
		t.Fatalf("generic success text decode error = %v", err)
	}
	if response.state != responseBefore.state {
		t.Fatal("failed generic success text decode changed value")
	}
}

func TestReadinessErrorsAreStaticAndRedactionSafe(t *testing.T) {
	secret := "secret://host.example/token-value"
	unsafeWire := strings.Replace(readinessSuccessVector, "helper-generation-1", secret, 1)
	_, err := DecodeReadinessSuccessResponse(testReadinessRequest(t), []byte(unsafeWire))
	if !errors.Is(err, ErrInvalidReadinessSuccessJSON) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
		t.Fatalf("error leaked input: %v", err)
	}
}

func TestReadinessPublicRepresentationsStayOpaque(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(ReadinessRequest{}), reflect.TypeOf(ReadinessSuccessResponse{})} {
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Errorf("%s field %q is exported", typ, typ.Field(index).Name)
			}
		}
	}
}

func assertReadinessRequestMetadata(t *testing.T, request ReadinessRequest) {
	t.Helper()
	wantCapabilities := []string{"credential_lifecycle", "credential_exec_binding", "helper_exact_pid", "file_tmpfs", "ssh_agent"}
	if !reflect.DeepEqual(request.RequiredCapabilities(), wantCapabilities) {
		t.Fatalf("capabilities = %v", request.RequiredCapabilities())
	}
	if request.ExpectedServiceUID() != 998 || request.ExpectedServiceGID() != 998 ||
		request.ExpectedWorkloadUID() != 1000 || request.ExpectedWorkloadGID() != 1000 ||
		request.HelperProtocol() != "guest-helper-v1" {
		t.Fatalf("request metadata is not exact")
	}
}

func assertReadinessSuccessMetadata(t *testing.T, response ReadinessSuccessResponse) {
	t.Helper()
	wantCapabilities := []string{"credential_lifecycle", "credential_exec_binding", "helper_exact_pid", "file_tmpfs", "ssh_agent"}
	if !reflect.DeepEqual(response.Capabilities(), wantCapabilities) {
		t.Fatalf("capabilities = %v", response.Capabilities())
	}
	if response.ServiceUID() != 998 || response.ServiceGID() != 998 ||
		response.WorkloadUID() != 1000 || response.WorkloadGID() != 1000 ||
		response.HelperProtocol() != "guest-helper-v1" {
		t.Fatalf("response metadata is not exact")
	}
}

func testReadinessRequest(t *testing.T) ReadinessRequest {
	t.Helper()
	request, err := NewReadinessRequest(testRequestID(t), testIdentityDigest())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testRequestID(t *testing.T) RequestID {
	t.Helper()
	var value [16]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	requestID, err := NewRequestID(value)
	if err != nil {
		t.Fatal(err)
	}
	return requestID
}

func testIdentityDigest() IdentityDigest {
	var value [32]byte
	for index := range value {
		value[index] = byte(index)
	}
	return NewIdentityDigest(value)
}

func replaceOnce(t *testing.T, value, old, replacement string) string {
	t.Helper()
	if strings.Count(value, old) != 1 {
		t.Fatalf("replacement target %q count = %d", old, strings.Count(value, old))
	}
	return strings.Replace(value, old, replacement, 1)
}

func replaceFieldWithNull(t *testing.T, wire, field string) string {
	t.Helper()
	colon := strings.IndexByte(field, ':')
	if colon < 0 {
		t.Fatalf("field %q has no colon", field)
	}
	return replaceOnce(t, wire, field, field[:colon+1]+"null")
}

func duplicateReadinessField(t *testing.T, wire, field string) string {
	t.Helper()
	return replaceOnce(t, wire, field, field+","+field)
}

func caseAliasReadinessField(t *testing.T, wire, field string) string {
	t.Helper()
	colon := strings.IndexByte(field, ':')
	if colon < 3 {
		t.Fatalf("field %q cannot be aliased", field)
	}
	name := field[:colon]
	alias := name[:1] + strings.ToUpper(name[1:2]) + name[2:]
	return replaceOnce(t, wire, name, alias)
}

func readinessRootBodyParts(t *testing.T, wire string) (string, string) {
	t.Helper()
	const marker = `,"body":`
	index := strings.Index(wire, marker)
	if index < 0 || len(wire) < index+len(marker)+2 || wire[len(wire)-1] != '}' {
		t.Fatalf("wire has no terminal root body")
	}
	return wire[:index], wire[index+len(marker) : len(wire)-1]
}

func omitReadinessRootBody(t *testing.T, wire string) string {
	t.Helper()
	prefix, _ := readinessRootBodyParts(t, wire)
	return prefix + "}"
}

func replaceReadinessRootBodyWithNull(t *testing.T, wire string) string {
	t.Helper()
	prefix, _ := readinessRootBodyParts(t, wire)
	return prefix + `,"body":null}`
}

func duplicateReadinessRootBody(t *testing.T, wire string) string {
	t.Helper()
	prefix, body := readinessRootBodyParts(t, wire)
	return prefix + `,"body":` + body + `,"body":` + body + "}"
}

func assertInvalidReadinessRequestJSON(t *testing.T, wire string) {
	t.Helper()
	if _, err := DecodeReadinessRequest([]byte(wire)); !errors.Is(err, ErrInvalidReadinessRequestJSON) {
		t.Fatalf("error = %v", err)
	}
}

func assertInvalidReadinessSuccessJSON(t *testing.T, request ReadinessRequest, wire string) {
	t.Helper()
	if _, err := DecodeReadinessSuccessResponse(request, []byte(wire)); !errors.Is(err, ErrInvalidReadinessSuccessJSON) {
		t.Fatalf("error = %v", err)
	}
}
