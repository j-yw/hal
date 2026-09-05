package v2control

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRequestIDCanonicalRoundTripAndDefensiveValue(t *testing.T) {
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	id, err := NewRequestID(raw)
	if err != nil {
		t.Fatal(err)
	}
	const canonical = "AQIDBAUGBwgJCgsMDQ4PEA"
	if got, err := EncodeRequestID(id); err != nil || got != canonical {
		t.Fatalf("EncodeRequestID = %q, %v", got, err)
	}
	decoded, err := ParseRequestID(canonical)
	if err != nil || decoded != id {
		t.Fatalf("ParseRequestID = %#v, %v", decoded, err)
	}
	copyValue := id.Bytes()
	copyValue[0] = 0xff
	if id.Bytes()[0] != 1 {
		t.Fatal("Bytes exposed mutable representation")
	}
}

func TestRequestIDRejectsNoncanonicalAndZeroValues(t *testing.T) {
	for _, encoded := range []string{
		"", "AQIDBAUGBwgJCgsMDQ4PE", "AQIDBAUGBwgJCgsMDQ4PEAA",
		"AQIDBAUGBwgJCgsMDQ4PEA=", "AQIDBAUGBwgJCgsMDQ4PE+",
		"AQIDBAUGBwgJCgsMDQ4PE/", "AQIDBAUGBwgJCgsMDQ4PEB",
		"AQIDBAUGBwgJCgsMDQ4PE\n",
		"AAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := ParseRequestID(encoded); err == nil {
			t.Errorf("ParseRequestID(%q) succeeded", encoded)
		}
	}
	if _, err := NewRequestID([16]byte{}); err == nil {
		t.Error("zero RequestID succeeded")
	}
	if _, err := EncodeRequestID(RequestID{}); err == nil {
		t.Error("zero RequestID encoded")
	}
}

func TestIdentityDigestCanonicalRoundTripAndDefensiveValue(t *testing.T) {
	var raw [32]byte
	for index := range raw {
		raw[index] = byte(index)
	}
	digest := NewIdentityDigest(raw)
	const canonical = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if got := EncodeIdentityDigest(digest); got != canonical {
		t.Fatalf("EncodeIdentityDigest = %q", got)
	}
	decoded, err := ParseIdentityDigest(canonical)
	if err != nil || decoded != digest {
		t.Fatalf("ParseIdentityDigest = %#v, %v", decoded, err)
	}
	copyValue := digest.Bytes()
	copyValue[0] = 0xff
	if digest.Bytes()[0] != 0 {
		t.Fatal("Bytes exposed mutable representation")
	}
}

func TestIdentityDigestRejectsNoncanonicalEncodings(t *testing.T) {
	valid := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, encoded := range []string{
		"", valid[:42], valid + "A", valid + "=", valid[:42] + "+",
		valid[:42] + "/", valid[:42] + "9", valid[:42] + "\n",
	} {
		if _, err := ParseIdentityDigest(encoded); err == nil {
			t.Errorf("ParseIdentityDigest(%q) succeeded", encoded)
		}
	}
	zero, err := ParseIdentityDigest(strings.Repeat("A", 43))
	if err != nil || zero.Bytes() != [32]byte{} {
		t.Fatalf("canonical zero digest = %#v, %v", zero, err)
	}
}

func TestControlScalarsFailClosedThroughGenericSerializationAndFormatting(t *testing.T) {
	var requestBytes [16]byte
	requestBytes[0] = 1
	requestID, err := NewRequestID(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	var digestBytes [32]byte
	digestBytes[0] = 2
	digest := NewIdentityDigest(digestBytes)

	for name, value := range map[string]any{"request": requestID, "digest": digest} {
		if _, err := json.Marshal(value); err == nil {
			t.Errorf("%s JSON serialization succeeded", name)
		}
		if marshaler, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Errorf("%s lacks MarshalText", name)
		} else if _, err := marshaler.MarshalText(); err == nil {
			t.Errorf("%s text serialization succeeded", name)
		}
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%x", "%q"} {
		if got := fmt.Sprintf(format, requestID); got != "<v2control.RequestID>" {
			t.Errorf("request format %q = %q", format, got)
		}
		if got := fmt.Sprintf(format, digest); got != "<v2control.IdentityDigest>" {
			t.Errorf("digest format %q = %q", format, got)
		}
	}
}

func TestControlScalarPublicMethodSetsAreExact(t *testing.T) {
	requestMethods := []string{
		"Bytes", "Format", "GoString", "MarshalJSON", "MarshalText", "String",
	}
	digestMethods := []string{
		"Bytes", "Format", "GoString", "MarshalJSON", "MarshalText", "String",
	}
	assertPublicMethods(t, reflect.TypeOf(RequestID{}), requestMethods)
	assertPublicMethods(t, reflect.TypeOf(&RequestID{}), requestMethods)
	assertPublicMethods(t, reflect.TypeOf(IdentityDigest{}), digestMethods)
	assertPublicMethods(t, reflect.TypeOf(&IdentityDigest{}), digestMethods)
	assertPublicMethods(t, reflect.TypeOf(Operation("")), nil)
	assertPublicMethods(t, reflect.TypeOf(OperationToken{}), nil)
	assertPublicMethods(t, reflect.TypeOf(ErrorCode("")), nil)
}

func TestControlScalarRepresentationsStayPrivateAndFixedSize(t *testing.T) {
	tests := []struct {
		name string
		typ  reflect.Type
		want reflect.Type
	}{
		{"RequestID", reflect.TypeOf(RequestID{}), reflect.TypeOf([16]byte{})},
		{"IdentityDigest", reflect.TypeOf(IdentityDigest{}), reflect.TypeOf([32]byte{})},
	}
	for _, test := range tests {
		if test.typ.NumField() != 1 {
			t.Fatalf("%s field count = %d", test.name, test.typ.NumField())
		}
		field := test.typ.Field(0)
		if field.IsExported() || field.Type != test.want {
			t.Fatalf("%s representation = exported:%t type:%s", test.name, field.IsExported(), field.Type)
		}
	}
}

func assertPublicMethods(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	var got []string
	for index := 0; index < typ.NumMethod(); index++ {
		got = append(got, typ.Method(index).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s methods = %v, want %v", typ, got, want)
	}
}
