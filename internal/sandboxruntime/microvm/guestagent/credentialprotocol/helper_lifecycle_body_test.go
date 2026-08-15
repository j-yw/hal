package credentialprotocol

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestHelperLifecycleBodiesExactVectorsAndRoundTrip(t *testing.T) {
	t.Parallel()

	const revision = uint64(0x0102030405060708)
	const negativeExpiry = int64(-2)

	renew := HelperRenewBody{
		Revision:       revision,
		ExpiryUnixNano: negativeExpiry,
		PriorProofID:   "proof",
	}
	wantRenew := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0x00, 0x05, 'p', 'r', 'o', 'o', 'f',
	}
	assertHelperLifecycleRoundTrip(t, "renew", renew, wantRenew, EncodeHelperRenewBody, DecodeHelperRenewBody)

	revoke := HelperRevokeBody{Revision: revision, Reason: RevokeReasonDaemonShutdown}
	wantRevoke := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x06}
	assertHelperLifecycleRoundTrip(t, "revoke", revoke, wantRevoke, EncodeHelperRevokeBody, DecodeHelperRevokeBody)

	event := HelperEventBody{Code: EventCodeCleanupRequired, Revision: revision, EventID: "event:1"}
	wantEvent := []byte{
		0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x07, 'e', 'v', 'e', 'n', 't', ':', '1',
	}
	assertHelperLifecycleRoundTrip(t, "event", event, wantEvent, EncodeHelperEventBody, DecodeHelperEventBody)

	closeNotify := HelperCloseNotifyBody{Reason: CloseReasonHelperLoss}
	assertHelperLifecycleRoundTrip(t, "close", closeNotify, []byte{0x05}, EncodeHelperCloseNotifyBody, DecodeHelperCloseNotifyBody)
}

func TestHelperRenewBodyTokenBoundsNegativeExpiryAndInputOwnership(t *testing.T) {
	t.Parallel()

	maximumToken := "A" + strings.Repeat("z", MaxBodyTokenBytes-1)
	value := HelperRenewBody{
		Revision:       ^uint64(0),
		ExpiryUnixNano: -0x0102030405060708,
		PriorProofID:   maximumToken,
	}
	encoded, err := EncodeHelperRenewBody(value)
	if err != nil {
		t.Fatalf("EncodeHelperRenewBody(maximum token) error = %v", err)
	}
	if len(encoded) != 8+8+2+MaxBodyTokenBytes {
		t.Fatalf("maximum renew body length = %d", len(encoded))
	}
	if binary.BigEndian.Uint64(encoded[:8]) != ^uint64(0) || int64(binary.BigEndian.Uint64(encoded[8:16])) != value.ExpiryUnixNano {
		t.Fatalf("maximum renew scalar encoding = %x", encoded[:16])
	}

	beforeDecode := cloneBytes(encoded)
	decoded, err := DecodeHelperRenewBody(encoded)
	if err != nil {
		t.Fatalf("DecodeHelperRenewBody(maximum token) error = %v", err)
	}
	if decoded != value {
		t.Fatalf("DecodeHelperRenewBody(maximum token) = %#v, want %#v", decoded, value)
	}
	if !bytes.Equal(encoded, beforeDecode) {
		t.Fatal("DecodeHelperRenewBody mutated its input")
	}
	for index := 18; index < len(encoded); index++ {
		encoded[index] = 'x'
	}
	if decoded.PriorProofID != maximumToken {
		t.Fatalf("decoded prior proof aliases input: %q", decoded.PriorProofID)
	}

	tooLong := HelperRenewBody{Revision: 1, PriorProofID: strings.Repeat("a", MaxBodyTokenBytes+1)}
	if _, err := EncodeHelperRenewBody(tooLong); !errors.Is(err, ErrInvalidBodyToken) {
		t.Fatalf("EncodeHelperRenewBody(token plus one) error = %v, want ErrInvalidBodyToken", err)
	}
	tooLongWire := make([]byte, 8+8+2+MaxBodyTokenBytes+1)
	binary.BigEndian.PutUint64(tooLongWire[:8], 1)
	binary.BigEndian.PutUint16(tooLongWire[16:18], MaxBodyTokenBytes+1)
	copy(tooLongWire[18:], strings.Repeat("a", MaxBodyTokenBytes+1))
	if _, err := DecodeHelperRenewBody(tooLongWire); !errors.Is(err, ErrInvalidBodyToken) {
		t.Fatalf("DecodeHelperRenewBody(token plus one) error = %v, want ErrInvalidBodyToken", err)
	}
}

func TestHelperEventBodyMaximumTokenAndInputOwnership(t *testing.T) {
	t.Parallel()

	maximumToken := "E" + strings.Repeat("v", MaxBodyTokenBytes-1)
	value := HelperEventBody{Code: EventCodeExpired, Revision: ^uint64(0), EventID: maximumToken}
	encoded, err := EncodeHelperEventBody(value)
	if err != nil {
		t.Fatalf("EncodeHelperEventBody(maximum token) error = %v", err)
	}
	if len(encoded) != 1+8+2+MaxBodyTokenBytes {
		t.Fatalf("maximum event body length = %d", len(encoded))
	}
	beforeDecode := cloneBytes(encoded)
	decoded, err := DecodeHelperEventBody(encoded)
	if err != nil {
		t.Fatalf("DecodeHelperEventBody(maximum token) error = %v", err)
	}
	if decoded != value || !bytes.Equal(encoded, beforeDecode) {
		t.Fatalf("decoded maximum event = %#v, wire mutated = %v", decoded, !bytes.Equal(encoded, beforeDecode))
	}
	for index := 11; index < len(encoded); index++ {
		encoded[index] = 'x'
	}
	if decoded.EventID != maximumToken {
		t.Fatalf("decoded event ID aliases input: %q", decoded.EventID)
	}

	tooLong := HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: strings.Repeat("a", MaxBodyTokenBytes+1)}
	if _, err := EncodeHelperEventBody(tooLong); !errors.Is(err, ErrInvalidBodyToken) {
		t.Fatalf("EncodeHelperEventBody(token plus one) error = %v, want ErrInvalidBodyToken", err)
	}
	tooLongWire := make([]byte, 1+8+2+MaxBodyTokenBytes+1)
	tooLongWire[0] = byte(EventCodeExpired)
	binary.BigEndian.PutUint64(tooLongWire[1:9], 1)
	binary.BigEndian.PutUint16(tooLongWire[9:11], MaxBodyTokenBytes+1)
	copy(tooLongWire[11:], strings.Repeat("a", MaxBodyTokenBytes+1))
	if _, err := DecodeHelperEventBody(tooLongWire); !errors.Is(err, ErrInvalidBodyToken) {
		t.Fatalf("DecodeHelperEventBody(token plus one) error = %v, want ErrInvalidBodyToken", err)
	}
}

func TestHelperLifecycleBodyEncodeRejectsZeroRevisionUnknownCatalogAndInvalidToken(t *testing.T) {
	t.Parallel()

	zeroRevision := []struct {
		name   string
		encode func() error
	}{
		{name: "renew", encode: func() error { _, err := EncodeHelperRenewBody(HelperRenewBody{PriorProofID: "proof"}); return err }},
		{name: "revoke", encode: func() error {
			_, err := EncodeHelperRevokeBody(HelperRevokeBody{Reason: RevokeReasonRequested})
			return err
		}},
		{name: "event", encode: func() error {
			_, err := EncodeHelperEventBody(HelperEventBody{Code: EventCodeExpired, EventID: "event"})
			return err
		}},
	}
	for _, test := range zeroRevision {
		if err := test.encode(); !errors.Is(err, ErrHelperLifecycleRevision) {
			t.Errorf("%s zero revision error = %v, want ErrHelperLifecycleRevision", test.name, err)
		}
	}

	unknown := []struct {
		name string
		err  error
		want error
	}{
		{name: "revoke zero", err: encodeHelperRevokeError(RevokeReason(0)), want: ErrUnknownRevokeReason},
		{name: "revoke plus one", err: encodeHelperRevokeError(RevokeReasonDaemonShutdown + 1), want: ErrUnknownRevokeReason},
		{name: "event zero", err: encodeHelperEventError(EventCode(0)), want: ErrUnknownEventCode},
		{name: "event plus one", err: encodeHelperEventError(EventCodeCleanupRequired + 1), want: ErrUnknownEventCode},
		{name: "close zero", err: encodeHelperCloseError(CloseReason(0)), want: ErrUnknownCloseReason},
		{name: "close plus one", err: encodeHelperCloseError(CloseReasonShutdown + 1), want: ErrUnknownCloseReason},
	}
	for _, test := range unknown {
		if !errors.Is(test.err, test.want) {
			t.Errorf("%s error = %v, want %v", test.name, test.err, test.want)
		}
	}

	invalidToken := "credential-value/private/path"
	if _, err := EncodeHelperRenewBody(HelperRenewBody{Revision: 1, PriorProofID: invalidToken}); !errors.Is(err, ErrInvalidBodyToken) {
		t.Errorf("renew invalid token error = %v, want ErrInvalidBodyToken", err)
	}
	if _, err := EncodeHelperEventBody(HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: invalidToken}); !errors.Is(err, ErrInvalidBodyToken) {
		t.Errorf("event invalid token error = %v, want ErrInvalidBodyToken", err)
	}
}

func TestHelperLifecycleBodyDecodeRejectsZeroRevisionUnknownCatalogAndInvalidToken(t *testing.T) {
	t.Parallel()

	renew := mustEncodeHelperRenewBody(t, HelperRenewBody{Revision: 1, ExpiryUnixNano: -1, PriorProofID: "proof"})
	binary.BigEndian.PutUint64(renew[:8], 0)
	if _, err := DecodeHelperRenewBody(renew); !errors.Is(err, ErrHelperLifecycleRevision) {
		t.Fatalf("DecodeHelperRenewBody(zero revision) error = %v", err)
	}

	revoke := mustEncodeHelperRevokeBody(t, HelperRevokeBody{Revision: 1, Reason: RevokeReasonRequested})
	binary.BigEndian.PutUint64(revoke[:8], 0)
	if _, err := DecodeHelperRevokeBody(revoke); !errors.Is(err, ErrHelperLifecycleRevision) {
		t.Fatalf("DecodeHelperRevokeBody(zero revision) error = %v", err)
	}
	binary.BigEndian.PutUint64(revoke[:8], 1)
	for _, reason := range []byte{0, byte(RevokeReasonDaemonShutdown + 1)} {
		revoke[8] = reason
		if _, err := DecodeHelperRevokeBody(revoke); !errors.Is(err, ErrUnknownRevokeReason) {
			t.Errorf("DecodeHelperRevokeBody(reason %d) error = %v", reason, err)
		}
	}

	event := mustEncodeHelperEventBody(t, HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: "event"})
	binary.BigEndian.PutUint64(event[1:9], 0)
	if _, err := DecodeHelperEventBody(event); !errors.Is(err, ErrHelperLifecycleRevision) {
		t.Fatalf("DecodeHelperEventBody(zero revision) error = %v", err)
	}
	binary.BigEndian.PutUint64(event[1:9], 1)
	for _, code := range []byte{0, byte(EventCodeCleanupRequired + 1)} {
		event[0] = code
		if _, err := DecodeHelperEventBody(event); !errors.Is(err, ErrUnknownEventCode) {
			t.Errorf("DecodeHelperEventBody(code %d) error = %v", code, err)
		}
	}

	for _, reason := range []byte{0, byte(CloseReasonShutdown + 1)} {
		if _, err := DecodeHelperCloseNotifyBody([]byte{reason}); !errors.Is(err, ErrUnknownCloseReason) {
			t.Errorf("DecodeHelperCloseNotifyBody(reason %d) error = %v", reason, err)
		}
	}

	unsafeRenew := mustEncodeHelperRenewBody(t, HelperRenewBody{Revision: 1, PriorProofID: "proof"})
	unsafeRenew[18] = '-'
	if _, err := DecodeHelperRenewBody(unsafeRenew); !errors.Is(err, ErrInvalidBodyToken) {
		t.Errorf("DecodeHelperRenewBody(unsafe token) error = %v, want ErrInvalidBodyToken", err)
	}
	unsafeEvent := mustEncodeHelperEventBody(t, HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: "event"})
	unsafeEvent[11] = '-'
	if _, err := DecodeHelperEventBody(unsafeEvent); !errors.Is(err, ErrInvalidBodyToken) {
		t.Errorf("DecodeHelperEventBody(unsafe token) error = %v, want ErrInvalidBodyToken", err)
	}
}

func TestHelperLifecycleBodyDecodeRejectsEveryTruncationAndTrailingByte(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		wire        []byte
		decode      func([]byte) error
		lengthErr   error
		trailingErr error
	}{
		{
			name: "renew", wire: mustEncodeHelperRenewBody(t, HelperRenewBody{Revision: 1, ExpiryUnixNano: -1, PriorProofID: "proof"}),
			decode:    func(wire []byte) error { _, err := DecodeHelperRenewBody(wire); return err },
			lengthErr: ErrHelperRenewBodyLength, trailingErr: ErrHelperRenewBodyTrailingData,
		},
		{
			name: "revoke", wire: mustEncodeHelperRevokeBody(t, HelperRevokeBody{Revision: 1, Reason: RevokeReasonRequested}),
			decode:    func(wire []byte) error { _, err := DecodeHelperRevokeBody(wire); return err },
			lengthErr: ErrHelperRevokeBodyLength, trailingErr: ErrHelperRevokeBodyTrailingData,
		},
		{
			name: "event", wire: mustEncodeHelperEventBody(t, HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: "event"}),
			decode:    func(wire []byte) error { _, err := DecodeHelperEventBody(wire); return err },
			lengthErr: ErrHelperEventBodyLength, trailingErr: ErrHelperEventBodyTrailingData,
		},
		{
			name: "close", wire: mustEncodeHelperCloseNotifyBody(t, HelperCloseNotifyBody{Reason: CloseReasonNormal}),
			decode:    func(wire []byte) error { _, err := DecodeHelperCloseNotifyBody(wire); return err },
			lengthErr: ErrHelperCloseNotifyBodyLength, trailingErr: ErrHelperCloseNotifyBodyTrailingData,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for length := 0; length < len(test.wire); length++ {
				candidate := cloneBytes(test.wire[:length])
				before := cloneBytes(candidate)
				err := test.decode(candidate)
				if err == nil || !errors.Is(err, test.lengthErr) {
					t.Errorf("decode length %d error = %v, want %v", length, err, test.lengthErr)
				}
				if !bytes.Equal(candidate, before) {
					t.Errorf("decode length %d mutated input", length)
				}
			}
			withTrailing := append(cloneBytes(test.wire), 0xa5)
			if err := test.decode(withTrailing); !errors.Is(err, test.trailingErr) {
				t.Errorf("decode trailing error = %v, want %v", err, test.trailingErr)
			}
		})
	}
}

func TestHelperLifecycleVariableBodyLengthErrorsPreserveTokenCause(t *testing.T) {
	t.Parallel()

	renew := mustEncodeHelperRenewBody(t, HelperRenewBody{Revision: 1, PriorProofID: "proof"})
	for _, length := range []int{17, 18, len(renew) - 1} {
		_, err := DecodeHelperRenewBody(renew[:length])
		if !errors.Is(err, ErrHelperRenewBodyLength) {
			t.Errorf("renew length %d error = %v, want body length", length, err)
		}
		if length >= 18 && !errors.Is(err, ErrBodyTokenEncoding) {
			t.Errorf("renew length %d error = %v, want token encoding cause", length, err)
		}
	}

	event := mustEncodeHelperEventBody(t, HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: "event"})
	for _, length := range []int{10, 11, len(event) - 1} {
		_, err := DecodeHelperEventBody(event[:length])
		if !errors.Is(err, ErrHelperEventBodyLength) {
			t.Errorf("event length %d error = %v, want body length", length, err)
		}
		if length >= 11 && !errors.Is(err, ErrBodyTokenEncoding) {
			t.Errorf("event length %d error = %v, want token encoding cause", length, err)
		}
	}
}

func TestHelperLifecycleBodiesHaveNoJSONTagsAndDenyGenericSerialization(t *testing.T) {
	t.Parallel()

	values := []any{
		HelperRenewBody{Revision: 7, ExpiryUnixNano: -9, PriorProofID: "credential-marker"},
		HelperRevokeBody{Revision: 7, Reason: RevokeReasonSourceRevoked},
		HelperEventBody{Code: EventCodeCleanupRequired, Revision: 7, EventID: "event-marker"},
		HelperCloseNotifyBody{Reason: CloseReasonProtocolError},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOf, field.Name, field.Tag)
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperLifecycleBodySerialization) {
			t.Errorf("json.Marshal(%s) error = %v, want serialization denial", typeOf, err)
		}
		textMarshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatalf("%s does not implement encoding.TextMarshaler denial", typeOf)
		}
		if _, err := textMarshaler.MarshalText(); !errors.Is(err, ErrHelperLifecycleBodySerialization) {
			t.Errorf("MarshalText(%s) error = %v, want serialization denial", typeOf, err)
		}

		pointer := reflect.New(typeOf)
		if err := json.Unmarshal([]byte(`{"Revision":9,"PriorProofID":"credential-marker"}`), pointer.Interface()); !errors.Is(err, ErrHelperLifecycleBodySerialization) {
			t.Errorf("json.Unmarshal(%s) error = %v, want serialization denial", typeOf, err)
		}
		textUnmarshaler, ok := pointer.Interface().(encoding.TextUnmarshaler)
		if !ok {
			t.Fatalf("*%s does not implement encoding.TextUnmarshaler denial", typeOf)
		}
		if err := textUnmarshaler.UnmarshalText([]byte("credential-marker")); !errors.Is(err, ErrHelperLifecycleBodySerialization) {
			t.Errorf("UnmarshalText(%s) error = %v, want serialization denial", typeOf, err)
		}
		if !reflect.ValueOf(pointer.Interface()).Elem().IsZero() {
			t.Errorf("generic decode mutated %s", typeOf)
		}
	}
}

func TestHelperLifecycleBodiesFormatOpaqueUnderEveryVerb(t *testing.T) {
	t.Parallel()

	const secretMarker = "credential-marker-never-format"
	values := []struct {
		value any
		name  string
	}{
		{value: HelperRenewBody{Revision: ^uint64(0), ExpiryUnixNano: -1, PriorProofID: secretMarker}, name: "HelperRenewBody"},
		{value: HelperRevokeBody{Revision: ^uint64(0), Reason: RevokeReasonDaemonShutdown}, name: "HelperRevokeBody"},
		{value: HelperEventBody{Code: EventCodeCleanupRequired, Revision: ^uint64(0), EventID: secretMarker}, name: "HelperEventBody"},
		{value: HelperCloseNotifyBody{Reason: CloseReasonShutdown}, name: "HelperCloseNotifyBody"},
	}
	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O",
		"%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T",
	}
	for _, test := range values {
		for _, verb := range verbs {
			formatted := fmt.Sprintf(verb, test.value)
			if strings.Contains(formatted, secretMarker) || strings.Contains(formatted, "184467") || strings.Contains(formatted, "daemon_shutdown") {
				t.Errorf("fmt.Sprintf(%q, %s) leaked body: %q", verb, test.name, formatted)
			}
			if verb != "%T" && formatted != test.name {
				t.Errorf("fmt.Sprintf(%q, %s) = %q, want opaque name", verb, test.name, formatted)
			}
		}
		pointer := reflect.New(reflect.TypeOf(test.value))
		pointer.Elem().Set(reflect.ValueOf(test.value))
		formattedPointer := fmt.Sprintf("%p", pointer.Interface())
		if strings.Contains(formattedPointer, secretMarker) || strings.Contains(formattedPointer, "184467") || strings.Contains(formattedPointer, "daemon_shutdown") {
			t.Errorf("fmt.Sprintf(%%p, *%s) leaked body: %q", test.name, formattedPointer)
		}
	}
}

func TestHelperLifecycleBodyErrorsAreStableAndDoNotEchoInput(t *testing.T) {
	t.Parallel()

	seed := "credential-value-never-echoed/private/path"
	checks := []error{
		encodeHelperRenewValueError(HelperRenewBody{Revision: 1, PriorProofID: seed}),
		encodeHelperEventValueError(HelperEventBody{Code: EventCodeExpired, Revision: 1, EventID: seed}),
		decodeHelperRenewError([]byte{0, 1, 2, 3}),
		decodeHelperEventError([]byte{0, 1, 2, 3}),
	}
	for _, err := range checks {
		if err == nil {
			t.Fatal("expected lifecycle body rejection")
		}
		if strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), "private/path") {
			t.Fatalf("error leaked rejected input: %q", err)
		}
	}

	stable := map[error]string{
		ErrHelperLifecycleRevision:           "credential protocol helper lifecycle revision is invalid",
		ErrHelperRenewBodyLength:             "credential protocol helper renew body length is invalid",
		ErrHelperRenewBodyTrailingData:       "credential protocol helper renew body has trailing data",
		ErrHelperRevokeBodyLength:            "credential protocol helper revoke body length is invalid",
		ErrHelperRevokeBodyTrailingData:      "credential protocol helper revoke body has trailing data",
		ErrHelperEventBodyLength:             "credential protocol helper event body length is invalid",
		ErrHelperEventBodyTrailingData:       "credential protocol helper event body has trailing data",
		ErrHelperCloseNotifyBodyLength:       "credential protocol helper close-notify body length is invalid",
		ErrHelperCloseNotifyBodyTrailingData: "credential protocol helper close-notify body has trailing data",
		ErrHelperLifecycleBodySerialization:  "credential protocol helper lifecycle body serialization is denied",
	}
	for err, want := range stable {
		if err.Error() != want {
			t.Errorf("stable error = %q, want %q", err, want)
		}
	}
}

func TestHelperLifecycleBodySourceGuardIsExactFileScoped(t *testing.T) {
	t.Parallel()

	const sourceFile = "helper_lifecycle_body.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), sourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", sourceFile, err)
	}
	allowedImports := map[string]bool{
		"encoding/binary": true,
		"errors":          true,
		"fmt":             true,
	}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import in %s: %v", sourceFile, err)
		}
		if imported.Name != nil || !allowedImports[path] {
			t.Errorf("%s imports %q; lifecycle bodies permit only exact pure codec/opaque-format packages", sourceFile, path)
		}
	}

	wantTypes := map[string]bool{
		"HelperRenewBody": true, "HelperRevokeBody": true,
		"HelperEventBody": true, "HelperCloseNotifyBody": true,
	}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok != token.TYPE {
				continue
			}
			for _, spec := range typed.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok || !wantTypes[typeSpec.Name.Name] {
					continue
				}
				for _, field := range structure.Fields.List {
					if field.Tag != nil {
						t.Errorf("%s.%s has durable tag %s", typeSpec.Name, fieldNameForGuard(field), field.Tag.Value)
					}
					switch field.Type.(type) {
					case *ast.InterfaceType, *ast.MapType:
						t.Errorf("%s.%s exposes generic body storage", typeSpec.Name, fieldNameForGuard(field))
					case *ast.ArrayType:
						array := field.Type.(*ast.ArrayType)
						if array.Len == nil {
							t.Errorf("%s.%s exposes slice body storage", typeSpec.Name, fieldNameForGuard(field))
						}
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Recv == nil && (typed.Name.Name == "EncodeHelperBody" || typed.Name.Name == "DecodeHelperBody") {
				t.Errorf("%s exposes forbidden generic body owner API %s", sourceFile, typed.Name)
			}
		}
	}

	source, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatalf("read %s: %v", sourceFile, err)
	}
	for _, forbidden := range []string{"json.RawMessage", "map[string]", "[]byte `json:", "EncodeHelperBody(", "DecodeHelperBody("} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Errorf("%s contains forbidden generic/durable marker %q", sourceFile, forbidden)
		}
	}
}

func assertHelperLifecycleRoundTrip[T comparable](
	t *testing.T,
	name string,
	value T,
	want []byte,
	encode func(T) ([]byte, error),
	decode func([]byte) (T, error),
) {
	t.Helper()
	encoded, err := encode(value)
	if err != nil {
		t.Fatalf("encode %s error = %v", name, err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %s = %x, want %x", name, encoded, want)
	}
	before := cloneBytes(encoded)
	decoded, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode %s error = %v", name, err)
	}
	if decoded != value {
		t.Fatalf("decoded %s = %#v, want %#v", name, decoded, value)
	}
	if !bytes.Equal(encoded, before) {
		t.Fatalf("decode %s mutated input", name)
	}
}

func encodeHelperRevokeError(reason RevokeReason) error {
	_, err := EncodeHelperRevokeBody(HelperRevokeBody{Revision: 1, Reason: reason})
	return err
}

func encodeHelperEventError(code EventCode) error {
	_, err := EncodeHelperEventBody(HelperEventBody{Code: code, Revision: 1, EventID: "event"})
	return err
}

func encodeHelperCloseError(reason CloseReason) error {
	_, err := EncodeHelperCloseNotifyBody(HelperCloseNotifyBody{Reason: reason})
	return err
}

func encodeHelperRenewValueError(value HelperRenewBody) error {
	_, err := EncodeHelperRenewBody(value)
	return err
}

func encodeHelperEventValueError(value HelperEventBody) error {
	_, err := EncodeHelperEventBody(value)
	return err
}

func decodeHelperRenewError(wire []byte) error {
	_, err := DecodeHelperRenewBody(wire)
	return err
}

func decodeHelperEventError(wire []byte) error {
	_, err := DecodeHelperEventBody(wire)
	return err
}

func mustEncodeHelperRenewBody(t *testing.T, value HelperRenewBody) []byte {
	t.Helper()
	encoded, err := EncodeHelperRenewBody(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeHelperRevokeBody(t *testing.T, value HelperRevokeBody) []byte {
	t.Helper()
	encoded, err := EncodeHelperRevokeBody(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeHelperEventBody(t *testing.T, value HelperEventBody) []byte {
	t.Helper()
	encoded, err := EncodeHelperEventBody(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeHelperCloseNotifyBody(t *testing.T, value HelperCloseNotifyBody) []byte {
	t.Helper()
	encoded, err := EncodeHelperCloseNotifyBody(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fieldNameForGuard(field *ast.Field) string {
	if len(field.Names) == 0 {
		return "<embedded>"
	}
	return field.Names[0].Name
}
