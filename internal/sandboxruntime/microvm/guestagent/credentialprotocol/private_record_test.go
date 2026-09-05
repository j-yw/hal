package credentialprotocol

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPrivateRecordExactIndependentVector(t *testing.T) {
	requestID := privateRecordTestRequestID()
	identityDigest := privateRecordTestIdentityDigest()
	payload := []byte("secret")
	payloadDigest := sha256.Sum256(payload)
	record, err := NewPrivateRecord(PrivateRecordKindFileBytes, requestID, identityDigest, 2, payload)
	if err != nil {
		t.Fatalf("NewPrivateRecord: %v", err)
	}
	defer record.Wipe()

	// This complete vector is independently fixed from the documented fields:
	// 100 header bytes followed by the six ASCII payload bytes.
	const wantHex = "484c384201010000" +
		"000102030405060708090a0b0c0d0e0f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
		"000200000001000000000006" +
		"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b" +
		"736563726574"

	wire, err := EncodePrivateRecord(record)
	if err != nil {
		t.Fatalf("EncodePrivateRecord: %v", err)
	}
	if got := hex.EncodeToString(wire); got != wantHex {
		t.Fatalf("wire = %s\nwant   %s", got, wantHex)
	}
	if PrivateRecordFixedHeaderBytes != 100 {
		t.Fatalf("PrivateRecordFixedHeaderBytes = %d, want 100", PrivateRecordFixedHeaderBytes)
	}

	decoded, err := DecodePrivateRecord(wire)
	if err != nil {
		t.Fatalf("DecodePrivateRecord: %v", err)
	}
	defer decoded.Wipe()
	if decoded.Kind() != PrivateRecordKindFileBytes || decoded.RequestID() != requestID || decoded.IdentityDigest() != identityDigest || decoded.BindingIndex() != 2 || decoded.ChunkIndex() != 0 || decoded.ChunkCount() != 1 || decoded.PayloadLength() != uint32(len(payload)) || decoded.PayloadSHA256() != payloadDigest {
		t.Fatal("decoded scalar metadata does not match the exact vector")
	}
	destination := make([]byte, len(payload))
	if n, err := decoded.CopyPayload(destination); err != nil || n != len(payload) || string(destination) != "secret" {
		t.Fatalf("CopyPayload = %d, %v, %q", n, err, destination)
	}

	// Both constructor and decoder own private copies.
	payload[0] = 'X'
	wire[len(wire)-1] = 'X'
	if n, err := decoded.CopyPayload(destination); err != nil || n != len(destination) || string(destination) != "secret" {
		t.Fatalf("decoded payload aliases input: %d, %v, %q", n, err, destination)
	}
}

func TestPrivateRecordDecodeRejectsNoncanonicalAndMalformedWireWithoutOwner(t *testing.T) {
	valid := privateRecordTestWire(t, PrivateRecordKindFileBytes, 3, []byte("private-value"))

	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{name: "truncated header", mutate: func(wire []byte) []byte { return wire[:PrivateRecordFixedHeaderBytes-1] }, want: ErrPrivateRecordLength},
		{name: "magic", mutate: func(wire []byte) []byte { wire[0] ^= 0xff; return wire }, want: ErrPrivateRecordMagic},
		{name: "version", mutate: func(wire []byte) []byte { wire[4] = 2; return wire }, want: ErrPrivateRecordVersion},
		{name: "zero kind", mutate: func(wire []byte) []byte { wire[5] = 0; return wire }, want: ErrPrivateRecordKind},
		{name: "unknown kind", mutate: func(wire []byte) []byte { wire[5] = 3; return wire }, want: ErrPrivateRecordKind},
		{name: "flags", mutate: func(wire []byte) []byte { wire[7] = 1; return wire }, want: ErrPrivateRecordFlags},
		{name: "zero request ID", mutate: func(wire []byte) []byte { clear(wire[8:24]); return wire }, want: ErrPrivateRecordRequestID},
		{name: "zero identity digest", mutate: func(wire []byte) []byte { clear(wire[24:56]); return wire }, want: ErrPrivateRecordIdentityDigest},
		{name: "file binding index plus one", mutate: func(wire []byte) []byte { wire[57] = MaxPreparePrivateRecordCount; return wire }, want: ErrPrivateRecordBindingIndex},
		{name: "chunk index", mutate: func(wire []byte) []byte { wire[59] = 1; return wire }, want: ErrPrivateRecordChunk},
		{name: "chunk count zero", mutate: func(wire []byte) []byte { wire[61] = 0; return wire }, want: ErrPrivateRecordChunk},
		{name: "chunk count two", mutate: func(wire []byte) []byte { wire[61] = 2; return wire }, want: ErrPrivateRecordChunk},
		{name: "reserved", mutate: func(wire []byte) []byte { wire[63] = 1; return wire }, want: ErrPrivateRecordReserved},
		{name: "zero payload", mutate: func(wire []byte) []byte { clear(wire[64:68]); return wire[:PrivateRecordFixedHeaderBytes] }, want: ErrPrivateRecordPayloadLength},
		{name: "payload plus one", mutate: func(wire []byte) []byte { wire[64], wire[65], wire[66], wire[67] = 0, 1, 0, 1; return wire }, want: ErrPrivateRecordPayloadLength},
		{name: "truncated payload", mutate: func(wire []byte) []byte { return wire[:len(wire)-1] }, want: ErrPrivateRecordLength},
		{name: "trailing byte", mutate: func(wire []byte) []byte { return append(wire, 0) }, want: ErrPrivateRecordTrailingData},
		{name: "zero digest", mutate: func(wire []byte) []byte { clear(wire[68:100]); return wire }, want: ErrPrivateRecordPayloadDigest},
		{name: "digest mismatch", mutate: func(wire []byte) []byte { wire[68] ^= 1; return wire }, want: ErrPrivateRecordPayloadDigest},
		{name: "payload mismatch", mutate: func(wire []byte) []byte { wire[len(wire)-1] ^= 1; return wire }, want: ErrPrivateRecordPayloadDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			got, err := DecodePrivateRecord(tt.mutate(wire))
			if got != nil {
				got.Wipe()
				t.Fatal("failed decode published a private-record owner")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	execWire := privateRecordTestWire(t, PrivateRecordKindOpaqueExecBinding, 0, []byte("opaque"))
	execWire[56], execWire[57] = 0, 1
	if got, err := DecodePrivateRecord(execWire); got != nil || !errors.Is(err, ErrPrivateRecordBindingIndex) {
		if got != nil {
			got.Wipe()
		}
		t.Fatalf("kind-2 nonzero binding decode = %v, %v", got, err)
	}
}

func TestPrivateRecordExactPayloadAndPrepareAggregateBounds(t *testing.T) {
	requestID := privateRecordTestRequestID()
	identity := privateRecordTestIdentityDigest()
	payload := make([]byte, MaxPrivateRecordPayloadBytes)
	for index := range payload {
		payload[index] = byte(index)
	}

	records := make([]*PrivateRecord, MaxPreparePrivateRecordCount)
	files := make([]PrivateFileRecordExpectation, MaxPreparePrivateRecordCount)
	hash := sha256.New()
	for index := range records {
		record, err := NewPrivateRecord(PrivateRecordKindFileBytes, requestID, identity, uint16(index), payload)
		if err != nil {
			t.Fatalf("NewPrivateRecord[%d]: %v", index, err)
		}
		records[index] = record
		defer record.Wipe()
		files[index] = PrivateFileRecordExpectation{BindingIndex: uint16(index), PayloadLength: MaxPrivateRecordPayloadBytes, PayloadSHA256: sha256.Sum256(payload)}
		_, _ = hash.Write(payload)
	}
	var aggregateDigest [32]byte
	copy(aggregateDigest[:], hash.Sum(nil))
	expected := PrivateRecordSetExpectation{
		RequestID: requestID, IdentityDigest: identity, RecordCount: MaxPreparePrivateRecordCount,
		AggregateBytes: MaxPreparePrivateAggregateBytes, AggregateSHA256: aggregateDigest,
	}
	if err := ValidatePreparePrivateRecords(records, files, expected); err != nil {
		t.Fatalf("exact maximum prepare set: %v", err)
	}

	wire, err := EncodePrivateRecord(records[0])
	if err != nil {
		t.Fatalf("EncodePrivateRecord maximum: %v", err)
	}
	decoded, err := DecodePrivateRecord(wire)
	if err != nil {
		t.Fatalf("DecodePrivateRecord maximum: %v", err)
	}
	decoded.Wipe()
}

func TestPrivateRecordConstructorValidatesAndDefensivelyCopies(t *testing.T) {
	requestID := privateRecordTestRequestID()
	identityDigest := privateRecordTestIdentityDigest()
	payload := make([]byte, 3, 32)
	copy(payload, "raw")
	record, err := NewPrivateRecord(PrivateRecordKindFileBytes, requestID, identityDigest, 0, payload)
	if err != nil {
		t.Fatalf("NewPrivateRecord: %v", err)
	}
	defer record.Wipe()
	if cap(record.state.payload) != len(record.state.payload) {
		t.Fatalf("owned payload cap = %d, len = %d", cap(record.state.payload), len(record.state.payload))
	}
	clear(payload[:cap(payload)])
	destination := make([]byte, 3)
	if n, err := record.CopyPayload(destination); err != nil || n != 3 || string(destination) != "raw" {
		t.Fatalf("constructor payload aliases caller: %d, %v, %q", n, err, destination)
	}

	zeroRequest := [16]byte{}
	zeroIdentity := [32]byte{}
	tests := []struct {
		name      string
		kind      PrivateRecordKind
		requestID [16]byte
		identity  [32]byte
		index     uint16
		payload   []byte
		want      error
	}{
		{name: "unknown kind", kind: 9, requestID: requestID, identity: identityDigest, payload: []byte("x"), want: ErrPrivateRecordKind},
		{name: "zero request", kind: PrivateRecordKindFileBytes, requestID: zeroRequest, identity: identityDigest, payload: []byte("x"), want: ErrPrivateRecordRequestID},
		{name: "zero identity", kind: PrivateRecordKindFileBytes, requestID: requestID, identity: zeroIdentity, payload: []byte("x"), want: ErrPrivateRecordIdentityDigest},
		{name: "file index plus one", kind: PrivateRecordKindFileBytes, requestID: requestID, identity: identityDigest, index: MaxPreparePrivateRecordCount, payload: []byte("x"), want: ErrPrivateRecordBindingIndex},
		{name: "exec index", kind: PrivateRecordKindOpaqueExecBinding, requestID: requestID, identity: identityDigest, index: 1, payload: []byte("x"), want: ErrPrivateRecordBindingIndex},
		{name: "empty", kind: PrivateRecordKindFileBytes, requestID: requestID, identity: identityDigest, payload: nil, want: ErrPrivateRecordPayloadLength},
		{name: "plus one", kind: PrivateRecordKindFileBytes, requestID: requestID, identity: identityDigest, payload: make([]byte, MaxPrivateRecordPayloadBytes+1), want: ErrPrivateRecordPayloadLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPrivateRecord(tt.kind, tt.requestID, tt.identity, tt.index, tt.payload)
			if got != nil {
				got.Wipe()
				t.Fatal("invalid constructor published an owner")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPrivateRecordValueCopiesShareWipeStateAndClearFullCapacity(t *testing.T) {
	record := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 4, []byte("wipe-canary"))
	alias := *record
	backing := record.state.payload[:cap(record.state.payload)]
	alias.Wipe()
	for index, value := range backing {
		if value != 0 {
			t.Fatalf("full-capacity byte %d survived wipe: %d", index, value)
		}
	}
	if record.state.payload != nil || alias.state.payload != nil || !record.state.wiped {
		t.Fatal("wipe did not release and invalidate shared state")
	}
	if record.Kind() != 0 || alias.RequestID() != [16]byte{} || alias.IdentityDigest() != [32]byte{} || alias.BindingIndex() != 0 || alias.ChunkIndex() != 0 || alias.ChunkCount() != 0 || alias.PayloadLength() != 0 || alias.PayloadSHA256() != [32]byte{} {
		t.Fatal("wipe did not zero all scalar metadata across aliases")
	}
	if n, err := record.CopyPayload(make([]byte, 64)); n != 0 || !errors.Is(err, ErrPrivateRecordWiped) {
		t.Fatalf("CopyPayload after wipe = %d, %v", n, err)
	}
	if wire, err := EncodePrivateRecord(record); wire != nil || !errors.Is(err, ErrPrivateRecordWiped) {
		t.Fatalf("EncodePrivateRecord after wipe = %x, %v", wire, err)
	}
	record.Wipe()
	alias.Wipe()
}

func TestPrivateRecordOpaqueFormattingAndSerializationDenial(t *testing.T) {
	record := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 0, []byte("format-canary"))
	defer record.Wipe()
	value := *record
	for _, candidate := range []struct {
		name  string
		value interface{}
	}{
		{name: "pointer", value: record},
		{name: "value", value: value},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, candidate.value)
			if got != "PrivateRecord" || strings.Contains(got, "format-canary") {
				t.Errorf("%s %s = %q", candidate.name, format, got)
			}
		}
	}
	if record.String() != "PrivateRecord" || record.GoString() != "PrivateRecord" || value.String() != "PrivateRecord" || value.GoString() != "PrivateRecord" {
		t.Fatal("String or GoString is not opaque")
	}

	for _, candidate := range []interface{}{value, record} {
		jsonMarshaler := candidate.(json.Marshaler)
		if payload, err := jsonMarshaler.MarshalJSON(); payload != nil || !errors.Is(err, ErrPrivateRecordSerialization) {
			t.Errorf("%T MarshalJSON = %q, %v", candidate, payload, err)
		}
		textMarshaler := candidate.(encoding.TextMarshaler)
		if payload, err := textMarshaler.MarshalText(); payload != nil || !errors.Is(err, ErrPrivateRecordSerialization) {
			t.Errorf("%T MarshalText = %q, %v", candidate, payload, err)
		}
		binaryMarshaler := candidate.(encoding.BinaryMarshaler)
		if payload, err := binaryMarshaler.MarshalBinary(); payload != nil || !errors.Is(err, ErrPrivateRecordSerialization) {
			t.Errorf("%T MarshalBinary = %q, %v", candidate, payload, err)
		}
	}

	wantPayload := make([]byte, record.PayloadLength())
	if _, err := record.CopyPayload(wantPayload); err != nil {
		t.Fatalf("CopyPayload before unmarshal denials: %v", err)
	}
	wantRequestID := record.RequestID()
	wantIdentity := record.IdentityDigest()
	for name, unmarshal := range map[string]func() error{
		"json":   func() error { return record.UnmarshalJSON([]byte(`{"payload":"attacker"}`)) },
		"text":   func() error { return record.UnmarshalText([]byte("attacker")) },
		"binary": func() error { return record.UnmarshalBinary([]byte("attacker")) },
	} {
		if err := unmarshal(); !errors.Is(err, ErrPrivateRecordSerialization) {
			t.Errorf("%s unmarshal error = %v", name, err)
		}
		gotPayload := make([]byte, record.PayloadLength())
		if _, err := record.CopyPayload(gotPayload); err != nil || string(gotPayload) != string(wantPayload) || record.RequestID() != wantRequestID || record.IdentityDigest() != wantIdentity {
			t.Errorf("%s unmarshal mutated seeded owner", name)
		}
	}
}

func TestValidatePreparePrivateRecordsCorrelatesExactOrderedFileManifest(t *testing.T) {
	requestID := privateRecordTestRequestID()
	identity := privateRecordTestIdentityDigest()
	first := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 1, []byte("alpha"))
	second := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 4, []byte("beta"))
	defer first.Wipe()
	defer second.Wipe()
	records := []*PrivateRecord{first, second}
	expectations := []PrivateFileRecordExpectation{
		{BindingIndex: 1, PayloadLength: 5, PayloadSHA256: sha256.Sum256([]byte("alpha"))},
		{BindingIndex: 4, PayloadLength: 4, PayloadSHA256: sha256.Sum256([]byte("beta"))},
	}
	expected := PrivateRecordSetExpectation{
		RequestID: requestID, IdentityDigest: identity, RecordCount: 2,
		AggregateBytes: 9, AggregateSHA256: sha256.Sum256([]byte("alphabeta")),
	}
	if err := ValidatePreparePrivateRecords(records, expectations, expected); err != nil {
		t.Fatalf("ValidatePreparePrivateRecords: %v", err)
	}

	empty := PrivateRecordSetExpectation{RequestID: requestID, IdentityDigest: identity, AggregateSHA256: sha256.Sum256(nil)}
	if err := ValidatePreparePrivateRecords(nil, nil, empty); err != nil {
		t.Fatalf("empty prepare records: %v", err)
	}

	tests := []struct {
		name         string
		records      []*PrivateRecord
		expectations []PrivateFileRecordExpectation
		expected     PrivateRecordSetExpectation
		want         error
	}{
		{name: "record count", records: records, expectations: expectations, expected: func() PrivateRecordSetExpectation { value := expected; value.RecordCount = 1; return value }(), want: ErrPrivateRecordSetCount},
		{name: "manifest count", records: records, expectations: expectations[:1], expected: expected, want: ErrPrivateRecordSetCount},
		{name: "order", records: []*PrivateRecord{second, first}, expectations: expectations, expected: expected, want: ErrPrivateRecordSetBindingOrder},
		{name: "expected order", records: records, expectations: []PrivateFileRecordExpectation{expectations[1], expectations[0]}, expected: expected, want: ErrPrivateRecordSetBindingOrder},
		{name: "duplicate expected index", records: records, expectations: []PrivateFileRecordExpectation{expectations[0], expectations[0]}, expected: expected, want: ErrPrivateRecordSetBindingOrder},
		{name: "request", records: records, expectations: expectations, expected: func() PrivateRecordSetExpectation { value := expected; value.RequestID[0] ^= 1; return value }(), want: ErrPrivateRecordSetRequestID},
		{name: "identity", records: records, expectations: expectations, expected: func() PrivateRecordSetExpectation { value := expected; value.IdentityDigest[0] ^= 1; return value }(), want: ErrPrivateRecordSetIdentityDigest},
		{name: "aggregate bytes", records: records, expectations: expectations, expected: func() PrivateRecordSetExpectation { value := expected; value.AggregateBytes++; return value }(), want: ErrPrivateRecordSetAggregateBytes},
		{name: "aggregate digest", records: records, expectations: expectations, expected: func() PrivateRecordSetExpectation { value := expected; value.AggregateSHA256[0] ^= 1; return value }(), want: ErrPrivateRecordSetAggregateDigest},
		{name: "file length", records: records, expectations: []PrivateFileRecordExpectation{{BindingIndex: 1, PayloadLength: 6, PayloadSHA256: expectations[0].PayloadSHA256}, expectations[1]}, expected: expected, want: ErrPrivateRecordSetPayload},
		{name: "file digest", records: records, expectations: []PrivateFileRecordExpectation{{BindingIndex: 1, PayloadLength: 5, PayloadSHA256: sha256.Sum256([]byte("wrong"))}, expectations[1]}, expected: expected, want: ErrPrivateRecordSetPayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePreparePrivateRecords(tt.records, tt.expectations, tt.expected); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	exec := privateRecordTestRecord(t, PrivateRecordKindOpaqueExecBinding, 0, []byte("alpha"))
	defer exec.Wipe()
	if err := ValidatePreparePrivateRecords([]*PrivateRecord{exec}, []PrivateFileRecordExpectation{expectations[0]}, PrivateRecordSetExpectation{RequestID: requestID, IdentityDigest: identity, RecordCount: 1, AggregateBytes: 5, AggregateSHA256: sha256.Sum256([]byte("alpha"))}); !errors.Is(err, ErrPrivateRecordSetKind) {
		t.Fatalf("prepare accepted exec kind: %v", err)
	}
}

func TestValidateExecPrivateRecordsCorrelatesHTTPPresenceAndAggregate(t *testing.T) {
	requestID := privateRecordTestRequestID()
	identity := privateRecordTestIdentityDigest()
	payload := []byte("opaque-exec-binding")
	record := privateRecordTestRecord(t, PrivateRecordKindOpaqueExecBinding, 0, payload)
	defer record.Wipe()
	expected := PrivateRecordSetExpectation{
		RequestID: requestID, IdentityDigest: identity, RecordCount: 1,
		AggregateBytes: uint64(len(payload)), AggregateSHA256: sha256.Sum256(payload),
	}
	if err := ValidateExecPrivateRecords([]*PrivateRecord{record}, true, expected); err != nil {
		t.Fatalf("ValidateExecPrivateRecords: %v", err)
	}
	empty := PrivateRecordSetExpectation{RequestID: requestID, IdentityDigest: identity, AggregateSHA256: sha256.Sum256(nil)}
	if err := ValidateExecPrivateRecords(nil, false, empty); err != nil {
		t.Fatalf("no-HTTP exec private records: %v", err)
	}

	tests := []struct {
		name     string
		records  []*PrivateRecord
		hasHTTP  bool
		expected PrivateRecordSetExpectation
		want     error
	}{
		{name: "missing with HTTP", hasHTTP: true, expected: expected, want: ErrPrivateRecordSetCount},
		{name: "present without HTTP", records: []*PrivateRecord{record}, expected: expected, want: ErrPrivateRecordSetCount},
		{name: "count", records: []*PrivateRecord{record}, hasHTTP: true, expected: func() PrivateRecordSetExpectation { value := expected; value.RecordCount = 0; return value }(), want: ErrPrivateRecordSetCount},
		{name: "bytes", records: []*PrivateRecord{record}, hasHTTP: true, expected: func() PrivateRecordSetExpectation { value := expected; value.AggregateBytes++; return value }(), want: ErrPrivateRecordSetAggregateBytes},
		{name: "digest", records: []*PrivateRecord{record}, hasHTTP: true, expected: func() PrivateRecordSetExpectation { value := expected; value.AggregateSHA256[0] ^= 1; return value }(), want: ErrPrivateRecordSetAggregateDigest},
		{name: "request", records: []*PrivateRecord{record}, hasHTTP: true, expected: func() PrivateRecordSetExpectation { value := expected; value.RequestID[0] ^= 1; return value }(), want: ErrPrivateRecordSetRequestID},
		{name: "identity", records: []*PrivateRecord{record}, hasHTTP: true, expected: func() PrivateRecordSetExpectation { value := expected; value.IdentityDigest[0] ^= 1; return value }(), want: ErrPrivateRecordSetIdentityDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateExecPrivateRecords(tt.records, tt.hasHTTP, tt.expected); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	file := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 0, payload)
	defer file.Wipe()
	if err := ValidateExecPrivateRecords([]*PrivateRecord{file}, true, expected); !errors.Is(err, ErrPrivateRecordSetKind) {
		t.Fatalf("exec accepted file kind: %v", err)
	}
}

func TestPrivateRecordCopyPayloadIsAllOrNothing(t *testing.T) {
	record := privateRecordTestRecord(t, PrivateRecordKindFileBytes, 0, []byte("secret"))
	defer record.Wipe()
	destination := []byte("keep!")
	if n, err := record.CopyPayload(destination); n != 0 || !errors.Is(err, ErrPrivateRecordDestination) || string(destination) != "keep!" {
		t.Fatalf("short CopyPayload = %d, %v, %q", n, err, destination)
	}
}

func privateRecordTestRecord(t *testing.T, kind PrivateRecordKind, bindingIndex uint16, payload []byte) *PrivateRecord {
	t.Helper()
	record, err := NewPrivateRecord(kind, privateRecordTestRequestID(), privateRecordTestIdentityDigest(), bindingIndex, payload)
	if err != nil {
		t.Fatalf("NewPrivateRecord: %v", err)
	}
	return record
}

func privateRecordTestWire(t *testing.T, kind PrivateRecordKind, bindingIndex uint16, payload []byte) []byte {
	t.Helper()
	record := privateRecordTestRecord(t, kind, bindingIndex, payload)
	defer record.Wipe()
	wire, err := EncodePrivateRecord(record)
	if err != nil {
		t.Fatalf("EncodePrivateRecord: %v", err)
	}
	return wire
}

func privateRecordTestRequestID() [16]byte {
	var requestID [16]byte
	for index := range requestID {
		requestID[index] = byte(index)
	}
	return requestID
}

func privateRecordTestIdentityDigest() [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(0x20 + index)
	}
	return digest
}
