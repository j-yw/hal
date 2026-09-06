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

func TestHelperResponseBodiesExactVectorsAndRoundTrip(t *testing.T) {
	t.Parallel()

	revision := uint64(0x0102030405060708)
	prepare := HelperResponseBody{
		RequestType: PacketTypePrepareCommit,
		Disposition: ResponseDispositionAccepted,
		Revision:    revision,
		FailureCode: FailureCodeNone,
		Prepare: &HelperPrepareResponseResult{
			ExpiresAtUnixNano: -2,
			ActiveProofID:     "active",
			ExecBindingID:     "exec",
			BindingProofs: []HelperBindingProof{
				{BindingID: "http", Mode: DeliveryModeHTTPProxy, ProofID: "proof:1"},
				{BindingID: "file", Mode: DeliveryModeFileTmpfs, ProofID: "proof:2"},
			},
		},
	}
	wantPrepare := helperResponseCommonVector(PacketTypePrepareCommit, ResponseDispositionAccepted, revision, FailureCodeNone)
	wantPrepare = append(wantPrepare,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0, 6, 'a', 'c', 't', 'i', 'v', 'e',
		0, 4, 'e', 'x', 'e', 'c',
		0, 2,
		0, 4, 'h', 't', 't', 'p', 1, 0, 7, 'p', 'r', 'o', 'o', 'f', ':', '1',
		0, 4, 'f', 'i', 'l', 'e', 2, 0, 7, 'p', 'r', 'o', 'o', 'f', ':', '2',
	)
	assertHelperResponseRoundTrip(t, "prepare", prepare, wantPrepare)

	renew := HelperResponseBody{
		RequestType: PacketTypeRenew,
		Disposition: ResponseDispositionAccepted,
		Revision:    revision,
		FailureCode: FailureCodeNone,
		Renew:       &HelperRenewResponseResult{ExpiresAtUnixNano: -3, ReplacementActiveProofID: "replacement"},
	}
	wantRenew := helperResponseCommonVector(PacketTypeRenew, ResponseDispositionAccepted, revision, FailureCodeNone)
	wantRenew = append(wantRenew,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
		0, 11, 'r', 'e', 'p', 'l', 'a', 'c', 'e', 'm', 'e', 'n', 't',
	)
	assertHelperResponseRoundTrip(t, "renew", renew, wantRenew)

	revoke := HelperResponseBody{
		RequestType: PacketTypeRevoke,
		Disposition: ResponseDispositionCleanupComplete,
		Revision:    revision,
		FailureCode: FailureCodeNone,
		Revoke:      &HelperRevokeResponseResult{CleanupProofID: "cleanup", AuthorityAbsent: true, ResourcesAbsent: true},
	}
	wantRevoke := helperResponseCommonVector(PacketTypeRevoke, ResponseDispositionCleanupComplete, revision, FailureCodeNone)
	wantRevoke = append(wantRevoke, 0, 7, 'c', 'l', 'e', 'a', 'n', 'u', 'p', 1, 1)
	assertHelperResponseRoundTrip(t, "revoke", revoke, wantRevoke)

	exec := HelperResponseBody{
		RequestType: PacketTypeExec,
		Disposition: ResponseDispositionAccepted,
		Revision:    revision,
		FailureCode: FailureCodeNone,
		Exec: &HelperExecResponseResult{
			ExitCode:   7,
			StdinBytes: 1, StdinSHA256: digestWithByte(1),
			StdoutBytes: 2, StdoutSHA256: digestWithByte(2), StdoutTruncated: true,
			StderrBytes: 3, StderrSHA256: digestWithByte(3), StderrTruncated: false,
			ExecTransactionSHA256: digestWithByte(4),
		},
	}
	wantExec := helperResponseCommonVector(PacketTypeExec, ResponseDispositionAccepted, revision, FailureCodeNone)
	execResult := make([]byte, 158)
	binary.BigEndian.PutUint32(execResult[0:4], 7)
	binary.BigEndian.PutUint64(execResult[4:12], 1)
	fillDigest(execResult[12:44], 1)
	binary.BigEndian.PutUint64(execResult[44:52], 2)
	fillDigest(execResult[52:84], 2)
	execResult[84] = 1
	binary.BigEndian.PutUint64(execResult[85:93], 3)
	fillDigest(execResult[93:125], 3)
	execResult[125] = 0
	fillDigest(execResult[126:158], 4)
	wantExec = append(wantExec, execResult...)
	assertHelperResponseRoundTrip(t, "exec", exec, wantExec)

	rejected := HelperResponseBody{
		RequestType: PacketTypePrepareCommit,
		Disposition: ResponseDispositionRejected,
		Revision:    revision,
		FailureCode: FailureCodePrepareFailed,
	}
	assertHelperResponseRoundTrip(t, "rejected", rejected,
		helperResponseCommonVector(PacketTypePrepareCommit, ResponseDispositionRejected, revision, FailureCodePrepareFailed))
}

func TestHelperResponseClosedRequestDispositionFailureMatrix(t *testing.T) {
	t.Parallel()

	operationFailures := map[PacketType][]FailureCode{
		PacketTypePrepareCommit: {
			FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeResourceLimit, FailureCodePrepareFailed,
			FailureCodeHelperUnavailable, FailureCodeCleanupIncomplete,
		},
		PacketTypeRenew: {
			FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeRenewFailed, FailureCodeHelperUnavailable,
		},
		PacketTypeRevoke: {
			FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeRevokeFailed, FailureCodeHelperUnavailable, FailureCodeCleanupIncomplete,
		},
		PacketTypeExec: {
			FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeResourceLimit, FailureCodeExecFailed,
			FailureCodeHelperUnavailable,
		},
	}

	for requestType, allowedFailures := range operationFailures {
		allowed := make(map[FailureCode]bool, len(allowedFailures))
		for _, failure := range allowedFailures {
			allowed[failure] = true
			for _, disposition := range []ResponseDisposition{ResponseDispositionRejected, ResponseDispositionCleanupRetry, ResponseDispositionStopVMRequired} {
				shouldAccept := disposition == ResponseDispositionRejected || requestType == PacketTypeRevoke
				body := HelperResponseBody{RequestType: requestType, Disposition: disposition, Revision: 1, FailureCode: failure}
				_, err := EncodeHelperResponseBody(body)
				if shouldAccept && err != nil {
					t.Errorf("encode request=%s disposition=%s failure=%s error = %v", requestType, disposition, failure, err)
				}
				if !shouldAccept && !errors.Is(err, ErrHelperResponseMatrix) {
					t.Errorf("encode request=%s disposition=%s failure=%s error = %v, want matrix rejection", requestType, disposition, failure, err)
				}
			}
		}
		for failure := FailureCode(1); failure <= FailureCodeHelperUnavailable; failure++ {
			if allowed[failure] {
				continue
			}
			body := HelperResponseBody{RequestType: requestType, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: failure}
			if _, err := EncodeHelperResponseBody(body); !errors.Is(err, ErrHelperResponseMatrix) {
				t.Errorf("encode request=%s forbidden failure=%s error = %v, want matrix rejection", requestType, failure, err)
			}
		}
	}

	successes := []HelperResponseBody{
		validPrepareResponse(), validRenewResponse(), validRevokeResponse(), validExecResponse(),
	}
	for _, body := range successes {
		if _, err := EncodeHelperResponseBody(body); err != nil {
			t.Errorf("valid success %s error = %v", body.RequestType, err)
		}
	}

	invalid := []HelperResponseBody{
		{RequestType: PacketTypePrepareBegin, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: FailureCodeMalformed},
		{RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionCleanupComplete, Revision: 1, FailureCode: FailureCodeNone, Revoke: validRevokeResponse().Revoke},
		{RequestType: PacketTypeRenew, Disposition: ResponseDispositionAccepted, Revision: 1, FailureCode: FailureCodeRenewFailed, Renew: validRenewResponse().Renew},
		{RequestType: PacketTypeRevoke, Disposition: ResponseDispositionCleanupRetry, Revision: 1, FailureCode: FailureCodeNone},
		{RequestType: PacketTypeExec, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: FailureCodeNone},
		{RequestType: PacketTypeExec, Disposition: ResponseDispositionAccepted, Revision: 1, FailureCode: FailureCodeExecFailed, Exec: validExecResponse().Exec},
	}
	for index, body := range invalid {
		if _, err := EncodeHelperResponseBody(body); !errors.Is(err, ErrHelperResponseMatrix) {
			t.Errorf("invalid matrix case %d error = %v, want ErrHelperResponseMatrix", index, err)
		}
	}
	invalidWireMatrices := [][]byte{
		helperResponseCommonVector(PacketTypePrepareBegin, ResponseDispositionRejected, 1, FailureCodeMalformed),
		helperResponseCommonVector(PacketTypePrepareCommit, ResponseDispositionCleanupComplete, 1, FailureCodeNone),
		helperResponseCommonVector(PacketTypeExec, ResponseDispositionCleanupRetry, 1, FailureCodeExecFailed),
		helperResponseCommonVector(PacketTypeRenew, ResponseDispositionRejected, 1, FailureCodePrepareFailed),
	}
	for index, wire := range invalidWireMatrices {
		if _, err := DecodeHelperResponseBody(wire); !errors.Is(err, ErrHelperResponseMatrix) {
			t.Errorf("invalid decoded matrix case %d error = %v, want ErrHelperResponseMatrix", index, err)
		}
	}
}

func TestHelperResponseResultsRejectWrongMissingOrMultipleUnionArms(t *testing.T) {
	t.Parallel()

	invalid := []HelperResponseBody{
		{RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionAccepted, Revision: 1},
		{RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionAccepted, Revision: 1, Renew: validRenewResponse().Renew},
		{RequestType: PacketTypeRenew, Disposition: ResponseDispositionAccepted, Revision: 1, Renew: validRenewResponse().Renew, Exec: validExecResponse().Exec},
		{RequestType: PacketTypeRevoke, Disposition: ResponseDispositionCleanupComplete, Revision: 1, Revoke: validRevokeResponse().Revoke, Prepare: validPrepareResponse().Prepare},
		{RequestType: PacketTypeExec, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: FailureCodeExecFailed, Exec: validExecResponse().Exec},
	}
	for index, body := range invalid {
		if _, err := EncodeHelperResponseBody(body); !errors.Is(err, ErrHelperResponseResult) {
			t.Errorf("invalid union case %d error = %v, want ErrHelperResponseResult", index, err)
		}
	}
}

func TestHelperPrepareResponseBoundsTokensModesUniquenessAndOwnership(t *testing.T) {
	t.Parallel()

	maximumToken := "A" + strings.Repeat("z", MaxBodyTokenBytes-1)
	proofs := make([]HelperBindingProof, MaxHelperBindings)
	for index := range proofs {
		proofs[index] = HelperBindingProof{
			BindingID: fmt.Sprintf("binding-%d", index),
			Mode:      DeliveryMode((index % 3) + 1),
			ProofID:   maximumToken,
		}
	}
	body := validPrepareResponse()
	body.Prepare.ActiveProofID = maximumToken
	body.Prepare.ExecBindingID = maximumToken
	body.Prepare.BindingProofs = proofs
	encodeInputBefore := cloneHelperResponseForTest(body)
	wire, err := EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperResponseBody(maximum prepare) error = %v", err)
	}
	if !reflect.DeepEqual(body, encodeInputBefore) {
		t.Fatal("EncodeHelperResponseBody mutated its input")
	}
	before := cloneBytes(wire)
	decoded, err := DecodeHelperResponseBody(wire)
	if err != nil {
		t.Fatalf("DecodeHelperResponseBody(maximum prepare) error = %v", err)
	}
	if !bytes.Equal(wire, before) || !reflect.DeepEqual(decoded, body) {
		t.Fatalf("maximum prepare round trip mismatch or input mutation")
	}
	for index := range wire {
		wire[index] = 0xa5
	}
	if decoded.Prepare.ActiveProofID != maximumToken || decoded.Prepare.BindingProofs[0].ProofID != maximumToken {
		t.Fatal("decoded prepare result aliases wire input")
	}
	proofs[0].ProofID = "changed"
	if decoded.Prepare.BindingProofs[0].ProofID != maximumToken {
		t.Fatal("decoded prepare result aliases caller input")
	}

	tooMany := validPrepareResponse()
	tooMany.Prepare.BindingProofs = append(make([]HelperBindingProof, 0, MaxHelperBindings+1), proofs...)
	tooMany.Prepare.BindingProofs = append(tooMany.Prepare.BindingProofs, HelperBindingProof{BindingID: "extra", Mode: DeliveryModeHTTPProxy, ProofID: "proof"})
	if _, err := EncodeHelperResponseBody(tooMany); !errors.Is(err, ErrHelperResponseBindingCount) {
		t.Errorf("prepare count plus one error = %v, want ErrHelperResponseBindingCount", err)
	}
	countWire, err := EncodeHelperResponseBody(validPrepareResponse())
	if err != nil {
		t.Fatal(err)
	}
	const countOffset = 11 + 8 + 2 + len("active") + 2 + len("exec")
	for _, count := range []uint16{0, MaxHelperBindings + 1} {
		candidate := cloneBytes(countWire[:countOffset+2])
		binary.BigEndian.PutUint16(candidate[countOffset:countOffset+2], count)
		if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseBindingCount) {
			t.Errorf("decoded prepare proof count %d error = %v, want ErrHelperResponseBindingCount", count, err)
		}
	}

	invalid := []HelperResponseBody{validPrepareResponse(), validPrepareResponse(), validPrepareResponse(), validPrepareResponse(), validPrepareResponse()}
	invalid[0].Prepare.ActiveProofID = strings.Repeat("a", MaxBodyTokenBytes+1)
	invalid[1].Prepare.BindingProofs[0].Mode = DeliveryMode(0)
	invalid[2].Prepare.BindingProofs[0].BindingID = "bad/path"
	invalid[3].Prepare.BindingProofs = append(invalid[3].Prepare.BindingProofs, invalid[3].Prepare.BindingProofs[0])
	invalid[4].Prepare.BindingProofs = nil
	wants := []error{ErrInvalidBodyToken, ErrUnknownDeliveryMode, ErrInvalidBodyToken, ErrHelperResponseBindingProof, ErrHelperResponseBindingCount}
	for index, candidate := range invalid {
		if _, err := EncodeHelperResponseBody(candidate); !errors.Is(err, wants[index]) {
			t.Errorf("invalid prepare case %d error = %v, want %v", index, err, wants[index])
		}
	}
}

func TestHelperResponseRejectsZeroRevisionNegativeExitAndNoncanonicalBooleans(t *testing.T) {
	t.Parallel()

	zeroRevision := validRenewResponse()
	zeroRevision.Revision = 0
	if _, err := EncodeHelperResponseBody(zeroRevision); !errors.Is(err, ErrHelperResponseRevision) {
		t.Fatalf("zero revision error = %v, want ErrHelperResponseRevision", err)
	}
	negativeExit := validExecResponse()
	negativeExit.Exec.ExitCode = -1
	if _, err := EncodeHelperResponseBody(negativeExit); !errors.Is(err, ErrHelperResponseExitCode) {
		t.Fatalf("negative exit code error = %v, want ErrHelperResponseExitCode", err)
	}
	execWire, err := EncodeHelperResponseBody(validExecResponse())
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(execWire[11:15], ^uint32(0))
	if _, err := DecodeHelperResponseBody(execWire); !errors.Is(err, ErrHelperResponseExitCode) {
		t.Fatalf("decoded negative exit code error = %v, want ErrHelperResponseExitCode", err)
	}

	revokeWire, err := EncodeHelperResponseBody(validRevokeResponse())
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{len(revokeWire) - 2, len(revokeWire) - 1} {
		candidate := cloneBytes(revokeWire)
		candidate[offset] = 2
		if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseBoolean) {
			t.Errorf("revoke boolean offset %d error = %v, want ErrHelperResponseBoolean", offset, err)
		}
	}
	for _, offset := range []int{len(revokeWire) - 2, len(revokeWire) - 1} {
		candidate := cloneBytes(revokeWire)
		candidate[offset] = 0
		if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseResult) {
			t.Errorf("revoke false absence offset %d error = %v, want ErrHelperResponseResult", offset, err)
		}
	}
	for _, mutate := range []func(*HelperRevokeResponseResult){
		func(result *HelperRevokeResponseResult) { result.AuthorityAbsent = false },
		func(result *HelperRevokeResponseResult) { result.ResourcesAbsent = false },
	} {
		candidate := validRevokeResponse()
		mutate(candidate.Revoke)
		if _, err := EncodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseResult) {
			t.Errorf("encode revoke false absence error = %v, want ErrHelperResponseResult", err)
		}
	}
	execWire, err = EncodeHelperResponseBody(validExecResponse())
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{11 + 84, 11 + 125} {
		candidate := cloneBytes(execWire)
		candidate[offset] = 2
		if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseBoolean) {
			t.Errorf("exec boolean offset %d error = %v, want ErrHelperResponseBoolean", offset, err)
		}
	}
}

func TestHelperExecResponsePreservesArbitraryFixedDigests(t *testing.T) {
	t.Parallel()

	body := validExecResponse()
	body.Exec.StdinSHA256 = [32]byte{}
	body.Exec.StdoutSHA256 = digestWithByte(0xff)
	body.Exec.StderrSHA256 = [32]byte{0, 1, 2, 3, 4, 5}
	body.Exec.ExecTransactionSHA256 = [32]byte{}
	wire, err := EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatalf("EncodeHelperResponseBody(arbitrary digests) error = %v", err)
	}
	decoded, err := DecodeHelperResponseBody(wire)
	if err != nil {
		t.Fatalf("DecodeHelperResponseBody(arbitrary digests) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, body) {
		t.Fatalf("arbitrary fixed digest round trip mismatch")
	}
}

func TestHelperResponseDecodeRejectsEveryTruncationTrailingAndUnknownValue(t *testing.T) {
	t.Parallel()

	values := []HelperResponseBody{
		validPrepareResponse(), validRenewResponse(), validRevokeResponse(), validExecResponse(),
		{RequestType: PacketTypeExec, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: FailureCodeExecFailed},
	}
	for _, value := range values {
		wire, err := EncodeHelperResponseBody(value)
		if err != nil {
			t.Fatal(err)
		}
		for length := 0; length < len(wire); length++ {
			candidate := cloneBytes(wire[:length])
			before := cloneBytes(candidate)
			if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, ErrHelperResponseBodyLength) {
				t.Errorf("%s truncation %d error = %v, want ErrHelperResponseBodyLength", value.RequestType, length, err)
			}
			if !bytes.Equal(candidate, before) {
				t.Errorf("%s truncation %d mutated input", value.RequestType, length)
			}
		}
		trailing := append(cloneBytes(wire), 0xa5)
		if _, err := DecodeHelperResponseBody(trailing); !errors.Is(err, ErrHelperResponseBodyTrailingData) {
			t.Errorf("%s trailing error = %v, want ErrHelperResponseBodyTrailingData", value.RequestType, err)
		}
	}

	base, err := EncodeHelperResponseBody(validRenewResponse())
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		offset int
		value  byte
		want   error
	}{
		{offset: 0, value: 0x11, want: ErrHelperResponseMatrix},
		{offset: 1, value: 0, want: ErrUnknownResponseDisposition},
		{offset: 10, value: 0xff, want: ErrUnknownFailureCode},
	}
	for _, mutation := range mutations {
		candidate := cloneBytes(base)
		candidate[mutation.offset] = mutation.value
		if _, err := DecodeHelperResponseBody(candidate); !errors.Is(err, mutation.want) {
			t.Errorf("unknown mutation offset %d error = %v, want %v", mutation.offset, err, mutation.want)
		}
	}
}

func TestHelperCleanupDispositionMappingIsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wire     ResponseDisposition
		want     HelperCleanupDisposition
		spelling string
	}{
		{ResponseDispositionCleanupComplete, HelperCleanupComplete, "cleanup_complete"},
		{ResponseDispositionCleanupRetry, HelperCleanupRetryRequired, "retry_required"},
		{ResponseDispositionStopVMRequired, HelperCleanupStopVMRequired, "stop_vm_required"},
	}
	for _, test := range tests {
		got, err := MapHelperCleanupDisposition(test.wire)
		if err != nil || got != test.want || got.String() != test.spelling {
			t.Errorf("MapHelperCleanupDisposition(%s) = %s, %v; want %s", test.wire, got, err, test.spelling)
		}
	}
	for _, invalid := range []ResponseDisposition{0, ResponseDispositionAccepted, ResponseDispositionRejected, 6, 255} {
		if _, err := MapHelperCleanupDisposition(invalid); !errors.Is(err, ErrUnknownHelperCleanupDisposition) {
			t.Errorf("MapHelperCleanupDisposition(%d) error = %v, want closed rejection", invalid, err)
		}
	}
	for _, invalid := range []HelperCleanupDisposition{"", "cleanup_retry", "STOP_VM_REQUIRED"} {
		if err := ValidateHelperCleanupDisposition(invalid); !errors.Is(err, ErrUnknownHelperCleanupDisposition) {
			t.Errorf("ValidateHelperCleanupDisposition(%q) error = %v", invalid, err)
		}
		if invalid.String() != "unknown" {
			t.Errorf("HelperCleanupDisposition(%q).String() = %q", invalid, invalid.String())
		}
	}
}

func TestHelperResponseBodiesDenyGenericSerializationAndFormatOpaque(t *testing.T) {
	t.Parallel()

	const marker = "credential-marker-never-format"
	prepare := validPrepareResponse()
	prepare.Prepare.ActiveProofID = marker
	values := []any{
		prepare,
		*prepare.Prepare,
		prepare.Prepare.BindingProofs[0],
		*validRenewResponse().Renew,
		*validRevokeResponse().Revoke,
		*validExecResponse().Exec,
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if field := typeOf.Field(index); field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOf, field.Name, field.Tag)
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperResponseBodySerialization) {
			t.Errorf("json.Marshal(%s) error = %v, want serialization denial", typeOf, err)
		}
		textMarshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatalf("%s lacks text serialization denial", typeOf)
		}
		if _, err := textMarshaler.MarshalText(); !errors.Is(err, ErrHelperResponseBodySerialization) {
			t.Errorf("MarshalText(%s) error = %v", typeOf, err)
		}
		pointer := reflect.New(typeOf)
		pointer.Elem().Set(reflect.ValueOf(value))
		if err := json.Unmarshal([]byte(`{"marker":"credential-marker-never-format"}`), pointer.Interface()); !errors.Is(err, ErrHelperResponseBodySerialization) {
			t.Errorf("json.Unmarshal(%s) error = %v", typeOf, err)
		}
		if !reflect.DeepEqual(pointer.Elem().Interface(), value) {
			t.Errorf("failed JSON decode mutated seeded %s", typeOf)
		}
		textUnmarshaler, ok := pointer.Interface().(encoding.TextUnmarshaler)
		if !ok {
			t.Fatalf("*%s lacks text deserialization denial", typeOf)
		}
		if err := textUnmarshaler.UnmarshalText([]byte(marker)); !errors.Is(err, ErrHelperResponseBodySerialization) {
			t.Errorf("UnmarshalText(%s) error = %v", typeOf, err)
		}
		if !reflect.DeepEqual(pointer.Elem().Interface(), value) {
			t.Errorf("failed text decode mutated seeded %s", typeOf)
		}
		verbs := []string{
			"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O",
			"%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T",
		}
		for _, verb := range verbs {
			formatted := fmt.Sprintf(verb, value)
			if strings.Contains(formatted, marker) {
				t.Errorf("fmt.Sprintf(%q, %s) leaked marker: %q", verb, typeOf, formatted)
			}
			if verb != "%T" && formatted != typeOf.Name() {
				t.Errorf("fmt.Sprintf(%q, %s) = %q, want opaque name", verb, typeOf, formatted)
			}
		}
		if formatted := fmt.Sprintf("%p", pointer.Interface()); strings.Contains(formatted, marker) {
			t.Errorf("fmt.Sprintf(%%p, *%s) leaked marker: %q", typeOf, formatted)
		}
	}
}

func TestHelperResponseBodyErrorsDoNotEchoInput(t *testing.T) {
	t.Parallel()

	marker := "credential-value-never-echoed/private/path"
	body := validPrepareResponse()
	body.Prepare.ActiveProofID = marker
	_, encodeErr := EncodeHelperResponseBody(body)
	_, decodeErr := DecodeHelperResponseBody([]byte(marker))
	for _, err := range []error{encodeErr, decodeErr} {
		if err == nil {
			t.Fatal("expected response body rejection")
		}
		if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "private/path") {
			t.Fatalf("response body error leaked input: %q", err)
		}
	}
}

func TestHelperResponseBodySourceGuardIsExactFileScoped(t *testing.T) {
	t.Parallel()

	const sourceFile = "helper_response_body.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), sourceFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", sourceFile, err)
	}
	allowedImports := map[string]bool{"encoding/binary": true, "errors": true, "fmt": true}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if imported.Name != nil || !allowedImports[path] {
			t.Errorf("%s imports %q; response bodies permit only pure codec/opaque-format packages", sourceFile, path)
		}
	}

	wantTypes := map[string]bool{
		"HelperResponseBody":          true,
		"HelperBindingProof":          true,
		"HelperPrepareResponseResult": true,
		"HelperRenewResponseResult":   true,
		"HelperRevokeResponseResult":  true,
		"HelperExecResponseResult":    true,
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
						t.Errorf("%s.%s has durable tag", typeSpec.Name, fieldNameForGuard(field))
					}
					switch field.Type.(type) {
					case *ast.InterfaceType, *ast.MapType:
						t.Errorf("%s.%s exposes generic body storage", typeSpec.Name, fieldNameForGuard(field))
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Recv == nil && (typed.Name.Name == "EncodeHelperBody" || typed.Name.Name == "DecodeHelperBody") {
				t.Errorf("%s exposes forbidden generic body API %s", sourceFile, typed.Name)
			}
		}
	}
	source, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"json.RawMessage", "map[string]", "EncodeHelperBody(", "DecodeHelperBody(", "net.", "os."} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Errorf("%s contains forbidden generic/live marker %q", sourceFile, forbidden)
		}
	}
}

func assertHelperResponseRoundTrip(t *testing.T, name string, value HelperResponseBody, want []byte) {
	t.Helper()
	encoded, err := EncodeHelperResponseBody(value)
	if err != nil {
		t.Fatalf("encode %s error = %v", name, err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %s = %x, want %x", name, encoded, want)
	}
	before := cloneBytes(encoded)
	decoded, err := DecodeHelperResponseBody(encoded)
	if err != nil {
		t.Fatalf("decode %s error = %v", name, err)
	}
	if !reflect.DeepEqual(decoded, value) || !bytes.Equal(encoded, before) {
		t.Fatalf("decoded %s mismatch or wire mutation", name)
	}
}

func helperResponseCommonVector(requestType PacketType, disposition ResponseDisposition, revision uint64, failure FailureCode) []byte {
	wire := make([]byte, 11)
	wire[0] = byte(requestType)
	wire[1] = byte(disposition)
	binary.BigEndian.PutUint64(wire[2:10], revision)
	wire[10] = byte(failure)
	return wire
}

func validPrepareResponse() HelperResponseBody {
	return HelperResponseBody{
		RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionAccepted, Revision: 1,
		Prepare: &HelperPrepareResponseResult{
			ExpiresAtUnixNano: -1, ActiveProofID: "active", ExecBindingID: "exec",
			BindingProofs: []HelperBindingProof{{BindingID: "binding", Mode: DeliveryModeHTTPProxy, ProofID: "proof"}},
		},
	}
}

func validRenewResponse() HelperResponseBody {
	return HelperResponseBody{
		RequestType: PacketTypeRenew, Disposition: ResponseDispositionAccepted, Revision: 1,
		Renew: &HelperRenewResponseResult{ExpiresAtUnixNano: -1, ReplacementActiveProofID: "replacement"},
	}
}

func validRevokeResponse() HelperResponseBody {
	return HelperResponseBody{
		RequestType: PacketTypeRevoke, Disposition: ResponseDispositionCleanupComplete, Revision: 1,
		Revoke: &HelperRevokeResponseResult{CleanupProofID: "cleanup", AuthorityAbsent: true, ResourcesAbsent: true},
	}
}

func validExecResponse() HelperResponseBody {
	return HelperResponseBody{
		RequestType: PacketTypeExec, Disposition: ResponseDispositionAccepted, Revision: 1,
		Exec: &HelperExecResponseResult{
			ExitCode:   0,
			StdinBytes: 0, StdinSHA256: digestWithByte(1),
			StdoutBytes: 1, StdoutSHA256: digestWithByte(2),
			StderrBytes: 2, StderrSHA256: digestWithByte(3),
			ExecTransactionSHA256: digestWithByte(4),
		},
	}
}

func digestWithByte(value byte) [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}

func cloneHelperResponseForTest(value HelperResponseBody) HelperResponseBody {
	clone := value
	if value.Prepare != nil {
		prepare := *value.Prepare
		prepare.BindingProofs = append([]HelperBindingProof(nil), value.Prepare.BindingProofs...)
		clone.Prepare = &prepare
	}
	if value.Renew != nil {
		renew := *value.Renew
		clone.Renew = &renew
	}
	if value.Revoke != nil {
		revoke := *value.Revoke
		clone.Revoke = &revoke
	}
	if value.Exec != nil {
		exec := *value.Exec
		clone.Exec = &exec
	}
	return clone
}

func fillDigest(destination []byte, value byte) {
	for index := range destination {
		destination[index] = value
	}
}
