package credentialprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

var helperSafeEncodedSink []byte

func TestHelperSafeSendBodyWritersAreAllocationFreeAndCanonical(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	responses := helperSafeSendResponseBodies(digest)
	for index, response := range responses {
		canonical, err := EncodeHelperResponseBody(response)
		if err != nil {
			t.Fatal(err)
		}
		assertAllocationFreeSafeWriter(t, "response", canonical,
			func() (uint32, error) { return HelperResponseBodyEncodedLength(response) },
			func(dst []byte) error { return EncodeHelperResponseBodyTo(dst, response) },
		)
		response.RequestType = PacketTypeCloseNotify
		if !bytes.Equal(canonical, mustEncodeSafeResponse(t, responses[index])) {
			t.Fatal("writer retained response source alias")
		}
	}

	event := HelperEventBody{Code: EventCodeExpired, Revision: 3, EventID: "event-1"}
	eventCanonical, err := EncodeHelperEventBody(event)
	if err != nil {
		t.Fatal(err)
	}
	assertAllocationFreeSafeWriter(t, "event", eventCanonical,
		func() (uint32, error) { return HelperEventBodyEncodedLength(event) },
		func(dst []byte) error { return EncodeHelperEventBodyTo(dst, event) },
	)

	credit := HelperExecCreditBody{Revision: 4, StreamKind: HelperExecStreamStdin, NextOffset: 5}
	creditCanonical, err := EncodeHelperExecCreditBody(credit)
	if err != nil {
		t.Fatal(err)
	}
	assertAllocationFreeSafeWriter(t, "exec credit", creditCanonical,
		func() (uint32, error) { return HelperExecCreditBodyEncodedLength(credit) },
		func(dst []byte) error { return EncodeHelperExecCreditBodyTo(dst, credit) },
	)

	closeBody := HelperCloseNotifyBody{Reason: CloseReasonNormal}
	closeCanonical, err := EncodeHelperCloseNotifyBody(closeBody)
	if err != nil {
		t.Fatal(err)
	}
	assertAllocationFreeSafeWriter(t, "close", closeCanonical,
		func() (uint32, error) { return HelperCloseNotifyBodyEncodedLength(closeBody) },
		func(dst []byte) error { return EncodeHelperCloseNotifyBodyTo(dst, closeBody) },
	)

	fixed := []struct {
		name   string
		length uint32
		want   []byte
		write  func([]byte) error
	}{
		{name: "helper ready", length: HelperReadyBodyEncodedLength(), want: []byte{}, write: EncodeHelperReadyBodyTo},
		{name: "bootstrap ack", length: HelperBootstrapAckBodyEncodedLength(), want: append([]byte(nil), digest[:]...), write: func(dst []byte) error { return EncodeHelperBootstrapAckBodyTo(dst, digest) }},
		{name: "agent hello ack", length: HelperAgentHelloAckBodyEncodedLength(), want: append([]byte(nil), digest[:]...), write: func(dst []byte) error { return EncodeHelperAgentHelloAckBodyTo(dst, digest) }},
		{name: "ssh accepted", length: HelperSSHAcceptedFDBodyEncodedLength(), want: helperSafeSSHAcceptedVector(digest), write: func(dst []byte) error { return EncodeHelperSSHAcceptedFDBodyTo(dst, 7, 2, 1, digest) }},
	}
	for _, tc := range fixed {
		assertAllocationFreeSafeWriter(t, tc.name, tc.want,
			func() (uint32, error) { return tc.length, nil }, tc.write)
	}
}

func TestHelperSafeSendBodyWritersRequireExactDestination(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	response := helperSafeSendResponseBodies(digest)[0]
	responseLength, err := HelperResponseBodyEncodedLength(response)
	if err != nil {
		t.Fatal(err)
	}
	event := HelperEventBody{Code: EventCodeExpired, Revision: 3, EventID: "event-1"}
	eventLength, err := HelperEventBodyEncodedLength(event)
	if err != nil {
		t.Fatal(err)
	}
	credit := HelperExecCreditBody{Revision: 4, StreamKind: HelperExecStreamStdin, NextOffset: 5}
	creditLength, err := HelperExecCreditBodyEncodedLength(credit)
	if err != nil {
		t.Fatal(err)
	}
	closeBody := HelperCloseNotifyBody{Reason: CloseReasonNormal}
	closeLength, err := HelperCloseNotifyBodyEncodedLength(closeBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		length uint32
		write  func([]byte) error
	}{
		{name: "helper ready", length: HelperReadyBodyEncodedLength(), write: EncodeHelperReadyBodyTo},
		{name: "bootstrap ack", length: HelperBootstrapAckBodyEncodedLength(), write: func(dst []byte) error { return EncodeHelperBootstrapAckBodyTo(dst, digest) }},
		{name: "agent hello ack", length: HelperAgentHelloAckBodyEncodedLength(), write: func(dst []byte) error { return EncodeHelperAgentHelloAckBodyTo(dst, digest) }},
		{name: "ssh accepted", length: HelperSSHAcceptedFDBodyEncodedLength(), write: func(dst []byte) error { return EncodeHelperSSHAcceptedFDBodyTo(dst, 7, 2, 1, digest) }},
		{name: "exec credit", length: creditLength, write: func(dst []byte) error { return EncodeHelperExecCreditBodyTo(dst, credit) }},
		{name: "response", length: responseLength, write: func(dst []byte) error { return EncodeHelperResponseBodyTo(dst, response) }},
		{name: "event", length: eventLength, write: func(dst []byte) error { return EncodeHelperEventBodyTo(dst, event) }},
		{name: "close", length: closeLength, write: func(dst []byte) error { return EncodeHelperCloseNotifyBodyTo(dst, closeBody) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length > 0 {
				short := bytes.Repeat([]byte{0xa5}, int(tc.length)-1)
				if err := tc.write(short); err == nil || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
					t.Fatalf("short destination = %x, %v", short, err)
				}
			}
			long := bytes.Repeat([]byte{0xa5}, int(tc.length)+1)
			if err := tc.write(long); err == nil || !bytes.Equal(long, bytes.Repeat([]byte{0xa5}, len(long))) {
				t.Fatalf("long destination = %x, %v", long, err)
			}
		})
	}
}

func TestHelperSafeSendBodyWritersDoNotTouchDestinationOnInvalidValue(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	invalidResponse := helperSafeSendResponseBodies(digest)[0]
	invalidResponse.Prepare.ActiveProofID = "not/a/token"
	for _, tc := range []struct {
		name  string
		size  int
		write func([]byte) error
	}{
		{name: "bootstrap ack", size: int(HelperBootstrapAckBodyEncodedLength()), write: func(dst []byte) error { return EncodeHelperBootstrapAckBodyTo(dst, [32]byte{}) }},
		{name: "agent hello ack", size: int(HelperAgentHelloAckBodyEncodedLength()), write: func(dst []byte) error { return EncodeHelperAgentHelloAckBodyTo(dst, [32]byte{}) }},
		{name: "ssh accepted", size: int(HelperSSHAcceptedFDBodyEncodedLength()), write: func(dst []byte) error { return EncodeHelperSSHAcceptedFDBodyTo(dst, 0, 0, 0, [32]byte{}) }},
		{name: "exec credit", size: HelperExecCreditBodyBytes, write: func(dst []byte) error { return EncodeHelperExecCreditBodyTo(dst, HelperExecCreditBody{}) }},
		{name: "response", size: 128, write: func(dst []byte) error { return EncodeHelperResponseBodyTo(dst, invalidResponse) }},
		{name: "event", size: 32, write: func(dst []byte) error { return EncodeHelperEventBodyTo(dst, HelperEventBody{}) }},
		{name: "close", size: 1, write: func(dst []byte) error { return EncodeHelperCloseNotifyBodyTo(dst, HelperCloseNotifyBody{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := bytes.Repeat([]byte{0xa5}, tc.size)
			if err := tc.write(dst); err == nil {
				t.Fatal("invalid value accepted")
			}
			if !bytes.Equal(dst, bytes.Repeat([]byte{0xa5}, len(dst))) {
				t.Fatalf("invalid value modified destination = %x", dst)
			}
		})
	}
}

func TestHelperSSHAcceptedFDWriterConnectionOrdinalBounds(t *testing.T) {
	digest := sha256.Sum256([]byte("relay capability"))
	for _, tc := range []struct {
		name    string
		ordinal uint8
		wantErr bool
	}{
		{name: "maximum", ordinal: 64},
		{name: "maximum plus one", ordinal: 65, wantErr: true},
		{name: "uint8 maximum", ordinal: 255, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := bytes.Repeat([]byte{0xa5}, int(HelperSSHAcceptedFDBodyEncodedLength()))
			err := EncodeHelperSSHAcceptedFDBodyTo(dst, 1, 0, tc.ordinal, digest)
			if tc.wantErr {
				if !errors.Is(err, ErrHelperSafeSendBodyValue) {
					t.Fatalf("ordinal %d error = %v, want ErrHelperSafeSendBodyValue", tc.ordinal, err)
				}
				if !bytes.Equal(dst, bytes.Repeat([]byte{0xa5}, len(dst))) {
					t.Fatalf("invalid ordinal %d modified destination = %x", tc.ordinal, dst)
				}
				return
			}
			if err != nil {
				t.Fatalf("ordinal %d rejected: %v", tc.ordinal, err)
			}
			if dst[10] != tc.ordinal {
				t.Fatalf("encoded ordinal = %d, want %d", dst[10], tc.ordinal)
			}
		})
	}
}

func TestHelperSafeSendBodyWriterSourceHasNoTransientBuffers(t *testing.T) {
	for _, name := range []string{"helper_safe_send_body.go", "helper_response_body.go", "helper_lifecycle_body.go", "helper_exec_body.go", "helper_primitives.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "bytes.Buffer") {
			t.Errorf("%s contains growable bytes.Buffer", name)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !strings.HasSuffix(function.Name.Name, "BodyTo") && function.Name.Name != "putBodyToken" {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				identifier, ok := call.Fun.(*ast.Ident)
				if ok && (identifier.Name == "make" || identifier.Name == "append" || identifier.Name == "EncodeBodyToken") {
					t.Errorf("%s %s uses transient/growable call %s", name, function.Name.Name, identifier.Name)
				}
				return true
			})
		}
	}
}

func TestHelperSSHAcceptedFDWriterSourcePinsOrdinalLimit(t *testing.T) {
	source, err := os.ReadFile("helper_safe_send_body.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "connectionOrdinal > SSHAgentRelayMaxLifetimeConnections") {
		t.Fatal("SSH accepted writer does not pin the relay lifetime ordinal limit")
	}
}

func TestHelperSafeSendBodyCodecImportBoundary(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "helper_safe_send_body.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"encoding/binary": true, "errors": true}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Name != nil || !want[path] {
			t.Errorf("safe send body codec imports forbidden dependency %q", path)
		}
		delete(want, path)
	}
	for missing := range want {
		t.Errorf("safe send body codec omits exact dependency %q", missing)
	}
}

func TestHelperSafeSendAllocatingWrappersUseOneExactAllocation(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	response := helperSafeSendResponseBodies(digest)[0]
	event := HelperEventBody{Code: EventCodeExpired, Revision: 3, EventID: "event-1"}
	credit := HelperExecCreditBody{Revision: 4, StreamKind: HelperExecStreamStdin, NextOffset: 5}
	closeBody := HelperCloseNotifyBody{Reason: CloseReasonNormal}
	for _, tc := range []struct {
		name   string
		encode func() ([]byte, error)
	}{
		{name: "response", encode: func() ([]byte, error) { return EncodeHelperResponseBody(response) }},
		{name: "event", encode: func() ([]byte, error) { return EncodeHelperEventBody(event) }},
		{name: "exec credit", encode: func() ([]byte, error) { return EncodeHelperExecCreditBody(credit) }},
		{name: "close", encode: func() ([]byte, error) { return EncodeHelperCloseNotifyBody(closeBody) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(100, func() {
				var err error
				helperSafeEncodedSink, err = tc.encode()
				if err != nil {
					panic(err)
				}
			})
			if allocs != 1 {
				t.Fatalf("allocating wrapper allocations = %v, want exactly one body allocation", allocs)
			}
		})
	}
	helperSafeEncodedSink = nil
}

func TestHelperSafeSendAllocatingWrappersClearImpossibleWriterFailure(t *testing.T) {
	for _, name := range []string{"helper_response_body.go", "helper_lifecycle_body.go", "helper_exec_body.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !strings.HasPrefix(function.Name.Name, "EncodeHelper") || strings.HasSuffix(function.Name.Name, "BodyTo") {
				continue
			}
			bodySource := string(source[function.Body.Pos()-file.Pos() : function.Body.End()-file.Pos()])
			if strings.Contains(bodySource, "make([]byte, length)") && !strings.Contains(bodySource, "clear(encoded)") {
				t.Errorf("%s %s does not clear an abandoned exact allocation", name, function.Name.Name)
			}
		}
	}
}

func assertAllocationFreeSafeWriter(t *testing.T, name string, want []byte, length func() (uint32, error), write func([]byte) error) {
	t.Helper()
	gotLength, err := length()
	if err != nil || gotLength != uint32(len(want)) {
		t.Fatalf("%s length = %d, %v, want %d", name, gotLength, err, len(want))
	}
	dst := make([]byte, len(want))
	if err := write(dst); err != nil || !bytes.Equal(dst, want) {
		t.Fatalf("%s encoding = %x, %v, want %x", name, dst, err, want)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if _, lengthErr := length(); lengthErr != nil {
			panic(lengthErr)
		}
		if writeErr := write(dst); writeErr != nil {
			panic(writeErr)
		}
	})
	if allocs != 0 {
		t.Fatalf("%s writer allocations = %v, want 0", name, allocs)
	}
}

func helperSafeSendResponseBodies(digest [32]byte) []HelperResponseBody {
	return []HelperResponseBody{
		{RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionAccepted, Revision: 1, Prepare: &HelperPrepareResponseResult{ExpiresAtUnixNano: 2, ActiveProofID: "active", ExecBindingID: "exec", BindingProofs: []HelperBindingProof{{BindingID: "binding-1", Mode: DeliveryModeHTTPProxy, ProofID: "proof-1"}, {BindingID: "binding-2", Mode: DeliveryModeFileTmpfs, ProofID: "proof-2"}}}},
		{RequestType: PacketTypeRenew, Disposition: ResponseDispositionAccepted, Revision: 1, Renew: &HelperRenewResponseResult{ExpiresAtUnixNano: 2, ReplacementActiveProofID: "replacement"}},
		{RequestType: PacketTypeRevoke, Disposition: ResponseDispositionCleanupComplete, Revision: 1, Revoke: &HelperRevokeResponseResult{CleanupProofID: "cleanup", AuthorityAbsent: true, ResourcesAbsent: true}},
		{RequestType: PacketTypeExec, Disposition: ResponseDispositionAccepted, Revision: 1, Exec: &HelperExecResponseResult{ExitCode: 1, StdinBytes: 1, StdinSHA256: digest, StdoutBytes: 2, StdoutSHA256: digest, StdoutTruncated: true, StderrBytes: 3, StderrSHA256: digest, ExecTransactionSHA256: digest}},
		{RequestType: PacketTypePrepareCommit, Disposition: ResponseDispositionRejected, Revision: 1, FailureCode: FailureCodePrepareFailed},
	}
}

func mustEncodeSafeResponse(t *testing.T, body HelperResponseBody) []byte {
	t.Helper()
	encoded, err := EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func helperSafeSSHAcceptedVector(digest [32]byte) []byte {
	encoded := make([]byte, 43)
	binary.BigEndian.PutUint64(encoded[:8], 7)
	binary.BigEndian.PutUint16(encoded[8:10], 2)
	encoded[10] = 1
	copy(encoded[11:], digest[:])
	return encoded
}
