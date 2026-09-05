package credentialhelper

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
)

func TestTransportConcreteLayoutsArePrivateTaglessAndRawFieldFree(t *testing.T) {
	for _, name := range []string{"transport_types.go", "transport_accessors.go", "transport_receive.go", "transport_send.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			structure, ok := node.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structure.Fields.List {
				if field.Tag != nil {
					t.Errorf("%s has forbidden struct tag %s", name, field.Tag.Value)
				}
				for _, fieldName := range field.Names {
					if fieldName.IsExported() {
						t.Errorf("%s exposes field %s", name, fieldName.Name)
					}
				}
				switch field.Type.(type) {
				case *ast.ArrayType:
					array := field.Type.(*ast.ArrayType)
					if array.Len == nil {
						t.Errorf("%s stores forbidden slice field", name)
					}
				case *ast.MapType:
					t.Errorf("%s stores forbidden generic map field", name)
				}
			}
			return true
		})
		for _, forbidden := range []string{"net/", "os/exec", "syscall", "golang.org/x/sys", "recvmsg(", "sendmsg(", "json.RawMessage", "map[string]"} {
			if strings.Contains(string(source), forbidden) {
				t.Errorf("%s contains forbidden live/generic marker %q", name, forbidden)
			}
		}
	}
}

func TestTransportExactStructFieldOrder(t *testing.T) {
	assertFields := func(value any, want []string) {
		t.Helper()
		typeOf := reflect.TypeOf(value)
		got := make([]string, typeOf.NumField())
		for index := 0; index < typeOf.NumField(); index++ {
			got[index] = typeOf.Field(index).Name
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields = %v, want %v", typeOf, got, want)
		}
	}
	assertFields(ReceivedKernelCredential{}, []string{"liveValue", "pid", "uid", "gid"})
	assertFields(ReceiveRequest{}, []string{"liveValue", "nextSequence", "maximumBodyBytes", "expectedRights", "state"})
	assertFields(ReceivedPacket{}, []string{"liveValue", "header", "arm", "credential", "body", "right"})
	assertFields(ReceivedPrepareBegin{}, []string{"liveValue", "revision", "expiryUnixNano", "manifest", "transaction"})
	assertFields(ReceivedExec{}, []string{"liveValue", "revision", "execBindingID", "privateLength", "privateSHA256", "plan", "transactionSeed"})
	assertFields(SendPacket{}, []string{"liveValue", "header", "arm", "right"})
}

func TestSendPacketEncodingWipeAndStreamBypassSourceGuards(t *testing.T) {
	source, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Count(text, "defer wipeBytes(encoded[:cap(encoded)])") != 1 {
		t.Fatal("shared safe send scratch primitive must wipe through full capacity")
	}
	constructorStream := strings.Index(text, "if stream, ok := arm.(sendExecStreamArm); ok {")
	constructorScratch := strings.Index(text, "withCanonicalScratch(arm, length")
	if constructorStream < 0 || constructorScratch < 0 || constructorStream > constructorScratch {
		t.Fatal("sensitive send stream does not bypass canonical encoding during construction")
	}
	if strings.Count(text, "make([]byte, int(length))") != 1 || strings.Count(text, "withCanonicalScratch(") != 3 {
		t.Fatal("safe send constructor/write must share one exact-length scratch primitive")
	}
	for _, forbidden := range []string{
		"credentialprotocol.EncodeHelperResponseBody(",
		"credentialprotocol.EncodeHelperEventBody(",
		"credentialprotocol.EncodeHelperExecCreditBody(",
		"credentialprotocol.EncodeHelperCloseNotifyBody(",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("credentialhelper duplicates/uses allocating safe codec %q", forbidden)
		}
	}
}

func TestSendPacketApprovedScratchSnapshotAndOneShotSourceContract(t *testing.T) {
	source, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"cloneHelperResponseBody",
		"bodySHA256",
		"atomic.Bool",
		"CompareAndSwap(false, true)",
		"exactForwardingSink",
		"forward.snapshot()",
		"defer wipeBytes(encoded[:cap(encoded)])",
		"encodeCanonicalTo(encoded)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("send path omits approved scratch/snapshot/one-shot marker %q", required)
		}
	}
	if strings.Contains(text, "LockedFillTarget") {
		t.Error("send path invents rejected locked-fill API expansion")
	}

	method, ok := reflect.TypeOf(SendPacket{}).MethodByName("WriteCanonicalBody")
	if !ok {
		t.Fatal("SendPacket omits WriteCanonicalBody")
	}
	credentialSink := reflect.TypeOf((*credentialmemory.CredentialSink)(nil)).Elem()
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	if method.Type.NumIn() != 3 || method.Type.In(1) != contextType || method.Type.In(2) != credentialSink {
		t.Errorf("WriteCanonicalBody input = %v, want exact context.Context, credentialmemory.CredentialSink", method.Type)
	}
}

func TestTransportContextOwnershipSourceContract(t *testing.T) {
	for _, name := range []string{"transport_receive.go", "transport_send.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{"context.Background()", "context.TODO()"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s retains forbidden ownership context %q", name, forbidden)
			}
		}
	}

	source, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "transport_receive.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"newReceivedPacket":          false,
		"NewReceivedBootstrapPacket": false, "NewReceivedAgentHelloPacket": false,
		"NewReceivedPrepareBeginPacket": false, "NewReceivedPrepareFilePacket": false,
		"NewReceivedPrepareCommitPacket": false, "NewReceivedRenewPacket": false,
		"NewReceivedRevokePacket": false, "NewReceivedExecPacket": false,
		"NewReceivedExecPrivatePacket": false, "NewReceivedExecStreamPacket": false,
		"NewReceivedExecCreditPacket": false, "NewReceivedCloseNotifyPacket": false,
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, tracked := want[function.Name.Name]; !tracked || len(function.Type.Params.List) == 0 {
			continue
		}
		selector, ok := function.Type.Params.List[0].Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == "context" && selector.Sel.Name == "Context" {
			want[function.Name.Name] = true
		}
	}
	for name, valid := range want {
		if !valid {
			t.Errorf("%s must take leading context.Context", name)
		}
	}

	source, err = os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err = parser.ParseFile(token.NewFileSet(), "transport_send.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantSend := map[string]bool{
		"newSendPacket": false, "newHelperReadyPacket": false, "newBootstrapAckPacket": false,
		"newAgentHelloAckPacket": false, "newSSHAcceptedPacket": false, "newExecCreditPacket": false,
		"newExecStreamPacket": false, "newResponsePacket": false, "newEventPacket": false,
		"newCloseNotifyPacket": false,
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, tracked := wantSend[function.Name.Name]; !tracked || len(function.Type.Params.List) == 0 {
			continue
		}
		selector, ok := function.Type.Params.List[0].Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == "context" && selector.Sel.Name == "Context" {
			wantSend[function.Name.Name] = true
		}
	}
	for name, valid := range wantSend {
		if !valid {
			t.Errorf("%s must take leading context.Context", name)
		}
	}
}

func TestTransportContextPreconditionsUseSharedTypedNilSafeHelper(t *testing.T) {
	for _, name := range []string{"transport_receive.go", "transport_send.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		if strings.Contains(text, "ctx == nil") {
			t.Errorf("%s retains a direct context nil check outside the shared precondition", name)
		}
		if !strings.Contains(text, "transportContextPrecondition(ctx)") {
			t.Errorf("%s omits shared typed-nil-safe context precondition", name)
		}
	}
}

func TestReceivedExecPublicMethodSetIsExact(t *testing.T) {
	typeOf := reflect.TypeOf(ReceivedExec{})
	got := make([]string, typeOf.NumMethod())
	for index := range got {
		got[index] = typeOf.Method(index).Name
	}
	want := []string{"ExecBindingID", "Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "Plan", "PrivateBindingLength", "PrivateBindingSHA256", "Revision", "String"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReceivedExec public methods = %v, want %v", got, want)
	}
}

func TestTransportValidationStateIsSynchronizedAndSticky(t *testing.T) {
	receive, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"type bodyValidationSink struct {\n\tmu",
		"type callbackValidationState struct {\n\tmu",
		"sink.writes != 1",
		"state.calls != 1 || err != nil",
		"sink.snapshot()",
		"callbacks.snapshot()",
	} {
		if !strings.Contains(string(receive), required) {
			t.Errorf("receive validator omits synchronized sticky marker %q", required)
		}
	}
	const receiveBorrowCallbackPrefix = "body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {\n\t\tvar callbackErr error\n\t\tif ctx.Err() != nil {"
	if strings.Count(string(receive), receiveBorrowCallbackPrefix) != 1 {
		t.Error("receive validation Borrow callback does not check cancellation before configured/view access")
	}
	send, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"type exactForwardingSink struct {\n\tmu",
		"sink.calls != 1 || len(value) != sink.expected",
		"forward.snapshot()",
		"writes != 1 || !writeValid",
	} {
		if !strings.Contains(string(send), required) {
			t.Errorf("send validator omits synchronized sticky marker %q", required)
		}
	}
	const sendWriteBorrowCallbackPrefix = "Borrow(ctx, func(view credentialmemory.BorrowedView) error {\n\t\t\tvar callbackErr error\n\t\t\tif ctx.Err() != nil {"
	const sendConstructBorrowCallbackPrefix = "Borrow(ctx, func(view credentialmemory.BorrowedView) error {\n\t\tvar callbackErr error\n\t\tif ctx.Err() != nil {"
	if strings.Count(string(send), sendWriteBorrowCallbackPrefix) != 1 || strings.Count(string(send), sendConstructBorrowCallbackPrefix) != 1 {
		t.Error("send construction/write Borrow callbacks do not check cancellation before configured/view access")
	}
}

func TestTransportCancellationOwnershipSourceContract(t *testing.T) {
	for _, name := range []string{"transport_receive.go", "transport_send.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		if !strings.Contains(text, "ctx.Err() != nil") || !strings.Contains(text, "ErrContractOwnership") {
			t.Errorf("%s omits sanitized cancellation ownership checks", name)
		}
		for _, forbidden := range []string{"return ctx.Err()", "%w", "context.Canceled", "context.DeadlineExceeded"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s exposes forbidden cancellation detail %q", name, forbidden)
			}
		}
	}

	receive, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"type payloadSlicingSink struct {\n\tctx",
		"func (body receivedPayloadBody) Borrow(ctx context.Context",
		"func (view borrowedPayloadView) WriteTo(ctx context.Context",
		"err := view.owner.WriteTo(ctx, &payloadSlicingSink{ctx: ctx",
		"err := sink.sink.WriteCredential(value[sink.offset : sink.offset+sink.length])",
		"func destroyTransportBody(ctx context.Context",
		"func closeTransportRight(ctx context.Context",
		"return destroyTransportBody(ctx, body.owner)",
	} {
		if !strings.Contains(string(receive), required) {
			t.Errorf("receive path omits retained cancellation/cleanup marker %q", required)
		}
	}

	send, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"destroyTransportBody(ctx, stream.body)",
		"closeTransportRight(ctx, right)",
		"return destroyTransportBody(ctx, stream.body)",
	} {
		if !strings.Contains(string(send), required) {
			t.Errorf("send path omits cancellation-safe cleanup marker %q", required)
		}
	}
}

func TestTransportCleanupPanicIsolationSourceContract(t *testing.T) {
	receive, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(receive)
	for _, required := range []string{
		"if recover() != nil || canceled || ctx.Err() != nil",
		"if cleanupErr := destroyTransportBody(ctx, body); cleanupErr != nil",
		"if cleanupErr := closeTransportRight(ctx, right); cleanupErr != nil",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("receive cleanup omits panic-isolation marker %q", required)
		}
	}

	tests, err := os.ReadFile("transport_values_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"TestRetainedPayloadCancellationStopsBeforeNextExternalCall",
		"TestTransportDestroyWrappersApplyContextAndCancellationMatrix",
		"TestTransportConstructorCleanupPanicsDoNotSkipOtherOwners",
	} {
		if !strings.Contains(string(tests), required) {
			t.Errorf("transport tests omit adversarial cleanup marker %q", required)
		}
	}
}

func TestTransportDirectionAndBootSequenceSourceContract(t *testing.T) {
	receive, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	send, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"streamKind != credentialprotocol.HelperExecStreamStdin",
		"decoded.StreamKind != credentialprotocol.HelperExecStreamStdout && decoded.StreamKind != credentialprotocol.HelperExecStreamStderr",
	} {
		if !strings.Contains(string(receive), required) {
			t.Errorf("receive direction source omits %q", required)
		}
	}
	for _, required := range []string{
		"body.StreamKind != credentialprotocol.HelperExecStreamStdin",
		"arm.streamKind != credentialprotocol.HelperExecStreamStdout && arm.streamKind != credentialprotocol.HelperExecStreamStderr",
		"sshAccepted.connectionOrdinal > credentialprotocol.SSHAgentRelayMaxLifetimeConnections",
		"header.Sequence != 0",
		"header.Sequence != 1",
		"header.Sequence != 2",
	} {
		if !strings.Contains(string(send), required) {
			t.Errorf("send direction/sequence source omits %q", required)
		}
	}
}

func TestTransportExecObservationUsesIndependentObservedDigestSourceContract(t *testing.T) {
	receive, err := os.ReadFile("transport_receive.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(receive)
	for _, forbidden := range []string{
		"NewHelperExecPrivateObservation(revision, privateBindingLength, privateBindingSHA256, privateBindingSHA256)",
		"NewHelperExecStreamObservation(revision, streamKind, flags, offset, payloadLength, payloadSHA256, payloadSHA256)",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("transport observation self-compares declared digest via %q", forbidden)
		}
	}
	for _, required := range []string{
		"observedPrivate.store(sha256.Sum256(encoded[44:]))",
		"observedPrivateSHA256 := observedPrivate.load()",
		"credentialprotocol.NewHelperExecPrivateObservation(revision, privateBindingLength, privateBindingSHA256, observedPrivateSHA256)",
		"observedPayload.store(sha256.Sum256(encoded[56:]))",
		"observedPayloadSHA256 := observedPayload.load()",
		"credentialprotocol.NewHelperExecStreamObservation(revision, streamKind, flags, offset, payloadLength, payloadSHA256, observedPayloadSHA256)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("transport observation omits independently observed digest marker %q", required)
		}
	}
}
