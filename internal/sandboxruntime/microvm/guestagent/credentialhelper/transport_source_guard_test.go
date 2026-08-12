package credentialhelper

import (
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
	assertFields(SendPacket{}, []string{"liveValue", "header", "arm", "right"})
}

func TestSendPacketEncodingWipeAndStreamBypassSourceGuards(t *testing.T) {
	source, err := os.ReadFile("transport_send.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Count(text, "defer wipeBytes(encoded[:cap(encoded)])") < 2 {
		t.Fatal("safe send encodings are not wiped after construction/hash and writing")
	}
	constructorStream := strings.Index(text, "if stream, ok := arm.(sendExecStreamArm); ok {")
	constructorEncode := strings.Index(text, "encoded, err := arm.encodeCanonical()")
	if constructorStream < 0 || constructorEncode < 0 || constructorStream > constructorEncode {
		t.Fatal("sensitive send stream does not bypass canonical encoding during construction")
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
		"defer wipeBytes(encoded[:cap(encoded)])",
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
	if method.Type.NumIn() != 2 || method.Type.In(1) != credentialSink {
		t.Errorf("WriteCanonicalBody input = %v, want exact credentialmemory.CredentialSink", method.Type)
	}
}
