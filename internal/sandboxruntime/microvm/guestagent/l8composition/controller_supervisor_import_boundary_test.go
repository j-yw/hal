package l8composition

import (
	"encoding"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestL8ControllerSupervisorExactPureImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	approved := "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	forbidden := map[string]bool{"net": true, "net/http": true, "os": true, "os/exec": true, "path/filepath": true, "syscall": true, "golang.org/x/sys/unix": true}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "controller_supervisor") || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if imported.Name != nil {
				t.Errorf("%s aliases import %q", entry.Name(), name)
			}
			if name == approved {
				continue
			}
			pkg, lookup := build.Default.Import(name, ".", build.FindOnly)
			if lookup != nil || !pkg.Goroot || forbidden[name] {
				t.Errorf("%s imports non-pure/live package %q", entry.Name(), name)
			}
		}
	}
}

func TestL8ControllerSupervisorHasNoLiveGenericDurableOrMutableGlobalSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "controller_supervisor") || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if typed.Name.Name == "init" {
					t.Errorf("%s declares init", entry.Name())
				}
			case *ast.GenDecl:
				if typed.Tok != token.VAR {
					continue
				}
				for _, spec := range typed.Specs {
					value := spec.(*ast.ValueSpec)
					for _, expression := range value.Values {
						call, ok := expression.(*ast.CallExpr)
						if !ok {
							t.Errorf("%s has mutable global", entry.Name())
							continue
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						if !ok {
							t.Errorf("%s globals must be stable errors", entry.Name())
							continue
						}
						identifier, idOK := selector.X.(*ast.Ident)
						if !idOK || identifier.Name != "errors" || selector.Sel.Name != "New" {
							t.Errorf("%s globals must be stable errors", entry.Name())
						}
					}
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.InterfaceType:
				t.Errorf("%s declares interface/any", entry.Name())
			case *ast.MapType:
				t.Errorf("%s declares forbidden map", entry.Name())
			case *ast.StructType:
				for _, field := range typed.Fields.List {
					if field.Tag != nil {
						t.Errorf("%s has struct tag", entry.Name())
					}
					for _, name := range field.Names {
						if name.IsExported() && (name.Name == "FD" || name.Name == "Body" || name.Name == "Raw" || name.Name == "Bytes" || name.Name == "Handle" || name.Name == "Ancillary") {
							t.Errorf("%s exposes generic/live field %s", entry.Name(), name)
						}
					}
				}
			}
			return true
		})
	}
}

func TestL8ControllerSupervisorOpaqueFormattingSerializationAndNoTags(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	values := []struct {
		value any
		name  string
	}{{ControllerSupervisorPacketTypeSupervisorReady, "ControllerSupervisorPacketType"}, {ControllerSupervisorDirectionPID1ToController, "ControllerSupervisorDirection"}, {ControllerSupervisorRightMonitorEndpoint, "ControllerSupervisorRightKind"}, {ControllerSupervisorAccessDuplexSeqpacket, "ControllerSupervisorRightAccess"}, {ControllerSupervisorReasonRequested, "ControllerSupervisorReason"}, {ControllerSupervisorEventShimExited, "ControllerSupervisorEventCode"}, {ControllerSupervisorFailureNone, "ControllerSupervisorFailureCode"}, {ControllerSupervisorExitExited, "ControllerSupervisorExitCategory"}, {ControllerSupervisorMonitorReady, "ControllerSupervisorMonitorState"}, {ControllerSupervisorCleanupComplete, "ControllerSupervisorCleanupCategory"}, {ControllerSupervisorHeader{}, "ControllerSupervisorHeader"}, {ControllerSupervisorKernelCredential{}, "ControllerSupervisorKernelCredential"}, {ControllerSupervisorRightMetadata{}, "ControllerSupervisorRightMetadata"}, {ControllerSupervisorReceiveMetadata{}, "ControllerSupervisorReceiveMetadata"}, {f.ready, "ControllerSupervisorSupervisorReadyBody"}, {f.create, "ControllerSupervisorCreateJobBody"}, {f.created, "ControllerSupervisorJobCreatedBody"}, {f.launch, "ControllerSupervisorLaunchShimBody"}, {f.started, "ControllerSupervisorShimStartedBody"}, {f.terminate, "ControllerSupervisorTerminateJobBody"}, {ControllerSupervisorDestroyJobBody(f.terminate), "ControllerSupervisorDestroyJobBody"}, {f.event, "ControllerSupervisorEventBody"}, {f.attestation, "ControllerSupervisorControllerAttestationBody"}, {f.accepted, "ControllerSupervisorCompositionAcceptedBody"}, {ControllerSupervisorCloseNotifyBody{}, "ControllerSupervisorCloseNotifyBody"}, {ControllerSupervisorPacket{}, "ControllerSupervisorPacket"}, {ControllerSupervisorTransitionContinue, "ControllerSupervisorTransitionDecision"}, {ControllerSupervisorExpected{}, "ControllerSupervisorExpected"}, {ControllerSupervisorShimExitObservation{}, "ControllerSupervisorShimExitObservation"}}
	for _, test := range values {
		want := strings.Repeat(test.name+"|", 4) + test.name
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", test.value, test.value, test.value, test.value, test.value); got != want {
			t.Errorf("%s format = %q", test.name, got)
		}
		pointer := reflect.New(reflect.TypeOf(test.value))
		pointer.Elem().Set(reflect.ValueOf(test.value))
		before := reflect.ValueOf(pointer.Elem().Interface())
		if data, err := json.Marshal(test.value); err == nil || data != nil {
			t.Errorf("%s json = %q/%v", test.name, data, err)
		}
		if data, err := test.value.(encoding.TextMarshaler).MarshalText(); err != ErrControllerSupervisorSerialization || data != nil {
			t.Errorf("%s text = %q/%v", test.name, data, err)
		}
		if data, err := test.value.(encoding.BinaryMarshaler).MarshalBinary(); err != ErrControllerSupervisorSerialization || data != nil {
			t.Errorf("%s binary = %q/%v", test.name, data, err)
		}
		if err := json.Unmarshal([]byte(`{"PID":999}`), pointer.Interface()); err == nil {
			t.Errorf("%s json unmarshal succeeded", test.name)
		}
		if err := pointer.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte("secret")); err != ErrControllerSupervisorSerialization {
			t.Errorf("%s text unmarshal = %v", test.name, err)
		}
		if err := pointer.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte{1}); err != ErrControllerSupervisorSerialization {
			t.Errorf("%s binary unmarshal = %v", test.name, err)
		}
		if !reflect.DeepEqual(pointer.Elem().Interface(), before.Interface()) {
			t.Errorf("%s unmarshal mutated receiver", test.name)
		}
	}
	for _, test := range values {
		typ := reflect.TypeOf(test.value)
		if typ.Kind() != reflect.Struct {
			continue
		}
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Tag != "" {
				t.Errorf("%s.%s tag = %q", typ.Name(), typ.Field(i).Name, typ.Field(i).Tag)
			}
		}
	}
}
