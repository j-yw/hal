package l8composition

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestAgentSupervisorExactPureImportBoundary(t *testing.T) {
	t.Parallel()

	const source = "agent_supervisor.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	allowed := []string{
		"bytes",
		"crypto/sha256",
		"encoding/binary",
		"errors",
		"fmt",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
	}
	if len(file.Imports) != len(allowed) {
		t.Fatalf("imports = %d, want exact %d", len(file.Imports), len(allowed))
	}
	for index, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if imported.Name != nil || path != allowed[index] {
			t.Errorf("import %d = %q, want exact %q without alias", index, path, allowed[index])
		}
	}
}

func TestAgentSupervisorHasNoLiveGenericDurableOrMutableGlobalSurface(t *testing.T) {
	t.Parallel()

	const source = "agent_supervisor.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "init" {
				t.Error("agent-supervisor codec declares init")
			}
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("agent-supervisor codec declares generic function %s", typed.Name)
			}
		case *ast.GenDecl:
			if typed.Tok == token.TYPE {
				for _, specification := range typed.Specs {
					typeSpecification := specification.(*ast.TypeSpec)
					if typeSpecification.TypeParams != nil && len(typeSpecification.TypeParams.List) != 0 {
						t.Errorf("agent-supervisor codec declares generic type %s", typeSpecification.Name)
					}
				}
			}
			if typed.Tok == token.VAR {
				for _, specification := range typed.Specs {
					valueSpecification := specification.(*ast.ValueSpec)
					for _, value := range valueSpecification.Values {
						call, ok := value.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							t.Error("agent-supervisor codec has mutable package-global state")
							continue
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						packageName, packageOK := selector.X.(*ast.Ident)
						if !ok || !packageOK || packageName.Name != "errors" || selector.Sel.Name != "New" {
							t.Error("agent-supervisor globals must be stable errors only")
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Errorf("agent-supervisor codec declares map at %d", typed.Pos())
		case *ast.InterfaceType:
			t.Errorf("agent-supervisor codec declares interface/any at %d", typed.Pos())
		case *ast.StructType:
			for _, field := range typed.Fields.List {
				if field.Tag != nil {
					t.Errorf("agent-supervisor struct field has tag %s", field.Tag.Value)
				}
				for _, name := range field.Names {
					if name.IsExported() && (name.Name == "Body" || name.Name == "Raw" || name.Name == "Bytes" || name.Name == "FD") {
						t.Errorf("agent-supervisor exposes generic/live field %s", name.Name)
					}
				}
			}
		}
		return true
	})
}

func TestAgentSupervisorOpaqueFormattingAndSerialization(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	state := newAgentSupervisorState(t, fixture)
	values := []struct {
		value any
		name  string
	}{
		{AgentSupervisorHeader{}, "AgentSupervisorHeader"},
		{fixture.config, "AgentSupervisorAgentConfigBody"},
		{AgentSupervisorClientAttestationBody{Descriptor: fixture.client}, "AgentSupervisorClientAttestationBody"},
		{AgentSupervisorCompositionAcceptedBody{CompositionSHA256: fixture.composition}, "AgentSupervisorCompositionAcceptedBody"},
		{AgentSupervisorCloseNotifyBody{}, "AgentSupervisorCloseNotifyBody"},
		{AgentSupervisorPacket{}, "AgentSupervisorPacket"},
		{fixture.pid1, "AgentSupervisorKernelCredential"},
		{fixture.pid1Metadata(), "AgentSupervisorReceiveMetadata"},
		{AgentSupervisorPreAdmissionExpected{}, "AgentSupervisorPreAdmissionExpected"},
		{*state, "AgentSupervisorPreAdmissionState"},
	}
	for _, test := range values {
		wantFormat := strings.Repeat(test.name+"|", 4) + test.name
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", test.value, test.value, test.value, test.value, test.value); got != wantFormat {
			t.Errorf("%s formatting = %q", test.name, got)
		}
		pointer := reflect.New(reflect.TypeOf(test.value))
		if reflect.TypeOf(test.value).Kind() == reflect.Pointer {
			pointer = reflect.ValueOf(test.value)
		} else {
			pointer.Elem().Set(reflect.ValueOf(test.value))
		}
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", pointer.Interface(), pointer.Interface(), pointer.Interface(), pointer.Interface(), pointer.Interface()); got != wantFormat {
			t.Errorf("%s pointer formatting = %q", test.name, got)
		}
		if encoded, err := json.Marshal(test.value); err == nil || encoded != nil || !strings.Contains(err.Error(), ErrAgentSupervisorSerialization.Error()) {
			t.Errorf("%s JSON = %q/%v", test.name, encoded, err)
		}
		textMarshaler, ok := test.value.(encoding.TextMarshaler)
		if !ok {
			t.Errorf("%s lacks encoding.TextMarshaler", test.name)
		} else if encoded, err := textMarshaler.MarshalText(); err != ErrAgentSupervisorSerialization || encoded != nil {
			t.Errorf("%s text = %q/%v", test.name, encoded, err)
		}
		binaryMarshaler, ok := test.value.(encoding.BinaryMarshaler)
		if !ok {
			t.Errorf("%s lacks encoding.BinaryMarshaler", test.name)
		} else if encoded, err := binaryMarshaler.MarshalBinary(); err != ErrAgentSupervisorSerialization || encoded != nil {
			t.Errorf("%s binary = %q/%v", test.name, encoded, err)
		}

		before := fmt.Sprintf("%#v", pointer.Interface())
		if err := json.Unmarshal([]byte(`{"PID":999,"ControllerPID":999,"BodyLength":999}`), pointer.Interface()); err == nil || !strings.Contains(err.Error(), ErrAgentSupervisorSerialization.Error()) {
			t.Errorf("%s JSON unmarshal error = %v", test.name, err)
		}
		if unmarshaler, ok := pointer.Interface().(encoding.TextUnmarshaler); !ok {
			t.Errorf("%s lacks encoding.TextUnmarshaler", test.name)
		} else if err := unmarshaler.UnmarshalText([]byte("seeded-sensitive-value")); err != ErrAgentSupervisorSerialization {
			t.Errorf("%s text unmarshal error = %v", test.name, err)
		}
		if unmarshaler, ok := pointer.Interface().(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s lacks encoding.BinaryUnmarshaler", test.name)
		} else if err := unmarshaler.UnmarshalBinary([]byte{1, 2, 3}); err != ErrAgentSupervisorSerialization {
			t.Errorf("%s binary unmarshal error = %v", test.name, err)
		}
		if after := fmt.Sprintf("%#v", pointer.Interface()); after != before {
			t.Errorf("%s unmarshal mutated value: %q != %q", test.name, after, before)
		}
		typeOf := reflect.TypeOf(test.value)
		if typeOf.Kind() == reflect.Pointer {
			typeOf = typeOf.Elem()
		}
		for index := 0; index < typeOf.NumField(); index++ {
			if tag := typeOf.Field(index).Tag; tag != "" {
				t.Errorf("%s.%s tag = %q", test.name, typeOf.Field(index).Name, tag)
			}
		}
	}
}

func TestAgentSupervisorEnumOpacity(t *testing.T) {
	t.Parallel()

	values := []struct {
		value any
		name  string
	}{
		{AgentSupervisorPacketTypeAgentConfig, "AgentSupervisorPacketType"},
		{AgentSupervisorDirectionPID1ToAgent, "AgentSupervisorDirection"},
		{AgentSupervisorDecisionContinue, "AgentSupervisorDecision"},
	}
	for _, test := range values {
		wantFormat := strings.Repeat(test.name+"|", 4) + test.name
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", test.value, test.value, test.value, test.value, test.value); got != wantFormat {
			t.Errorf("%s formatting = %q", test.name, got)
		}
		if encoded, err := json.Marshal(test.value); err == nil || encoded != nil {
			t.Errorf("%s JSON = %q/%v", test.name, encoded, err)
		}
		pointer := reflect.New(reflect.TypeOf(test.value))
		pointer.Elem().Set(reflect.ValueOf(test.value))
		if got := fmt.Sprintf("%v|%+v|%#v|%s|%q", pointer.Interface(), pointer.Interface(), pointer.Interface(), pointer.Interface(), pointer.Interface()); got != wantFormat {
			t.Errorf("%s pointer formatting = %q", test.name, got)
		}
		before := append([]byte(nil), []byte(fmt.Sprintf("%#v", pointer.Interface()))...)
		if err := json.Unmarshal([]byte("99"), pointer.Interface()); err == nil {
			t.Errorf("%s JSON unmarshal succeeded", test.name)
		}
		if marshaler, ok := test.value.(encoding.TextMarshaler); !ok {
			t.Errorf("%s lacks encoding.TextMarshaler", test.name)
		} else if encoded, err := marshaler.MarshalText(); err != ErrAgentSupervisorSerialization || encoded != nil {
			t.Errorf("%s text = %q/%v", test.name, encoded, err)
		}
		if marshaler, ok := test.value.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%s lacks encoding.BinaryMarshaler", test.name)
		} else if encoded, err := marshaler.MarshalBinary(); err != ErrAgentSupervisorSerialization || encoded != nil {
			t.Errorf("%s binary = %q/%v", test.name, encoded, err)
		}
		if unmarshaler, ok := pointer.Interface().(encoding.TextUnmarshaler); !ok {
			t.Errorf("%s lacks encoding.TextUnmarshaler", test.name)
		} else if err := unmarshaler.UnmarshalText([]byte("99")); err != ErrAgentSupervisorSerialization {
			t.Errorf("%s text unmarshal = %v", test.name, err)
		}
		if unmarshaler, ok := pointer.Interface().(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s lacks encoding.BinaryUnmarshaler", test.name)
		} else if err := unmarshaler.UnmarshalBinary([]byte{99}); err != ErrAgentSupervisorSerialization {
			t.Errorf("%s binary unmarshal = %v", test.name, err)
		}
		if after := []byte(fmt.Sprintf("%#v", pointer.Interface())); !bytes.Equal(after, before) {
			t.Errorf("%s JSON unmarshal mutated value", test.name)
		}
	}
}
