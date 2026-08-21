package credentialclient

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestClientProductionPolicyHasExactIdentityAndFailClosedSurface(t *testing.T) {
	t.Parallel()

	policy := NewClientPolicy()
	if policy == nil {
		t.Fatal("NewClientPolicy() returned nil")
	}
	typeOfPolicy := reflect.TypeOf(policy)
	if typeOfPolicy.Kind() == reflect.Pointer || typeOfPolicy.Name() != "clientPolicy" {
		t.Fatalf("NewClientPolicy() dynamic type = %v, want private non-pointer clientPolicy", typeOfPolicy)
	}
	first := policy.Descriptor()
	second := policy.Descriptor()
	want := newClientPolicyDescriptor()
	if first.ID() != "client-policy-v1" || first.ID() != second.ID() || first.SHA256() != second.SHA256() || first.SHA256() != want.SHA256() {
		t.Fatalf("policy descriptor = %q/%x then %q/%x, want exact stable client-policy-v1", first.ID(), first.SHA256(), second.ID(), second.SHA256())
	}
	assertFailsClosed(t, policy)
	assertFailsClosed(t, first)
}

func TestClientProductionPolicyAllowsOnlyClosedCanonicalTransitions(t *testing.T) {
	t.Parallel()

	policy := NewClientPolicy()
	bindings := []credentialprotocol.SafeID{"binding-1", "binding-2"}
	modes := []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeFileTmpfs, credentialprotocol.DeliveryModeSSHAgent}
	descriptor := credentialprotocol.SSHRelayV1ExtensionDescriptor()

	tests := []struct {
		name      string
		operation credentialprotocol.PacketType
		revision  uint64
		bindings  []credentialprotocol.SafeID
		modes     []credentialprotocol.DeliveryMode
	}{
		{name: "prepare", operation: credentialprotocol.PacketTypePrepareBegin, revision: 1, bindings: bindings, modes: modes},
		{name: "renew", operation: credentialprotocol.PacketTypeRenew, revision: 2},
		{name: "revoke", operation: credentialprotocol.PacketTypeRevoke, revision: 2},
		{name: "exec", operation: credentialprotocol.PacketTypeExec, revision: 2, bindings: bindings, modes: modes},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := newClientPolicyRequest(test.operation, [32]byte{1}, test.revision, test.bindings, test.modes, descriptor, "helper-limits-v1")
			decision, err := policy.Authorize(request)
			if err != nil || !decision.allow || decision.rejectionCode != "" {
				t.Fatalf("Authorize() = (%#v, %v), want exact allow", decision, err)
			}
		})
	}
}

func TestClientProductionPolicyRejectsEveryMalformedDimension(t *testing.T) {
	t.Parallel()

	policy := NewClientPolicy()
	canonical := newClientPolicyRequest(
		credentialprotocol.PacketTypePrepareBegin,
		[32]byte{1},
		1,
		[]credentialprotocol.SafeID{"binding-1"},
		[]credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent},
		credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		"helper-limits-v1",
	)
	explicitEmpty := []credentialprotocol.SafeID{}
	explicitEmptyModes := []credentialprotocol.DeliveryMode{}
	tooManyIDs := make([]credentialprotocol.SafeID, credentialprotocol.MaxHelperBindings+1)
	tooManyModes := make([]credentialprotocol.DeliveryMode, credentialprotocol.MaxHelperBindings+1)
	for index := range tooManyIDs {
		tooManyIDs[index] = credentialprotocol.SafeID(fmt.Sprintf("binding-%d", index))
		tooManyModes[index] = credentialprotocol.DeliveryModeFileTmpfs
	}

	tests := []struct {
		name   string
		mutate func(*ClientPolicyRequest)
	}{
		{name: "zero operation", mutate: func(request *ClientPolicyRequest) { request.operation = 0 }},
		{name: "bootstrap operation", mutate: func(request *ClientPolicyRequest) { request.operation = credentialprotocol.PacketTypeBootstrap }},
		{name: "prepare file operation", mutate: func(request *ClientPolicyRequest) { request.operation = credentialprotocol.PacketTypePrepareFile }},
		{name: "prepare commit operation", mutate: func(request *ClientPolicyRequest) { request.operation = credentialprotocol.PacketTypePrepareCommit }},
		{name: "extension operation", mutate: func(request *ClientPolicyRequest) { request.operation = credentialprotocol.PacketTypeSSHAcceptedFD }},
		{name: "response operation", mutate: func(request *ClientPolicyRequest) { request.operation = credentialprotocol.PacketTypeResponse }},
		{name: "zero identity", mutate: func(request *ClientPolicyRequest) { request.identityDigest = [32]byte{} }},
		{name: "zero revision", mutate: func(request *ClientPolicyRequest) { request.revision = 0 }},
		{name: "prepare later revision", mutate: func(request *ClientPolicyRequest) { request.revision = 2 }},
		{name: "wrong limits", mutate: func(request *ClientPolicyRequest) { request.fixedLimitSetID = "other-limits-v1" }},
		{name: "empty limits", mutate: func(request *ClientPolicyRequest) { request.fixedLimitSetID = "" }},
		{name: "missing bindings", mutate: func(request *ClientPolicyRequest) { request.bindingIDs = nil; request.bindingModes = nil }},
		{name: "mismatched binding count", mutate: func(request *ClientPolicyRequest) { request.bindingModes = nil }},
		{name: "explicit empty bindings", mutate: func(request *ClientPolicyRequest) {
			request.bindingIDs = explicitEmpty
			request.bindingModes = explicitEmptyModes
		}},
		{name: "too many bindings", mutate: func(request *ClientPolicyRequest) {
			request.bindingIDs = tooManyIDs
			request.bindingModes = tooManyModes
		}},
		{name: "unsafe binding", mutate: func(request *ClientPolicyRequest) { request.bindingIDs[0] = "not safe" }},
		{name: "duplicate binding", mutate: func(request *ClientPolicyRequest) {
			request.bindingIDs = []credentialprotocol.SafeID{"binding-1", "binding-1"}
			request.bindingModes = []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeFileTmpfs, credentialprotocol.DeliveryModeSSHAgent}
		}},
		{name: "unknown mode", mutate: func(request *ClientPolicyRequest) { request.bindingModes[0] = 0 }},
		{name: "two HTTP bindings", mutate: func(request *ClientPolicyRequest) {
			request.bindingIDs = []credentialprotocol.SafeID{"binding-1", "binding-2"}
			request.bindingModes = []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeHTTPProxy, credentialprotocol.DeliveryModeHTTPProxy}
		}},
		{name: "zero descriptor", mutate: func(request *ClientPolicyRequest) { request.descriptor = credentialprotocol.ExtensionDescriptor{} }},
		{name: "near SSH descriptor", mutate: func(request *ClientPolicyRequest) {
			request.descriptor.Modes = []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeFileTmpfs}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := newClientPolicyRequest(canonical.operation, canonical.identityDigest, canonical.revision, canonical.bindingIDs, canonical.bindingModes, canonical.descriptor, canonical.fixedLimitSetID)
			test.mutate(&request)
			decision, err := policy.Authorize(request)
			if err != nil || decision.allow || decision.rejectionCode != "malformed_request" {
				t.Fatalf("Authorize() = (%#v, %v), want sanitized malformed_request rejection", decision, err)
			}
		})
	}

	for _, operation := range []credentialprotocol.PacketType{credentialprotocol.PacketTypeRenew, credentialprotocol.PacketTypeRevoke} {
		request := newClientPolicyRequest(operation, [32]byte{1}, 2, []credentialprotocol.SafeID{}, []credentialprotocol.DeliveryMode{}, credentialprotocol.SSHRelayV1ExtensionDescriptor(), "helper-limits-v1")
		decision, err := policy.Authorize(request)
		if err != nil || decision.allow || decision.rejectionCode != "malformed_request" {
			t.Errorf("Authorize(%s with explicit empty slices) = (%#v, %v), want rejection", operation, decision, err)
		}
	}
}

func TestClientProductionPolicyPacketCatalogIsClosed(t *testing.T) {
	t.Parallel()

	policy := NewClientPolicy()
	allowed := map[credentialprotocol.PacketType]bool{
		credentialprotocol.PacketTypePrepareBegin: true,
		credentialprotocol.PacketTypeRenew:        true,
		credentialprotocol.PacketTypeRevoke:       true,
		credentialprotocol.PacketTypeExec:         true,
	}
	for raw := 0; raw <= 255; raw++ {
		operation := credentialprotocol.PacketType(raw)
		revision := uint64(2)
		var ids []credentialprotocol.SafeID
		var modes []credentialprotocol.DeliveryMode
		if operation == credentialprotocol.PacketTypePrepareBegin {
			revision = 1
		}
		if operation == credentialprotocol.PacketTypePrepareBegin || operation == credentialprotocol.PacketTypeExec {
			ids = []credentialprotocol.SafeID{"binding-1"}
			modes = []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}
		}
		request := newClientPolicyRequest(operation, [32]byte{1}, revision, ids, modes, credentialprotocol.SSHRelayV1ExtensionDescriptor(), "helper-limits-v1")
		decision, err := policy.Authorize(request)
		if allowed[operation] {
			if err != nil || !decision.allow || decision.rejectionCode != "" {
				t.Errorf("Authorize(packet 0x%02x) = (%#v, %v), want allow", raw, decision, err)
			}
			continue
		}
		if err != nil || decision.allow || decision.rejectionCode != "malformed_request" {
			t.Errorf("Authorize(packet 0x%02x) = (%#v, %v), want closed rejection", raw, decision, err)
		}
	}
}

func TestClientProductionPolicySourceShapeAndMutationGuard(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("client_policy.go")
	if err != nil {
		t.Fatalf("ReadFile(client_policy.go): %v", err)
	}
	if err := validateClientProductionPolicySource(source); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{name: "pointer result", old: "return clientPolicy{}", new: "return &clientPolicy{}"},
		{name: "default allow", old: "return rejectClientPolicyRequest()", new: "return newClientPolicyAllowDecision(), nil"},
		{name: "accept extension packet", old: "case credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypeExec:", new: "case credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypeExec, credentialprotocol.PacketTypeSSHAcceptedFD:"},
		{name: "drop exact descriptor", old: "credentialprotocol.ExtensionDescriptorEqual(request.descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor())", new: "credentialprotocol.ValidateExtensionDescriptor(request.descriptor) == nil"},
		{name: "identity selective direct allow", old: "func (clientPolicy) Authorize(request ClientPolicyRequest) (ClientPolicyDecision, error) {", new: "func (clientPolicy) Authorize(request ClientPolicyRequest) (ClientPolicyDecision, error) {\n\tif request.identityDigest == ([32]byte{9}) {\n\t\treturn ClientPolicyDecision{allow: true}, nil\n\t}"},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(string(source), mutation.old, mutation.new, 1)
			if mutated == string(source) {
				t.Fatal("mutation did not change source")
			}
			if err := validateClientProductionPolicySource([]byte(mutated)); err == nil {
				t.Fatal("source guard accepted adversarial mutation")
			}
		})
	}
}

func TestClientProductionPolicyRejectsMalformedOperationsAcrossIdentities(t *testing.T) {
	t.Parallel()

	policy := NewClientPolicy()
	identities := [][32]byte{
		{},
		{1},
		{2},
		{9},
		{1, 2, 3},
		{31: 9},
	}
	allowed := map[credentialprotocol.PacketType]bool{
		credentialprotocol.PacketTypePrepareBegin: true,
		credentialprotocol.PacketTypeRenew:        true,
		credentialprotocol.PacketTypeRevoke:       true,
		credentialprotocol.PacketTypeExec:         true,
	}
	for identityIndex, identity := range identities {
		for raw := 0; raw <= 255; raw++ {
			operation := credentialprotocol.PacketType(raw)
			if allowed[operation] && identity != ([32]byte{}) {
				continue
			}
			request := newClientPolicyRequest(
				operation,
				identity,
				1,
				[]credentialprotocol.SafeID{"binding-1"},
				[]credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent},
				credentialprotocol.SSHRelayV1ExtensionDescriptor(),
				"helper-limits-v1",
			)
			decision, err := policy.Authorize(request)
			if err != nil || decision.allow || decision.rejectionCode != "malformed_request" {
				t.Errorf("Authorize(identity %d, packet 0x%02x) = (%#v, %v), want closed rejection", identityIndex, raw, decision, err)
			}
		}
	}
}

func TestClientProductionPolicyConstructorHasOnePackageWideOwner(t *testing.T) {
	t.Parallel()

	if err := validateClientProductionPolicyPackage("."); err != nil {
		t.Fatal(err)
	}
}

func TestClientProductionPolicyPackageWideAllowGuardMutations(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name   string
		source string
	}{
		{name: "package alias", source: "var alternateClientPolicyAllow = newClientPolicyAllowDecision"},
		{name: "typed function value", source: "var alternateClientPolicyAllow func() ClientPolicyDecision = newClientPolicyAllowDecision"},
		{name: "stored call result", source: "var alternateClientPolicyAllow = newClientPolicyAllowDecision()"},
		{name: "function value composite", source: "var alternateClientPolicyAllow = []func() ClientPolicyDecision{newClientPolicyAllowDecision}"},
		{name: "struct function value composite", source: "var alternateClientPolicyAllow = struct{ issue func() ClientPolicyDecision }{issue: newClientPolicyAllowDecision}"},
		{name: "closure call", source: "var alternateClientPolicyAllow = func() ClientPolicyDecision { return newClientPolicyAllowDecision() }"},
		{name: "address escape", source: "var alternateClientPolicyAllow = &newClientPolicyAllowDecision"},
		{name: "local alias", source: "func init() { alternateClientPolicyAllow := newClientPolicyAllowDecision; _ = alternateClientPolicyAllow }"},
		{name: "direct allow composite", source: "var alternateClientPolicyAllow = ClientPolicyDecision{allow: true}"},
		{name: "aliased direct allow composite", source: "type alternateClientPolicyDecision = ClientPolicyDecision\nvar alternateClientPolicyAllow = alternateClientPolicyDecision{allow: true}"},
		{name: "alias chain direct allow composite", source: "type firstAlternateClientPolicyDecision = ClientPolicyDecision\ntype secondAlternateClientPolicyDecision = firstAlternateClientPolicyDecision\nvar alternateClientPolicyAllow = secondAlternateClientPolicyDecision{allow: true}"},
		{name: "local alias direct allow composite", source: "func alternateClientPolicyAllow() { type alternateClientPolicyDecision = ClientPolicyDecision; _ = alternateClientPolicyDecision{allow: true} }"},
		{name: "defined wrapper direct allow composite", source: "type alternateClientPolicyDecision ClientPolicyDecision\nvar alternateClientPolicyAllow = alternateClientPolicyDecision{allow: true}"},
		{name: "defined wrapper chain direct allow composite", source: "type firstAlternateClientPolicyDecision ClientPolicyDecision\ntype secondAlternateClientPolicyDecision firstAlternateClientPolicyDecision\nvar alternateClientPolicyAllow = secondAlternateClientPolicyDecision{allow: true}"},
		{name: "generic defined wrapper direct allow composite", source: "type alternateClientPolicyDecision[T any] ClientPolicyDecision\nvar alternateClientPolicyAllow = alternateClientPolicyDecision[int]{allow: true}"},
		{name: "keyed allow constant", source: "const alternateClientPolicyAllowValue = true\nvar alternateClientPolicyAllow = ClientPolicyDecision{allow: alternateClientPolicyAllowValue}"},
		{name: "unkeyed allow composite", source: "var alternateClientPolicyAllow = ClientPolicyDecision{liveValue{}, true, \"\"}"},
		{name: "struct conversion", source: "import \"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol\"\nvar alternateClientPolicyAllow = ClientPolicyDecision(struct { liveValue; allow bool; rejectionCode credentialprotocol.SafeID }{allow: true})"},
		{name: "allow field assignment", source: "var alternateClientPolicyAllow ClientPolicyDecision\nfunc init() { alternateClientPolicyAllow.allow = true }"},
		{name: "allow field multi assignment", source: "var alternateClientPolicyAllow ClientPolicyDecision\nfunc init() { alternateClientPolicyAllow.allow, _ = true, 0 }"},
		{name: "allow field address escape", source: "var alternateClientPolicyAllow ClientPolicyDecision\nvar alternateClientPolicyAllowAddress = &alternateClientPolicyAllow.allow"},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			directory := t.TempDir()
			entries, err := os.ReadDir(".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				source, err := os.ReadFile(entry.Name())
				if err != nil {
					t.Fatalf("ReadFile(%s): %v", entry.Name(), err)
				}
				if err := os.WriteFile(directory+"/"+entry.Name(), source, 0o600); err != nil {
					t.Fatalf("WriteFile(%s): %v", entry.Name(), err)
				}
			}
			mutatedSource := "package credentialclient\n\n" + mutation.source + "\n"
			if err := os.WriteFile(directory+"/allow_mutation.go", []byte(mutatedSource), 0o600); err != nil {
				t.Fatalf("WriteFile(allow_mutation.go): %v", err)
			}
			if err := validateClientProductionPolicyPackage(directory); err == nil {
				t.Fatal("package-wide allow guard accepted adversarial declaration/reference")
			}
		})
	}
}

func validateClientProductionPolicyPackage(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read package: %w", err)
	}
	files := make([]clientPolicyProductionFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), directory+"/"+entry.Name(), nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		files = append(files, clientPolicyProductionFile{name: entry.Name(), syntax: file})
	}
	decisionTypeNames, decisionTypeWrappers := clientPolicyDecisionTypeClosure(files)
	if len(decisionTypeWrappers) != 0 {
		return fmt.Errorf("ClientPolicyDecision has forbidden production aliases/wrappers %v", decisionTypeWrappers)
	}
	owners := make([]string, 0, 1)
	allowConstructors := make([]string, 0, 1)
	unexpectedAllowReferences := make([]string, 0, 1)
	unexpectedAllowValueSites := make([]string, 0, 1)
	var canonicalAllowDeclaration *ast.Ident
	var canonicalAllowCall *ast.Ident
	var canonicalAllowLiteral *ast.CompositeLit
	for _, productionFile := range files {
		entryName := productionFile.name
		file := productionFile.syntax
		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Name.Name == "NewClientPolicy" {
					owners = append(owners, entryName)
				}
				if typed.Name.Name == "newClientPolicyAllowDecision" {
					allowConstructors = append(allowConstructors, entryName)
					if entryName == "contracts.go" {
						literal, ok := clientPolicyCanonicalAllowConstructor(typed)
						if ok && canonicalAllowDeclaration == nil {
							canonicalAllowDeclaration = typed.Name
							canonicalAllowLiteral = literal
						}
					}
				}
				if entryName == "client_policy.go" {
					if identifier := clientPolicyCanonicalAllowCallIdentifier(typed); identifier != nil && canonicalAllowCall == nil {
						canonicalAllowCall = identifier
					}
				}
			case *ast.GenDecl:
				for _, specification := range typed.Specs {
					value, ok := specification.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range value.Names {
						if name.Name == "NewClientPolicy" {
							owners = append(owners, entryName)
						}
						if name.Name == "newClientPolicyAllowDecision" {
							allowConstructors = append(allowConstructors, entryName)
						}
					}
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.Ident:
				if value.Name == "newClientPolicyAllowDecision" && value != canonicalAllowDeclaration && value != canonicalAllowCall {
					unexpectedAllowReferences = append(unexpectedAllowReferences, entryName)
				}
			case *ast.CompositeLit:
				if clientPolicyDecisionLiteralOwnsAllow(value, decisionTypeNames) && value != canonicalAllowLiteral {
					unexpectedAllowValueSites = append(unexpectedAllowValueSites, entryName)
				}
			case *ast.AssignStmt:
				if clientPolicyAssignmentWritesAllow(value) {
					unexpectedAllowValueSites = append(unexpectedAllowValueSites, entryName)
				}
			case *ast.CallExpr:
				if name, ok := clientPolicyDirectNamedType(value.Fun); ok && decisionTypeNames[name] {
					unexpectedAllowValueSites = append(unexpectedAllowValueSites, entryName)
				}
			case *ast.UnaryExpr:
				if value.Op == token.AND && clientPolicyExpressionSelectsAllow(value.X) {
					unexpectedAllowValueSites = append(unexpectedAllowValueSites, entryName)
				}
			case *ast.IncDecStmt:
				if clientPolicyExpressionSelectsAllow(value.X) {
					unexpectedAllowValueSites = append(unexpectedAllowValueSites, entryName)
				}
			}
			return true
		})
	}
	if !reflect.DeepEqual(owners, []string{"client_policy.go"}) {
		return fmt.Errorf("NewClientPolicy production owners = %v, want [client_policy.go]", owners)
	}
	if !reflect.DeepEqual(allowConstructors, []string{"contracts.go"}) {
		return fmt.Errorf("allow-decision constructors = %v, want [contracts.go]", allowConstructors)
	}
	if canonicalAllowDeclaration == nil || canonicalAllowCall == nil || canonicalAllowLiteral == nil {
		return errors.New("canonical allow declaration/call is absent or malformed")
	}
	if len(unexpectedAllowReferences) != 0 {
		return fmt.Errorf("allow-decision constructor has noncanonical references in %v", unexpectedAllowReferences)
	}
	if len(unexpectedAllowValueSites) != 0 {
		return fmt.Errorf("allow value has noncanonical construction/write sites in %v", unexpectedAllowValueSites)
	}
	return nil
}

type clientPolicyProductionFile struct {
	name   string
	syntax *ast.File
}

type clientPolicyTypeDefinition struct {
	name       string
	expression ast.Expr
}

func clientPolicyDecisionTypeClosure(files []clientPolicyProductionFile) (map[string]bool, []string) {
	definitions := make([]clientPolicyTypeDefinition, 0)
	for _, productionFile := range files {
		ast.Inspect(productionFile.syntax, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name == "ClientPolicyDecision" {
				return true
			}
			definitions = append(definitions, clientPolicyTypeDefinition{name: typeSpec.Name.Name, expression: typeSpec.Type})
			return true
		})
	}

	decisionTypes := map[string]bool{"ClientPolicyDecision": true}
	wrappers := make([]string, 0)
	for changed := true; changed; {
		changed = false
		for _, definition := range definitions {
			if decisionTypes[definition.name] {
				continue
			}
			underlyingName, ok := clientPolicyDirectNamedType(definition.expression)
			if !ok || !decisionTypes[underlyingName] {
				continue
			}
			decisionTypes[definition.name] = true
			wrappers = append(wrappers, definition.name)
			changed = true
		}
	}
	return decisionTypes, wrappers
}

func clientPolicyDirectNamedType(expression ast.Expr) (string, bool) {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name, true
	case *ast.ParenExpr:
		return clientPolicyDirectNamedType(typed.X)
	case *ast.IndexExpr:
		return clientPolicyDirectNamedType(typed.X)
	case *ast.IndexListExpr:
		return clientPolicyDirectNamedType(typed.X)
	default:
		return "", false
	}
}

func clientPolicyDecisionLiteralOwnsAllow(literal *ast.CompositeLit, decisionTypes map[string]bool) bool {
	if literal == nil {
		return false
	}
	typeName, ok := clientPolicyDirectNamedType(literal.Type)
	if !ok || !decisionTypes[typeName] {
		return false
	}
	for index, element := range literal.Elts {
		if field, ok := element.(*ast.KeyValueExpr); ok {
			key, keyOK := field.Key.(*ast.Ident)
			if keyOK && key.Name == "allow" {
				return true
			}
			continue
		}
		if index == 1 {
			return true
		}
	}
	return false
}

func clientPolicyAssignmentWritesAllow(assignment *ast.AssignStmt) bool {
	if assignment == nil {
		return false
	}
	for _, expression := range assignment.Lhs {
		writesAllow := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if clientPolicyExpressionSelectsAllow(node) {
				writesAllow = true
				return false
			}
			return true
		})
		if writesAllow {
			return true
		}
	}
	return false
}

func clientPolicyExpressionSelectsAllow(value ast.Node) bool {
	selector, ok := value.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "allow"
}

func clientPolicyCanonicalAllowConstructor(function *ast.FuncDecl) (*ast.CompositeLit, bool) {
	if function == nil || function.Recv != nil || function.Name.Name != "newClientPolicyAllowDecision" ||
		function.Type.Params.NumFields() != 0 || function.Type.Results == nil || function.Type.Results.NumFields() != 1 ||
		normalizeClientPolicyExpression(function.Type.Results.List[0].Type) != "ClientPolicyDecision" ||
		function.Body == nil || len(function.Body.List) != 1 {
		return nil, false
	}
	result, ok := function.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(result.Results) != 1 {
		return nil, false
	}
	literal, ok := result.Results[0].(*ast.CompositeLit)
	return literal, ok && normalizeClientPolicyExpression(literal) == "ClientPolicyDecision{allow: true}"
}

func clientPolicyCanonicalAllowCallIdentifier(function *ast.FuncDecl) *ast.Ident {
	if function == nil || function.Name.Name != "Authorize" || function.Recv == nil || len(function.Recv.List) != 1 ||
		clientPolicyExpressionText(function.Recv.List[0].Type) != "clientPolicy" || function.Body == nil || len(function.Body.List) == 0 {
		return nil
	}
	result, ok := function.Body.List[len(function.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(result.Results) != 2 {
		return nil
	}
	call, ok := result.Results[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil
	}
	identifier, ok := call.Fun.(*ast.Ident)
	nilResult, nilOK := result.Results[1].(*ast.Ident)
	if !ok || identifier.Name != "newClientPolicyAllowDecision" || !nilOK || nilResult.Name != "nil" {
		return nil
	}
	return identifier
}

func validateClientProductionPolicySource(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "client_policy.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse client policy: %w", err)
	}
	var constructor *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || function.Name.Name != "NewClientPolicy" {
			continue
		}
		if constructor != nil {
			return errors.New("client policy declares duplicate production constructors")
		}
		constructor = function
	}
	if constructor == nil || constructor.Type.Params.NumFields() != 0 || constructor.Type.Results == nil || constructor.Type.Results.NumFields() != 1 {
		return errors.New("client policy constructor shape is not exact")
	}
	if got := clientPolicyExpressionText(constructor.Type.Results.List[0].Type); got != "Policy" {
		return fmt.Errorf("client policy constructor result = %s, want Policy", got)
	}
	if err := validateClientPolicyAuthorizeControlFlow(file); err != nil {
		return err
	}
	normalized := strings.Join(strings.Fields(string(source)), " ")
	for _, required := range []struct {
		text  string
		count int
	}{
		{text: "return clientPolicy{}", count: 1},
		{text: "return rejectClientPolicyRequest()", count: 5},
		{text: "return newClientPolicyAllowDecision(), nil", count: 1},
		{text: "case credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypeExec:", count: 1},
		{text: "case credentialprotocol.PacketTypeRenew, credentialprotocol.PacketTypeRevoke:", count: 1},
		{text: "credentialprotocol.ExtensionDescriptorEqual(request.descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor())", count: 1},
	} {
		if strings.Count(normalized, strings.Join(strings.Fields(required.text), " ")) != required.count {
			return fmt.Errorf("client policy source does not contain %d exact %q", required.count, required.text)
		}
	}
	return nil
}

func validateClientPolicyAuthorizeControlFlow(file *ast.File) error {
	var authorize *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Authorize" || function.Recv == nil || len(function.Recv.List) != 1 || clientPolicyExpressionText(function.Recv.List[0].Type) != "clientPolicy" {
			continue
		}
		if authorize != nil {
			return errors.New("client policy declares duplicate Authorize methods")
		}
		authorize = function
	}
	if authorize == nil || authorize.Body == nil || len(authorize.Body.List) != 3 {
		return errors.New("client policy Authorize control flow is not exact")
	}
	common, ok := authorize.Body.List[0].(*ast.IfStmt)
	if !ok || !clientPolicyRejectingIf(common, "request.identityDigest == ([32]byte{}) || request.revision == 0 || request.fixedLimitSetID != clientPolicyLimitSetID || !credentialprotocol.ExtensionDescriptorEqual(request.descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor())") {
		return errors.New("client policy common validation does not dominate allow")
	}
	operationSwitch, ok := authorize.Body.List[1].(*ast.SwitchStmt)
	if !ok || operationSwitch.Init != nil || normalizeClientPolicyExpression(operationSwitch.Tag) != "request.operation" || operationSwitch.Body == nil || len(operationSwitch.Body.List) != 3 {
		return errors.New("client policy transition switch is not exact")
	}
	prepareExec, ok := operationSwitch.Body.List[0].(*ast.CaseClause)
	if !ok || !clientPolicyCaseNamesEqual(prepareExec.List, []string{"credentialprotocol.PacketTypePrepareBegin", "credentialprotocol.PacketTypeExec"}) || len(prepareExec.Body) != 2 {
		return errors.New("client policy prepare/exec transition case is not exact")
	}
	prepareRevision, revisionOK := prepareExec.Body[0].(*ast.IfStmt)
	bindings, bindingsOK := prepareExec.Body[1].(*ast.IfStmt)
	if !revisionOK || !bindingsOK ||
		!clientPolicyRejectingIf(prepareRevision, "request.operation == credentialprotocol.PacketTypePrepareBegin && request.revision != 1") ||
		!clientPolicyRejectingIf(bindings, "!validClientPolicyBindings(request.bindingIDs, request.bindingModes)") {
		return errors.New("client policy prepare/exec validation does not dominate allow")
	}
	renewRevoke, ok := operationSwitch.Body.List[1].(*ast.CaseClause)
	if !ok || !clientPolicyCaseNamesEqual(renewRevoke.List, []string{"credentialprotocol.PacketTypeRenew", "credentialprotocol.PacketTypeRevoke"}) || len(renewRevoke.Body) != 1 {
		return errors.New("client policy renew/revoke transition case is not exact")
	}
	emptyBindings, ok := renewRevoke.Body[0].(*ast.IfStmt)
	if !ok || !clientPolicyRejectingIf(emptyBindings, "request.bindingIDs != nil || request.bindingModes != nil") {
		return errors.New("client policy renew/revoke validation does not dominate allow")
	}
	defaultCase, ok := operationSwitch.Body.List[2].(*ast.CaseClause)
	if !ok || defaultCase.List != nil || len(defaultCase.Body) != 1 || !clientPolicyRejectReturn(defaultCase.Body[0]) {
		return errors.New("client policy default transition is not a closed rejection")
	}
	if !clientPolicyAllowReturn(authorize.Body.List[2]) {
		return errors.New("client policy sole allow is not the final post-validation statement")
	}

	allowReferences := 0
	directAllows := 0
	forbiddenFlow := false
	ast.Inspect(authorize.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.Ident:
			if value.Name == "newClientPolicyAllowDecision" {
				allowReferences++
			}
		case *ast.CompositeLit:
			if clientPolicyDecisionLiteralAllows(value) {
				directAllows++
			}
		case *ast.BranchStmt, *ast.GoStmt, *ast.DeferStmt, *ast.FuncLit:
			forbiddenFlow = true
		}
		return true
	})
	if allowReferences != 1 || directAllows != 0 || forbiddenFlow {
		return errors.New("client policy contains an alternate allow or control-flow site")
	}
	return nil
}

func clientPolicyRejectingIf(statement *ast.IfStmt, condition string) bool {
	return statement != nil && statement.Init == nil && statement.Else == nil &&
		normalizeClientPolicyExpression(statement.Cond) == strings.Join(strings.Fields(condition), " ") &&
		statement.Body != nil && len(statement.Body.List) == 1 && clientPolicyRejectReturn(statement.Body.List[0])
}

func clientPolicyRejectReturn(statement ast.Stmt) bool {
	result, ok := statement.(*ast.ReturnStmt)
	if !ok || len(result.Results) != 1 {
		return false
	}
	call, ok := result.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	identifier, identifierOK := call.Fun.(*ast.Ident)
	return identifierOK && identifier.Name == "rejectClientPolicyRequest" && len(call.Args) == 0
}

func clientPolicyAllowReturn(statement ast.Stmt) bool {
	result, ok := statement.(*ast.ReturnStmt)
	if !ok || len(result.Results) != 2 {
		return false
	}
	call, ok := result.Results[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	constructor, ok := call.Fun.(*ast.Ident)
	nilResult, nilOK := result.Results[1].(*ast.Ident)
	return ok && constructor.Name == "newClientPolicyAllowDecision" && nilOK && nilResult.Name == "nil"
}

func clientPolicyCaseNamesEqual(expressions []ast.Expr, want []string) bool {
	if len(expressions) != len(want) {
		return false
	}
	for index := range expressions {
		if normalizeClientPolicyExpression(expressions[index]) != want[index] {
			return false
		}
	}
	return true
}

func clientPolicyDecisionLiteralAllows(literal *ast.CompositeLit) bool {
	if literal == nil || normalizeClientPolicyExpression(literal.Type) != "ClientPolicyDecision" {
		return false
	}
	for index, element := range literal.Elts {
		if field, ok := element.(*ast.KeyValueExpr); ok {
			key, keyOK := field.Key.(*ast.Ident)
			value, valueOK := field.Value.(*ast.Ident)
			if keyOK && valueOK && key.Name == "allow" && value.Name == "true" {
				return true
			}
			continue
		}
		value, ok := element.(*ast.Ident)
		if index == 1 && ok && value.Name == "true" {
			return true
		}
	}
	return false
}

func normalizeClientPolicyExpression(expression ast.Expr) string {
	return strings.Join(strings.Fields(clientPolicyExpressionText(expression)), " ")
}

func clientPolicyExpressionText(expression ast.Expr) string {
	var output bytes.Buffer
	_ = printer.Fprint(&output, token.NewFileSet(), expression)
	return output.String()
}
