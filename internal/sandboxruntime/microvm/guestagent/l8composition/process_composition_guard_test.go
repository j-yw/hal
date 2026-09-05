package l8composition

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestL8D6CompositionSourceOwnsOnlyExplicitProcessLocalAssembly(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("process_composition.go")
	if err != nil {
		t.Fatalf("ReadFile(process_composition.go): %v", err)
	}
	if err := validateL8D6CompositionSource(source); err != nil {
		t.Fatal(err)
	}
}

func TestL8D6CompositionSourceGuardRejectsAuthorityMutations(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("process_composition.go")
	if err != nil {
		t.Fatalf("ReadFile(process_composition.go): %v", err)
	}
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{name: "derive host from core", old: "Host:       options.Host,", new: "Host:       options.Core.(credentialhelper.ExtensionHost),"},
		{name: "derive runtime from core", old: "Runtime:    options.Runtime,", new: "Runtime:    options.Core.(credentialhelper.ServiceRuntime),"},
		{name: "omit helper registration", old: "credentialhelper.NewExtensionRegistry(options.SSH)", new: "credentialhelper.NewExtensionRegistry()"},
		{name: "extra helper registration", old: "credentialhelper.NewExtensionRegistry(options.SSH)", new: "credentialhelper.NewExtensionRegistry(options.SSH, options.SSH)"},
		{name: "omit client registration", old: "credentialclient.NewExtensionRegistry(options.SSH)", new: "credentialclient.NewExtensionRegistry()"},
		{name: "extra client registration", old: "credentialclient.NewExtensionRegistry(options.SSH)", new: "credentialclient.NewExtensionRegistry(options.SSH, options.SSH)"},
		{name: "replace explicit host", old: "Host:       options.Host,", new: "Host:       nil,"},
		{name: "replace explicit runtime", old: "Runtime:    options.Runtime,", new: "Runtime:    nil,"},
		{name: "drop client descriptor view", old: "Descriptor: view,", new: "Descriptor: nil,"},
		{name: "default SSH helper", old: "registry, err := credentialhelper.NewExtensionRegistry(options.SSH)", new: "registration, _ := sshrelay.NewHelperExtension(sshrelay.HelperOptions{})\nregistry, err := credentialhelper.NewExtensionRegistry(registration)"},
		{name: "reassign helper registry", old: "service, err := credentialhelper.NewService", new: "registry, _ = credentialhelper.NewExtensionRegistry()\n\tservice, err := credentialhelper.NewService"},
		{name: "alias helper registry", old: "service, err := credentialhelper.NewService", new: "registryAlias := registry\n\tregistry = registryAlias\n\tservice, err := credentialhelper.NewService"},
		{name: "shadow helper registry", old: "service, err := credentialhelper.NewService", new: "{\n\t\tregistry, _ := credentialhelper.NewExtensionRegistry()\n\t\t_ = registry\n\t}\n\tservice, err := credentialhelper.NewService"},
		{name: "address escape helper registry", old: "service, err := credentialhelper.NewService", new: "registryAddress := &registry\n\t_ = registryAddress\n\tservice, err := credentialhelper.NewService"},
		{name: "reassign client registry", old: "client, err := credentialclient.NewClient", new: "registry, _ = credentialclient.NewExtensionRegistry()\n\tclient, err := credentialclient.NewClient"},
		{name: "alias client registry", old: "client, err := credentialclient.NewClient", new: "registryAlias := registry\n\tregistry = registryAlias\n\tclient, err := credentialclient.NewClient"},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(string(source), mutation.old, mutation.new, 1)
			if mutated == string(source) {
				t.Fatal("mutation did not change production source")
			}
			if err := validateL8D6CompositionSource([]byte(mutated)); err == nil {
				t.Fatal("composition source guard accepted authority mutation")
			}
		})
	}
}

func TestL8D6CredentialClientDescriptorMappingIsDestroyedAndNotRetained(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("../server/credentialclient/client.go")
	if err != nil {
		t.Fatalf("ReadFile(credentialclient/client.go): %v", err)
	}
	if strings.Count(string(source), "destroyErr := mapping.Destroy()") != 1 {
		t.Fatal("credentialclient constructor does not destroy its sole temporary descriptor mapping exactly once")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", source, 0)
	if err != nil {
		t.Fatalf("parse credentialclient client.go: %v", err)
	}
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, specification := range generic.Specs {
			typeSpec := specification.(*ast.TypeSpec)
			if typeSpec.Name.Name != "Client" {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatal("credentialclient.Client is not a struct")
			}
			for _, field := range structure.Fields.List {
				text := l8D6ExpressionText(field.Type)
				if text == "ClientProcessDescriptor" || text == "[]byte" {
					t.Fatalf("credentialclient.Client retains descriptor authority as %s", text)
				}
			}
		}
	}
}

func TestL8D6CompositionDeclarationsHaveOnePackageWideOwner(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	want := map[string]string{
		"HelperOptions": "process_composition.go",
		"ClientOptions": "process_composition.go",
		"NewHelper":     "process_composition.go",
		"NewClient":     "process_composition.go",
	}
	owners := make(map[string][]string, len(want))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", entry.Name(), err)
			}
			if strings.HasSuffix(path, "/credentialhelper/sshrelay") || strings.HasSuffix(path, "/credentialclient/sshrelay") {
				t.Errorf("%s imports a default SSH extension constructor", entry.Name())
			}
		}
		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if _, protected := want[typed.Name.Name]; protected {
					owners[typed.Name.Name] = append(owners[typed.Name.Name], entry.Name())
				}
			case *ast.GenDecl:
				for _, specification := range typed.Specs {
					switch value := specification.(type) {
					case *ast.TypeSpec:
						if _, protected := want[value.Name.Name]; protected {
							owners[value.Name.Name] = append(owners[value.Name.Name], entry.Name())
						}
					case *ast.ValueSpec:
						for _, name := range value.Names {
							if _, protected := want[name.Name]; protected {
								owners[name.Name] = append(owners[name.Name], entry.Name())
							}
						}
					}
				}
			}
		}
	}
	for name, owner := range want {
		if got := owners[name]; len(got) != 1 || got[0] != owner {
			t.Errorf("%s production owners = %v, want [%s]", name, got, owner)
		}
	}
}

func validateL8D6CompositionSource(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "process_composition.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse D6 composition: %w", err)
	}
	approvedImports := map[string]bool{
		"crypto/sha256": true,
		"errors":        true,
		"fmt":           true,
		"reflect":       true,
		"github.com/jywlabs/hal/internal/credentialmemory":                                          true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper":        true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol":      true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient": true,
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return fmt.Errorf("unquote D6 composition import: %w", err)
		}
		if imported.Name != nil || !approvedImports[path] {
			return fmt.Errorf("D6 composition imports unapproved dependency %q", path)
		}
	}

	var typeAssertion bool
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "init" {
			return fmt.Errorf("D6 composition declares forbidden init")
		}
		if generic, ok := declaration.(*ast.GenDecl); ok && generic.Tok == token.VAR {
			for _, specification := range generic.Specs {
				value := specification.(*ast.ValueSpec)
				if typeContainsMutableCompositionState(value.Type) || valueContainsMutableCompositionState(value.Values) {
					return fmt.Errorf("D6 composition declares mutable package-global state")
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if _, ok := node.(*ast.TypeAssertExpr); ok {
			typeAssertion = true
		}
		return true
	})
	if typeAssertion {
		return fmt.Errorf("D6 composition uses a hidden type assertion")
	}
	if err := validateL8D6RegistryFlow(file, l8D6RegistryFlowSpec{
		function:              "NewHelper",
		registryQualifier:     "credentialhelper",
		downstreamConstructor: "NewService",
		downstreamOptionsType: "ServiceOptions",
		descriptorRole:        "ProcessRoleHelper",
	}); err != nil {
		return err
	}
	if err := validateL8D6RegistryFlow(file, l8D6RegistryFlowSpec{
		function:              "NewClient",
		registryQualifier:     "credentialclient",
		downstreamConstructor: "NewClient",
		downstreamOptionsType: "ClientOptions",
		descriptorRole:        "ProcessRoleClient",
	}); err != nil {
		return err
	}

	normalized := strings.Join(strings.Fields(string(source)), " ")
	for _, required := range []struct {
		text  string
		count int
	}{
		{text: "registry, err := credentialhelper.NewExtensionRegistry(options.SSH)", count: 1},
		{text: "registry, err := credentialclient.NewExtensionRegistry(options.SSH)", count: 1},
		{text: "Core: options.Core,", count: 1},
		{text: "Transport: options.Transport,", count: 2},
		{text: "Policy: options.Policy,", count: 2},
		{text: "Extensions: registry,", count: 2},
		{text: "Host: options.Host,", count: 1},
		{text: "Runtime: options.Runtime,", count: 1},
		{text: "Descriptor: view,", count: 1},
		{text: "credentialhelper.NewService(credentialhelper.ServiceOptions{", count: 1},
		{text: "credentialclient.NewClient(credentialclient.ClientOptions{", count: 1},
	} {
		if strings.Count(normalized, strings.Join(strings.Fields(required.text), " ")) != required.count {
			return fmt.Errorf("D6 composition requires %d exact %q occurrences", required.count, required.text)
		}
	}
	for _, forbidden := range []string{
		"NewHelperExtension",
		"NewClientExtension",
		"credentialhelper/sshrelay",
		"credentialclient/sshrelay",
		"guestagent/credentialhelper/linux",
		"syscall",
		"unsafe",
		"os/exec",
	} {
		if strings.Contains(string(source), forbidden) {
			return fmt.Errorf("D6 composition contains forbidden authority marker %q", forbidden)
		}
	}
	return nil
}

type l8D6RegistryFlowSpec struct {
	function              string
	registryQualifier     string
	downstreamConstructor string
	downstreamOptionsType string
	descriptorRole        string
}

func validateL8D6RegistryFlow(file *ast.File, spec l8D6RegistryFlowSpec) error {
	function := findL8D6Function(file, spec.function)
	if function == nil || function.Body == nil {
		return fmt.Errorf("D6 composition omits %s body", spec.function)
	}
	parents := l8D6ParentMap(function.Body)
	allowedRegistry := make(map[*ast.Ident]bool)
	allowedExtensions := make(map[*ast.Ident]bool)
	registryDefinitions := 0
	extensionDefinitions := 0
	invalidDefinition := false

	ast.Inspect(function.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, left := range assignment.Lhs {
			identifier, ok := left.(*ast.Ident)
			if !ok {
				continue
			}
			switch identifier.Name {
			case "registry":
				registryDefinitions++
				if assignment.Tok != token.DEFINE || index != 0 || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 || !l8D6ExactRegistryConstructor(assignment.Rhs[0], spec.registryQualifier) {
					invalidDefinition = true
					return false
				}
				allowedRegistry[identifier] = true
			case "extensions":
				extensionDefinitions++
				if assignment.Tok != token.DEFINE || index != 0 || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
					invalidDefinition = true
					return false
				}
				call, ok := assignment.Rhs[0].(*ast.CallExpr)
				selector, selectorOK := call.Fun.(*ast.SelectorExpr)
				registry, registryOK := selector.X.(*ast.Ident)
				if !ok || !selectorOK || !registryOK || registry.Name != "registry" || selector.Sel.Name != "Descriptors" || len(call.Args) != 0 {
					invalidDefinition = true
					return false
				}
				allowedExtensions[identifier] = true
				allowedRegistry[registry] = true
			}
		}
		return true
	})
	if invalidDefinition || registryDefinitions != 1 || extensionDefinitions != 1 {
		return fmt.Errorf("%s registry/descriptors are not single-assignment", spec.function)
	}

	downstreamRegistry, err := l8D6DownstreamRegistryUse(function, spec)
	if err != nil {
		return err
	}
	allowedRegistry[downstreamRegistry] = true
	descriptorExtension, err := l8D6DescriptorExtensionUse(function, spec.descriptorRole)
	if err != nil {
		return err
	}
	allowedExtensions[descriptorExtension] = true
	checkExtension, err := l8D6ExactExtensionCheckUse(function)
	if err != nil {
		return err
	}
	allowedExtensions[checkExtension] = true

	var unexpected string
	ast.Inspect(function.Body, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || (identifier.Name != "registry" && identifier.Name != "extensions") {
			return true
		}
		if identifier.Name == "registry" && allowedRegistry[identifier] {
			return true
		}
		if identifier.Name == "extensions" && allowedExtensions[identifier] {
			return true
		}
		parent := parents[identifier]
		unexpected = fmt.Sprintf("%s has unexpected %s use under %T", spec.function, identifier.Name, parent)
		return false
	})
	if unexpected != "" {
		return fmt.Errorf("%s", unexpected)
	}
	return nil
}

func findL8D6Function(file *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name {
			return function
		}
	}
	return nil
}

func l8D6ParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	stack := make([]ast.Node, 0, 32)
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func l8D6ExactRegistryConstructor(expression ast.Expr, qualifier string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !l8D6Selector(call.Fun, qualifier, "NewExtensionRegistry") {
		return false
	}
	selector, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok {
		return false
	}
	options, optionsOK := selector.X.(*ast.Ident)
	return optionsOK && options.Name == "options" && selector.Sel.Name == "SSH"
}

func l8D6DownstreamRegistryUse(function *ast.FuncDecl, spec l8D6RegistryFlowSpec) (*ast.Ident, error) {
	var result *ast.Ident
	var invalid bool
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !l8D6Selector(call.Fun, spec.registryQualifier, spec.downstreamConstructor) {
			return true
		}
		if result != nil || len(call.Args) != 1 {
			invalid = true
			return false
		}
		literal, ok := call.Args[0].(*ast.CompositeLit)
		if !ok || !l8D6Selector(literal.Type, spec.registryQualifier, spec.downstreamOptionsType) {
			invalid = true
			return false
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			key, keyOK := field.Key.(*ast.Ident)
			if !ok || !keyOK || key.Name != "Extensions" {
				continue
			}
			identifier, identifierOK := field.Value.(*ast.Ident)
			if !identifierOK || identifier.Name != "registry" || result != nil {
				invalid = true
				return false
			}
			result = identifier
		}
		return true
	})
	if invalid || result == nil {
		return nil, fmt.Errorf("%s does not pass the exact registry directly to %s.%s", spec.function, spec.registryQualifier, spec.downstreamConstructor)
	}
	return result, nil
}

func l8D6DescriptorExtensionUse(function *ast.FuncDecl, role string) (*ast.Ident, error) {
	var result *ast.Ident
	var descriptorCount int
	ast.Inspect(function.Body, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typeName, ok := literal.Type.(*ast.Ident)
		if !ok || typeName.Name != "ProcessDescriptor" {
			return true
		}
		hasRoleField := false
		roleMatches := false
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			key, keyOK := field.Key.(*ast.Ident)
			if !ok || !keyOK {
				continue
			}
			if key.Name == "Role" {
				hasRoleField = true
				identifier, identifierOK := field.Value.(*ast.Ident)
				roleMatches = identifierOK && identifier.Name == role
			}
			if key.Name != "Extensions" {
				continue
			}
			call, callOK := field.Value.(*ast.CallExpr)
			if !callOK || len(call.Args) != 1 || !l8D6Selector(call.Fun, "credentialprotocol", "CloneExtensionDescriptors") {
				continue
			}
			identifier, identifierOK := call.Args[0].(*ast.Ident)
			if identifierOK && identifier.Name == "extensions" {
				result = identifier
			}
		}
		if !hasRoleField {
			return true
		}
		descriptorCount++
		if !roleMatches {
			result = nil
		}
		return true
	})
	if descriptorCount != 1 || result == nil {
		return nil, fmt.Errorf("%s does not snapshot the exact extensions into its %s descriptor", function.Name.Name, role)
	}
	return result, nil
}

func l8D6ExactExtensionCheckUse(function *ast.FuncDecl) (*ast.Ident, error) {
	var result *ast.Ident
	var count int
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		identifier, identifierOK := call.Fun.(*ast.Ident)
		if !identifierOK || identifier.Name != "exactSSHCompositionExtensions" {
			return true
		}
		count++
		if len(call.Args) == 1 {
			candidate, candidateOK := call.Args[0].(*ast.Ident)
			if candidateOK && candidate.Name == "extensions" {
				result = candidate
			}
		}
		return true
	})
	if count != 1 || result == nil {
		return nil, fmt.Errorf("%s does not validate its exact extension snapshot once", function.Name.Name)
	}
	return result, nil
}

func l8D6Selector(expression ast.Expr, qualifier, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	identifier, identifierOK := selector.X.(*ast.Ident)
	return identifierOK && identifier.Name == qualifier && selector.Sel.Name == name
}

func typeContainsMutableCompositionState(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.ArrayType, *ast.MapType:
		return true
	case *ast.StarExpr:
		return typeContainsMutableCompositionState(typed.X)
	default:
		return false
	}
}

func valueContainsMutableCompositionState(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		mutable := false
		ast.Inspect(expression, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				mutable = mutable || typeContainsMutableCompositionState(typed.Type)
			case *ast.CallExpr:
				identifier, ok := typed.Fun.(*ast.Ident)
				if ok && (identifier.Name == "make" || identifier.Name == "new") && len(typed.Args) > 0 {
					mutable = mutable || typeContainsMutableCompositionState(typed.Args[0])
				}
			}
			return !mutable
		})
		if mutable {
			return true
		}
	}
	return false
}

func l8D6ExpressionText(expression ast.Expr) string {
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	if array, ok := expression.(*ast.ArrayType); ok && array.Len == nil {
		return "[]" + l8D6ExpressionText(array.Elt)
	}
	return fmt.Sprintf("%T", expression)
}
