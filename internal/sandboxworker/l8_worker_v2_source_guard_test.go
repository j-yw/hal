package sandboxworker

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestL8WorkerV2SourceGuardsKeepV1JobPayloadsCredentialFree(t *testing.T) {
	jobSource := l8ReadWorkerSource(t, "job_types.go")
	for _, marker := range []string{
		"JobContractVersionV2",
		"JobStartRequestV2",
		"JobCredentialIntentV2",
		"productionCredentialsRequested",
		"admissionGrantId",
		"sourceReferenceIds",
	} {
		if strings.Contains(jobSource, marker) {
			t.Fatalf("v1 job_types.go contains v2 marker %q", marker)
		}
	}

	envelopeSource := l8ReadWorkerSource(t, "types.go")
	for _, marker := range []string{
		"productionCredentialsRequested",
		"admissionGrantId",
		"admissionGrantRevision",
		"sourceReferenceIds",
		"authenticatedPrincipal",
	} {
		if strings.Contains(envelopeSource, marker) {
			t.Fatalf("outer envelope source contains inline credential field %q; v2 payloads must remain distinct", marker)
		}
	}
}

func TestL8WorkerV2SourceGuardsRejectSecretAndLiveAuthoritySurfaces(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matched, matchErr := build.Default.MatchFile(".", path)
		if matchErr != nil {
			t.Fatalf("match production file %s: %v", path, matchErr)
		}
		if !matched {
			continue
		}
		sources[path] = l8ReadWorkerSource(t, path)
	}
	if err := l8AuditWorkerV2Sources(sources, l8WorkerV2ProductionGuardPolicy()); err != nil {
		t.Fatal(err)
	}
}

type l8WorkerV2GuardPolicy struct {
	dedicated map[string]bool
	mixed     map[string]bool
}

func l8WorkerV2ProductionGuardPolicy() l8WorkerV2GuardPolicy {
	return l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{
			"job_manager_v2.go": true,
			"job_service_v2.go": true,
			"job_store_v2.go":   true,
			"job_v2_client.go":  true,
			"job_v2_helpers.go": true,
			"job_v2_service.go": true,
			"job_v2_types.go":   true,
		},
		mixed: map[string]bool{
			"client.go":          true,
			"handler.go":         true,
			"job_helpers.go":     true,
			"protocol_decode.go": true,
			"server.go":          true,
			"types.go":           true,
		},
	}
}

func (policy l8WorkerV2GuardPolicy) allows(path string) bool {
	base := filepath.Base(path)
	return policy.dedicated[base] || policy.mixed[base]
}

type l8WorkerV2ParsedFile struct {
	path          string
	fileSet       *token.FileSet
	parsed        *ast.File
	imports       map[string]string
	alwaysImports []string
}

type l8WorkerV2GuardScope struct {
	file *l8WorkerV2ParsedFile
	node ast.Node
}

func l8AuditWorkerV2Sources(sources map[string]string, policy l8WorkerV2GuardPolicy) error {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	fileSet := token.NewFileSet()
	parsedFiles := make([]*l8WorkerV2ParsedFile, 0, len(paths))
	filesByAST := make(map[*ast.File]*l8WorkerV2ParsedFile, len(paths))
	var roots []l8WorkerV2GuardScope
	for _, path := range paths {
		parsed, err := parser.ParseFile(fileSet, path, sources[path], 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		file := &l8WorkerV2ParsedFile{
			path:    path,
			fileSet: fileSet,
			parsed:  parsed,
			imports: make(map[string]string, len(parsed.Imports)),
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("unquote import in %s: %w", path, err)
			}
			name := filepath.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." || name == "_" {
				file.alwaysImports = append(file.alwaysImports, importPath)
				continue
			}
			file.imports[name] = importPath
		}
		parsedFiles = append(parsedFiles, file)
		filesByAST[parsed] = file

		base := filepath.Base(path)
		containsV2 := l8WorkerV2ASTContainsMarker(parsed)
		if containsV2 && !policy.allows(path) {
			return fmt.Errorf("production file %s contains worker-v2 declarations/references outside the exact allowlist", path)
		}
		switch {
		case policy.dedicated[base]:
			for _, declaration := range parsed.Decls {
				if generated, ok := declaration.(*ast.GenDecl); ok && generated.Tok == token.IMPORT {
					continue
				}
				for _, unit := range l8WorkerV2DeclarationUnits(declaration) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: unit})
				}
			}
		case policy.mixed[base] && containsV2:
			for _, declaration := range parsed.Decls {
				for _, node := range l8WorkerV2MixedDeclarationScopes(declaration) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: node})
				}
			}
		}
	}
	if len(roots) == 0 {
		return nil
	}

	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	astFiles := make([]*ast.File, 0, len(parsedFiles))
	for _, file := range parsedFiles {
		astFiles = append(astFiles, file.parsed)
	}
	var typeImporter types.Importer = importer.Default()
	for _, file := range parsedFiles {
		allImports := append(append([]string(nil), file.alwaysImports...), l8WorkerV2ImportValues(file.imports)...)
		for _, importPath := range allImports {
			if strings.HasPrefix(importPath, "github.com/jywlabs/hal/") {
				typeImporter = importer.ForCompiler(fileSet, "source", nil)
				break
			}
		}
	}
	config := types.Config{Importer: typeImporter}
	checkedPackage, err := config.Check("github.com/jywlabs/hal/internal/sandboxworker", fileSet, astFiles, info)
	if err != nil {
		return fmt.Errorf("type-check worker-v2 guard sources: %w", err)
	}

	objects := make(map[types.Object]l8WorkerV2GuardScope)
	for _, file := range parsedFiles {
		for _, declaration := range file.parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if object := info.Defs[typed.Name]; object != nil {
					objects[object] = l8WorkerV2GuardScope{file: file, node: typed}
				}
			case *ast.GenDecl:
				if typed.Tok == token.IMPORT {
					continue
				}
				for _, spec := range typed.Specs {
					switch value := spec.(type) {
					case *ast.TypeSpec:
						if object := info.Defs[value.Name]; object != nil {
							objects[object] = l8WorkerV2GuardScope{file: file, node: value}
						}
					case *ast.ValueSpec:
						for _, name := range value.Names {
							if object := info.Defs[name]; object != nil {
								objects[object] = l8WorkerV2GuardScope{file: file, node: value}
							}
						}
					}
				}
			}
		}
	}

	selected := make(map[ast.Node]bool)
	queue := make([]l8WorkerV2GuardScope, 0, len(roots))
	selectScope := func(scope l8WorkerV2GuardScope) error {
		if scope.node == nil || selected[scope.node] {
			return nil
		}
		if !policy.allows(scope.file.path) {
			return fmt.Errorf("worker-v2 declaration closure reaches production file %s outside the exact allowlist", scope.file.path)
		}
		selected[scope.node] = true
		queue = append(queue, scope)
		return nil
	}
	for _, root := range roots {
		if err := selectScope(root); err != nil {
			return err
		}
	}

	for len(queue) > 0 {
		scope := queue[0]
		queue = queue[1:]
		if err := l8InspectWorkerV2Scope(scope, info); err != nil {
			return err
		}
		if err := l8RejectWorkerV2ForbiddenSurface(scope); err != nil {
			return err
		}
		var closureErr error
		ast.Inspect(scope.node, func(node ast.Node) bool {
			if closureErr != nil {
				return false
			}
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			object := info.Uses[identifier]
			if object == nil || object.Pkg() != checkedPackage {
				return true
			}
			referenced, ok := objects[object]
			if !ok {
				return true
			}
			for _, narrowed := range l8WorkerV2ReferencedDeclarationScopes(referenced) {
				if err := selectScope(narrowed); err != nil {
					closureErr = err
					return false
				}
			}
			return true
		})
		if closureErr != nil {
			return closureErr
		}
	}
	return nil
}

func l8WorkerV2ImportValues(imports map[string]string) []string {
	values := make([]string, 0, len(imports))
	for _, importPath := range imports {
		values = append(values, importPath)
	}
	return values
}

func l8WorkerV2MixedDeclarationScopes(declaration ast.Decl) []ast.Node {
	switch typed := declaration.(type) {
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return nil
		}
		var scopes []ast.Node
		for _, spec := range typed.Specs {
			if !l8WorkerV2ASTContainsMarker(spec) {
				continue
			}
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || strings.Contains(strings.ToLower(typeSpec.Name.Name), "v2") {
				scopes = append(scopes, spec)
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				scopes = append(scopes, spec)
				continue
			}
			for _, field := range structType.Fields.List {
				if l8WorkerV2ASTContainsMarker(field) {
					scopes = append(scopes, field)
				}
			}
		}
		return scopes
	case *ast.FuncDecl:
		if l8WorkerV2FunctionSignatureContainsMarker(typed) {
			return []ast.Node{typed}
		}
		return l8WorkerV2MixedFunctionBodyScopes(typed.Body)
	default:
		return nil
	}
}

func l8WorkerV2FunctionSignatureContainsMarker(function *ast.FuncDecl) bool {
	if function == nil {
		return false
	}
	cloned := *function
	cloned.Body = nil
	return l8WorkerV2ASTContainsMarker(&cloned)
}

func l8WorkerV2MixedFunctionBodyScopes(body *ast.BlockStmt) []ast.Node {
	if body == nil || !l8WorkerV2ASTContainsMarker(body) {
		return nil
	}
	// Mixed dispatch functions are intentionally audited as one control-flow
	// unit. Case-only slicing misses switch initializers, fallthrough targets,
	// and later switches reached after a V2 branch. Unrelated legacy sibling
	// functions remain outside the object-identity closure.
	return []ast.Node{body}
}

func l8WorkerV2ReferencedDeclarationScopes(scope l8WorkerV2GuardScope) []l8WorkerV2GuardScope {
	typeSpec, ok := scope.node.(*ast.TypeSpec)
	if !ok || strings.Contains(strings.ToLower(typeSpec.Name.Name), "v2") {
		return []l8WorkerV2GuardScope{scope}
	}
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok || !l8WorkerV2ASTContainsMarker(structType) {
		return []l8WorkerV2GuardScope{scope}
	}
	var result []l8WorkerV2GuardScope
	for _, field := range structType.Fields.List {
		if l8WorkerV2ASTContainsMarker(field) {
			result = append(result, l8WorkerV2GuardScope{file: scope.file, node: field})
		}
	}
	return result
}

func l8InspectWorkerV2Scope(scope l8WorkerV2GuardScope, info *types.Info) error {
	var inspectionErr error
	ast.Inspect(scope.node, func(node ast.Node) bool {
		if inspectionErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		kind := l8WorkerV2DynamicCallKind(call.Fun, info)
		if kind != "" {
			inspectionErr = fmt.Errorf("worker-v2 production path in %s uses forbidden %s dispatch", scope.file.path, kind)
			return false
		}
		return true
	})
	return inspectionErr
}

func l8WorkerV2DynamicCallKind(expression ast.Expr, info *types.Info) string {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		default:
			goto unwrapped
		}
	}

unwrapped:
	switch typed := expression.(type) {
	case *ast.Ident:
		switch info.Uses[typed].(type) {
		case *types.Builtin, *types.Func, *types.TypeName:
			return ""
		}
	case *ast.SelectorExpr:
		if selection := info.Selections[typed]; selection != nil {
			receiver := selection.Recv()
			if pointer, ok := receiver.(*types.Pointer); ok {
				receiver = pointer.Elem()
			}
			if _, ok := receiver.Underlying().(*types.Interface); ok {
				return "interface"
			}
			if _, ok := selection.Obj().(*types.Func); ok {
				return ""
			}
		} else if _, ok := info.Uses[typed.Sel].(*types.Func); ok {
			return ""
		}
	}
	if _, ok := info.TypeOf(expression).Underlying().(*types.Signature); ok {
		return "function-value"
	}
	return ""
}

func l8RejectWorkerV2ForbiddenSurface(scope l8WorkerV2GuardScope) error {
	buffer := &bytes.Buffer{}
	if err := format.Node(buffer, scope.file.fileSet, scope.node); err != nil {
		return fmt.Errorf("render worker-v2 declaration in %s: %w", scope.file.path, err)
	}
	source := buffer.String()
	for _, forbidden := range []string{
		`json:"value`,
		`json:"secret`,
		`json:"callback`,
		`json:"ticket`,
		`json:"socket`,
		`json:"endpoint`,
		`json:"hostPath`,
		`json:"path`,
		`json:"keySerial`,
		`json:"execBinding`,
		`json:"authenticatedPrincipal`,
		"RawValue",
		"SecretValue",
		"Callback",
		"Ticket",
		"Socket",
		"Endpoint",
		"HostPath",
		"KeySerial",
		"LiveSecretSource",
		"JobCredentialExecBinding",
		"keyctl_read",
		"tls.Conn",
		"net.Listen",
		"os/exec",
	} {
		if strings.Contains(source, forbidden) {
			return fmt.Errorf("v2 protocol production file %s contains forbidden live/secret marker %q", scope.file.path, forbidden)
		}
	}

	usedImports := make(map[string]bool)
	for _, importPath := range scope.file.alwaysImports {
		usedImports[importPath] = true
	}
	ast.Inspect(scope.node, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if ok {
			if importPath, exists := scope.file.imports[qualifier.Name]; exists {
				usedImports[importPath] = true
			}
		}
		return true
	})
	for importPath := range usedImports {
		for _, forbidden := range []string{
			"github.com/jywlabs/hal/internal/credentialmemory",
			"github.com/jywlabs/hal/internal/credentialsource",
			"github.com/jywlabs/hal/internal/credentialproxy",
			"github.com/jywlabs/hal/internal/factory",
			"crypto/tls",
			"net",
			"net/http",
			"os/exec",
		} {
			if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
				return fmt.Errorf("v2 protocol production file %s imports live/provider dependency %q", scope.file.path, importPath)
			}
		}
	}
	return nil
}

func l8WorkerV2DeclarationUnits(declaration ast.Decl) []ast.Decl {
	generated, ok := declaration.(*ast.GenDecl)
	if !ok || len(generated.Specs) <= 1 {
		return []ast.Decl{declaration}
	}
	units := make([]ast.Decl, 0, len(generated.Specs))
	for _, spec := range generated.Specs {
		unit := *generated
		unit.Lparen = token.NoPos
		unit.Rparen = token.NoPos
		unit.Specs = []ast.Spec{spec}
		units = append(units, &unit)
	}
	return units
}

func l8WorkerV2ASTContainsMarker(node ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if found {
			return false
		}
		switch typed := candidate.(type) {
		case *ast.Ident:
			found = strings.Contains(strings.ToLower(typed.Name), "v2")
		case *ast.BasicLit:
			found = strings.Contains(strings.ToLower(typed.Value), "v2")
		}
		return !found
	})
	return found
}

func TestL8WorkerV2GuardMixedFunctionsAreNarrowAndTransitive(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"client.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"client.go": `package sandboxworker
import httpalias "net/http"
func JobStartV2Fixture() {}
func unrelatedV1() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"client.go": `package sandboxworker
import httpalias "net/http"
func JobStartV2Fixture() { liveHelper() }
func liveHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardMixedSwitchesAuditCompleteReachableControlFlow(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"handler.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string) {
	switch operation {
	case "job_start_v2":
		safeHelper()
	}
}
func safeHelper() {}
func unrelatedLegacyDispatch() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	initializers := []struct {
		name   string
		source string
	}{
		{name: "value switch init", source: `package sandboxworker
import httpalias "net/http"
func forbiddenInit() int { _, _ = httpalias.Get("https://authority.example.invalid"); return 1 }
func dispatch(operation string) {
	switch initialized := forbiddenInit(); operation {
	case "job_start_v2": _ = initialized
	}
}`},
		{name: "type switch init", source: `package sandboxworker
import httpalias "net/http"
type JobStartV2Fixture struct{}
func forbiddenInit() int { _, _ = httpalias.Get("https://authority.example.invalid"); return 1 }
func dispatch(value any) {
	switch initialized := forbiddenInit(); value.(type) {
	case JobStartV2Fixture: _ = initialized
	}
}`},
	}
	for _, fixture := range initializers {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{"handler.go": fixture.source}, policy, "net/http")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string) {
	switch operation {
	case "job_start_v2":
		fallthrough
	case "job_start":
		_, _ = httpalias.Get("https://authority.example.invalid")
	}
}`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation, phase string) {
	switch operation {
	case "job_start_v2":
	}
	switch phase {
	case "legacy_phase":
		_, _ = httpalias.Get("https://authority.example.invalid")
	}
}`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardResolvesExactReceiverMethodObjects(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
import execalias "os/exec"
type safeReceiver struct{}
func (safeReceiver) dispatch() {}
type unsafeReceiver struct{}
func (unsafeReceiver) dispatch() { _ = execalias.Command("forbidden-live-helper") }`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() { safeReceiver{}.dispatch() }`,
		"shared.go": shared,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() { unsafeReceiver{}.dispatch() }`,
		"shared.go": shared,
	}, policy, "os/exec")
}

func TestL8WorkerV2GuardRejectsInterfaceAndFunctionValueDispatch(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
type dispatcher interface { dispatch() }
type concreteDispatcher struct{}
func (concreteDispatcher) dispatch() {}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() { concreteDispatcher{}.dispatch() }`,
		"shared.go": shared,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture(value dispatcher) { value.dispatch() }`,
		"shared.go": shared,
	}, policy, "interface dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobLogsV2Fixture() { fn := crossFileHelper; fn() }`,
		"shared.go": `package sandboxworker
func crossFileHelper() {}`,
	}, policy, "function-value dispatch")
}

func TestL8WorkerV2GuardRequiresEveryReachedFileOnExactAllowlist(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStatusV2Fixture() { crossFileHelper() }`,
		"unlisted_helper.go": `package sandboxworker
func crossFileHelper() {}`,
	}, policy, "outside the exact allowlist")
}

func l8AssertWorkerV2GuardAllows(t *testing.T, sources map[string]string, policy l8WorkerV2GuardPolicy) {
	t.Helper()
	if err := l8AuditWorkerV2Sources(sources, policy); err != nil {
		t.Fatalf("guard rejected safe fixture: %v", err)
	}
}

func l8AssertWorkerV2GuardRejects(t *testing.T, sources map[string]string, policy l8WorkerV2GuardPolicy, want string) {
	t.Helper()
	err := l8AuditWorkerV2Sources(sources, policy)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("guard error = %v, want rejection containing %q", err, want)
	}
}

func TestL8WorkerV2SourceGuardsPrincipalCannotBeDecodedFromJSON(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := l8ReadWorkerSource(t, path)
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		for _, declaration := range parsed.Decls {
			generated, ok := declaration.(*ast.GenDecl)
			if !ok || generated.Tok != token.TYPE {
				continue
			}
			for _, spec := range generated.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					tag, unquoteErr := strconv.Unquote(field.Tag.Value)
					if unquoteErr != nil {
						t.Fatalf("unquote field tag in %s: %v", path, unquoteErr)
					}
					jsonTag := strings.ToLower(reflectStructTagJSON(tag))
					if strings.Contains(jsonTag, "peeruid") || strings.Contains(jsonTag, "peergid") {
						t.Fatalf("production field in %s exposes peer credential through JSON tag %q", path, jsonTag)
					}
					if !strings.Contains(jsonTag, "principal") {
						continue
					}
					privateDurablePrincipal := filepath.Base(path) == "job_store_v2.go" && typeSpec.Name.Name == "storedJobStateV2" && jsonTag == "principalid"
					if privateDurablePrincipal && len(field.Names) == 1 && field.Names[0].Name == "PrincipalID" {
						continue
					}
					t.Fatalf("production field in %s exposes server-derived principal outside storedJobStateV2 through JSON tag %q", path, jsonTag)
				}
			}
		}
	}
}

func reflectStructTagJSON(tag string) string {
	for _, part := range strings.Fields(tag) {
		if strings.HasPrefix(part, `json:"`) {
			value := strings.TrimPrefix(part, `json:"`)
			return strings.TrimSuffix(value, `"`)
		}
	}
	return ""
}

func l8ReadWorkerSource(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
