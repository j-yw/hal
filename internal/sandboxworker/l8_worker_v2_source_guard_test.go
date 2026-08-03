package sandboxworker

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	pathpkg "path"
	"path/filepath"
	"reflect"
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
	allowedV2Files := map[string]bool{
		"client.go":          true,
		"handler.go":         true,
		"job_helpers.go":     true,
		"job_manager_v2.go":  true,
		"job_service_v2.go":  true,
		"job_store_v2.go":    true,
		"job_v2_client.go":   true,
		"job_v2_helpers.go":  true,
		"job_v2_service.go":  true,
		"job_v2_types.go":    true,
		"protocol_decode.go": true,
		"server.go":          true,
		"types.go":           true,
	}
	v2Markers := []string{
		"JobContractVersionV2",
		"OperationJobStartV2",
		"OperationJobResolveV2",
		"OperationJobStatusV2",
		"OperationJobLogsV2",
		"OperationJobCancelV2",
		"JobStartRequestV2",
		"JobResolveRequestV2",
		"JobStatusRequestV2",
		"JobLogsRequestV2",
		"JobCancelRequestV2",
		"JobCredentialIntentV2",
		"JobCredentialBindingV2",
		"JobLogsResponseV2",
		"JobV2",
		`json:"jobStartV2`,
		`json:"jobResolveV2`,
		`json:"jobStatusV2`,
		`json:"jobLogsV2`,
		`json:"jobCancelV2`,
		`json:"jobV2`,
	}
	sources := make(map[string]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := l8ReadWorkerSource(t, path)
		sources[path] = source
		containsV2 := false
		for _, marker := range v2Markers {
			if strings.Contains(source, marker) {
				containsV2 = true
				break
			}
		}
		if containsV2 && !allowedV2Files[path] {
			t.Fatalf("production file %s contains worker-v2 declarations/references outside the exact allowlist", path)
		}
	}
	scopedSources, scopedImports, err := l8WorkerV2PackageScope(sources)
	if err != nil {
		t.Fatalf("scope worker-v2 production declarations: %v", err)
	}
	for path, scopedSource := range scopedSources {
		if !allowedV2Files[path] {
			t.Fatalf("worker-v2 declaration closure reaches production file %s outside the exact allowlist", path)
		}
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
			if strings.Contains(scopedSource, forbidden) {
				t.Fatalf("v2 protocol production file %s contains forbidden live/secret marker %q", path, forbidden)
			}
		}
		for _, importPath := range scopedImports[path] {
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
					t.Fatalf("v2 protocol production file %s imports live/provider dependency %q", path, importPath)
				}
			}
		}
	}
}

type l8WorkerV2SourceFile struct {
	path            string
	fileSet         *token.FileSet
	parsed          *ast.File
	imports         map[string]string
	alwaysImports   []string
	declarationRefs []*l8WorkerV2SourceDeclaration
}

type l8WorkerV2SourceDeclaration struct {
	file        *l8WorkerV2SourceFile
	declaration ast.Decl
}

func l8WorkerV2PackageScope(sources map[string]string) (map[string]string, map[string][]string, error) {
	paths := make([]string, 0, len(sources))
	for sourcePath := range sources {
		paths = append(paths, sourcePath)
	}
	sort.Strings(paths)

	declarationsByName := make(map[string][]*l8WorkerV2SourceDeclaration)
	declarations := make([]*l8WorkerV2SourceDeclaration, 0)
	for _, sourcePath := range paths {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, sourcePath, sources[sourcePath], 0)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", sourcePath, err)
		}
		file := &l8WorkerV2SourceFile{
			path:    sourcePath,
			fileSet: fileSet,
			parsed:  parsed,
			imports: make(map[string]string, len(parsed.Imports)),
		}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return nil, nil, fmt.Errorf("unquote import in %s: %w", sourcePath, unquoteErr)
			}
			name := pathpkg.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." || name == "_" {
				file.alwaysImports = append(file.alwaysImports, importPath)
				continue
			}
			file.imports[name] = importPath
		}
		for _, declaration := range parsed.Decls {
			if declaration, ok := declaration.(*ast.GenDecl); ok && declaration.Tok == token.IMPORT {
				continue
			}
			for _, unit := range l8WorkerV2DeclarationUnits(declaration) {
				reference := &l8WorkerV2SourceDeclaration{file: file, declaration: unit}
				file.declarationRefs = append(file.declarationRefs, reference)
				declarations = append(declarations, reference)
				for _, name := range l8WorkerV2DeclaredNames(unit) {
					declarationsByName[name] = append(declarationsByName[name], reference)
				}
			}
		}
	}

	selected := make(map[*l8WorkerV2SourceDeclaration]ast.Node)
	queue := make([]*l8WorkerV2SourceDeclaration, 0)
	selectDeclaration := func(declaration *l8WorkerV2SourceDeclaration, scopedNode ast.Node) {
		if selected[declaration] != nil || scopedNode == nil {
			return
		}
		selected[declaration] = scopedNode
		queue = append(queue, declaration)
	}
	for _, declaration := range declarations {
		selectDeclaration(declaration, l8WorkerV2RootScope(declaration.declaration))
	}
	for len(queue) > 0 {
		declaration := queue[0]
		queue = queue[1:]
		scopedNode := selected[declaration]
		importIdentifiers := make(map[token.Pos]bool)
		ast.Inspect(scopedNode, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, isIdentifier := selector.X.(*ast.Ident)
			if !isIdentifier {
				return true
			}
			if _, isImport := declaration.file.imports[qualifier.Name]; isImport {
				importIdentifiers[qualifier.Pos()] = true
				importIdentifiers[selector.Sel.Pos()] = true
			}
			return true
		})
		ast.Inspect(scopedNode, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || importIdentifiers[identifier.Pos()] {
				return true
			}
			for _, referenced := range declarationsByName[identifier.Name] {
				referencedScope := l8WorkerV2RootScope(referenced.declaration)
				if referencedScope == nil {
					referencedScope = referenced.declaration
				}
				selectDeclaration(referenced, referencedScope)
			}
			return true
		})
	}

	scopedSources := make(map[string]string)
	scopedImports := make(map[string][]string)
	buffers := make(map[string]*bytes.Buffer)
	usedImports := make(map[string]map[string]bool)
	for _, declaration := range declarations {
		scopedNode := selected[declaration]
		if scopedNode == nil {
			continue
		}
		if buffers[declaration.file.path] == nil {
			buffers[declaration.file.path] = &bytes.Buffer{}
			usedImports[declaration.file.path] = make(map[string]bool)
			for _, importPath := range declaration.file.alwaysImports {
				usedImports[declaration.file.path][importPath] = true
			}
		}
		ast.Inspect(scopedNode, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if ok {
				if importPath, exists := declaration.file.imports[qualifier.Name]; exists {
					usedImports[declaration.file.path][importPath] = true
				}
			}
			return true
		})
		if err := format.Node(buffers[declaration.file.path], declaration.file.fileSet, scopedNode); err != nil {
			return nil, nil, fmt.Errorf("render declaration in %s: %w", declaration.file.path, err)
		}
		buffers[declaration.file.path].WriteByte('\n')
	}
	for sourcePath, buffer := range buffers {
		scopedSources[sourcePath] = buffer.String()
		for importPath := range usedImports[sourcePath] {
			scopedImports[sourcePath] = append(scopedImports[sourcePath], importPath)
		}
		sort.Strings(scopedImports[sourcePath])
	}
	return scopedSources, scopedImports, nil
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

func l8WorkerV2RootScope(declaration ast.Decl) ast.Node {
	if !l8WorkerV2ASTContainsMarker(declaration) {
		return nil
	}
	generated, ok := declaration.(*ast.GenDecl)
	if !ok || len(generated.Specs) != 1 {
		return declaration
	}
	typeSpec, ok := generated.Specs[0].(*ast.TypeSpec)
	if !ok || strings.Contains(strings.ToLower(typeSpec.Name.Name), "v2") {
		return declaration
	}
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		return declaration
	}
	fields := make([]*ast.Field, 0, len(structType.Fields.List))
	for _, field := range structType.Fields.List {
		if l8WorkerV2ASTContainsMarker(field) {
			fields = append(fields, field)
		}
	}
	if len(fields) == 0 {
		return declaration
	}
	clonedFields := *structType.Fields
	clonedFields.List = fields
	clonedStruct := *structType
	clonedStruct.Fields = &clonedFields
	clonedTypeSpec := *typeSpec
	clonedTypeSpec.Type = &clonedStruct
	clonedDeclaration := *generated
	clonedDeclaration.Specs = []ast.Spec{&clonedTypeSpec}
	return &clonedDeclaration
}

func l8WorkerV2DeclaredNames(declaration ast.Decl) []string {
	switch typed := declaration.(type) {
	case *ast.FuncDecl:
		return []string{typed.Name.Name}
	case *ast.GenDecl:
		var names []string
		for _, spec := range typed.Specs {
			switch value := spec.(type) {
			case *ast.TypeSpec:
				names = append(names, value.Name.Name)
			case *ast.ValueSpec:
				for _, name := range value.Names {
					names = append(names, name.Name)
				}
			}
		}
		return names
	default:
		return nil
	}
}

func l8WorkerV2ASTContainsMarker(node ast.Node) bool {
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

func TestL8WorkerV2MixedFileGuardIncludesTransitiveHelpersAndTheirImports(t *testing.T) {
	generatedHelper := "hide" + strings.ReplaceAll(t.Name(), "/", "")
	sources := map[string]string{"generated_fixture.go": `package sandboxworker
import httpalias "net/http"
func JobStartV2Fixture() { ` + generatedHelper + `() }
func ` + generatedHelper + `() { _, _ = httpalias.Get("https://authority.example.invalid") }
func unrelatedV1() {}`}
	scoped, imports, err := l8WorkerV2PackageScope(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(scoped["generated_fixture.go"], generatedHelper) || !strings.Contains(scoped["generated_fixture.go"], "httpalias.Get") {
		t.Fatalf("mixed-file scope omitted transitively called helper:\n%s", scoped["generated_fixture.go"])
	}
	if !reflect.DeepEqual(imports["generated_fixture.go"], []string{"net/http"}) {
		t.Fatalf("mixed-file scoped imports = %v, want forbidden transitive import", imports)
	}
}

func TestL8WorkerV2PackageGuardFollowsFunctionValueReferences(t *testing.T) {
	generatedHelper := "functionValue" + strings.ReplaceAll(t.Name(), "/", "")
	sources := map[string]string{"function_value_fixture.go": `package sandboxworker
import tlsalias "crypto/tls"
func JobLogsV2Fixture() { fn := ` + generatedHelper + `; fn() }
func ` + generatedHelper + `() { _ = tlsalias.VersionTLS13 }`}
	scoped, imports, err := l8WorkerV2PackageScope(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(scoped["function_value_fixture.go"], generatedHelper) || !strings.Contains(scoped["function_value_fixture.go"], "tlsalias.VersionTLS13") {
		t.Fatalf("package scope omitted function-value helper:\n%s", scoped["function_value_fixture.go"])
	}
	if !reflect.DeepEqual(imports["function_value_fixture.go"], []string{"crypto/tls"}) {
		t.Fatalf("function-value scoped imports = %v, want forbidden helper import", imports)
	}
}

func TestL8WorkerV2PackageGuardDoesNotOvercloseMixedEnvelopeSiblings(t *testing.T) {
	sources := map[string]string{
		"types.go": `package sandboxworker
type Request struct {
	V1 *LegacyRequest ` + "`json:\"v1,omitempty\"`" + `
	V2 *JobStartRequestV2 ` + "`json:\"v2,omitempty\"`" + `
}
type JobStartRequestV2 struct { ContractVersion string }`,
		"job_types.go": `package sandboxworker
type LegacyRequest struct { SecretValue string }`,
	}
	scoped, _, err := l8WorkerV2PackageScope(sources)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scoped["types.go"], "LegacyRequest") || scoped["job_types.go"] != "" {
		t.Fatalf("mixed V2 envelope overclosed through unrelated V1 sibling: types=%q legacy=%q", scoped["types.go"], scoped["job_types.go"])
	}
	if !strings.Contains(scoped["types.go"], "JobStartRequestV2") {
		t.Fatalf("mixed V2 envelope omitted V2 field/type: %q", scoped["types.go"])
	}
}

func TestL8WorkerV2PackageGuardIncludesCrossFileHelpersAndTheirImports(t *testing.T) {
	generatedHelper := "crossFile" + strings.ReplaceAll(t.Name(), "/", "")
	sources := map[string]string{
		"v2_root.go": `package sandboxworker
func JobStatusV2Fixture() { ` + generatedHelper + `() }`,
		"shared_helper.go": `package sandboxworker
import execalias "os/exec"
func ` + generatedHelper + `() { _ = execalias.Command("forbidden-live-helper") }`,
	}
	scoped, imports, err := l8WorkerV2PackageScope(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(scoped["shared_helper.go"], generatedHelper) || !strings.Contains(scoped["shared_helper.go"], "execalias.Command") {
		t.Fatalf("package scope omitted cross-file helper:\n%s", scoped["shared_helper.go"])
	}
	if !reflect.DeepEqual(imports["shared_helper.go"], []string{"os/exec"}) {
		t.Fatalf("cross-file scoped imports = %v, want forbidden helper import", imports)
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
