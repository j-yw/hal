package sandboxworker

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
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
	path           string
	fileSet        *token.FileSet
	parsed         *ast.File
	imports        map[string]string
	alwaysImports  []string
	valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec
}

type l8WorkerV2GuardScope struct {
	file *l8WorkerV2ParsedFile
	node ast.Node
}

type l8WorkerV2SemanticUnit struct {
	scope       l8WorkerV2GuardScope
	definitions []types.Object
	uses        []types.Object
	tainted     bool
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
		valueSpecUnits, err := l8WorkerV2NormalizeValueSpecUnits(parsed)
		if err != nil {
			return fmt.Errorf("normalize value declarations in %s: %w", path, err)
		}
		file := &l8WorkerV2ParsedFile{
			path:           path,
			fileSet:        fileSet,
			parsed:         parsed,
			imports:        make(map[string]string, len(parsed.Imports)),
			valueSpecUnits: valueSpecUnits,
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
				for _, node := range l8WorkerV2MixedDeclarationScopes(declaration, file.valueSpecUnits) {
					roots = append(roots, l8WorkerV2GuardScope{file: file, node: node})
				}
			}
		}
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
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
	config := types.Config{Importer: l8WorkerV2GuardImporter{fallback: typeImporter}}
	checkedPackage, err := config.Check("github.com/jywlabs/hal/internal/sandboxworker", fileSet, astFiles, info)
	if err != nil {
		return fmt.Errorf("type-check worker-v2 guard sources: %w", err)
	}
	semanticRoots := l8WorkerV2SemanticRoots(parsedFiles, info)
	roots = append(roots, semanticRoots...)
	if len(roots) == 0 {
		return nil
	}
	// Initializers execute before any request can reach a V2 handler. Once the
	// package contains V2-relevant production, every package initializer is
	// therefore part of the reachable process-global surface.
	roots = append(roots, l8WorkerV2PackageInitializerRoots(parsedFiles)...)

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
						for _, unit := range file.valueSpecUnits[value] {
							for _, name := range unit.Names {
								if object := info.Defs[name]; object != nil {
									objects[object] = l8WorkerV2GuardScope{file: file, node: unit}
								}
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
		if function, ok := scope.node.(*ast.FuncDecl); ok && function.Body == nil {
			return fmt.Errorf("worker-v2 production path in %s reaches forbidden bodyless declaration", scope.file.path)
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

func l8WorkerV2SemanticRoots(files []*l8WorkerV2ParsedFile, info *types.Info) []l8WorkerV2GuardScope {
	var units []l8WorkerV2SemanticUnit
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			for _, node := range l8WorkerV2SemanticDeclarationUnits(declaration, file.valueSpecUnits) {
				unit := l8WorkerV2SemanticUnit{
					scope:   l8WorkerV2GuardScope{file: file, node: node},
					tainted: l8WorkerV2ASTContainsMarker(node) || l8WorkerV2ContainsExactOperationConstant(node, info),
				}
				ast.Inspect(node, func(candidate ast.Node) bool {
					identifier, ok := candidate.(*ast.Ident)
					if !ok {
						return true
					}
					if object := info.Defs[identifier]; object != nil {
						unit.definitions = append(unit.definitions, object)
					}
					if object := info.Uses[identifier]; object != nil {
						unit.uses = append(unit.uses, object)
					}
					return true
				})
				units = append(units, unit)
			}
		}
	}

	taintedObjects := make(map[types.Object]bool)
	addDefinitions := func(unit l8WorkerV2SemanticUnit) {
		for _, object := range unit.definitions {
			taintedObjects[object] = true
		}
	}
	for _, unit := range units {
		if unit.tainted {
			addDefinitions(unit)
		}
	}
	for changed := true; changed; {
		changed = false
		for index := range units {
			if units[index].tainted {
				continue
			}
			for _, object := range units[index].uses {
				if !taintedObjects[object] {
					continue
				}
				units[index].tainted = true
				addDefinitions(units[index])
				changed = true
				break
			}
		}
	}

	var roots []l8WorkerV2GuardScope
	for _, unit := range units {
		if unit.tainted {
			roots = append(roots, unit.scope)
		}
	}
	return roots
}

func l8WorkerV2PackageInitializerRoots(files []*l8WorkerV2ParsedFile) []l8WorkerV2GuardScope {
	var roots []l8WorkerV2GuardScope
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || function.Name.Name != "init" {
				continue
			}
			roots = append(roots, l8WorkerV2GuardScope{file: file, node: function})
		}
	}
	return roots
}

func l8WorkerV2ContainsExactOperationConstant(node ast.Node, info *types.Info) bool {
	if node == nil || info == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if found {
			return false
		}
		if expression, ok := candidate.(ast.Expr); ok {
			found = l8WorkerV2IsExactOperationConstant(info.Types[expression].Value)
			if !found {
				value, exact := l8WorkerV2StaticString(expression, info)
				found = exact && l8WorkerV2IsExactOperationString(value)
			}
		}
		identifier, ok := candidate.(*ast.Ident)
		if !ok || found {
			return !found
		}
		for _, object := range []types.Object{info.Defs[identifier], info.Uses[identifier]} {
			value, ok := object.(*types.Const)
			if ok && l8WorkerV2IsExactOperationConstant(value.Val()) {
				found = true
				break
			}
		}
		return !found
	})
	return found
}

func l8WorkerV2StaticString(expression ast.Expr, info *types.Info) (string, bool) {
	if expression == nil || info == nil {
		return "", false
	}
	if value := info.Types[expression].Value; value != nil && value.Kind() == constant.String {
		return constant.StringVal(value), true
	}
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return l8WorkerV2StaticString(typed.X, info)
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", false
		}
		left, leftOK := l8WorkerV2StaticString(typed.X, info)
		right, rightOK := l8WorkerV2StaticString(typed.Y, info)
		if !leftOK || !rightOK {
			return "", false
		}
		return left + right, true
	case *ast.CallExpr:
		if len(typed.Args) != 1 || !l8WorkerV2IsStringConversion(typed.Fun, info) {
			return "", false
		}
		return l8WorkerV2StaticCodePoints(typed.Args[0], info)
	default:
		return "", false
	}
}

func l8WorkerV2IsStringConversion(expression ast.Expr, info *types.Info) bool {
	identifier, ok := expression.(*ast.Ident)
	if !ok || identifier.Name != "string" {
		return false
	}
	typeName, ok := info.Uses[identifier].(*types.TypeName)
	if !ok {
		return false
	}
	basic, ok := typeName.Type().Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func l8WorkerV2StaticCodePoints(expression ast.Expr, info *types.Info) (string, bool) {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.CallExpr:
			if len(typed.Args) != 1 {
				return "", false
			}
			if _, ok := info.TypeOf(typed.Fun).(*types.Signature); ok {
				return "", false
			}
			expression = typed.Args[0]
		default:
			goto unwrapped
		}
	}

unwrapped:
	literal, ok := expression.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	typ := info.TypeOf(literal)
	if typ == nil {
		return "", false
	}
	underlying := typ.Underlying()
	var element types.Type
	switch typed := underlying.(type) {
	case *types.Slice:
		element = typed.Elem()
	case *types.Array:
		element = typed.Elem()
	default:
		return "", false
	}
	basic, ok := types.Unalias(element).Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return "", false
	}
	indexedValues := make(map[int64]rune, len(literal.Elts))
	nextIndex := int64(0)
	maxIndex := int64(-1)
	for _, rawElement := range literal.Elts {
		index := nextIndex
		if keyed, ok := rawElement.(*ast.KeyValueExpr); ok {
			key := info.Types[keyed.Key].Value
			if key == nil || key.Kind() != constant.Int {
				return "", false
			}
			var exact bool
			index, exact = constant.Int64Val(key)
			if !exact || index < 0 {
				return "", false
			}
			rawElement = keyed.Value
		}
		expression, ok := rawElement.(ast.Expr)
		if !ok {
			return "", false
		}
		value := info.Types[expression].Value
		if value == nil || value.Kind() != constant.Int {
			return "", false
		}
		integer, exact := constant.Int64Val(value)
		if !exact || integer < 0 || integer > 0x10ffff {
			return "", false
		}
		indexedValues[index] = rune(integer)
		if index > maxIndex {
			maxIndex = index
		}
		nextIndex = index + 1
	}
	values := make([]rune, maxIndex+1)
	for index, value := range indexedValues {
		values[index] = value
	}
	if basic.Kind() == types.Uint8 {
		bytesValue := make([]byte, len(values))
		for index, value := range values {
			if value > 0xff {
				return "", false
			}
			bytesValue[index] = byte(value)
		}
		return string(bytesValue), true
	}
	return string(values), true
}

func l8WorkerV2IsExactOperationConstant(value constant.Value) bool {
	if value == nil || value.Kind() != constant.String {
		return false
	}
	return l8WorkerV2IsExactOperationString(constant.StringVal(value))
}

func l8WorkerV2IsExactOperationString(value string) bool {
	switch value {
	case "job_start_v2", "job_resolve_v2", "job_status_v2", "job_logs_v2", "job_cancel_v2":
		return true
	default:
		return false
	}
}

func l8WorkerV2SemanticDeclarationUnits(declaration ast.Decl, valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec) []ast.Node {
	switch typed := declaration.(type) {
	case *ast.FuncDecl:
		return []ast.Node{typed}
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return nil
		}
		var units []ast.Node
		for _, spec := range typed.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for _, unit := range valueSpecUnits[valueSpec] {
					units = append(units, unit)
				}
				continue
			}
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || l8WorkerV2ASTContainsMarker(typeSpec.Name) {
				units = append(units, spec)
				continue
			}
			switch value := typeSpec.Type.(type) {
			case *ast.StructType:
				for _, field := range value.Fields.List {
					units = append(units, field)
				}
			case *ast.InterfaceType:
				for _, field := range value.Methods.List {
					units = append(units, field)
				}
			default:
				units = append(units, spec)
			}
		}
		return units
	default:
		return nil
	}
}

func l8WorkerV2NormalizeValueSpecUnits(file *ast.File) (map[*ast.ValueSpec][]*ast.ValueSpec, error) {
	unitsBySpec := make(map[*ast.ValueSpec][]*ast.ValueSpec)
	for _, declaration := range file.Decls {
		generated, ok := declaration.(*ast.GenDecl)
		if !ok || generated.Tok == token.IMPORT {
			continue
		}

		var inheritedValues []ast.Expr
		var inheritedType ast.Expr
		for _, rawSpec := range generated.Specs {
			spec, ok := rawSpec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			effective := spec
			if generated.Tok == token.CONST {
				switch {
				case len(spec.Values) > 0:
					inheritedValues = spec.Values
					inheritedType = spec.Type
				case len(inheritedValues) == 0:
					return nil, fmt.Errorf("const declaration omits values before a preceding expression list")
				default:
					clone := *spec
					clone.Type = inheritedType
					clone.Values = append([]ast.Expr(nil), inheritedValues...)
					effective = &clone
				}
				if len(effective.Names) == 0 || len(effective.Names) != len(effective.Values) {
					return nil, fmt.Errorf("const declaration has ambiguous name/value cardinality")
				}
			}
			unitsBySpec[spec] = l8WorkerV2SplitValueSpecSemanticUnits(effective)
		}
	}
	return unitsBySpec, nil
}

func l8WorkerV2SplitValueSpecSemanticUnits(spec *ast.ValueSpec) []*ast.ValueSpec {
	if len(spec.Names) == 0 || len(spec.Names) != len(spec.Values) {
		// A single RHS may produce multiple values. Likewise, an explicit type
		// applies to every name in a declaration without initializers. Keep those
		// declarations whole so one V2 dependency cannot be hidden in a sibling.
		return []*ast.ValueSpec{spec}
	}

	units := make([]*ast.ValueSpec, 0, len(spec.Names))
	for index, name := range spec.Names {
		unit := *spec
		unit.Names = []*ast.Ident{name}
		unit.Values = []ast.Expr{spec.Values[index]}
		units = append(units, &unit)
	}
	return units
}

func l8WorkerV2ImportValues(imports map[string]string) []string {
	values := make([]string, 0, len(imports))
	for _, importPath := range imports {
		values = append(values, importPath)
	}
	return values
}

type l8WorkerV2GuardImporter struct {
	fallback types.Importer
}

func (value l8WorkerV2GuardImporter) Import(path string) (*types.Package, error) {
	if path == "golang.org/x/sys/unix" {
		return l8WorkerV2UnixFixturePackage(), nil
	}
	return value.fallback.Import(path)
}

func l8WorkerV2UnixFixturePackage() *types.Package {
	pkg := types.NewPackage("golang.org/x/sys/unix", "unix")
	scope := pkg.Scope()
	empty := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	for _, name := range []string{
		"RawSyscall", "RawSyscall6", "Syscall", "Syscall6", "Socket", "Connect",
		"Mmap", "Mlock", "Munlock", "Munmap", "Exec", "Kill", "Mount", "Unshare", "Setns",
	} {
		scope.Insert(types.NewFunc(token.NoPos, pkg, name, empty))
	}
	errorType := types.Universe.Lookup("error").Type()
	flockParameters := types.NewTuple(
		types.NewParam(token.NoPos, pkg, "fd", types.Typ[types.Int]),
		types.NewParam(token.NoPos, pkg, "how", types.Typ[types.Int]),
	)
	flockResults := types.NewTuple(types.NewParam(token.NoPos, pkg, "err", errorType))
	scope.Insert(types.NewFunc(token.NoPos, pkg, "Flock", types.NewSignatureType(nil, nil, nil, flockParameters, flockResults, false)))
	statFields := []*types.Var{
		types.NewField(token.NoPos, pkg, "Uid", types.Typ[types.Uint32], false),
		types.NewField(token.NoPos, pkg, "Gid", types.Typ[types.Uint32], false),
		types.NewField(token.NoPos, pkg, "Mode", types.Typ[types.Uint32], false),
	}
	statName := types.NewTypeName(token.NoPos, pkg, "Stat_t", nil)
	types.NewNamed(statName, types.NewStruct(statFields, nil), nil)
	scope.Insert(statName)
	for index, name := range []string{"LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"} {
		scope.Insert(types.NewConst(token.NoPos, pkg, name, types.Typ[types.UntypedInt], constant.MakeInt64(int64(index+1))))
	}
	pkg.MarkComplete()
	return pkg
}

func l8WorkerV2MixedDeclarationScopes(declaration ast.Decl, valueSpecUnits map[*ast.ValueSpec][]*ast.ValueSpec) []ast.Node {
	switch typed := declaration.(type) {
	case *ast.GenDecl:
		if typed.Tok == token.IMPORT {
			return nil
		}
		var scopes []ast.Node
		for _, spec := range typed.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for _, unit := range valueSpecUnits[valueSpec] {
					if l8WorkerV2ASTContainsMarker(unit) {
						scopes = append(scopes, unit)
					}
				}
				continue
			}
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
	if err := l8RejectWorkerV2SemanticExternalSurfaces(scope, info); err != nil {
		return err
	}
	var inspectionErr error
	ast.Inspect(scope.node, func(node ast.Node) bool {
		if inspectionErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if l8WorkerV2CallMayInvokeImplicitInterface(call, info) {
			inspectionErr = fmt.Errorf("worker-v2 production path in %s uses forbidden implicit interface callback through external call", scope.file.path)
			return false
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

func l8WorkerV2CallMayInvokeImplicitInterface(call *ast.CallExpr, info *types.Info) bool {
	object := l8WorkerV2CalledObject(call.Fun, info)
	if object == nil || object.Pkg() == nil || object.Pkg().Path() == "github.com/jywlabs/hal/internal/sandboxworker" {
		return false
	}
	// Imports with their own stronger dynamic-runtime guard retain that stable
	// evidence instead of being reported through the more general callback rule.
	if object.Pkg().Path() == "reflect" {
		return false
	}
	signature, ok := object.Type().Underlying().(*types.Signature)
	if !ok || signature.Params() == nil || signature.Params().Len() == 0 {
		return false
	}
	for index, argument := range call.Args {
		parameterIndex := index
		if parameterIndex >= signature.Params().Len() {
			if !signature.Variadic() {
				break
			}
			parameterIndex = signature.Params().Len() - 1
		}
		parameterType := signature.Params().At(parameterIndex).Type()
		if signature.Variadic() && parameterIndex == signature.Params().Len()-1 {
			if slice, ok := parameterType.(*types.Slice); ok {
				parameterType = slice.Elem()
			}
		}
		if !l8WorkerV2IsInterfaceType(parameterType) {
			continue
		}
		if l8WorkerV2InterfaceCapableArgument(info.TypeOf(argument)) {
			return true
		}
	}
	return false
}

func l8WorkerV2CalledObject(expression ast.Expr, info *types.Info) types.Object {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.Ident:
			return info.Uses[typed]
		case *ast.SelectorExpr:
			if selection := info.Selections[typed]; selection != nil {
				return selection.Obj()
			}
			return info.Uses[typed.Sel]
		default:
			return nil
		}
	}
}

func l8WorkerV2InterfaceCapableArgument(typ types.Type) bool {
	if typ == nil {
		return false
	}
	if l8WorkerV2IsInterfaceType(typ) {
		return true
	}
	if l8WorkerV2LocalNamedType(typ) == nil {
		return false
	}
	return types.NewMethodSet(typ).Len() > 0 || types.NewMethodSet(types.NewPointer(typ)).Len() > 0
}

func l8WorkerV2LocalNamedType(typ types.Type) *types.Named {
	if typ == nil {
		return nil
	}
	typ = types.Unalias(typ)
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/jywlabs/hal/internal/sandboxworker" {
		return nil
	}
	return named
}

func l8RejectWorkerV2SemanticExternalSurfaces(scope l8WorkerV2GuardScope, info *types.Info) error {
	selectorIdentifiers := make(map[*ast.Ident]bool)
	directCallSelectors := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(scope.node, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			selectorIdentifiers[selector.Sel] = true
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if selector := l8WorkerV2CalledSelector(call.Fun); selector != nil {
				directCallSelectors[selector] = true
			}
		}
		return true
	})

	var inspectionErr error
	ast.Inspect(scope.node, func(node ast.Node) bool {
		if inspectionErr != nil {
			return false
		}
		var surface string
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if selection := info.Selections[typed]; selection != nil {
				surface = l8WorkerV2ForbiddenSelectionSurface(selection, directCallSelectors[typed])
			} else {
				surface = l8WorkerV2ForbiddenObjectSurface(info.Uses[typed.Sel])
			}
		case *ast.Ident:
			if selectorIdentifiers[typed] {
				return true
			}
			surface = l8WorkerV2ForbiddenObjectSurface(info.Uses[typed])
		}
		if surface != "" {
			inspectionErr = fmt.Errorf("worker-v2 production path in %s uses forbidden external live surface %q", scope.file.path, surface)
			return false
		}
		return true
	})
	return inspectionErr
}

func l8WorkerV2CalledSelector(expression ast.Expr) *ast.SelectorExpr {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			expression = typed.X
		case *ast.IndexListExpr:
			expression = typed.X
		case *ast.SelectorExpr:
			return typed
		default:
			return nil
		}
	}
}

func l8WorkerV2ForbiddenSelectionSurface(selection *types.Selection, directCall bool) string {
	if selection == nil {
		return ""
	}
	if !directCall && l8WorkerV2SelectionUsesInterface(selection) {
		return "interface method-value"
	}
	receiver := l8WorkerV2NamedTypeObject(selection.Recv())
	if receiver != nil && receiver.Pkg() != nil {
		path := receiver.Pkg().Path()
		if path == "os" && (receiver.Name() == "Process" || receiver.Name() == "ProcessState") {
			return path + "." + selection.Obj().Name()
		}
		if selection.Kind() == types.FieldVal && l8WorkerV2RawSyscallPackage(path) && receiver.Name() == "Stat_t" {
			return ""
		}
	}
	return l8WorkerV2ForbiddenObjectSurface(selection.Obj())
}

func l8WorkerV2NamedTypeObject(typ types.Type) *types.TypeName {
	if typ == nil {
		return nil
	}
	typ = types.Unalias(typ)
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return nil
	}
	return named.Obj()
}

func l8WorkerV2ForbiddenObjectSurface(object types.Object) string {
	if object == nil || object.Pkg() == nil {
		return ""
	}
	path := object.Pkg().Path()
	name := object.Name()
	switch {
	case path == "unsafe", path == "plugin":
		return path + "." + name
	case l8WorkerV2RawSyscallPackage(path):
		if l8WorkerV2AllowedRawSyscallObject(name) {
			return ""
		}
		return path + "." + name
	case path == "os" && l8WorkerV2ForbiddenOSObject(name):
		return path + "." + name
	case path == "log" && l8WorkerV2ForbiddenLogObject(name):
		return path + "." + name
	default:
		return ""
	}
}

func l8WorkerV2RawSyscallPackage(path string) bool {
	return path == "syscall" || path == "golang.org/x/sys/unix"
}

func l8WorkerV2AllowedRawSyscallObject(name string) bool {
	switch name {
	case "Flock", "Stat_t", "LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN", "EINTR", "EAGAIN", "EWOULDBLOCK":
		return true
	default:
		return false
	}
}

func l8WorkerV2ForbiddenOSObject(name string) bool {
	switch name {
	case "Args", "Stdin", "Stdout", "Stderr", "Interrupt", "Kill", "Chdir",
		"Process", "ProcessState", "ProcAttr", "Signal", "StartProcess", "FindProcess", "Exit",
		"Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv", "Unsetenv", "Clearenv",
		"Getpid", "Getppid", "Getuid", "Geteuid", "Getgid", "Getegid", "Getgroups",
		"Executable", "Hostname", "UserHomeDir", "UserCacheDir", "UserConfigDir", "Pipe", "NewFile":
		return true
	default:
		return false
	}
}

func l8WorkerV2ForbiddenLogObject(name string) bool {
	switch name {
	case "Fatal", "Fatalf", "Fatalln":
		return true
	default:
		return false
	}
}

func l8WorkerV2DynamicCallKind(expression ast.Expr, info *types.Info) string {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.IndexExpr:
			if !l8WorkerV2IsGenericInstantiation(typed, typed.X, info) {
				return "function-value"
			}
			expression = typed.X
		case *ast.IndexListExpr:
			if !l8WorkerV2IsGenericInstantiation(typed, typed.X, info) {
				return "function-value"
			}
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
			if l8WorkerV2SelectionUsesInterface(selection) {
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

func l8WorkerV2SelectionUsesInterface(selection *types.Selection) bool {
	if selection == nil {
		return false
	}
	if l8WorkerV2IsInterfaceType(selection.Recv()) {
		return true
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	signature, _ := method.Type().(*types.Signature)
	return signature != nil && signature.Recv() != nil && l8WorkerV2IsInterfaceType(signature.Recv().Type())
}

func l8WorkerV2IsGenericInstantiation(indexed ast.Expr, base ast.Expr, info *types.Info) bool {
	// Type information distinguishes a semantic generic instantiation from an
	// ordinary map, slice, or array lookup whose result happens to be callable.
	if _, ok := info.Types[indexed]; !ok {
		return false
	}
	for {
		switch typed := base.(type) {
		case *ast.ParenExpr:
			base = typed.X
		case *ast.Ident:
			_, ok := info.Instances[typed]
			return ok
		case *ast.SelectorExpr:
			_, ok := info.Instances[typed.Sel]
			return ok
		default:
			return false
		}
	}
}

func l8WorkerV2IsInterfaceType(typ types.Type) bool {
	for typ != nil {
		if pointer, ok := typ.(*types.Pointer); ok {
			typ = pointer.Elem()
			continue
		}
		if pointer, ok := typ.Underlying().(*types.Pointer); ok {
			typ = pointer.Elem()
			continue
		}
		_, ok := typ.Underlying().(*types.Interface)
		return ok
	}
	return false
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
			"os/signal",
			"plugin",
			"reflect",
			"runtime",
			"runtime/debug",
			"runtime/pprof",
			"runtime/trace",
			"unsafe",
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

func TestL8WorkerV2GuardSemanticAliasesTaintConsumers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
type JobStartRequestV2 struct{}`
	aliases := `package sandboxworker
const selectedOperation = OperationJobStartV2
const routedOperation, legacyOperation = selectedOperation, "job_start"
type selectedRequest = JobStartRequestV2
type routedRequest = selectedRequest`

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
import httpalias "net/http"
func dispatch(operation string, request routedRequest) {
	switch operation {
	case routedOperation:
		safeHelper(request)
	}
}
func unrelatedLegacyDispatch() {
	_ = legacyOperation
	_, _ = httpalias.Get("https://legacy.example.invalid")
}`,
		"shared.go": `package sandboxworker
func safeHelper(routedRequest) {}`,
	}, policy)

	for _, fixture := range []struct {
		name    string
		handler string
	}{
		{name: "const alias chain", handler: `package sandboxworker
func dispatch(operation string) {
	switch operation {
	case routedOperation:
		forbiddenHelper()
	}
}`},
		{name: "type alias chain", handler: `package sandboxworker
func dispatch(request routedRequest) { forbiddenHelperWithRequest(request) }`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   aliases,
				"handler.go":   fixture.handler,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }
func forbiddenHelperWithRequest(routedRequest) { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"unlisted_handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == routedOperation {}
}`,
	}, policy, "outside the exact allowlist")
}

func TestL8WorkerV2GuardRecognizesExactOperationConstantValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	for _, fixture := range []struct {
		name       string
		definition string
	}{
		{name: "start escaped literal", definition: `const hiddenOperation = "job_start_v\u0032"`},
		{name: "resolve concatenation", definition: `const hiddenOperation = "job_" + "resolve_" + "v" + "2"`},
		{name: "status parenthesized conversion", definition: `const hiddenOperation = string((("job_status_" + "v" + "2")))`},
		{name: "logs alias conversion", definition: "type operationAlias = string\nconst hiddenOperation = operationAlias((\"job_logs_\" + \"v\" + \"2\"))"},
		{name: "cancel named conversion", definition: "type operationValue string\nconst hiddenOperation = operationValue(\"job_cancel_\" + string('v') + string('2'))"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   "package sandboxworker\n" + fixture.definition,
				"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == string(hiddenOperation) { forbiddenRoutedHelper() }
}`,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}
}

func TestL8WorkerV2GuardRecognizesRuntimeBuiltExactOperationValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
type JobStartRequestV2 struct{}`
	for _, fixture := range []struct {
		name       string
		definition string
	}{
		{
			name:       "byte slice conversion",
			definition: `var hiddenOperation = string([]byte{106, 111, 98, 95, 115, 116, 97, 114, 116, 95, 118, 50})`,
		},
		{
			name:       "keyed byte slice conversion",
			definition: `var hiddenOperation = string([]byte{9: 95, 10: 118, 11: 50, 0: 106, 1: 111, 2: 98, 3: 95, 4: 115, 5: 116, 6: 97, 7: 114, 8: 116})`,
		},
		{
			name: "named byte slice conversion",
			definition: `type operationBytes []byte
var hiddenOperation = string(operationBytes{106, 111, 98, 95, 115, 116, 97, 116, 117, 115, 95, 118, 50})`,
		},
		{
			name: "local builder wrapper",
			definition: `func hiddenOperation() string {
	return string([]rune{106, 111, 98, 95, 114, 101, 115, 111, 108, 118, 101, 95, 118, 50})
}`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			operation := "hiddenOperation"
			if strings.Contains(fixture.definition, "func hiddenOperation") {
				operation += "()"
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   "package sandboxworker\n" + fixture.definition,
				"handler.go": `package sandboxworker
func dispatch(operation string) hiddenSchema {
	if operation == ` + operation + ` { forbiddenRoutedHelper() }
	return hiddenSchema{}
}`,
				"shared.go": `package sandboxworker
import processapi "os"
type hiddenSchema struct { Value string ` + "`json:\"value\"`" + ` }
func forbiddenRoutedHelper() { _, _ = processapi.StartProcess("worker", nil, nil) }`,
			}, policy, `json:\"value`)
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
var hiddenLegacyOperation = string([]byte{106, 111, 98, 95, 115, 116, 97, 114, 116})`,
		"handler.go": `package sandboxworker
func legacyDispatch(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsUnboundedRuntimeOperationAssembly(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": `package sandboxworker
type JobStartRequestV2 struct{}`,
		"aliases.go": `package sandboxworker
var hiddenOperation = string([]byte{9223372036854775807: 50})`,
	}, policy, "runtime operation assembly")
}

func TestL8WorkerV2GuardRejectsDirectStdlibRuntimeOperationAssembly(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"contracts.go": true}}
	contracts := `package sandboxworker
type JobStartRequestV2 struct{}`
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "strings join",
			source: `package sandboxworker
import text "strings"
var hiddenOperation = text.Join([]string{"job", "_start_", "v", "2"}, "")`,
		},
		{
			name: "fmt sprintf",
			source: `package sandboxworker
import formatting "fmt"
var hiddenOperation = formatting.Sprintf("%s%c%d", "job_status_", 'v', 2)`,
		},
		{
			name: "strings repeat",
			source: `package sandboxworker
import text "strings"
var hiddenOperation = "job_logs_" + text.Repeat("v", 1) + string([]byte{50})`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"unlisted.go":  fixture.source,
			}, policy, "outside the exact allowlist")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
func JobStartV2Fixture() string { return OperationJobStartV2 }`,
		"legacy.go": `package sandboxworker
import text "strings"
func unrelatedLegacyText(parts []string) string { return text.Join(parts, "") }`,
	}, l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"legacy.go":    true,
	}})
}

func TestL8WorkerV2GuardConstantValueTaintClosesChainsAndUnlistedRoots(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"chain.go":     true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	shared := `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`

	t.Run("cross-file alias chain", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"aliases.go": `package sandboxworker
const hiddenRoot = "job_resolve_" + "v" + "2"`,
			"chain.go": `package sandboxworker
const hiddenAlias = ((hiddenRoot))`,
			"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == hiddenAlias { forbiddenRoutedHelper() }
}`,
			"shared.go": shared,
		}, policy, "net/http")
	})

	t.Run("inherited constant", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"aliases.go": `package sandboxworker
const (
	hiddenRoot = "job_cancel_" + "v" + "2"
	hiddenInherited
)`,
			"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == hiddenInherited { forbiddenRoutedHelper() }
}`,
			"shared.go": shared,
		}, policy, "net/http")
	})

	t.Run("unlisted semantic root", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"contracts.go": contracts,
			"unlisted.go": `package sandboxworker
const hiddenOperation = "job_logs_v\u0032"`,
		}, policy, "outside the exact allowlist")
	})

	t.Run("unlisted semantic root without visible root", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"unlisted.go": `package sandboxworker
const hiddenOperation = "job_start_" + "v" + "2"`,
		}, policy, "outside the exact allowlist")
	})
}

func TestL8WorkerV2GuardExactOperationValuesDoNotOvertaintV1Siblings(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`,
		"aliases.go": `package sandboxworker
const hiddenRoutedOperation, hiddenLegacyOperation = "job_status_" + "v" + "2", string(("job_" + "status"))`,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)
}

func TestL8WorkerV2GuardGroupedValueSpecsRemainSemanticallyPrecise(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"`
	aliases := `package sandboxworker
const routedOperation, legacyOperation = OperationJobStartV2, "job_start"`

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
func JobStartHandler(operation string) {
	if operation == routedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == legacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   aliases,
		"handler.go": `package sandboxworker
func JobStartHandler(operation string) {
	if operation == routedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	for _, fixture := range []struct {
		name    string
		aliases string
	}{
		{name: "one RHS returning multiple values", aliases: `package sandboxworker
var routedOperation, legacyOperation = groupedOperations()
func groupedOperations() (string, string) { return OperationJobStartV2, "job_start" }`},
		{name: "one explicit type for uninitialized names", aliases: `package sandboxworker
type routedOperationType = JobOperationV2
var routedOperation, legacyOperation routedOperationType`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			fixtureContracts := contracts
			if strings.Contains(fixture.aliases, "JobOperationV2") {
				fixtureContracts += "\ntype JobOperationV2 string"
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": fixtureContracts,
				"aliases.go":   fixture.aliases,
				"handler.go": `package sandboxworker
func legacyHandler() { _ = legacyOperation; forbiddenHelper() }`,
				"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
			}, policy, "net/http")
		})
	}
}

func TestL8WorkerV2GuardNormalizesImplicitConstValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"contracts.go": true,
		"aliases.go":   true,
		"handler.go":   true,
		"shared.go":    true,
	}}
	contracts := `package sandboxworker
const OperationJobStartV2 = "job_start_v2"
type JobOperationV2 string`

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation = OperationJobStartV2
	hiddenOperation
	chainedOperation
)`,
		"handler.go": `package sandboxworker
func dispatch(operation string) {
	if operation == chainedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation JobOperationV2 = "job_start"
	hiddenOperation
)`,
		"handler.go": `package sandboxworker
func dispatch(operation JobOperationV2) {
	if operation == hiddenOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go": `package sandboxworker
const (
	routedOperation = OperationJobStartV2
	hiddenRoutedOperation
	legacyOperation = "job_start"
	hiddenLegacyOperation
)`,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	multiNameAliases := `package sandboxworker
const (
	routedOperation, legacyOperation = OperationJobStartV2, "job_start"
	hiddenRoutedOperation, hiddenLegacyOperation
)`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   multiNameAliases,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { safeRoutedHelper() }
}
func legacyHandler(operation string) {
	if operation == hiddenLegacyOperation { forbiddenLegacyHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func safeRoutedHelper() {}
func forbiddenLegacyHelper() { _, _ = httpalias.Get("https://legacy.example.invalid") }`,
	}, policy)

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"contracts.go": contracts,
		"aliases.go":   multiNameAliases,
		"handler.go": `package sandboxworker
func routedHandler(operation string) {
	if operation == hiddenRoutedOperation { forbiddenRoutedHelper() }
}`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func forbiddenRoutedHelper() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	for _, fixture := range []struct {
		name    string
		aliases string
		want    string
	}{
		{
			name: "implicit values before an expression list",
			aliases: `package sandboxworker
const (
	hiddenOperation
	routedOperation = OperationJobStartV2
)`,
			want: "before a preceding expression list",
		},
		{
			name: "inherited cardinality mismatch",
			aliases: `package sandboxworker
const (
	routedOperation, legacyOperation = OperationJobStartV2, "job_start"
	ambiguousOperation
)`,
			want: "ambiguous name/value cardinality",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"contracts.go": contracts,
				"aliases.go":   fixture.aliases,
			}, policy, fixture.want)
		})
	}
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
func (concreteDispatcher) dispatch() {}
type embeddedInterfaceDispatcher struct { dispatcher }
type embeddedConcreteDispatcher struct { concreteDispatcher }
func genericDispatch[T any]() {}
func genericDispatchPair[A, B any]() {}`
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture() {
	concreteDispatcher{}.dispatch()
	genericDispatch[int]()
	genericDispatchPair[int, string]()
}
func JobResolveV2Fixture(value embeddedConcreteDispatcher, pointer *embeddedConcreteDispatcher) {
	value.dispatch()
	pointer.dispatch()
}
func JobStatusV2Fixture(value concreteDispatcher) { concreteDispatcher.dispatch(value) }`,
		"shared.go": shared,
	}, policy)
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture(value dispatcher) { value.dispatch() }`,
		"shared.go": shared,
	}, policy, "interface dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type processTerminator interface { Kill() error }
func JobStartV2Fixture(value processTerminator) { terminate := value.Kill; _ = terminate }`,
		"shared.go": shared,
	}, policy, "interface method-value")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobStartV2Fixture(value embeddedInterfaceDispatcher) { dispatch := value.dispatch; _ = dispatch }`,
		"shared.go": shared,
	}, policy, "interface method-value")
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{name: "promoted interface method on value", source: `package sandboxworker
func JobResolveV2Fixture(value embeddedInterfaceDispatcher) { value.dispatch() }`},
		{name: "promoted interface method on pointer", source: `package sandboxworker
func JobStatusV2Fixture(value *embeddedInterfaceDispatcher) { value.dispatch() }`},
		{name: "promoted interface method expression", source: `package sandboxworker
func JobLogsV2Fixture(value embeddedInterfaceDispatcher) { embeddedInterfaceDispatcher.dispatch(value) }`},
		{name: "type parameter interface dispatch", source: `package sandboxworker
func JobCancelV2Fixture[T dispatcher](value T) { value.dispatch() }`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
				"shared.go":         shared,
			}, policy, "interface dispatch")
		})
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobLogsV2Fixture() { fn := crossFileHelper; fn() }`,
		"shared.go": `package sandboxworker
func crossFileHelper() {}`,
	}, policy, "function-value dispatch")
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
func JobCancelV2Fixture() { genericForbidden[int]() }`,
		"shared.go": `package sandboxworker
import httpalias "net/http"
func genericForbidden[T any]() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")
}

func TestL8WorkerV2GuardRejectsImplicitInterfaceCallbacks(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	shared := `package sandboxworker
import (
	formatting "fmt"
	processapi "os"
)
type implicitRenderer struct{}
func (implicitRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}
func renderThroughWrapper(value any) string { return formatting.Sprint(value) }`
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "renamed fmt import invokes Stringer",
			source: `package sandboxworker
import formatting "fmt"
func JobStartV2Fixture() { _ = formatting.Sprint(implicitRenderer{}) }`,
		},
		{
			name: "local any wrapper invokes Stringer",
			source: `package sandboxworker
func JobResolveV2Fixture() { _ = renderThroughWrapper(implicitRenderer{}) }`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
				"shared.go":         shared,
			}, policy, "implicit interface callback")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
type inertRenderer struct{}
func JobStatusV2Fixture() { _ = formatting.Sprint("safe", inertRenderer{}) }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsPromotedCallbacksOnAnonymousValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{
		dedicated: map[string]bool{"job_v2_fixture.go": true},
		mixed:     map[string]bool{"shared.go": true},
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobStartV2Fixture() {
	_ = formatting.Sprint(struct{ promotedRenderer }{})
}`,
		"shared.go": `package sandboxworker
import processapi "os"
type promotedRenderer struct{}
func (promotedRenderer) String() string {
	_, _ = processapi.StartProcess("worker", nil, nil)
	return ""
}`,
	}, policy, "implicit interface callback")

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import formatting "fmt"
func JobResolveV2Fixture() { _ = formatting.Sprint(struct{ Value string }{Value: "safe"}) }`,
	}, policy)
}

func TestL8WorkerV2GuardAuditsPackageInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"handler.go": true,
		"init.go":    true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
func JobStartV2Fixture() {}`,
		"init.go": `package sandboxworker
import httpalias "net/http"
func init() { _, _ = httpalias.Get("https://authority.example.invalid") }`,
	}, policy, "net/http")

	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
func JobResolveV2Fixture() {}`,
		"unlisted_init.go": `package sandboxworker
func init() {}`,
	}, policy, "outside the exact allowlist")
}

func TestL8WorkerV2GuardAuditsPackageVariableInitializers(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"handler.go": true,
		"state.go":   true,
	}}
	t.Run("reachable initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": `package sandboxworker
func JobStartV2Fixture() {}`,
			"state.go": `package sandboxworker
import httpalias "net/http"
var initializedState = forbiddenInitializer()
func forbiddenInitializer() string {
	_, _ = httpalias.Get("https://authority.example.invalid")
	return ""
}`,
		}, policy, "net/http")
	})

	t.Run("unlisted initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": `package sandboxworker
func JobResolveV2Fixture() {}`,
			"unlisted_state.go": `package sandboxworker
var initializedState = safeInitializer()
func safeInitializer() string { return "safe" }`,
		}, policy, "outside the exact allowlist")
	})

	t.Run("grouped initializer", func(t *testing.T) {
		l8AssertWorkerV2GuardRejects(t, map[string]string{
			"handler.go": `package sandboxworker
func JobStatusV2Fixture() {}`,
			"state.go": `package sandboxworker
import httpalias "net/http"
var (
	safeState = "safe"
	firstState, secondState = "safe", forbiddenGroupedInitializer()
)
func forbiddenGroupedInitializer() string {
	_, _ = httpalias.Get("https://authority.example.invalid")
	return ""
}`,
		}, policy, "net/http")
	})

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"handler.go": `package sandboxworker
func JobLogsV2Fixture() {}`,
		"state.go": `package sandboxworker
var (
	safeState = "safe"
	firstState, secondState = "safe", safeGroupedInitializer()
	uninitializedState string
)
func safeGroupedInitializer() string { return "safe" }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsReachedBodylessDeclarations(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			name: "bodyless function",
			source: `package sandboxworker
func hiddenLiveImplementation()
func JobStartV2Fixture() { hiddenLiveImplementation() }`,
		},
		{
			name: "bodyless method",
			source: `package sandboxworker
type hiddenLiveReceiver struct{}
func (hiddenLiveReceiver) dispatch()
func JobResolveV2Fixture() { hiddenLiveReceiver{}.dispatch() }`,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "bodyless declaration")
		})
	}
}

func TestL8WorkerV2GuardRejectsIndexedFunctionValues(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
	}{
		{name: "map index", source: `package sandboxworker
func indexedHelper() {}
func JobStartV2Fixture(key string) { map[string]func(){"run": indexedHelper}[key]() }`},
		{name: "slice index", source: `package sandboxworker
func indexedHelper() {}
func JobResolveV2Fixture(index int) { []func(){indexedHelper}[index]() }`},
		{name: "array index", source: `package sandboxworker
func indexedHelper() {}
func JobStatusV2Fixture(index int) { [1]func(){indexedHelper}[index]() }`},
		{name: "map alias index", source: `package sandboxworker
type functionMapAlias = map[string]func()
func JobLogsV2Fixture(functions functionMapAlias, key string) { functions[key]() }`},
		{name: "slice defined type index", source: `package sandboxworker
type functionSlice []func()
func JobCancelV2Fixture(functions functionSlice, index int) { functions[index]() }`},
		{name: "array defined type index", source: `package sandboxworker
type functionArray [1]func()
func JobStatusV2Fixture(functions functionArray, index int) { functions[index]() }`},
		{name: "indexed method value", source: `package sandboxworker
type indexedReceiver struct{}
func (indexedReceiver) dispatch() {}
func JobStartV2Fixture(value indexedReceiver) { []func(){value.dispatch}[0]() }`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "function-value dispatch")
		})
	}
}

func TestL8WorkerV2GuardRejectsReflectiveDispatch(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
	}{
		{name: "aliased function call", source: `package sandboxworker
import reflectalias "reflect"
func JobStartV2Fixture(function any) { reflectalias.ValueOf(function).Call(nil) }`},
		{name: "aliased method call slice", source: `package sandboxworker
import reflectalias "reflect"
func JobStatusV2Fixture(value any) { reflectalias.ValueOf(value).MethodByName("dispatch").CallSlice(nil) }`},
		{name: "dot imported call", source: `package sandboxworker
import . "reflect"
func JobLogsV2Fixture(function any) { ValueOf(function).Call(nil) }`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, "reflect")
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
type concreteReflectControl struct{}
func (concreteReflectControl) dispatch() {}
func JobCancelV2Fixture() { concreteReflectControl{}.dispatch() }`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsSemanticProcessAndRawSyscallSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "renamed os start process capture",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { start := processapi.StartProcess; _ = start }`,
			want: "os.StartProcess",
		},
		{
			name: "dot imported os exit",
			source: `package sandboxworker
import . "os"
func JobResolveV2Fixture() { Exit(1) }`,
			want: "os.Exit",
		},
		{
			name: "os find process capture",
			source: `package sandboxworker
import processapi "os"
func JobStatusV2Fixture() { find := processapi.FindProcess; _ = find }`,
			want: "os.FindProcess",
		},
		{
			name: "os process kill method expression",
			source: `package sandboxworker
import processapi "os"
func JobLogsV2Fixture() { kill := (*processapi.Process).Kill; _ = kill }`,
			want: "os.Kill",
		},
		{
			name: "os process signal method expression",
			source: `package sandboxworker
import processapi "os"
func JobCancelV2Fixture() { signal := (*processapi.Process).Signal; _ = signal }`,
			want: "os.Signal",
		},
		{
			name: "os process wait method expression",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { wait := (*processapi.Process).Wait; _ = wait }`,
			want: "os.Wait",
		},
		{
			name: "os process release method expression",
			source: `package sandboxworker
import processapi "os"
func JobResolveV2Fixture() { release := (*processapi.Process).Release; _ = release }`,
			want: "os.Release",
		},
		{
			name: "os process interface method value",
			source: `package sandboxworker
import processapi "os"
type hiddenWaiter interface { Wait() (*processapi.ProcessState, error) }
func JobStatusV2Fixture(process hiddenWaiter) { wait := process.Wait; _ = wait }`,
			want: "os.ProcessState",
		},
		{
			name: "os environment capture",
			source: `package sandboxworker
import environment "os"
func JobLogsV2Fixture() { lookup := environment.LookupEnv; _ = lookup }`,
			want: "os.LookupEnv",
		},
		{
			name: "renamed syscall raw syscall capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.RawSyscall; _ = call }`,
			want: "syscall.RawSyscall",
		},
		{
			name: "syscall syscall capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.Syscall; _ = call }`,
			want: "syscall.Syscall",
		},
		{
			name: "syscall raw syscall six capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.RawSyscall6; _ = call }`,
			want: "syscall.RawSyscall6",
		},
		{
			name: "syscall syscall six capture",
			source: `package sandboxworker
import kernel "syscall"
func JobCancelV2Fixture() { call := kernel.Syscall6; _ = call }`,
			want: "syscall.Syscall6",
		},
		{
			name: "dot imported syscall fork exec",
			source: `package sandboxworker
import . "syscall"
func JobStartV2Fixture() { start := ForkExec; _ = start }`,
			want: "syscall.ForkExec",
		},
		{
			name: "syscall network primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobResolveV2Fixture() { socket := kernel.Socket; _ = socket }`,
			want: "syscall.Socket",
		},
		{
			name: "syscall memory primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { mapping := kernel.Mmap; _ = mapping }`,
			want: "syscall.Mmap",
		},
		{
			name: "syscall exec primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { execute := kernel.Exec; _ = execute }`,
			want: "syscall.Exec",
		},
		{
			name: "syscall kill primitive",
			source: `package sandboxworker
import kernel "syscall"
func JobStatusV2Fixture() { signal := kernel.Kill; _ = signal }`,
			want: "syscall.Kill",
		},
		{
			name: "renamed unix raw syscall capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.RawSyscall; _ = call }`,
			want: "golang.org/x/sys/unix.RawSyscall",
		},
		{
			name: "unix syscall capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.Syscall; _ = call }`,
			want: "golang.org/x/sys/unix.Syscall",
		},
		{
			name: "unix raw syscall six capture",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobLogsV2Fixture() { call := kernel.RawSyscall6; _ = call }`,
			want: "golang.org/x/sys/unix.RawSyscall6",
		},
		{
			name: "unix network primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobCancelV2Fixture() { socket := kernel.Socket; _ = socket }`,
			want: "golang.org/x/sys/unix.Socket",
		},
		{
			name: "unix memory primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { mapping := kernel.Mmap; _ = mapping }`,
			want: "golang.org/x/sys/unix.Mmap",
		},
		{
			name: "unix exec primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { execute := kernel.Exec; _ = execute }`,
			want: "golang.org/x/sys/unix.Exec",
		},
		{
			name: "unix kill primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { signal := kernel.Kill; _ = signal }`,
			want: "golang.org/x/sys/unix.Kill",
		},
		{
			name: "unix namespace mount primitive",
			source: `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobStartV2Fixture() { mount := kernel.Mount; _ = mount }`,
			want: "golang.org/x/sys/unix.Mount",
		},
		{
			name: "unsafe pointer conversion",
			source: `package sandboxworker
import memory "unsafe"
func JobResolveV2Fixture() { _ = memory.Pointer(nil) }`,
			want: "unsafe.Pointer",
		},
		{
			name: "dot imported unsafe size",
			source: `package sandboxworker
import . "unsafe"
func JobStatusV2Fixture(value int) { _ = Sizeof(value) }`,
			want: "unsafe.Sizeof",
		},
		{
			name: "blank unsafe linkname escape",
			source: `package sandboxworker
import _ "unsafe"
//go:linkname hiddenProcessStart runtime.fork
func hiddenProcessStart()
func JobStatusV2Fixture() { hiddenProcessStart() }`,
			want: "unsafe",
		},
		{
			name: "plugin open capture",
			source: `package sandboxworker
import dynamiccode "plugin"
func JobLogsV2Fixture() { open := dynamiccode.Open; _ = open }`,
			want: "plugin.Open",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}
}

func TestL8WorkerV2GuardRejectsProcessGlobalDirectoryAndFatalSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "os chdir",
			source: `package sandboxworker
import processapi "os"
func JobStartV2Fixture() { _ = processapi.Chdir("work") }`,
			want: "os.Chdir",
		},
		{
			name: "os file chdir",
			source: `package sandboxworker
import processapi "os"
func JobResolveV2Fixture(file *processapi.File) { _ = file.Chdir() }`,
			want: "os.Chdir",
		},
		{
			name: "log fatal",
			source: `package sandboxworker
import logging "log"
func JobStatusV2Fixture() { logging.Fatal("stop") }`,
			want: "log.Fatal",
		},
		{
			name: "log fatalf",
			source: `package sandboxworker
import logging "log"
func JobLogsV2Fixture() { logging.Fatalf("stop: %s", "now") }`,
			want: "log.Fatalf",
		},
		{
			name: "log fatalln",
			source: `package sandboxworker
import logging "log"
func JobCancelV2Fixture() { logging.Fatalln("stop") }`,
			want: "log.Fatalln",
		},
		{
			name: "logger fatal method",
			source: `package sandboxworker
import logging "log"
func JobStartV2Fixture(logger *logging.Logger) { logger.Fatal("stop") }`,
			want: "log.Fatal",
		},
		{
			name: "logger fatalf method expression",
			source: `package sandboxworker
import logging "log"
func JobResolveV2Fixture() { fatal := (*logging.Logger).Fatalf; _ = fatal }`,
			want: "log.Fatalf",
		},
		{
			name: "logger fatalln method",
			source: `package sandboxworker
import logging "log"
func JobStatusV2Fixture(logger *logging.Logger) { logger.Fatalln("stop") }`,
			want: "log.Fatalln",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}

	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_fixture.go": `package sandboxworker
import (
	logging "log"
	filesystem "os"
	kernel "syscall"
)
func JobStartV2Store(path string, owner *kernel.Stat_t) error {
	logging.Print("opening durable state")
	_ = owner.Uid
	file, err := filesystem.OpenFile(path, filesystem.O_CREATE|filesystem.O_RDWR, 0o600)
	if err != nil { return err }
	defer file.Close()
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_EX|kernel.LOCK_NB); err != nil { return err }
	if err := file.Sync(); err != nil { return err }
	return kernel.Flock(int(file.Fd()), kernel.LOCK_UN)
}`,
	}, policy)
}

func TestL8WorkerV2GuardRejectsImportOnlyDynamicRuntimeSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{"job_v2_fixture.go": true}}
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name: "blank unsafe import",
			source: `package sandboxworker
import _ "unsafe"
func JobStartV2Fixture() {}`,
			want: "unsafe",
		},
		{
			name: "blank plugin import",
			source: `package sandboxworker
import _ "plugin"
func JobResolveV2Fixture() {}`,
			want: "plugin",
		},
		{
			name: "blank signal import",
			source: `package sandboxworker
import _ "os/signal"
func JobStatusV2Fixture() {}`,
			want: "os/signal",
		},
		{
			name: "renamed signal import",
			source: `package sandboxworker
import notifications "os/signal"
func JobLogsV2Fixture() { stop := notifications.Stop; _ = stop }`,
			want: "os/signal",
		},
		{
			name: "renamed runtime import",
			source: `package sandboxworker
import processruntime "runtime"
func JobCancelV2Fixture() { exit := processruntime.Goexit; _ = exit }`,
			want: "runtime",
		},
		{
			name: "dot runtime debug import",
			source: `package sandboxworker
import . "runtime/debug"
func JobStartV2Fixture() { SetTraceback("all") }`,
			want: "runtime/debug",
		},
		{
			name: "blank runtime pprof import",
			source: `package sandboxworker
import _ "runtime/pprof"
func JobResolveV2Fixture() {}`,
			want: "runtime/pprof",
		},
		{
			name: "blank runtime trace import",
			source: `package sandboxworker
import _ "runtime/trace"
func JobStatusV2Fixture() {}`,
			want: "runtime/trace",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				"job_v2_fixture.go": fixture.source,
			}, policy, fixture.want)
		})
	}
}

func TestL8WorkerV2GuardClosesSemanticExternalSurfaceDependencies(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{
		"handler.go": true,
		"helper.go":  true,
		"capture.go": true,
	}}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"handler.go": `package sandboxworker
func JobStartV2Fixture() { hiddenHelper() }`,
		"helper.go": `package sandboxworker
func hiddenHelper() { _ = hiddenKernelCall }`,
		"capture.go": `package sandboxworker
import kernel "syscall"
var hiddenKernelCall = kernel.RawSyscall`,
	}, policy, "syscall.RawSyscall")
}

func TestL8WorkerV2GuardAllowsExactDurableStoreFileAndLockSurfaces(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{dedicated: map[string]bool{
		"job_v2_store.go":      true,
		"job_v2_unix_store.go": true,
	}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"job_v2_store.go": `package sandboxworker
import (
	filesystem "os"
	kernel "syscall"
)
const semanticGuardDocumentation = "os.StartProcess syscall.RawSyscall unsafe.Pointer plugin.Open"
func JobStartV2Store(path string, owner *kernel.Stat_t) error {
	_ = semanticGuardDocumentation
	_ = owner.Uid
	file, err := filesystem.OpenFile(path, filesystem.O_CREATE|filesystem.O_RDWR, 0o600)
	if err != nil { return err }
	defer file.Close()
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_EX|kernel.LOCK_NB); err != nil && err != kernel.EINTR { return err }
	if err := file.Sync(); err != nil { return err }
	if err := kernel.Flock(int(file.Fd()), kernel.LOCK_UN); err != nil { return err }
	if _, err := filesystem.ReadFile(path); err != nil { return err }
	if err := filesystem.Rename(path, path+".json"); err != nil { return err }
	return filesystem.Remove(path+".json")
}`,
		"job_v2_unix_store.go": `package sandboxworker
import kernel "golang.org/x/sys/unix"
func JobResolveV2Store(fd int, owner *kernel.Stat_t) error {
	_ = owner.Uid
	if err := kernel.Flock(fd, kernel.LOCK_EX|kernel.LOCK_NB); err != nil { return err }
	return kernel.Flock(fd, kernel.LOCK_UN)
}`,
	}, policy)
}

func TestL8WorkerV2GuardKeepsSemanticLiveSurfaceChecksOutOfV1Siblings(t *testing.T) {
	policy := l8WorkerV2GuardPolicy{mixed: map[string]bool{"mixed.go": true}}
	l8AssertWorkerV2GuardAllows(t, map[string]string{
		"mixed.go": `package sandboxworker
import (
	processapi "os"
	notifications "os/signal"
	kernel "syscall"
	dynamiccode "plugin"
	processruntime "runtime"
	memory "unsafe"
)
func JobStartV2Fixture() {}
func unrelatedV1() {
	_ = processapi.Exit
	_ = notifications.Stop
	_ = kernel.RawSyscall
	_ = dynamiccode.Open
	_ = processruntime.Gosched
	_ = memory.Pointer(nil)
}`,
	}, policy)
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
