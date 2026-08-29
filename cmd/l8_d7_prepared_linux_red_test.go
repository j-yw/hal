package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const l8D7PreparedLinuxBlockedMessage = "dependency_unaccepted: D7 prepared-Linux remains blocked by sealed PID1 expected digests, live helper transport, durable handle store, and production L7 session factory"

func TestL8D7PreparedLinuxLiveStubIsBuildTaggedAndFatal(t *testing.T) {
	path := l8D7PreparedLinuxLiveStubPath()
	source := readL8CredentialDeliveryFile(t, path)
	if !strings.HasPrefix(strings.TrimSpace(source), l8D7PreparedLinuxLiveBuildLine()) {
		t.Fatalf("%s missing exact four-tag go:build line", filepath.ToSlash(path))
	}
	if strings.Count(source, "//go:build") != 1 {
		t.Fatalf("%s must declare exactly one go:build line", filepath.ToSlash(path))
	}
	if err := l8D7ValidatePreparedLinuxRedStub(source); err != nil {
		t.Fatalf("%s does not preserve the exact RED stub: %v", filepath.ToSlash(path), err)
	}
}

func TestL8D7PreparedLinuxLiveStubGuardRejectsFalseGreenShapes(t *testing.T) {
	source := readL8CredentialDeliveryFile(t, l8D7PreparedLinuxLiveStubPath())
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "prerequisites fatal moved to unused helper",
			old:  "func TestL8PreparedLinuxCredentialDeliveryPrerequisites(t *testing.T) {\n\tt.Fatal(l8D7PreparedLinuxBlocked)\n}",
			new:  "func TestL8PreparedLinuxCredentialDeliveryPrerequisites(t *testing.T) { _ = t }\nfunc retainUnusedD7Fatal(t *testing.T) { t.Fatal(l8D7PreparedLinuxBlocked) }",
		},
		{
			name: "prerequisites fatal is conditional",
			old:  "\tt.Fatal(l8D7PreparedLinuxBlocked)\n}",
			new:  "\tif false { t.Fatal(l8D7PreparedLinuxBlocked) }\n}",
		},
		{
			name: "e2e subtest passes",
			old:  "\t\tt.Run(name, func(t *testing.T) {\n\t\t\tt.Fatal(l8D7PreparedLinuxBlocked)\n\t\t})",
			new:  "\t\tt.Run(name, func(t *testing.T) { _ = t })",
		},
		{
			name: "e2e parent passes",
			old:  "\t}\n\tt.Fatal(l8D7PreparedLinuxBlocked)\n}",
			new:  "\t}\n\t_ = t\n}",
		},
		{
			name: "subtest name duplicated",
			old:  "\t\t\"http_only\",\n\t\t\"file_tmpfs_only\",",
			new:  "\t\t\"http_only\",\n\t\t\"http_only\",",
		},
		{
			name: "skip replaces fatal",
			old:  "func TestL8PreparedLinuxCredentialDeliveryPrerequisites(t *testing.T) {\n\tt.Fatal(l8D7PreparedLinuxBlocked)\n}",
			new:  "func TestL8PreparedLinuxCredentialDeliveryPrerequisites(t *testing.T) {\n\tt.Skip(l8D7PreparedLinuxBlocked)\n}",
		},
		{
			name: "blocked message is detached from fatal",
			old:  "t.Fatal(l8D7PreparedLinuxBlocked)",
			new:  `t.Fatal("dependency_unaccepted")`,
		},
		{
			name: "blocked message becomes a variable",
			old:  "const l8D7PreparedLinuxBlocked =",
			new:  "var l8D7PreparedLinuxBlocked =",
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(source, mutation.old, mutation.new, 1)
			if mutated == source {
				t.Fatalf("mutation source %q was not found", mutation.old)
			}
			if err := l8D7ValidatePreparedLinuxRedStub(mutated); err == nil {
				t.Fatal("false-green RED stub was accepted")
			}
		})
	}
}

func TestL8D7PreparedLinuxUntaggedSourcesDoNotDeclareLiveTests(t *testing.T) {
	roots := []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost"),
		"hal-guest-init",
	}
	foundLiveStub := false
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			source := readL8CredentialDeliveryFile(t, path)
			if l8D7SourceHasPreparedLinuxLiveBuild(source) {
				if filepath.Base(path) == l8D7PreparedLinuxLiveStubName() {
					foundLiveStub = true
				}
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil {
					continue
				}
				switch fn.Name.Name {
				case "TestL8PreparedLinuxCredentialDeliveryPrerequisites",
					"TestL8PreparedLinuxCredentialDeliveryE2E":
					t.Errorf("untagged file %s declares %s", filepath.ToSlash(path), fn.Name.Name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !foundLiveStub {
		t.Fatal("D7 prepared-Linux live stub was not discovered")
	}
}

func TestL8D7PreparedLinuxPID1StartGateExpectedRemainsAbsent(t *testing.T) {
	path := filepath.Join("hal-guest-init", "pid1_start_gate_linux.go")
	source := readL8CredentialDeliveryFile(t, path)
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := l8D7FindFunc(file, "loadPID1StartGateExpected")
	if fn == nil {
		t.Fatal("loadPID1StartGateExpected missing")
	}
	for _, forbidden := range []string{
		"os.Getenv",
		"os.LookupEnv",
		"os.ReadFile",
		"os.Open(",
		"/proc/cmdline",
		"go:embed",
		"flag.String",
		"flag.Parse",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("loadPID1StartGateExpected source uses unsigned digest input %q", forbidden)
		}
	}
	if !strings.Contains(source, "return l8composition.PID1StartGateExpected{}, false, nil") {
		t.Fatal("missing or invalid sealed expected must still return present=false")
	}
	foundAbsent := false
	foundPresent := false
	ast.Inspect(fn, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 3 {
			return true
		}
		ident, ok := ret.Results[1].(*ast.Ident)
		if !ok {
			return true
		}
		switch ident.Name {
		case "false":
			foundAbsent = true
		case "true":
			foundPresent = true
		}
		return true
	})
	if !foundAbsent {
		t.Fatal("loadPID1StartGateExpected body no longer returns present false")
	}
	if !foundPresent {
		t.Fatal("loadPID1StartGateExpected sealed-FD present path is missing")
	}
}

func TestL8D7PreparedLinuxRecoverJobCredentialsRemainsDependencyUnaccepted(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go")
	source := readL8CredentialDeliveryFile(t, path)
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := l8D7FindFunc(file, "RecoverJobCredentials")
	if fn == nil {
		t.Fatal("RecoverJobCredentials missing")
	}
	if !strings.Contains(source, "return sandboxruntime.JobCredentialCleanupProof{}, errL8JobCredentialRuntimeDependencyUnaccepted") {
		t.Fatal("nil store and missing store metadata must still return errL8JobCredentialRuntimeDependencyUnaccepted")
	}
	foundUnaccepted := false
	foundStore := false
	foundMint := false
	ast.Inspect(fn, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.Ident:
			switch typed.Name {
			case "errL8JobCredentialRuntimeDependencyUnaccepted":
				foundUnaccepted = true
			case "present", "HandleStore":
				foundStore = true
			}
		case *ast.SelectorExpr:
			if typed.Sel == nil {
				return true
			}
			switch typed.Sel.Name {
			case "NewJobCredentialCleanupProof":
				foundMint = true
			case "HandleStore":
				foundStore = true
			}
		}
		return true
	})
	if !foundUnaccepted {
		t.Fatal("RecoverJobCredentials must still return errL8JobCredentialRuntimeDependencyUnaccepted when the store is nil or metadata is missing")
	}
	if foundMint && !foundStore {
		t.Fatal("RecoverJobCredentials minted a cleanup proof without store metadata")
	}
}

func TestL8D7PreparedLinuxCredentialClientHasNoLiveHelperTransport(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "credentialclient", "control_contract_red.go")
	source := readL8CredentialDeliveryFile(t, path)
	for _, forbidden := range []string{
		"net.Listen",
		"net.Dial",
		"unix.Socket",
		"SOCK_STREAM",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("credentialclient control_contract_red.go contains live helper transport %q", forbidden)
		}
	}
}

func TestL8D7PreparedLinuxDefaultConstructorsDoNotCreateL7SessionFactory(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go")
	source := readL8CredentialDeliveryFile(t, path)
	if strings.Contains(source, "l7network.NewReconciler") {
		t.Fatal("NewProductionL8JobCredentialRuntime production file calls l7network.NewReconciler")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"NewProductionL8JobCredentialRuntime", "newL8JobCredentialRuntime"} {
		fn := l8D7FindFunc(file, name)
		if fn == nil {
			t.Fatalf("%s missing", name)
		}
		ast.Inspect(fn, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if l8D7CallName(call) == "NewReconciler" {
				t.Errorf("%s calls NewReconciler", name)
			}
			return true
		})
	}
}

func TestL8D7PreparedLinuxVerifySelectedLiveScript(t *testing.T) {
	path := filepath.Join("..", "tools", "microvm", "l8", "verify-selected-live.sh")
	script := readL8CredentialDeliveryFile(t, path)
	for _, required := range []string{
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"TestL8PreparedLinuxCredentialDeliveryE2E",
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
		"./internal/sandboxruntime/microvm/firecrackerhost",
		"firecracker" + "_" + "live",
		"network_enforcement" + "_" + "live",
		"l7_linux_network_integration",
		"l8_production_" + "credential_" + "delivery_" + "live",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("verify-selected-live.sh omits %q", required)
		}
	}
}

func TestL8D7PreparedLinuxGolangciLintGuidancePresent(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PreparedLinuxAcceptanceDoc))
	if !strings.Contains(doc, "command -v golangci-lint") {
		t.Fatal("D7 prepared-Linux acceptance document omits golangci-lint availability guidance")
	}
	if !strings.Contains(doc, "does not claim L8 complete") ||
		!strings.Contains(doc, "does not claim L10") ||
		!strings.Contains(doc, "does not claim L11") {
		t.Fatal("D7 prepared-Linux acceptance document does not forbid claiming L8/L10/L11 complete")
	}
}

func l8D7PreparedLinuxLiveStubName() string {
	return "l8_prepared_linux_" + "credential_" + "delivery_" + "live_test.go"
}

func l8D7PreparedLinuxLiveStubPath() string {
	return filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", l8D7PreparedLinuxLiveStubName())
}

func l8D7PreparedLinuxLiveBuildLine() string {
	return "//go:build linux && " +
		"firecracker" + "_" + "live" + " && " +
		"network_enforcement" + "_" + "live" + " && " +
		"l7_linux_network_integration && " +
		"l8_production_" + "credential_" + "delivery_" + "live"
}

func l8D7SourceHasPreparedLinuxLiveBuild(source string) bool {
	want := l8D7PreparedLinuxLiveBuildLine()
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == want {
			return true
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			return false
		}
	}
	return false
}

func l8D7FindFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func l8D7CallName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}

func l8D7ValidatePreparedLinuxRedStub(source string) error {
	file, err := parser.ParseFile(token.NewFileSet(), l8D7PreparedLinuxLiveStubName(), source, 0)
	if err != nil {
		return err
	}
	if file.Name == nil || file.Name.Name != "firecrackerhost" {
		return fmt.Errorf("package = %v, want firecrackerhost", file.Name)
	}
	if len(file.Imports) != 1 || file.Imports[0].Name != nil || file.Imports[0].Path == nil || file.Imports[0].Path.Value != `"testing"` {
		return fmt.Errorf("imports must contain only testing")
	}
	if len(file.Decls) != 4 {
		return fmt.Errorf("declarations = %d, want import, blocked constant, and two tests", len(file.Decls))
	}

	blockedCount := 0
	functions := make(map[string]*ast.FuncDecl, 2)
	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			if !l8D7ExactBlockedConstant(typed) {
				return fmt.Errorf("noncanonical declaration in RED stub")
			}
			blockedCount++
		case *ast.FuncDecl:
			if typed.Name == nil {
				return fmt.Errorf("unnamed function declaration")
			}
			if _, exists := functions[typed.Name.Name]; exists {
				return fmt.Errorf("duplicate function %s", typed.Name.Name)
			}
			functions[typed.Name.Name] = typed
		default:
			return fmt.Errorf("unsupported declaration %T", decl)
		}
	}
	if blockedCount != 1 {
		return fmt.Errorf("blocked constants = %d, want 1", blockedCount)
	}
	if len(functions) != 2 {
		return fmt.Errorf("test functions = %d, want 2", len(functions))
	}

	prerequisites := functions["TestL8PreparedLinuxCredentialDeliveryPrerequisites"]
	if !l8D7ExactTestingTest(prerequisites) || len(prerequisites.Body.List) != 1 || !l8D7ExactFatalStatement(prerequisites.Body.List[0], "t") {
		return fmt.Errorf("prerequisites test must directly fatal with the blocked constant")
	}
	e2e := functions["TestL8PreparedLinuxCredentialDeliveryE2E"]
	if !l8D7ExactTestingTest(e2e) || len(e2e.Body.List) != 2 {
		return fmt.Errorf("E2E test must contain only the exact subtest loop and parent fatal")
	}
	rangeStmt, ok := e2e.Body.List[0].(*ast.RangeStmt)
	if !ok || rangeStmt.Tok != token.DEFINE || !l8D7IdentNamed(rangeStmt.Key, "_") || !l8D7IdentNamed(rangeStmt.Value, "name") ||
		!l8D7ExactSubtestNames(rangeStmt.X) || rangeStmt.Body == nil || len(rangeStmt.Body.List) != 1 ||
		!l8D7ExactFatalSubtestStatement(rangeStmt.Body.List[0]) {
		return fmt.Errorf("E2E subtest loop must directly register the five exact fatal subtests")
	}
	if !l8D7ExactFatalStatement(e2e.Body.List[1], "t") {
		return fmt.Errorf("E2E parent must directly fatal with the blocked constant")
	}
	return nil
}

func l8D7ExactBlockedConstant(decl *ast.GenDecl) bool {
	if decl == nil || decl.Tok != token.CONST || len(decl.Specs) != 1 {
		return false
	}
	value, ok := decl.Specs[0].(*ast.ValueSpec)
	if !ok || value.Type != nil || len(value.Names) != 1 || value.Names[0].Name != "l8D7PreparedLinuxBlocked" || len(value.Values) != 1 {
		return false
	}
	literal, ok := value.Values[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	decoded, err := strconv.Unquote(literal.Value)
	return err == nil && decoded == l8D7PreparedLinuxBlockedMessage
}

func l8D7ExactTestingTest(fn *ast.FuncDecl) bool {
	return fn != nil && fn.Recv == nil && fn.Body != nil && fn.Type != nil && fn.Type.TypeParams == nil &&
		fn.Type.Results == nil && l8D7ExactTestingTParameter(fn.Type.Params, "t")
}

func l8D7ExactTestingTParameter(params *ast.FieldList, name string) bool {
	if params == nil || len(params.List) != 1 || len(params.List[0].Names) != 1 || params.List[0].Names[0].Name != name {
		return false
	}
	pointer, ok := params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	return ok && l8D7IdentNamed(selector.X, "testing") && selector.Sel != nil && selector.Sel.Name == "T"
}

func l8D7ExactFatalStatement(stmt ast.Stmt, receiver string) bool {
	expression, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && l8D7IdentNamed(selector.X, receiver) && selector.Sel != nil && selector.Sel.Name == "Fatal" &&
		l8D7IdentNamed(call.Args[0], "l8D7PreparedLinuxBlocked")
}

func l8D7ExactSubtestNames(expression ast.Expr) bool {
	want := [...]string{
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
	}
	literal, ok := expression.(*ast.CompositeLit)
	if !ok || len(literal.Elts) != len(want) {
		return false
	}
	sliceType, ok := literal.Type.(*ast.ArrayType)
	if !ok || sliceType.Len != nil || !l8D7IdentNamed(sliceType.Elt, "string") {
		return false
	}
	for index, element := range literal.Elts {
		name, ok := element.(*ast.BasicLit)
		if !ok || name.Kind != token.STRING {
			return false
		}
		decoded, err := strconv.Unquote(name.Value)
		if err != nil || decoded != want[index] {
			return false
		}
	}
	return true
}

func l8D7ExactFatalSubtestStatement(stmt ast.Stmt) bool {
	expression, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !l8D7IdentNamed(selector.X, "t") || selector.Sel == nil || selector.Sel.Name != "Run" || !l8D7IdentNamed(call.Args[0], "name") {
		return false
	}
	callback, ok := call.Args[1].(*ast.FuncLit)
	return ok && callback.Type != nil && callback.Type.TypeParams == nil && callback.Type.Results == nil &&
		l8D7ExactTestingTParameter(callback.Type.Params, "t") && callback.Body != nil && len(callback.Body.List) == 1 &&
		l8D7ExactFatalStatement(callback.Body.List[0], "t")
}

func l8D7IdentNamed(expression ast.Expr, name string) bool {
	ident, ok := expression.(*ast.Ident)
	return ok && ident.Name == name
}
