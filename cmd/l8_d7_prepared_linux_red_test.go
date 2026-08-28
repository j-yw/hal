package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D7PreparedLinuxLiveStubIsBuildTaggedAndFatal(t *testing.T) {
	path := l8D7PreparedLinuxLiveStubPath()
	source := readL8CredentialDeliveryFile(t, path)
	if !strings.HasPrefix(strings.TrimSpace(source), l8D7PreparedLinuxLiveBuildLine()) {
		t.Fatalf("%s missing exact four-tag go:build line", filepath.ToSlash(path))
	}
	if strings.Count(source, "//go:build") != 1 {
		t.Fatalf("%s must declare exactly one go:build line", filepath.ToSlash(path))
	}
	for _, required := range []string{
		"func TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"func TestL8PreparedLinuxCredentialDeliveryE2E",
		`"http_only"`,
		`"file_tmpfs_only"`,
		`"ssh_agent_only"`,
		`"all_modes"`,
		`"failure_recovery_matrix"`,
		"t.Fatal",
		"dependency_unaccepted: D7 prepared-Linux remains blocked by sealed PID1 expected digests, live helper transport, durable handle store, and production L7 session factory",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("%s omits %q", filepath.ToSlash(path), required)
		}
	}
	if strings.Contains(source, "t.Skip") {
		t.Fatalf("%s contains t.Skip", filepath.ToSlash(path))
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
	if !strings.Contains(source, "return l8composition.PID1StartGateExpected{}, false, nil") {
		t.Fatal("loadPID1StartGateExpected must still return absent present=false")
	}
	foundAbsent := false
	ast.Inspect(fn, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 3 {
			return true
		}
		ident, ok := ret.Results[1].(*ast.Ident)
		if ok && ident.Name == "false" {
			foundAbsent = true
		}
		return true
	})
	if !foundAbsent {
		t.Fatal("loadPID1StartGateExpected body no longer returns present false")
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
		t.Fatal("RecoverJobCredentials must still return errL8JobCredentialRuntimeDependencyUnaccepted")
	}
	found := false
	ast.Inspect(fn, func(node ast.Node) bool {
		ident, ok := node.(*ast.Ident)
		if ok && ident.Name == "errL8JobCredentialRuntimeDependencyUnaccepted" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("RecoverJobCredentials production body no longer returns errL8JobCredentialRuntimeDependencyUnaccepted")
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
