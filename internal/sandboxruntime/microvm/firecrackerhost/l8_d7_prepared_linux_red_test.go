package firecrackerhost

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D7PreparedLinuxLiveStubStaysBuildTaggedAndDefaultHidden(t *testing.T) {
	liveFile := "l8_prepared_linux_" + "credential_" + "delivery_" + "live_test.go"
	payload, err := os.ReadFile(liveFile)
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	wantBuild := l8D7PreparedLinuxLiveBuildLine()
	if !strings.HasPrefix(strings.TrimSpace(source), wantBuild) {
		t.Fatalf("%s missing exact D7 live go:build line", liveFile)
	}

	matches, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("firecrackerhost matched no test files")
	}
	for _, path := range matches {
		fileSource, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if l8D7SourceHasPreparedLinuxLiveBuild(string(fileSource)) {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, fileSource, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			switch fn.Name.Name {
			case "TestL8PreparedLinuxCredentialDeliveryPrerequisites",
				"TestL8PreparedLinuxCredentialDeliveryE2E":
				t.Fatalf("untagged package file %s declares %s", path, fn.Name.Name)
			}
		}
	}
}

func l8D7PreparedLinuxLiveBuildLine() string {
	return "//go:build linux && " +
		"firecracker" + "_" + "live" + " && " +
		"network_enforcement" + "_" + "live" + " && " +
		"l7_linux_network_integration && " +
		"l8_production_" + "credential_" + "delivery_" + "live"
}

func l8D7SourceHasPreparedLinuxLiveBuild(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == l8D7PreparedLinuxLiveBuildLine() {
			return true
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			return false
		}
	}
	return false
}
