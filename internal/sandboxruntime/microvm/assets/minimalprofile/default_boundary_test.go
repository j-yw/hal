//go:build linux

package minimalprofile

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestMinimalDefaultTestsDoNotUseImageTools(t *testing.T) {
	ctx := build.Default
	ctx.BuildTags = nil
	ctx.GOOS = "linux"
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		selected, err := ctx.MatchFile(".", file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !selected {
			continue
		}
		source, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if defaultTestUsesTools(source) {
			t.Errorf("default test file reaches real image tools: %s", file.Name())
		}
	}
}

func TestMinimalDefaultToolGuardRejectsSeededCalls(t *testing.T) {
	for _, source := range []string{
		`package fixture; import "os/exec"; var _ = exec.Command`,
		`package fixture; func test(){ checkImageTools(nil) }`,
		`package fixture; var run = BuildImage`,
		`package fixture; func test(){ Publish(nil, request) }`,
	} {
		if !defaultTestUsesTools([]byte(source)) {
			t.Fatal("guard accepted real-tool reference")
		}
	}
	if defaultTestUsesTools([]byte(`package fixture; func test(){ inspect(fakeQuery, pins) }`)) {
		t.Fatal("guard rejected pure inspector")
	}
}

func defaultTestUsesTools(source []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		return true
	}
	for _, imp := range f.Imports {
		value, err := strconv.Unquote(imp.Path.Value)
		if err != nil || value == "os/exec" {
			return true
		}
	}
	forbidden := map[string]bool{"BuildImage": true, "Publish": true, "checkImageTools": true, "requireImageTools": true, "debugTool": true, "runTool": true}
	found := false
	ast.Inspect(f, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && forbidden[id.Name] {
			found = true
		}
		return true
	})
	return found
}
