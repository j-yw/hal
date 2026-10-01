package sandboxworker

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestMinimalLaunchSourceGuardPinsOpaqueIDEntropy(t *testing.T) {
	source := l8ReadWorkerSource(t, "job_helpers.go")
	start, end := strings.Index(source, "func newOpaqueJobID("), strings.Index(source, "func cloneJob(")
	if start < 0 || end <= start {
		t.Fatal("missing existing entropy function")
	}
	helper := "package sandboxworker\nimport (\"crypto/rand\";\"encoding/hex\";\"io\")\n" + source[start:end]
	if err := minimalLaunchOpaqueIDEntropyGuard(helper); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ name, old, replacement string }{
		{"foreign reader", "rand.Reader", "foreignReader"},
		{"short entropy", "[16]byte", "[1]byte"},
		{"unbounded extent", "value[:])", "arbitraryBuffer)"},
		{"additional reader", "var value [16]byte", "_, _ = io.ReadFull(foreignReader, arbitraryBuffer); var value [16]byte"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(helper, fixture.old) {
				t.Fatal("entropy mutation did not match")
			}
			mutated := strings.Replace(helper, fixture.old, fixture.replacement, 1) + "\nvar foreignReader io.Reader = rand.Reader\nvar arbitraryBuffer []byte"
			if err := minimalLaunchOpaqueIDEntropyGuard(mutated); err == nil {
				t.Fatal("entropy guard accepted mutated helper")
			}
		})
	}
}

// Pin the surviving V1 job-ID helper without restoring the removed V2 launch call-graph guard.
func minimalLaunchOpaqueIDEntropyGuard(source string) error {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "job_helpers.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse job helper: %w", err)
	}
	required := map[string]string{"crypto/rand": "rand", "encoding/hex": "hex", "io": "io"}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return fmt.Errorf("parse import: %w", err)
		}
		if name, ok := required[path]; ok && (imported.Name == nil || imported.Name.Name == name) {
			delete(required, path)
		}
	}
	if len(required) != 0 {
		return fmt.Errorf("changed entropy helper imports")
	}
	const want = `func newOpaqueJobID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(value[:]), nil
}`
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "newOpaqueJobID" {
			continue
		}
		var body bytes.Buffer
		if err := format.Node(&body, set, function); err != nil {
			return fmt.Errorf("format job helper: %w", err)
		}
		if body.String() != want {
			return fmt.Errorf("changed exact job-ID entropy helper")
		}
		return nil
	}
	return fmt.Errorf("missing job-ID entropy helper")
}
