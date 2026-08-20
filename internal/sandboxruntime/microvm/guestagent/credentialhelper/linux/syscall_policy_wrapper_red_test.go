//go:build linux && l8_d4_full_syscall_adapter

package linux

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestL8D4FullSyscallWrapperSourceContract is the red gate for the later live
// half of D4. The default build deliberately does not claim this authority:
// D7 must first issue the complete adapter rows and final-binary evidence.
func TestL8D4FullSyscallWrapperSourceContract(t *testing.T) {
	payload, err := os.ReadFile("syscall_policy_wrapper_linux.go")
	if err != nil {
		t.Fatalf("read sole live wrapper: %v", err)
	}
	text := string(payload)
	for _, marker := range []string{
		"type wrapperState uint8",
		"wrapperStateUnstarted wrapperState = 1",
		"wrapperStateClaimed wrapperState = 2",
		"wrapperStateExecuted wrapperState = 3",
		"wrapperStateFinalized wrapperState = 4",
		"NewAdapterBindings",
		"AuthorizePre",
		"AuthorizePost",
		"CommitNoObject",
		"AbortPermit",
		"newPostObservationSource",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("sole live wrapper lacks %q", marker)
		}
	}
}

func TestL8D4FullSyscallWrapperHasNoRawBypass(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && (identifier.Name == "syscall" || identifier.Name == "unix") && strings.HasPrefix(selector.Sel.Name, "Syscall") {
				t.Errorf("%s contains raw syscall bypass %s.%s", name, identifier.Name, selector.Sel.Name)
			}
			return true
		})
	}
}
