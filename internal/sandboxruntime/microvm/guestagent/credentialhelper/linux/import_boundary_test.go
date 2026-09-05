package linux

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCoreFoundationImportBoundary(t *testing.T) {
	allowed := map[string]bool{
		"context":         true,
		"crypto/sha256":   true,
		"crypto/subtle":   true,
		"encoding/binary": true,
		"errors":          true,
		"reflect":         true,
		"sync":            true,
		"github.com/jywlabs/hal/internal/credentialmemory":                                   true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper": true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap":    true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy":    true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		for _, specification := range parsed.Imports {
			path, err := strconv.Unquote(specification.Path.Value)
			if err != nil || !allowed[path] {
				t.Errorf("production import %q in %s is outside the injected foundation boundary", specification.Path.Value, name)
			}
		}
	}

	assertCorePlatformTag(t, "core_linux.go", "linux")
	assertCorePlatformTag(t, "core_other.go", "!linux")
	assertCorePlatformTag(t, "syscall_policy_kernel_linux.go", "linux")
	assertCorePlatformTag(t, "syscall_policy_kernel_other.go", "!linux")
	assertCorePlatformTag(t, "syscall_policy_wrapper_linux.go", "linux && amd64 && l8_d4_full_syscall_adapter")
}

func assertCorePlatformTag(t *testing.T, name, want string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	first, _, _ := strings.Cut(string(payload), "\n")
	if first != "//go:build "+want {
		t.Fatalf("%s first line = %q, want exact platform split", name, first)
	}
}
