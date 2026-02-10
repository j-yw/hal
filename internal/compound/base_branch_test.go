package compound

import (
	"errors"
	"testing"
)

func TestResolveBaseBranch(t *testing.T) {
	t.Run("uses explicit base without lookup", func(t *testing.T) {
		called := false
		base := ResolveBaseBranch("  develop  ", func() (string, error) {
			called = true
			return "main", nil
		}, nil)
		if called {
			t.Fatal("current branch lookup should not be called when --base is set")
		}
		if base != "develop" {
			t.Fatalf("base = %q, want %q", base, "develop")
		}
	})

	t.Run("uses current branch when available", func(t *testing.T) {
		base := ResolveBaseBranch("", func() (string, error) {
			return "main", nil
		}, nil)
		if base != "main" {
			t.Fatalf("base = %q, want %q", base, "main")
		}
	})

	t.Run("allows detached head empty branch", func(t *testing.T) {
		base := ResolveBaseBranch("", func() (string, error) {
			return "", nil
		}, nil)
		if base != "" {
			t.Fatalf("base = %q, want empty", base)
		}
	})

	t.Run("falls back to empty and warns on lookup error", func(t *testing.T) {
		warned := false
		base := ResolveBaseBranch("", func() (string, error) {
			return "", errors.New("git failed")
		}, func(format string, args ...any) {
			warned = true
		})
		if base != "" {
			t.Fatalf("base = %q, want empty", base)
		}
		if !warned {
			t.Fatal("expected warning callback to be called")
		}
	})
}
