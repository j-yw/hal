package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveRunBaseBranch(t *testing.T) {
	t.Run("uses explicit base without resolving current branch", func(t *testing.T) {
		called := false
		base, err := resolveRunBaseBranch("  develop  ", func() (string, error) {
			called = true
			return "main", nil
		})
		if err != nil {
			t.Fatalf("resolveRunBaseBranch returned error: %v", err)
		}
		if called {
			t.Fatal("current branch resolver should not be called when --base is set")
		}
		if base != "develop" {
			t.Fatalf("base = %q, want %q", base, "develop")
		}
	})

	t.Run("falls back to current branch when base flag is empty", func(t *testing.T) {
		base, err := resolveRunBaseBranch("", func() (string, error) {
			return "main", nil
		})
		if err != nil {
			t.Fatalf("resolveRunBaseBranch returned error: %v", err)
		}
		if base != "main" {
			t.Fatalf("base = %q, want %q", base, "main")
		}
	})

	t.Run("allows detached head fallback", func(t *testing.T) {
		base, err := resolveRunBaseBranch("", func() (string, error) {
			return "", nil
		})
		if err != nil {
			t.Fatalf("resolveRunBaseBranch returned error: %v", err)
		}
		if base != "" {
			t.Fatalf("base = %q, want empty", base)
		}
	})

	t.Run("returns wrapped resolver error", func(t *testing.T) {
		wantErr := errors.New("git failed")
		_, err := resolveRunBaseBranch("", func() (string, error) {
			return "", wantErr
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to determine current branch for --base") {
			t.Fatalf("error = %q, missing context", err.Error())
		}
		if !strings.Contains(err.Error(), wantErr.Error()) {
			t.Fatalf("error = %q, missing wrapped error", err.Error())
		}
	})
}
