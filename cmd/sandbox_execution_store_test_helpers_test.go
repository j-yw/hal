package cmd

import (
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func newPrivateSandboxExecutionTestStore(t testing.TB) sandboxexecution.Store {
	t.Helper()
	return sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
}
