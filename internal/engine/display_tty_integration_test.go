//go:build integration
// +build integration

package engine

import "testing"

// Display TTY integration tests are intentionally separated from default unit runs.
//
// Scope:
//   - PTY-backed lifecycle coverage for Display spinner rendering and terminal teardown.
//   - Assertions that rely on real TTY redraw behavior (\r and ANSI control sequences).
//
// Determinism constraints:
//   - Use bounded waits (no unbounded sleeps/loops).
//   - Normalize terminal output before asserting.
//   - Keep cleanup strict so spinner goroutines and PTY handles never leak.
func TestDisplayTTYIntegrationScaffold(t *testing.T) {
	t.Skip("integration scaffold: PTY lifecycle tests will be added in subsequent stories")
}
