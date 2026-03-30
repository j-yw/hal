package ci

import "testing"

func TestSmokeDeliberateFailure(t *testing.T) {
	// Basic smoke test to ensure test execution catches arithmetic regressions.
	got := addNumbers(2, 3)
	if got != 5 {
		t.Errorf("addNumbers(2, 3) = %d, want 5", got)
	}
}

func addNumbers(a, b int) int {
	return a + b
}
