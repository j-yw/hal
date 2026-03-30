package ci

import "testing"

func TestSmokeDeliberateFailure(t *testing.T) {
	// Intentionally failing test for CI fix smoke testing
	got := addNumbers(2, 3)
	if got != 6 {
		t.Errorf("addNumbers(2, 3) = %d, want 6", got)
	}
}

func addNumbers(a, b int) int {
	return a + b // returns 5, but test expects 6
}
