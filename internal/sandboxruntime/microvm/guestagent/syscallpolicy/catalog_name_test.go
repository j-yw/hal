package syscallpolicy

import "testing"

func TestPolicyCatalogNameAllowsOnlyThePinnedLegacySysctlException(t *testing.T) {
	tests := []struct {
		name    string
		number  SyscallNumber
		value   string
		allowed bool
	}{
		{name: "ordinary", number: 0, value: "read", allowed: true},
		{name: "pinned legacy sysctl", number: 156, value: "_sysctl", allowed: true},
		{name: "legacy name wrong number", number: 155, value: "_sysctl", allowed: false},
		{name: "legacy number wrong name", number: 156, value: "sysctl", allowed: false},
		{name: "other leading underscore", number: 1, value: "_write", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validPolicyCatalogName(test.number, test.value); got != test.allowed {
				t.Fatalf("validPolicyCatalogName(%d, %q) = %t, want %t", test.number, test.value, got, test.allowed)
			}
		})
	}
}
