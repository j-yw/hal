//go:build linux

package server

import "testing"

func TestL7GeneratedLowercaseProxyEnvironmentIsNarrowlyAllowed(t *testing.T) {
	entries, err := normalizeLinuxEnvironment([]string{
		"http_proxy=http://198.18.0.1:18080",
		"https_proxy=http://198.18.0.1:18080",
	}, false)
	if err != nil {
		t.Fatalf("normalizeLinuxEnvironment() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("normalizeLinuxEnvironment() = %#v, want two entries", entries)
	}
	if _, err := normalizeLinuxEnvironment([]string{"arbitrary_lowercase=value"}, false); err == nil {
		t.Fatal("normalizeLinuxEnvironment() accepted arbitrary lowercase environment name")
	}
}
