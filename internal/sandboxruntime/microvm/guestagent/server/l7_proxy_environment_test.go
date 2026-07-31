package server

import "testing"

func TestL7GeneratedLowercaseProxyEnvironmentIsNarrowlyAllowed(t *testing.T) {
	for _, name := range []string{"http_proxy", "https_proxy"} {
		if !validLinuxEnvironmentName(name) {
			t.Errorf("validLinuxEnvironmentName(%q) = false, want true", name)
		}
	}
	if validLinuxEnvironmentName("arbitrary_lowercase") {
		t.Fatal("validLinuxEnvironmentName() accepted arbitrary lowercase environment name")
	}
}
