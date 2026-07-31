package server

import "testing"

func TestL7GeneratedLowercaseProxyEnvironmentIsNarrowlyAllowed(t *testing.T) {
	for _, name := range []string{"http_proxy", "https_proxy"} {
		if !validLinuxBaseEnvironmentName(name) {
			t.Errorf("validLinuxBaseEnvironmentName(%q) = false, want true", name)
		}
		if validLinuxRequestEnvironmentName(name) {
			t.Errorf("validLinuxRequestEnvironmentName(%q) = true, want false", name)
		}
	}
	if validLinuxBaseEnvironmentName("arbitrary_lowercase") {
		t.Fatal("validLinuxBaseEnvironmentName() accepted arbitrary lowercase environment name")
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "PATH", "L7_VALUE_1"} {
		if !validLinuxRequestEnvironmentName(name) {
			t.Errorf("validLinuxRequestEnvironmentName(%q) = false, want true", name)
		}
	}
}
