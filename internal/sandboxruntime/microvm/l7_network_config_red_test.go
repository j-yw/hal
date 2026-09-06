package microvm

import "testing"

func TestL7NetworkModeIsExplicitOptInAndDefaultRemainsNoNetwork(t *testing.T) {
	if NetworkModeL7PolicyProxy == NetworkModeNoLiveNetworking || NetworkModeL7PolicyProxy == "" {
		t.Fatalf("NetworkModeL7PolicyProxy = %q, want distinct explicit mode", NetworkModeL7PolicyProxy)
	}
	config := minimalValidConfig()
	config.NetworkMode = NetworkModeL7PolicyProxy
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("ValidateConfig(L7 mode) error = %v", err)
	}
	if got := DefaultConfig().NetworkMode; got != NetworkModeNoLiveNetworking {
		t.Fatalf("DefaultConfig().NetworkMode = %q, want %q", got, NetworkModeNoLiveNetworking)
	}
}
