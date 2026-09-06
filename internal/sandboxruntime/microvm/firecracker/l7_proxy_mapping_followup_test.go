package firecracker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL7FirecrackerAcceptsDistinctSyntheticProxyAddress(t *testing.T) {
	config := validL7NetworkBackendConfig(t)
	config.StaticNetwork.ProxyURL = "http://198.18.0.1:18080"

	rendered, err := liveBootConfig(config)
	if err != nil {
		t.Fatalf("liveBootConfig() error = %v", err)
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(encoded), "hal_l7_proxy=http://198.18.0.1:18080") {
		t.Fatalf("rendered config missing distinct proxy bootstrap")
	}
}
