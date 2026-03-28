package sandbox

import (
	"strings"
	"testing"
)

func TestBootstrapScriptsUseCanonicalRepository(t *testing.T) {
	const want = "https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh"

	tests := []struct {
		name   string
		script string
	}{
		{name: "digitalocean", script: generateDOCloudInit(nil, false)},
		{name: "hetzner", script: generateCloudInit(nil, false)},
		{name: "lightsail", script: generateLightsailCloudInit(nil, false)},
	}

	for _, tt := range tests {
		if !strings.Contains(tt.script, want) {
			t.Errorf("%s bootstrap script should use %q", tt.name, want)
		}
	}
}
