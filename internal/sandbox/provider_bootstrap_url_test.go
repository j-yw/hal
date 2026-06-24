package sandbox

import (
	"strings"
	"testing"
)

func TestBootstrapScriptsUseCanonicalRepository(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{name: "digitalocean", script: generateDOCloudInit(nil, false)},
		{name: "hetzner", script: generateCloudInit(nil, false)},
		{name: "lightsail", script: generateLightsailCloudInit(nil, false)},
	}

	for _, tt := range tests {
		if !strings.Contains(tt.script, defaultSetupScriptURL) {
			t.Errorf("%s bootstrap script should use %q", tt.name, defaultSetupScriptURL)
		}
		if !strings.Contains(tt.script, "GITHUB_TOKEN") {
			t.Errorf("%s bootstrap script should support authenticated private-repo fetches", tt.name)
		}
		if !strings.Contains(tt.script, "GH_TOKEN") {
			t.Errorf("%s bootstrap script should support GH_TOKEN for authenticated private-repo fetches", tt.name)
		}
		if !strings.Contains(tt.script, "https://raw.githubusercontent.com/*|https://github.com/*/raw/*") {
			t.Errorf("%s bootstrap script should restrict token forwarding to trusted GitHub URLs", tt.name)
		}
		if !strings.Contains(tt.script, "curl -fsSL -H @\"$header_file\" \"$setup_url\" -o \"$script_file\" || exit 1") {
			t.Errorf("%s bootstrap script should pass the GitHub token through a temporary header file", tt.name)
		}
		if strings.Contains(tt.script, "| bash") {
			t.Errorf("%s bootstrap script should not pipe curl directly into bash", tt.name)
		}
	}
}
