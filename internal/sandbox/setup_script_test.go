package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxScriptsConfigureGitHubTokenAuthForSSHStyleRemotes(t *testing.T) {
	scripts := map[string]struct {
		path     string
		required []string
	}{
		"setup.sh": {
			path: filepath.Join("..", "..", "sandbox", "setup.sh"),
			required: []string{
				`${BASH_SOURCE[0]:-}`,
				"HAL_REPO_REF",
				"--branch \"$HAL_REPO_REF\"",
			},
		},
		"entrypoint.sh": {
			path: filepath.Join("..", "..", "sandbox", "entrypoint.sh"),
		},
	}

	commonRequired := []string{
		`export HOME="${HOME:-/root}"`,
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"gh auth login --with-token",
		"env -u GITHUB_TOKEN -u GH_TOKEN",
		"gh auth setup-git",
		`ensure_git_instead_of "https://github.com/" "git@github.com:"`,
		`ensure_git_instead_of "https://github.com/" "ssh://git@github.com/"`,
	}

	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(script.path)
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", script.path, err)
			}
			text := string(content)
			required := append(append([]string(nil), commonRequired...), script.required...)
			for _, needle := range required {
				if !strings.Contains(text, needle) {
					t.Fatalf("%s missing %q", name, needle)
				}
			}
			if strings.Contains(text, "x-access-token:${token}") {
				t.Fatalf("%s should not persist the token in git config", name)
			}
		})
	}
}
