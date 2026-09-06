package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestSandboxImageVersionPinsStayAligned(t *testing.T) {
	setup, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"GO_VERSION": "1.25.7", "NODE_MAJOR": "22", "CLAUDE_CODE_VERSION": "2.1.207",
		"PI_CODING_AGENT_VERSION": "0.85.0", "CODEX_VERSION": "0.144.1",
	} {
		t.Run(name, func(t *testing.T) {
			setupPattern := regexp.MustCompile(`(?m)^` + name + `="\$\{` + name + `:-([^}]+)\}"$`)
			dockerPattern := regexp.MustCompile(`(?m)^ARG ` + name + `=(\S+)$`)
			for source, match := range map[string][]string{"setup.sh": setupPattern.FindStringSubmatch(string(setup)), "Dockerfile": dockerPattern.FindStringSubmatch(string(dockerfile))} {
				if len(match) != 2 || match[1] != want {
					t.Errorf("%s %s default = %v, want %s", source, name, match, want)
				}
			}
		})
	}
}

func TestSandboxReadmeDocumentsPinnedAgentVersions(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| **Claude Code** | 2.1.207 |", "| **Pi** | 0.85.0 |", "| **Codex** | 0.144.1 |"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("README.md is missing pinned version %q", want)
		}
	}
	if strings.Contains(string(data), "install the latest npm release by default") {
		t.Error("README.md incorrectly claims unpinned default agent versions")
	}
}

func TestSetupScriptRetriesRemoteDownloads(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(sourcePath), "setup.sh"))
	if err != nil {
		t.Fatalf("ReadFile(setup.sh) error = %v", err)
	}
	script := string(data)
	for _, want := range []string{
		"curl_retry()",
		"--retry 5",
		"--retry-delay 2",
		"--retry-all-errors",
		"--connect-timeout 30",
		"download_retry()",
		"curl download failed; retrying with wget",
		"wget --tries=5 --timeout=30 --retry-connrefused",
		"install_github_cli_repo()",
		"download_retry https://cli.github.com/packages/githubcli-archive-keyring.gpg \"$keyring_tmp\"",
		"install_github_cli_distro()",
		"GitHub CLI repository unavailable; falling back to the distro package",
		"rm -f /etc/apt/sources.list.d/github-cli.list",
		"install_nodesource_node()",
		"download_retry \"https://deb.nodesource.com/setup_${NODE_MAJOR}.x\" \"$setup_tmp\"",
		"install_nodejs_archive()",
		"NodeSource unavailable; falling back to the verified official Node.js archive",
		"https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/SHASUMS256.txt",
		"sha256sum -c -",
		"install_agent_clis()",
		"--fetch-retries=5",
		"--fetch-retry-mintimeout=10000",
		"npm agent CLI install failed; retrying",
		"install_tailscale_repo()",
		"https://pkgs.tailscale.com/stable/${distro_id}/${distro_codename}",
		"${repo_base}.noarmor.gpg",
		"${repo_base}.tailscale-keyring.list",
		"/usr/share/keyrings/tailscale-archive-keyring.gpg",
		"download_retry \"https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz\" \"$GO_ARCHIVE\"",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("setup.sh missing resilient download contract %q", want)
		}
	}
}
