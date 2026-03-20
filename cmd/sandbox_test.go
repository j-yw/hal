package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
)

// noopPasswordReader is a passwordReader that is never called in tests
// (input is always a non-*os.File reader, so the plain-text path is taken).
func noopPasswordReader(_ int) ([]byte, error) {
	return nil, nil
}

// fakeLookPath always succeeds — simulates all CLIs being available.
func fakeLookPath(_ string) (string, error) {
	return "/usr/bin/fake", nil
}

// fakeLookPathMissing returns an error — simulates CLI not on PATH.
func fakeLookPathMissing(name string) (string, error) {
	return "", fmt.Errorf("executable file not found in $PATH: %s", name)
}

// newlines for all env-var prompts: anthropic, openai, github, git name, git email, tailscale key, tailscale hostname
const emptyEnvInputs = "\n\n\n\n\n\n\n"

// daytonaSetupInput builds stdin input for the Daytona setup path:
// provider choice "1", api key, server url, then env var prompts.
func daytonaSetupInput(apiKey, serverURL string) string {
	return "1\n" + apiKey + "\n" + serverURL + "\n" + emptyEnvInputs
}

// hetznerSetupInput builds stdin input for the Hetzner setup path:
// provider choice "2", ssh key name, server type, image, then env var prompts.
func hetznerSetupInput(sshKey, serverType, image string) string {
	return "2\n" + sshKey + "\n" + serverType + "\n" + image + "\n" + emptyEnvInputs
}

// digitaloceanSetupInput builds stdin input for the DigitalOcean setup path:
// provider choice "3", ssh key fingerprint, droplet size, then env var prompts.
func digitaloceanSetupInput(sshKey, size string) string {
	return "3\n" + sshKey + "\n" + size + "\n" + emptyEnvInputs
}

func TestRunSandboxSetup(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		stdinInput string
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string)
	}{
		{
			name: "daytona: saves credentials with custom server URL",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "1\nmy-api-key\nhttps://custom.server\n" + emptyEnvInputs,
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadDaytonaConfig(dir)
				if err != nil {
					t.Fatalf("LoadDaytonaConfig() error: %v", err)
				}
				if cfg.APIKey != "my-api-key" {
					t.Errorf("APIKey = %q, want %q", cfg.APIKey, "my-api-key")
				}
				if cfg.ServerURL != "https://custom.server" {
					t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://custom.server")
				}
				sCfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if sCfg.Provider != "daytona" {
					t.Errorf("Provider = %q, want %q", sCfg.Provider, "daytona")
				}
			},
		},
		{
			name: "daytona: uses default server URL when empty input",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: daytonaSetupInput("my-api-key", ""),
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadDaytonaConfig(dir)
				if err != nil {
					t.Fatalf("LoadDaytonaConfig() error: %v", err)
				}
				if cfg.APIKey != "my-api-key" {
					t.Errorf("APIKey = %q, want %q", cfg.APIKey, "my-api-key")
				}
				if cfg.ServerURL != "https://app.daytona.io/api" {
					t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://app.daytona.io/api")
				}
			},
		},
		{
			name: "daytona: overwrites previous credentials",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				old := &compound.DaytonaConfig{APIKey: "old-key", ServerURL: "https://old.server"}
				if err := compound.SaveConfig(dir, old); err != nil {
					t.Fatal(err)
				}
			},
			stdinInput: "1\nnew-key\nhttps://new.server\n" + emptyEnvInputs,
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadDaytonaConfig(dir)
				if err != nil {
					t.Fatalf("LoadDaytonaConfig() error: %v", err)
				}
				if cfg.APIKey != "new-key" {
					t.Errorf("APIKey = %q, want %q", cfg.APIKey, "new-key")
				}
				if cfg.ServerURL != "https://new.server" {
					t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://new.server")
				}
			},
		},
		{
			name: "daytona: preserves existing engine config",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				existingYAML := "engine: pi\nmaxIterations: 5\n"
				os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644)
			},
			stdinInput: "1\nmy-key\nhttps://my.server\n" + emptyEnvInputs,
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadDaytonaConfig(dir)
				if err != nil {
					t.Fatalf("LoadDaytonaConfig() error: %v", err)
				}
				if cfg.APIKey != "my-key" {
					t.Errorf("APIKey = %q, want %q", cfg.APIKey, "my-key")
				}
				data, err := os.ReadFile(filepath.Join(dir, template.HalDir, "config.yaml"))
				if err != nil {
					t.Fatalf("reading config.yaml: %v", err)
				}
				if !strings.Contains(string(data), "engine:") {
					t.Error("engine section was clobbered")
				}
			},
		},
		{
			name: "daytona: saves sandbox env vars",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "1\nmy-key\n\nsk-ant-test\nsk-openai\nghp-token\nj-yw\nj@example.com\ntskey-auth-xxx\nmy-sandbox\n",
			wantOutput: "7 env vars configured",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "daytona" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "daytona")
				}
				if cfg.Env["ANTHROPIC_API_KEY"] != "sk-ant-test" {
					t.Errorf("ANTHROPIC_API_KEY = %q, want %q", cfg.Env["ANTHROPIC_API_KEY"], "sk-ant-test")
				}
				if cfg.Env["GIT_USER_NAME"] != "j-yw" {
					t.Errorf("GIT_USER_NAME = %q, want %q", cfg.Env["GIT_USER_NAME"], "j-yw")
				}
				if cfg.Env["TAILSCALE_HOSTNAME"] != "my-sandbox" {
					t.Errorf("TAILSCALE_HOSTNAME = %q, want %q", cfg.Env["TAILSCALE_HOSTNAME"], "my-sandbox")
				}
			},
		},
			{
				name: "hetzner: saves ssh key and server type",
				setup: func(t *testing.T, dir string) {
					os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
				},
				stdinInput: hetznerSetupInput("my-ssh-key", "cx32", "debian-12"),
				wantOutput: "Saved to .hal/config.yaml",
				checkFn: func(t *testing.T, dir string) {
					cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "hetzner" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "hetzner")
				}
				if cfg.Hetzner.SSHKey != "my-ssh-key" {
					t.Errorf("Hetzner.SSHKey = %q, want %q", cfg.Hetzner.SSHKey, "my-ssh-key")
				}
					if cfg.Hetzner.ServerType != "cx32" {
						t.Errorf("Hetzner.ServerType = %q, want %q", cfg.Hetzner.ServerType, "cx32")
					}
					if cfg.Hetzner.Image != "debian-12" {
						t.Errorf("Hetzner.Image = %q, want %q", cfg.Hetzner.Image, "debian-12")
					}
				},
			},
			{
				name: "hetzner: uses default server type when empty",
				setup: func(t *testing.T, dir string) {
					os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
				},
				stdinInput: hetznerSetupInput("my-ssh-key", "", ""),
				wantOutput: "Saved to .hal/config.yaml",
				checkFn: func(t *testing.T, dir string) {
					cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "hetzner" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "hetzner")
				}
				if cfg.Hetzner.SSHKey != "my-ssh-key" {
					t.Errorf("Hetzner.SSHKey = %q, want %q", cfg.Hetzner.SSHKey, "my-ssh-key")
				}
					if cfg.Hetzner.ServerType != "cx22" {
						t.Errorf("Hetzner.ServerType = %q, want %q (default)", cfg.Hetzner.ServerType, "cx22")
					}
					if cfg.Hetzner.Image != "ubuntu-24.04" {
						t.Errorf("Hetzner.Image = %q, want %q (default)", cfg.Hetzner.Image, "ubuntu-24.04")
					}
				},
			},
		{
			name: "hetzner: saves env vars alongside hetzner config",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			// 3 vars: sk-ant-test, j-yw, + hal-sandbox (tailscale hostname default)
				stdinInput: "2\nmy-ssh-key\n\n\nsk-ant-test\n\n\nj-yw\n\n\n\n",
			wantOutput: "3 env vars configured",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "hetzner" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "hetzner")
				}
				if cfg.Env["ANTHROPIC_API_KEY"] != "sk-ant-test" {
					t.Errorf("ANTHROPIC_API_KEY = %q, want %q", cfg.Env["ANTHROPIC_API_KEY"], "sk-ant-test")
				}
				if cfg.Env["GIT_USER_NAME"] != "j-yw" {
					t.Errorf("GIT_USER_NAME = %q, want %q", cfg.Env["GIT_USER_NAME"], "j-yw")
				}
			},
		},
		{
			name: "hetzner: preserves existing engine config",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				existingYAML := "engine: pi\nmaxIterations: 5\n"
				os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644)
			},
				stdinInput: hetznerSetupInput("my-key", "", ""),
				wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				data, err := os.ReadFile(filepath.Join(dir, template.HalDir, "config.yaml"))
				if err != nil {
					t.Fatalf("reading config.yaml: %v", err)
				}
				if !strings.Contains(string(data), "engine:") {
					t.Error("engine section was clobbered")
				}
			},
		},
		{
			name: "hetzner: error when SSH key is empty",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "2\n\n",
			wantErr:    "is required",
		},
		{
			name: "defaults to daytona when pressing enter on provider",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "\nmy-api-key\n\n" + emptyEnvInputs,
			wantOutput: "Provider:   daytona",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "daytona" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "daytona")
				}
			},
		},
		{
			name: "defaults to hetzner when existing config is hetzner",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
					sandboxCfg := &compound.SandboxConfig{
						Provider: "hetzner",
						Hetzner:  compound.HetznerConfig{SSHKey: "old-key", Image: "debian-12"},
						Env:      map[string]string{},
					}
					compound.SaveSandboxConfig(dir, sandboxCfg)
				},
				stdinInput: "\n\n\n\n" + emptyEnvInputs, // enter=hetzner default, keep old ssh key/default type/default image
				wantOutput: "Provider:   hetzner",
				checkFn: func(t *testing.T, dir string) {
					cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "hetzner" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "hetzner")
				}
					if cfg.Hetzner.SSHKey != "old-key" {
						t.Errorf("Hetzner.SSHKey = %q, want %q", cfg.Hetzner.SSHKey, "old-key")
					}
					if cfg.Hetzner.Image != "debian-12" {
						t.Errorf("Hetzner.Image = %q, want %q", cfg.Hetzner.Image, "debian-12")
					}
				},
			},
		{
			name: "digitalocean: saves ssh key and size",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: digitaloceanSetupInput("ab:cd:ef:12:34", "s-4vcpu-8gb"),
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "digitalocean" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "digitalocean")
				}
				if cfg.DigitalOcean.SSHKey != "ab:cd:ef:12:34" {
					t.Errorf("DigitalOcean.SSHKey = %q, want %q", cfg.DigitalOcean.SSHKey, "ab:cd:ef:12:34")
				}
				if cfg.DigitalOcean.Size != "s-4vcpu-8gb" {
					t.Errorf("DigitalOcean.Size = %q, want %q", cfg.DigitalOcean.Size, "s-4vcpu-8gb")
				}
			},
		},
		{
			name: "digitalocean: uses default size when empty",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: digitaloceanSetupInput("ab:cd:ef:12:34", ""),
			wantOutput: "Saved to .hal/config.yaml",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "digitalocean" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "digitalocean")
				}
				if cfg.DigitalOcean.SSHKey != "ab:cd:ef:12:34" {
					t.Errorf("DigitalOcean.SSHKey = %q, want %q", cfg.DigitalOcean.SSHKey, "ab:cd:ef:12:34")
				}
				if cfg.DigitalOcean.Size != "s-2vcpu-4gb" {
					t.Errorf("DigitalOcean.Size = %q, want %q (default)", cfg.DigitalOcean.Size, "s-2vcpu-4gb")
				}
			},
		},
		{
			name: "digitalocean: error when SSH key fingerprint is empty",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "3\n\n",
			wantErr:    "is required",
		},
		{
			name: "digitalocean: saves env vars alongside DO config",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "3\nab:cd:ef\n\nsk-ant-test\n\n\nj-yw\n\n\n\n",
			wantOutput: "3 env vars configured",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "digitalocean" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "digitalocean")
				}
				if cfg.Env["ANTHROPIC_API_KEY"] != "sk-ant-test" {
					t.Errorf("ANTHROPIC_API_KEY = %q, want %q", cfg.Env["ANTHROPIC_API_KEY"], "sk-ant-test")
				}
				if cfg.Env["GIT_USER_NAME"] != "j-yw" {
					t.Errorf("GIT_USER_NAME = %q, want %q", cfg.Env["GIT_USER_NAME"], "j-yw")
				}
			},
		},
		{
			name: "digitalocean: defaults to DO when existing config is digitalocean",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				sandboxCfg := &compound.SandboxConfig{
					Provider:     "digitalocean",
					DigitalOcean: compound.DigitalOceanConfig{SSHKey: "old-fp", Size: "s-1vcpu-1gb"},
					Env:          map[string]string{},
				}
				compound.SaveSandboxConfig(dir, sandboxCfg)
			},
			stdinInput: "\n\n\n" + emptyEnvInputs, // enter=DO default, keep old ssh key, keep old size
			wantOutput: "Provider:   digitalocean",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
				}
				if cfg.Provider != "digitalocean" {
					t.Errorf("Provider = %q, want %q", cfg.Provider, "digitalocean")
				}
				if cfg.DigitalOcean.SSHKey != "old-fp" {
					t.Errorf("DigitalOcean.SSHKey = %q, want %q", cfg.DigitalOcean.SSHKey, "old-fp")
				}
				if cfg.DigitalOcean.Size != "s-1vcpu-1gb" {
					t.Errorf("DigitalOcean.Size = %q, want %q", cfg.DigitalOcean.Size, "s-1vcpu-1gb")
				}
			},
		},
		{
			name: "invalid provider choice returns error",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "4\n",
			wantErr:    "invalid provider choice",
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			stdinInput: "1\nkey\nhttps://server\n",
			wantErr:    ".hal/ not found",
		},
		{
			name: "daytona: error when API key is empty",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "1\n\nhttps://server\n",
			wantErr:    "is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			in := strings.NewReader(tt.stdinInput)
			var out bytes.Buffer

			err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPath)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, dir)
			}
		})
	}
}

func TestRunSandboxSetup_PromptOutput_Daytona(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader(daytonaSetupInput("test-key", ""))
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Select Provider") {
		t.Error("output should contain provider selection prompt")
	}
	if !strings.Contains(output, "Daytona API key") {
		t.Error("output should contain API key prompt")
	}
	if !strings.Contains(output, "Server URL") {
		t.Errorf("output should contain server URL prompt, got: %q", output)
	}
	if !strings.Contains(output, "Anthropic API key") {
		t.Error("output should contain Anthropic prompt")
	}
	if !strings.Contains(output, "Tailscale") {
		t.Error("output should contain Tailscale section")
	}
	if !strings.Contains(output, "Provider:   daytona") {
		t.Error("output should show daytona as provider in summary")
	}
}

func TestRunSandboxSetup_PromptOutput_Hetzner(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader(hetznerSetupInput("my-key", "", ""))
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Select Provider") {
		t.Error("output should contain provider selection prompt")
	}
	if !strings.Contains(output, "── Hetzner ──") {
		t.Error("output should contain Hetzner section header")
	}
	if !strings.Contains(output, "SSH key name") {
		t.Error("output should contain SSH key prompt")
	}
	if !strings.Contains(output, "Server type") {
		t.Error("output should contain server type prompt")
	}
	if !strings.Contains(output, "Image") {
		t.Error("output should contain image prompt")
	}
	if !strings.Contains(output, "Provider:   hetzner") {
		t.Error("output should show hetzner as provider in summary")
	}
	if !strings.Contains(output, "ssh-key=my-key") {
		t.Error("output should show SSH key in summary")
	}
}

func TestRunSandboxSetup_NonTerminalFileInputFallsBackToPlaintext(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, template.HalDir), 0755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}

	inputFile, err := os.CreateTemp(t.TempDir(), "sandbox-stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error: %v", err)
	}
	t.Cleanup(func() {
		_ = inputFile.Close()
	})

	// Write input for all prompts: provider choice, api key, server url, env vars
	if _, err := inputFile.WriteString("1\npiped-api-key\n\n" + emptyEnvInputs); err != nil {
		t.Fatalf("WriteString() error: %v", err)
	}
	if _, err := inputFile.Seek(0, 0); err != nil {
		t.Fatalf("Seek() error: %v", err)
	}

	readPasswordCalled := false
	readPassword := func(_ int) ([]byte, error) {
		readPasswordCalled = true
		return nil, fmt.Errorf("should not call readPassword for non-terminal stdin")
	}

	var out bytes.Buffer
	if err := runSandboxSetup(dir, inputFile, &out, readPassword, fakeLookPath); err != nil {
		t.Fatalf("runSandboxSetup() error: %v", err)
	}

	if readPasswordCalled {
		t.Fatal("readPassword was called for non-terminal *os.File input")
	}

	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		t.Fatalf("LoadDaytonaConfig() error: %v", err)
	}
	if cfg.APIKey != "piped-api-key" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "piped-api-key")
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "••••"},
		{"abc", "••••"},
		{"abcdef", "••••cdef"},
		{"sk-ant-abc123xyz", "••••3xyz"},
	}
	for _, tt := range tests {
		got := maskSecret(tt.input)
		if got != tt.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRunSandboxSetup_PromptOutput_DigitalOcean(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader(digitaloceanSetupInput("ab:cd:ef:12:34", ""))
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Select Provider") {
		t.Error("output should contain provider selection prompt")
	}
	if !strings.Contains(output, "DigitalOcean") {
		t.Error("output should contain DigitalOcean in provider selection")
	}
	if !strings.Contains(output, "── DigitalOcean ──") {
		t.Error("output should contain DigitalOcean section header")
	}
	if !strings.Contains(output, "SSH key fingerprint") {
		t.Error("output should contain SSH key fingerprint prompt")
	}
	if !strings.Contains(output, "doctl compute ssh-key list") {
		t.Error("output should contain doctl hint for SSH key")
	}
	if !strings.Contains(output, "Droplet size") {
		t.Error("output should contain droplet size prompt")
	}
	if !strings.Contains(output, "Provider:   digitalocean") {
		t.Error("output should show digitalocean as provider in summary")
	}
	if !strings.Contains(output, "ssh-key=ab:cd:ef:12:34") {
		t.Error("output should show SSH key fingerprint in summary")
	}
}

func TestRunSandboxSetup_DigitalOcean_DoctlNotFound(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader("3\n")
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPathMissing)
	if err == nil {
		t.Fatal("expected error when doctl is not on PATH, got nil")
	}
	if !strings.Contains(err.Error(), "doctl not found") {
		t.Errorf("error %q should contain 'doctl not found'", err.Error())
	}
	if !strings.Contains(err.Error(), "doctl auth init") {
		t.Errorf("error %q should contain install/auth instructions", err.Error())
	}

	// Verify no config was saved (no partial state)
	cfg, _ := compound.LoadSandboxConfig(dir)
	if cfg != nil && cfg.Provider == "digitalocean" {
		t.Error("should not save digitalocean config when doctl is missing")
	}
}

func TestRunSandboxSetup_DoctlCheckOnlyForDigitalOcean(t *testing.T) {
	// Daytona and Hetzner should work even when doctl is missing
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader(daytonaSetupInput("my-key", ""))
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader, fakeLookPathMissing)
	if err != nil {
		t.Fatalf("Daytona setup should succeed even when doctl is missing: %v", err)
	}
}

func TestParseEnvFlags(t *testing.T) {
	tests := []struct {
		input []string
		want  map[string]string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"KEY=value"}, map[string]string{"KEY": "value"}},
		{[]string{"A=1", "B=2=3"}, map[string]string{"A": "1", "B": "2=3"}},
	}
	for _, tt := range tests {
		got := parseEnvFlags(tt.input)
		if tt.want == nil {
			if got != nil {
				t.Errorf("parseEnvFlags(%v) = %v, want nil", tt.input, got)
			}
			continue
		}
		for k, v := range tt.want {
			if got[k] != v {
				t.Errorf("parseEnvFlags(%v)[%q] = %q, want %q", tt.input, k, got[k], v)
			}
		}
	}
}
