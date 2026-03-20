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

// newlines for all prompts: daytona key, server url, anthropic, openai, github, git name, git email, tailscale key, tailscale hostname
const emptyEnvInputs = "\n\n\n\n\n\n\n"

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
			name: "saves credentials with custom server URL",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "my-api-key\nhttps://custom.server\n" + emptyEnvInputs,
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
			},
		},
		{
			name: "uses default server URL when empty input",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "my-api-key\n\n" + emptyEnvInputs,
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
			name: "overwrites previous credentials",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				old := &compound.DaytonaConfig{APIKey: "old-key", ServerURL: "https://old.server"}
				if err := compound.SaveConfig(dir, old); err != nil {
					t.Fatal(err)
				}
			},
			stdinInput: "new-key\nhttps://new.server\n" + emptyEnvInputs,
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
			name: "preserves existing engine config",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
				existingYAML := "engine: pi\nmaxIterations: 5\n"
				os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644)
			},
			stdinInput: "my-key\nhttps://my.server\n" + emptyEnvInputs,
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
			name: "saves sandbox env vars",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "my-key\n\nsk-ant-test\nsk-openai\nghp-token\nj-yw\nj@example.com\ntskey-auth-xxx\nmy-sandbox\n",
			wantOutput: "7 env vars configured",
			checkFn: func(t *testing.T, dir string) {
				cfg, err := compound.LoadSandboxConfig(dir)
				if err != nil {
					t.Fatalf("LoadSandboxConfig() error: %v", err)
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
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			stdinInput: "key\nhttps://server\n",
			wantErr:    ".hal/ not found",
		},
		{
			name: "error when API key is empty",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)
			},
			stdinInput: "\nhttps://server\n",
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

			err := runSandboxSetup(dir, in, &out, noopPasswordReader)

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

func TestRunSandboxSetup_PromptOutput(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	in := strings.NewReader("test-key\n\n" + emptyEnvInputs)
	var out bytes.Buffer

	err := runSandboxSetup(dir, in, &out, noopPasswordReader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
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

	// Write input for all prompts
	if _, err := inputFile.WriteString("piped-api-key\n\n" + emptyEnvInputs); err != nil {
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
	if err := runSandboxSetup(dir, inputFile, &out, readPassword); err != nil {
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
