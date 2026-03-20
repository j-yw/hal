package compound

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultAutoConfig(t *testing.T) {
	cfg := DefaultAutoConfig()

	if cfg.ReportsDir != ".hal/reports" {
		t.Errorf("ReportsDir = %q, want %q", cfg.ReportsDir, ".hal/reports")
	}
	if cfg.BranchPrefix != "compound/" {
		t.Errorf("BranchPrefix = %q, want %q", cfg.BranchPrefix, "compound/")
	}
	if cfg.MaxIterations != 25 {
		t.Errorf("MaxIterations = %d, want %d", cfg.MaxIterations, 25)
	}
	if len(cfg.QualityChecks) != 0 {
		t.Errorf("QualityChecks length = %d, want 0", len(cfg.QualityChecks))
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	defaults := DefaultAutoConfig()

	t.Run("non-existent directory returns defaults", func(t *testing.T) {
		cfg, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist"))
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		assertConfigMatchesDefaults(t, cfg, &defaults)
	})

	t.Run("directory exists but no config.yaml returns defaults", func(t *testing.T) {
		dir := t.TempDir()
		cfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		assertConfigMatchesDefaults(t, cfg, &defaults)
	})
}

func assertConfigMatchesDefaults(t *testing.T, got, want *AutoConfig) {
	t.Helper()
	if got.ReportsDir != want.ReportsDir {
		t.Errorf("ReportsDir = %q, want %q", got.ReportsDir, want.ReportsDir)
	}
	if got.BranchPrefix != want.BranchPrefix {
		t.Errorf("BranchPrefix = %q, want %q", got.BranchPrefix, want.BranchPrefix)
	}
	if got.MaxIterations != want.MaxIterations {
		t.Errorf("MaxIterations = %d, want %d", got.MaxIterations, want.MaxIterations)
	}
	if len(got.QualityChecks) != len(want.QualityChecks) {
		t.Errorf("QualityChecks length = %d, want %d", len(got.QualityChecks), len(want.QualityChecks))
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	defaults := DefaultAutoConfig()

	tests := []struct {
		name        string
		yaml        string
		wantDir     string
		wantPrefix  string
		wantMaxIter int
		wantQCCount int
	}{
		{
			name: "full config overrides all defaults",
			yaml: `auto:
  reportsDir: "custom/reports"
  branchPrefix: "feature/"
  maxIterations: 10
  qualityChecks:
    - "make test"
    - "make lint"
`,
			wantDir:     "custom/reports",
			wantPrefix:  "feature/",
			wantMaxIter: 10,
			wantQCCount: 2,
		},
		{
			name: "partial config merges with defaults",
			yaml: `auto:
  reportsDir: "my/reports"
`,
			wantDir:     "my/reports",
			wantPrefix:  defaults.BranchPrefix,
			wantMaxIter: defaults.MaxIterations,
			wantQCCount: 0,
		},
		{
			name:        "empty auto section uses all defaults",
			yaml:        "auto:\n",
			wantDir:     defaults.ReportsDir,
			wantPrefix:  defaults.BranchPrefix,
			wantMaxIter: defaults.MaxIterations,
			wantQCCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			cfg, err := LoadConfig(dir)
			if err != nil {
				t.Fatalf("LoadConfig() unexpected error: %v", err)
			}

			if cfg.ReportsDir != tt.wantDir {
				t.Errorf("ReportsDir = %q, want %q", cfg.ReportsDir, tt.wantDir)
			}
			if cfg.BranchPrefix != tt.wantPrefix {
				t.Errorf("BranchPrefix = %q, want %q", cfg.BranchPrefix, tt.wantPrefix)
			}
			if cfg.MaxIterations != tt.wantMaxIter {
				t.Errorf("MaxIterations = %d, want %d", cfg.MaxIterations, tt.wantMaxIter)
			}
			if len(cfg.QualityChecks) != tt.wantQCCount {
				t.Errorf("QualityChecks length = %d, want %d", len(cfg.QualityChecks), tt.wantQCCount)
			}
		})
	}
}

func TestLoadEngineConfig(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		engineName   string
		wantNil      bool
		wantModel    string
		wantProvider string
		wantTimeout  time.Duration
	}{
		{
			name:       "no engines section returns nil",
			yaml:       "engine: claude\n",
			engineName: "pi",
			wantNil:    true,
		},
		{
			name: "engine not in engines map returns nil",
			yaml: `engines:
  claude:
    model: claude-sonnet-4-20250514
`,
			engineName: "pi",
			wantNil:    true,
		},
		{
			name: "pi with model and provider",
			yaml: `engines:
  pi:
    provider: google
    model: gemini-2.5-pro
    timeout: 30m
`,
			engineName:   "pi",
			wantModel:    "gemini-2.5-pro",
			wantProvider: "google",
			wantTimeout:  30 * time.Minute,
		},
		{
			name: "claude with model only",
			yaml: `engines:
  claude:
    model: claude-sonnet-4-20250514
`,
			engineName: "claude",
			wantModel:  "claude-sonnet-4-20250514",
		},
		{
			name: "pi with provider only",
			yaml: `engines:
  pi:
    provider: anthropic
`,
			engineName:   "pi",
			wantProvider: "anthropic",
		},
		{
			name: "codex with timeout only",
			yaml: `engines:
  codex:
    timeout: 45m
`,
			engineName:  "codex",
			wantTimeout: 45 * time.Minute,
		},
		{
			name: "invalid timeout is ignored when no other settings exist",
			yaml: `engines:
  codex:
    timeout: later
`,
			engineName: "codex",
			wantNil:    true,
		},
		{
			name: "empty values return nil",
			yaml: `engines:
  pi:
    provider: ""
    model: ""
`,
			engineName: "pi",
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			cfg := LoadEngineConfig(dir, tt.engineName)

			if tt.wantNil {
				if cfg != nil {
					t.Errorf("expected nil, got %+v", cfg)
				}
				return
			}

			if cfg == nil {
				t.Fatal("expected non-nil config, got nil")
			}
			if cfg.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", cfg.Model, tt.wantModel)
			}
			if cfg.Provider != tt.wantProvider {
				t.Errorf("Provider = %q, want %q", cfg.Provider, tt.wantProvider)
			}
			if cfg.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", cfg.Timeout, tt.wantTimeout)
			}
		})
	}
}

func TestLoadEngineConfig_MissingFile(t *testing.T) {
	cfg := LoadEngineConfig(t.TempDir(), "pi")
	if cfg != nil {
		t.Errorf("expected nil for missing config file, got %+v", cfg)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErrSub string
	}{
		{
			name:       "invalid YAML syntax",
			yaml:       ":::not yaml",
			wantErrSub: "",
		},
		{
			name: "maxIterations negative triggers validation",
			yaml: `auto:
  maxIterations: -1
`,
			wantErrSub: "maxIterations",
		},
		{
			name: "explicit empty reportsDir triggers validation",
			yaml: `auto:
  reportsDir: ""
`,
			wantErrSub: "reportsDir",
		},
		{
			name: "explicit empty branchPrefix triggers validation",
			yaml: `auto:
  branchPrefix: ""
`,
			wantErrSub: "branchPrefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			_, err := LoadConfig(dir)
			if err == nil {
				t.Fatal("LoadConfig() expected error, got nil")
			}
			if tt.wantErrSub != "" && !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
			}
		})
	}
}

func TestLoadDefaultEngine(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		want    string
		wantErr string
	}{
		{
			name: "missing config falls back to codex",
			setup: func(t *testing.T, dir string) {
				_ = dir
			},
			want: "codex",
		},
		{
			name: "empty engine falls back to codex",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, ".hal")
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatalf("mkdir .hal: %v", err)
				}
				if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte("engine: \"\"\n"), 0644); err != nil {
					t.Fatalf("write config: %v", err)
				}
			},
			want: "codex",
		},
		{
			name: "reads configured engine",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, ".hal")
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatalf("mkdir .hal: %v", err)
				}
				if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte("engine: Claude\n"), 0644); err != nil {
					t.Fatalf("write config: %v", err)
				}
			},
			want: "claude",
		},
		{
			name: "invalid yaml returns error",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, ".hal")
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatalf("mkdir .hal: %v", err)
				}
				if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(":::invalid"), 0644); err != nil {
					t.Fatalf("write config: %v", err)
				}
			},
			wantErr: "cannot unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			got, err := LoadDefaultEngine(dir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("engine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultDaytonaConfig(t *testing.T) {
	cfg := DefaultDaytonaConfig()
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty", cfg.APIKey)
	}
	if cfg.ServerURL != "" {
		t.Errorf("ServerURL = %q, want empty", cfg.ServerURL)
	}
}

func TestLoadDaytonaConfig_MissingFile(t *testing.T) {
	t.Run("non-existent directory returns defaults", func(t *testing.T) {
		cfg, err := LoadDaytonaConfig(filepath.Join(t.TempDir(), "does-not-exist"))
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if cfg.APIKey != "" {
			t.Errorf("APIKey = %q, want empty", cfg.APIKey)
		}
		if cfg.ServerURL != "" {
			t.Errorf("ServerURL = %q, want empty", cfg.ServerURL)
		}
	})

	t.Run("directory exists but no config.yaml returns defaults", func(t *testing.T) {
		cfg, err := LoadDaytonaConfig(t.TempDir())
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if cfg.APIKey != "" {
			t.Errorf("APIKey = %q, want empty", cfg.APIKey)
		}
		if cfg.ServerURL != "" {
			t.Errorf("ServerURL = %q, want empty", cfg.ServerURL)
		}
	})
}

func TestLoadDaytonaConfig_ValidYAML(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		wantAPIKey    string
		wantServerURL string
	}{
		{
			name: "full daytona config",
			yaml: `daytona:
  apiKey: "my-secret-key"
  serverURL: "https://daytona.example.com"
`,
			wantAPIKey:    "my-secret-key",
			wantServerURL: "https://daytona.example.com",
		},
		{
			name: "only apiKey set",
			yaml: `daytona:
  apiKey: "key-only"
`,
			wantAPIKey:    "key-only",
			wantServerURL: "",
		},
		{
			name: "only serverURL set",
			yaml: `daytona:
  serverURL: "https://custom.server"
`,
			wantAPIKey:    "",
			wantServerURL: "https://custom.server",
		},
		{
			name:          "empty daytona section uses defaults",
			yaml:          "daytona:\n",
			wantAPIKey:    "",
			wantServerURL: "",
		},
		{
			name:          "no daytona section uses defaults",
			yaml:          "engine: claude\n",
			wantAPIKey:    "",
			wantServerURL: "",
		},
		{
			name: "daytona alongside other sections",
			yaml: `engine: claude
auto:
  reportsDir: .hal/reports
  branchPrefix: compound/
  maxIterations: 25
daytona:
  apiKey: "alongside-key"
  serverURL: "https://alongside.server"
`,
			wantAPIKey:    "alongside-key",
			wantServerURL: "https://alongside.server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			cfg, err := LoadDaytonaConfig(dir)
			if err != nil {
				t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
			}
			if cfg.APIKey != tt.wantAPIKey {
				t.Errorf("APIKey = %q, want %q", cfg.APIKey, tt.wantAPIKey)
			}
			if cfg.ServerURL != tt.wantServerURL {
				t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, tt.wantServerURL)
			}
		})
	}
}

func TestLoadDaytonaConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("Failed to create .hal dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(":::not yaml"), 0644); err != nil {
		t.Fatalf("Failed to write config.yaml: %v", err)
	}

	_, err := LoadDaytonaConfig(dir)
	if err == nil {
		t.Fatal("LoadDaytonaConfig() expected error for invalid YAML, got nil")
	}
}

func TestSaveConfig(t *testing.T) {
	t.Run("creates config.yaml when none exists", func(t *testing.T) {
		dir := t.TempDir()
		daytona := &DaytonaConfig{
			APIKey:    "new-key",
			ServerURL: "https://new.server",
		}

		if err := SaveConfig(dir, daytona); err != nil {
			t.Fatalf("SaveConfig() unexpected error: %v", err)
		}

		// Verify we can read it back
		cfg, err := LoadDaytonaConfig(dir)
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if cfg.APIKey != "new-key" {
			t.Errorf("APIKey = %q, want %q", cfg.APIKey, "new-key")
		}
		if cfg.ServerURL != "https://new.server" {
			t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://new.server")
		}
	})

	t.Run("tightens existing config.yaml permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission bits are not portable on Windows")
		}

		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}

		configPath := filepath.Join(halDir, "config.yaml")
		if err := os.WriteFile(configPath, []byte("engine: claude\n"), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		daytona := &DaytonaConfig{
			APIKey:    "saved-key",
			ServerURL: "https://saved.server",
		}
		if err := SaveConfig(dir, daytona); err != nil {
			t.Fatalf("SaveConfig() unexpected error: %v", err)
		}

		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("Failed to stat config.yaml: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("config.yaml permissions = %o, want %o", info.Mode().Perm(), 0600)
		}
	})

	t.Run("preserves existing engine and auto sections", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}

		existingYAML := `engine: pi
maxIterations: 5
auto:
  reportsDir: custom/reports
  branchPrefix: feature/
  maxIterations: 10
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		daytona := &DaytonaConfig{
			APIKey:    "saved-key",
			ServerURL: "https://saved.server",
		}
		if err := SaveConfig(dir, daytona); err != nil {
			t.Fatalf("SaveConfig() unexpected error: %v", err)
		}

		// Verify daytona was saved
		dayCfg, err := LoadDaytonaConfig(dir)
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if dayCfg.APIKey != "saved-key" {
			t.Errorf("APIKey = %q, want %q", dayCfg.APIKey, "saved-key")
		}

		// Verify auto section was not clobbered
		autoCfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		if autoCfg.ReportsDir != "custom/reports" {
			t.Errorf("ReportsDir = %q, want %q", autoCfg.ReportsDir, "custom/reports")
		}
		if autoCfg.BranchPrefix != "feature/" {
			t.Errorf("BranchPrefix = %q, want %q", autoCfg.BranchPrefix, "feature/")
		}
		if autoCfg.MaxIterations != 10 {
			t.Errorf("MaxIterations = %d, want %d", autoCfg.MaxIterations, 10)
		}
	})

	t.Run("overwrites previous daytona section", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}

		existingYAML := `engine: claude
daytona:
  apiKey: "old-key"
  serverURL: "https://old.server"
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		daytona := &DaytonaConfig{
			APIKey:    "updated-key",
			ServerURL: "https://updated.server",
		}
		if err := SaveConfig(dir, daytona); err != nil {
			t.Fatalf("SaveConfig() unexpected error: %v", err)
		}

		cfg, err := LoadDaytonaConfig(dir)
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if cfg.APIKey != "updated-key" {
			t.Errorf("APIKey = %q, want %q", cfg.APIKey, "updated-key")
		}
		if cfg.ServerURL != "https://updated.server" {
			t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://updated.server")
		}
	})
}

func TestLoadSandboxConfig_MissingFile(t *testing.T) {
	t.Run("non-existent directory returns defaults with daytona provider", func(t *testing.T) {
		cfg, err := LoadSandboxConfig(filepath.Join(t.TempDir(), "does-not-exist"))
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if cfg.Provider != "daytona" {
			t.Errorf("Provider = %q, want %q", cfg.Provider, "daytona")
		}
		if len(cfg.Env) != 0 {
			t.Errorf("Env length = %d, want 0", len(cfg.Env))
		}
	})

	t.Run("directory exists but no config.yaml returns defaults", func(t *testing.T) {
		cfg, err := LoadSandboxConfig(t.TempDir())
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if cfg.Provider != "daytona" {
			t.Errorf("Provider = %q, want %q", cfg.Provider, "daytona")
		}
	})
}

func TestLoadSandboxConfig_ValidYAML(t *testing.T) {
	tests := []struct {
		name           string
		yaml           string
		wantProvider   string
		wantEnvCount   int
		wantSSHKey     string
		wantServerType string
		wantImage      string
	}{
		{
			name:         "missing provider defaults to daytona",
			yaml:         "engine: claude\n",
			wantProvider: "daytona",
		},
		{
			name: "empty sandbox section defaults provider to daytona",
			yaml: "sandbox:\n",
			wantProvider: "daytona",
		},
		{
			name: "explicit daytona provider",
			yaml: `sandbox:
  provider: daytona
  env:
    KEY: value
`,
			wantProvider: "daytona",
			wantEnvCount: 1,
		},
		{
			name: "hetzner provider with full config",
			yaml: `sandbox:
  provider: hetzner
  hetzner:
    sshKey: my-key
    serverType: cx22
    image: ubuntu-24.04
  env:
    A: "1"
    B: "2"
`,
			wantProvider:   "hetzner",
			wantEnvCount:   2,
			wantSSHKey:     "my-key",
			wantServerType: "cx22",
			wantImage:      "ubuntu-24.04",
		},
		{
			name: "hetzner with partial config",
			yaml: `sandbox:
  provider: hetzner
  hetzner:
    sshKey: partial-key
`,
			wantProvider: "hetzner",
			wantSSHKey:   "partial-key",
		},
		{
			name: "explicit empty provider defaults to daytona",
			yaml: `sandbox:
  provider: ""
`,
			wantProvider: "daytona",
		},
		{
			name: "sandbox alongside other sections",
			yaml: `engine: claude
auto:
  reportsDir: .hal/reports
sandbox:
  provider: hetzner
  hetzner:
    sshKey: alongside-key
    serverType: cpx11
`,
			wantProvider:   "hetzner",
			wantSSHKey:     "alongside-key",
			wantServerType: "cpx11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("Failed to create .hal dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("Failed to write config.yaml: %v", err)
			}

			cfg, err := LoadSandboxConfig(dir)
			if err != nil {
				t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
			}
			if cfg.Provider != tt.wantProvider {
				t.Errorf("Provider = %q, want %q", cfg.Provider, tt.wantProvider)
			}
			if len(cfg.Env) != tt.wantEnvCount {
				t.Errorf("Env length = %d, want %d", len(cfg.Env), tt.wantEnvCount)
			}
			if cfg.Hetzner.SSHKey != tt.wantSSHKey {
				t.Errorf("Hetzner.SSHKey = %q, want %q", cfg.Hetzner.SSHKey, tt.wantSSHKey)
			}
			if cfg.Hetzner.ServerType != tt.wantServerType {
				t.Errorf("Hetzner.ServerType = %q, want %q", cfg.Hetzner.ServerType, tt.wantServerType)
			}
			if cfg.Hetzner.Image != tt.wantImage {
				t.Errorf("Hetzner.Image = %q, want %q", cfg.Hetzner.Image, tt.wantImage)
			}
		})
	}
}

func TestSaveSandboxConfig_RoundTrip(t *testing.T) {
	t.Run("round-trips provider and hetzner fields", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &SandboxConfig{
			Provider: "hetzner",
			Env:      map[string]string{"KEY": "value"},
			Hetzner: HetznerConfig{
				SSHKey:     "my-ssh-key",
				ServerType: "cx22",
				Image:      "ubuntu-24.04",
			},
		}

		if err := SaveSandboxConfig(dir, cfg); err != nil {
			t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
		}

		loaded, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if loaded.Provider != "hetzner" {
			t.Errorf("Provider = %q, want %q", loaded.Provider, "hetzner")
		}
		if loaded.Env["KEY"] != "value" {
			t.Errorf("Env[KEY] = %q, want %q", loaded.Env["KEY"], "value")
		}
		if loaded.Hetzner.SSHKey != "my-ssh-key" {
			t.Errorf("Hetzner.SSHKey = %q, want %q", loaded.Hetzner.SSHKey, "my-ssh-key")
		}
		if loaded.Hetzner.ServerType != "cx22" {
			t.Errorf("Hetzner.ServerType = %q, want %q", loaded.Hetzner.ServerType, "cx22")
		}
		if loaded.Hetzner.Image != "ubuntu-24.04" {
			t.Errorf("Hetzner.Image = %q, want %q", loaded.Hetzner.Image, "ubuntu-24.04")
		}
	})

	t.Run("round-trips daytona provider without hetzner section", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &SandboxConfig{
			Provider: "daytona",
			Env:      map[string]string{"TOKEN": "abc"},
		}

		if err := SaveSandboxConfig(dir, cfg); err != nil {
			t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
		}

		loaded, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if loaded.Provider != "daytona" {
			t.Errorf("Provider = %q, want %q", loaded.Provider, "daytona")
		}
		if loaded.Env["TOKEN"] != "abc" {
			t.Errorf("Env[TOKEN] = %q, want %q", loaded.Env["TOKEN"], "abc")
		}
		// Hetzner fields should be empty
		if loaded.Hetzner.SSHKey != "" {
			t.Errorf("Hetzner.SSHKey = %q, want empty", loaded.Hetzner.SSHKey)
		}
	})

	t.Run("preserves unrelated config sections", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}

		existingYAML := `engine: pi
auto:
  reportsDir: custom/reports
  branchPrefix: feature/
  maxIterations: 10
daytona:
  apiKey: "keep-this"
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		cfg := &SandboxConfig{
			Provider: "hetzner",
			Env:      map[string]string{"NEW": "val"},
			Hetzner:  HetznerConfig{SSHKey: "test-key"},
		}
		if err := SaveSandboxConfig(dir, cfg); err != nil {
			t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
		}

		// Verify auto section was not clobbered
		autoCfg, err := LoadConfig(dir)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		if autoCfg.ReportsDir != "custom/reports" {
			t.Errorf("ReportsDir = %q, want %q", autoCfg.ReportsDir, "custom/reports")
		}

		// Verify daytona section was not clobbered
		dayCfg, err := LoadDaytonaConfig(dir)
		if err != nil {
			t.Fatalf("LoadDaytonaConfig() unexpected error: %v", err)
		}
		if dayCfg.APIKey != "keep-this" {
			t.Errorf("APIKey = %q, want %q", dayCfg.APIKey, "keep-this")
		}

		// Verify sandbox was saved
		sandboxCfg, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if sandboxCfg.Provider != "hetzner" {
			t.Errorf("Provider = %q, want %q", sandboxCfg.Provider, "hetzner")
		}
		if sandboxCfg.Hetzner.SSHKey != "test-key" {
			t.Errorf("Hetzner.SSHKey = %q, want %q", sandboxCfg.Hetzner.SSHKey, "test-key")
		}
	})
}

func TestLoadSandboxConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("Failed to create .hal dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(":::not yaml"), 0644); err != nil {
		t.Fatalf("Failed to write config.yaml: %v", err)
	}

	_, err := LoadSandboxConfig(dir)
	if err == nil {
		t.Fatal("LoadSandboxConfig() expected error for invalid YAML, got nil")
	}
}
