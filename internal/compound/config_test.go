package compound

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestDefaultAutoConfig(t *testing.T) {
	cfg := DefaultAutoConfig()

	if cfg.ReportsDir != ".hal/reports" {
		t.Errorf("ReportsDir = %q, want %q", cfg.ReportsDir, ".hal/reports")
	}
	if cfg.BranchPrefix != "compound/" {
		t.Errorf("BranchPrefix = %q, want %q", cfg.BranchPrefix, "compound/")
	}
	if cfg.SourcePriority != AutoSourcePriorityReportFirst {
		t.Errorf("SourcePriority = %q, want %q", cfg.SourcePriority, AutoSourcePriorityReportFirst)
	}
	if cfg.ConvertMode != AutoConvertModeAuto {
		t.Errorf("ConvertMode = %q, want %q", cfg.ConvertMode, AutoConvertModeAuto)
	}
	if cfg.MaxIterations != 25 {
		t.Errorf("MaxIterations = %d, want %d", cfg.MaxIterations, 25)
	}
	if len(cfg.QualityChecks) != 0 {
		t.Errorf("QualityChecks length = %d, want 0", len(cfg.QualityChecks))
	}
	if cfg.Mode != AutoModeBalanced {
		t.Errorf("Mode = %q, want %q", cfg.Mode, AutoModeBalanced)
	}
	if !cfg.CIEnabled {
		t.Errorf("CIEnabled = %v, want true", cfg.CIEnabled)
	}
	if !cfg.ReviewEnabled {
		t.Errorf("ReviewEnabled = %v, want true", cfg.ReviewEnabled)
	}
	if cfg.ReviewCleanStreak != 1 {
		t.Errorf("ReviewCleanStreak = %d, want %d", cfg.ReviewCleanStreak, 1)
	}
	if cfg.ReviewMaxIterations != 10 {
		t.Errorf("ReviewMaxIterations = %d, want %d", cfg.ReviewMaxIterations, 10)
	}
}

func TestResolveAutoModeSettings(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		wantMode   string
		wantCI     bool
		wantReview bool
		wantStreak int
		wantMax    int
		wantErr    bool
	}{
		{name: "empty defaults to balanced", mode: "", wantMode: AutoModeBalanced, wantCI: true, wantReview: true, wantStreak: 1, wantMax: 10},
		{name: "fast", mode: "fast", wantMode: AutoModeFast, wantCI: false, wantReview: false, wantStreak: 1, wantMax: 5},
		{name: "strict", mode: "strict", wantMode: AutoModeStrict, wantCI: true, wantReview: true, wantStreak: 3, wantMax: 15},
		{name: "invalid", mode: "turbo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveAutoModeSettings(tt.mode)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveAutoModeSettings() error: %v", err)
			}
			if got.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, tt.wantMode)
			}
			if got.CIEnabled != tt.wantCI {
				t.Errorf("CIEnabled = %v, want %v", got.CIEnabled, tt.wantCI)
			}
			if got.ReviewEnabled != tt.wantReview {
				t.Errorf("ReviewEnabled = %v, want %v", got.ReviewEnabled, tt.wantReview)
			}
			if got.ReviewCleanStreak != tt.wantStreak {
				t.Errorf("ReviewCleanStreak = %d, want %d", got.ReviewCleanStreak, tt.wantStreak)
			}
			if got.ReviewMaxIterations != tt.wantMax {
				t.Errorf("ReviewMaxIterations = %d, want %d", got.ReviewMaxIterations, tt.wantMax)
			}
		})
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
	if got.SourcePriority != want.SourcePriority {
		t.Errorf("SourcePriority = %q, want %q", got.SourcePriority, want.SourcePriority)
	}
	if got.ConvertMode != want.ConvertMode {
		t.Errorf("ConvertMode = %q, want %q", got.ConvertMode, want.ConvertMode)
	}
	if len(got.QualityChecks) != len(want.QualityChecks) {
		t.Errorf("QualityChecks length = %d, want %d", len(got.QualityChecks), len(want.QualityChecks))
	}
	if got.Mode != want.Mode {
		t.Errorf("Mode = %q, want %q", got.Mode, want.Mode)
	}
	if got.CIEnabled != want.CIEnabled {
		t.Errorf("CIEnabled = %v, want %v", got.CIEnabled, want.CIEnabled)
	}
	if got.ReviewEnabled != want.ReviewEnabled {
		t.Errorf("ReviewEnabled = %v, want %v", got.ReviewEnabled, want.ReviewEnabled)
	}
	if got.ReviewCleanStreak != want.ReviewCleanStreak {
		t.Errorf("ReviewCleanStreak = %d, want %d", got.ReviewCleanStreak, want.ReviewCleanStreak)
	}
	if got.ReviewMaxIterations != want.ReviewMaxIterations {
		t.Errorf("ReviewMaxIterations = %d, want %d", got.ReviewMaxIterations, want.ReviewMaxIterations)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	defaults := DefaultAutoConfig()

	tests := []struct {
		name               string
		yaml               string
		wantDir            string
		wantPrefix         string
		wantSourcePriority string
		wantConvertMode    string
		wantMaxIter        int
		wantQCCount        int
		wantMode           string
		wantCIEnabled      bool
		wantReview         bool
		wantReviewStreak   int
		wantReviewMax      int
	}{
		{
			name: "full config overrides all defaults",
			yaml: `auto:
  reportsDir: "custom/reports"
  branchPrefix: "feature/"
  sourcePriority: markdown_first
  convertMode: standard
  maxIterations: 10
  qualityChecks:
    - "make test"
    - "make lint"
  mode: strict
  ciEnabled: false
  reviewEnabled: true
  reviewCleanStreak: 4
  reviewMaxIterations: 12
`,
			wantDir:            "custom/reports",
			wantPrefix:         "feature/",
			wantSourcePriority: AutoSourcePriorityMarkdownFirst,
			wantConvertMode:    AutoConvertModeStandard,
			wantMaxIter:        10,
			wantQCCount:        2,
			wantMode:           AutoModeStrict,
			wantCIEnabled:      false,
			wantReview:         true,
			wantReviewStreak:   4,
			wantReviewMax:      12,
		},
		{
			name: "partial config merges with defaults",
			yaml: `auto:
  reportsDir: "my/reports"
`,
			wantDir:            "my/reports",
			wantPrefix:         defaults.BranchPrefix,
			wantSourcePriority: defaults.SourcePriority,
			wantConvertMode:    defaults.ConvertMode,
			wantMaxIter:        defaults.MaxIterations,
			wantQCCount:        0,
			wantMode:           defaults.Mode,
			wantCIEnabled:      defaults.CIEnabled,
			wantReview:         defaults.ReviewEnabled,
			wantReviewStreak:   defaults.ReviewCleanStreak,
			wantReviewMax:      defaults.ReviewMaxIterations,
		},
		{
			name:               "empty auto section uses all defaults",
			yaml:               "auto:\n",
			wantDir:            defaults.ReportsDir,
			wantPrefix:         defaults.BranchPrefix,
			wantSourcePriority: defaults.SourcePriority,
			wantConvertMode:    defaults.ConvertMode,
			wantMaxIter:        defaults.MaxIterations,
			wantQCCount:        0,
			wantMode:           defaults.Mode,
			wantCIEnabled:      defaults.CIEnabled,
			wantReview:         defaults.ReviewEnabled,
			wantReviewStreak:   defaults.ReviewCleanStreak,
			wantReviewMax:      defaults.ReviewMaxIterations,
		},
		{
			name: "mode strict applies stricter defaults",
			yaml: `auto:
  mode: strict
`,
			wantDir:            defaults.ReportsDir,
			wantPrefix:         defaults.BranchPrefix,
			wantSourcePriority: defaults.SourcePriority,
			wantConvertMode:    defaults.ConvertMode,
			wantMaxIter:        defaults.MaxIterations,
			wantQCCount:        0,
			wantMode:           AutoModeStrict,
			wantCIEnabled:      true,
			wantReview:         true,
			wantReviewStreak:   3,
			wantReviewMax:      15,
		},
		{
			name: "mode fast disables review and ci by default",
			yaml: `auto:
  mode: fast
`,
			wantDir:            defaults.ReportsDir,
			wantPrefix:         defaults.BranchPrefix,
			wantSourcePriority: defaults.SourcePriority,
			wantConvertMode:    defaults.ConvertMode,
			wantMaxIter:        defaults.MaxIterations,
			wantQCCount:        0,
			wantMode:           AutoModeFast,
			wantCIEnabled:      false,
			wantReview:         false,
			wantReviewStreak:   1,
			wantReviewMax:      5,
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
			if cfg.SourcePriority != tt.wantSourcePriority {
				t.Errorf("SourcePriority = %q, want %q", cfg.SourcePriority, tt.wantSourcePriority)
			}
			if cfg.ConvertMode != tt.wantConvertMode {
				t.Errorf("ConvertMode = %q, want %q", cfg.ConvertMode, tt.wantConvertMode)
			}
			if len(cfg.QualityChecks) != tt.wantQCCount {
				t.Errorf("QualityChecks length = %d, want %d", len(cfg.QualityChecks), tt.wantQCCount)
			}
			if cfg.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", cfg.Mode, tt.wantMode)
			}
			if cfg.CIEnabled != tt.wantCIEnabled {
				t.Errorf("CIEnabled = %v, want %v", cfg.CIEnabled, tt.wantCIEnabled)
			}
			if cfg.ReviewEnabled != tt.wantReview {
				t.Errorf("ReviewEnabled = %v, want %v", cfg.ReviewEnabled, tt.wantReview)
			}
			if cfg.ReviewCleanStreak != tt.wantReviewStreak {
				t.Errorf("ReviewCleanStreak = %d, want %d", cfg.ReviewCleanStreak, tt.wantReviewStreak)
			}
			if cfg.ReviewMaxIterations != tt.wantReviewMax {
				t.Errorf("ReviewMaxIterations = %d, want %d", cfg.ReviewMaxIterations, tt.wantReviewMax)
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
		{
			name: "invalid mode triggers validation",
			yaml: `auto:
  mode: turbo
`,
			wantErrSub: "auto.mode",
		},
		{
			name: "invalid sourcePriority triggers validation",
			yaml: `auto:
  sourcePriority: reports_first
`,
			wantErrSub: "auto.sourcePriority must be one of report_first, markdown_first",
		},
		{
			name: "invalid convertMode triggers validation",
			yaml: `auto:
  convertMode: task
`,
			wantErrSub: "auto.convertMode must be one of auto, standard, granular",
		},
		{
			name: "review clean streak must be positive",
			yaml: `auto:
  reviewCleanStreak: 0
`,
			wantErrSub: "reviewCleanStreak",
		},
		{
			name: "review max iterations must be positive",
			yaml: `auto:
  reviewMaxIterations: 0
`,
			wantErrSub: "reviewMaxIterations",
		},
		{
			name: "review clean streak must be <= review max iterations",
			yaml: `auto:
  reviewCleanStreak: 4
  reviewMaxIterations: 3
`,
			wantErrSub: "reviewCleanStreak",
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

func TestLoadSandboxConfig_MissingFile(t *testing.T) {
	t.Run("non-existent directory returns empty provider", func(t *testing.T) {
		cfg, err := LoadSandboxConfig(filepath.Join(t.TempDir(), "does-not-exist"))
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if cfg.Provider != "" {
			t.Errorf("Provider = %q, want empty", cfg.Provider)
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
		if cfg.Provider != "" {
			t.Errorf("Provider = %q, want empty", cfg.Provider)
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
		wantLSRegion   string
		wantLSAZ       string
		wantLSBundle   string
		wantLSKeyPair  string
	}{
		{
			name:         "missing provider remains empty",
			yaml:         "engine: claude\n",
			wantProvider: "",
		},
		{
			name:         "empty sandbox section keeps provider empty",
			yaml:         "sandbox:\n",
			wantProvider: "",
		},
		{
			name: "explicit unsupported provider remains visible",
			yaml: `sandbox:
  provider: retired-provider
  env:
    KEY: value
`,
			wantProvider: "retired-provider",
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
			name: "lightsail provider with full config",
			yaml: `sandbox:
  provider: lightsail
  lightsail:
    region: us-west-2
    availabilityZone: us-west-2a
    bundle: small_3_0
    keyPairName: my-ls-key
`,
			wantProvider:  "lightsail",
			wantLSRegion:  "us-west-2",
			wantLSAZ:      "us-west-2a",
			wantLSBundle:  "small_3_0",
			wantLSKeyPair: "my-ls-key",
		},
		{
			name: "explicit empty provider remains empty",
			yaml: `sandbox:
  provider: ""
`,
			wantProvider: "",
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
			if cfg.Lightsail.Region != tt.wantLSRegion {
				t.Errorf("Lightsail.Region = %q, want %q", cfg.Lightsail.Region, tt.wantLSRegion)
			}
			if cfg.Lightsail.AvailabilityZone != tt.wantLSAZ {
				t.Errorf("Lightsail.AvailabilityZone = %q, want %q", cfg.Lightsail.AvailabilityZone, tt.wantLSAZ)
			}
			if cfg.Lightsail.Bundle != tt.wantLSBundle {
				t.Errorf("Lightsail.Bundle = %q, want %q", cfg.Lightsail.Bundle, tt.wantLSBundle)
			}
			if cfg.Lightsail.KeyPairName != tt.wantLSKeyPair {
				t.Errorf("Lightsail.KeyPairName = %q, want %q", cfg.Lightsail.KeyPairName, tt.wantLSKeyPair)
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

	t.Run("round-trips lightsail fields", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &SandboxConfig{
			Provider: "lightsail",
			Env:      map[string]string{"TOKEN": "abc"},
			Lightsail: LightsailConfig{
				Region:           "us-east-1",
				AvailabilityZone: "us-east-1a",
				Bundle:           "small_3_0",
				KeyPairName:      "my-keypair",
			},
		}

		if err := SaveSandboxConfig(dir, cfg); err != nil {
			t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
		}

		loaded, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if loaded.Provider != "lightsail" {
			t.Errorf("Provider = %q, want %q", loaded.Provider, "lightsail")
		}
		if loaded.Env["TOKEN"] != "abc" {
			t.Errorf("Env[TOKEN] = %q, want %q", loaded.Env["TOKEN"], "abc")
		}
		if loaded.Lightsail.Region != "us-east-1" {
			t.Errorf("Lightsail.Region = %q, want %q", loaded.Lightsail.Region, "us-east-1")
		}
		if loaded.Lightsail.AvailabilityZone != "us-east-1a" {
			t.Errorf("Lightsail.AvailabilityZone = %q, want %q", loaded.Lightsail.AvailabilityZone, "us-east-1a")
		}
		if loaded.Lightsail.Bundle != "small_3_0" {
			t.Errorf("Lightsail.Bundle = %q, want %q", loaded.Lightsail.Bundle, "small_3_0")
		}
		if loaded.Lightsail.KeyPairName != "my-keypair" {
			t.Errorf("Lightsail.KeyPairName = %q, want %q", loaded.Lightsail.KeyPairName, "my-keypair")
		}
	})

	t.Run("round-trips empty provider without provider-specific sections", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &SandboxConfig{
			Env: map[string]string{"TOKEN": "abc"},
		}

		if err := SaveSandboxConfig(dir, cfg); err != nil {
			t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
		}

		loaded, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if loaded.Provider != "" {
			t.Errorf("Provider = %q, want empty", loaded.Provider)
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
customMetadata:
  keep: this
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

		// Verify unrelated metadata was not clobbered.
		raw, err := os.ReadFile(filepath.Join(halDir, "config.yaml"))
		if err != nil {
			t.Fatalf("read config.yaml: %v", err)
		}
		if !strings.Contains(string(raw), "customMetadata:") || !strings.Contains(string(raw), "keep: this") {
			t.Fatalf("config.yaml lost unrelated metadata:\n%s", raw)
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

func TestSandboxPolicyConfig(t *testing.T) {
	t.Run("loads local sandbox network policy metadata", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}
		yaml := `sandbox:
  provider: hetzner
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: api.example.com
        decision: allow
      - kind: metadata_endpoint
        value: "169.254.169.254"
        decision: deny
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(yaml), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		cfg, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if cfg.NetworkPolicy == nil {
			t.Fatal("NetworkPolicy = nil, want parsed policy")
		}
		if cfg.NetworkPolicy.Preset != sandbox.SandboxNetworkPolicyPresetAllowListed {
			t.Fatalf("NetworkPolicy.Preset = %q, want %q", cfg.NetworkPolicy.Preset, sandbox.SandboxNetworkPolicyPresetAllowListed)
		}
		wantRules := []sandbox.SandboxNetworkPolicyRule{
			{Kind: sandbox.SandboxNetworkPolicyRuleKindDomain, Value: "api.example.com", Decision: sandbox.SandboxNetworkPolicyDecisionAllow},
			{Kind: sandbox.SandboxNetworkPolicyRuleKindMetadataEndpoint, Value: "169.254.169.254", Decision: sandbox.SandboxNetworkPolicyDecisionDeny},
		}
		if !reflect.DeepEqual(cfg.NetworkPolicy.Rules, wantRules) {
			t.Fatalf("NetworkPolicy.Rules = %#v, want %#v", cfg.NetworkPolicy.Rules, wantRules)
		}
	})

	t.Run("rejects invalid policy with sanitized error", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}
		yaml := `sandbox:
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: "https://user:secret@example.com/query"
        decision: allow
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(yaml), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		_, err := LoadSandboxConfig(dir)
		if err == nil {
			t.Fatal("LoadSandboxConfig() error = nil, want policy validation error")
		}
		got := err.Error()
		if !strings.Contains(got, "sandbox.networkPolicy.rules[0]") || !strings.Contains(got, string(sandbox.SandboxNetworkPolicyValidationCredentialBearingURL)) {
			t.Fatalf("error = %q, want sanitized policy location and code", got)
		}
		for _, unsafe := range []string{"user:secret", "example.com/query", "https://"} {
			if strings.Contains(got, unsafe) {
				t.Fatalf("error = %q leaks unsafe policy value fragment %q", got, unsafe)
			}
		}
	})
}

func TestSandboxSecretConfig(t *testing.T) {
	t.Run("loads local sandbox secret mode metadata", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}
		yaml := `sandbox:
  secrets:
    requestedModes:
      - " env "
      - http_proxy
      - env
    activeModes:
      - env
      - legacy_auth_sync
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(yaml), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		cfg, err := LoadSandboxConfig(dir)
		if err != nil {
			t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
		}
		if cfg.Secrets == nil {
			t.Fatal("Secrets = nil, want parsed secret metadata")
		}
		if !reflect.DeepEqual(cfg.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeHTTPProxy}) {
			t.Fatalf("Secrets.RequestedModes = %#v, want normalized unique modes", cfg.Secrets.RequestedModes)
		}
		if !reflect.DeepEqual(cfg.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv, sandbox.SandboxSecretModeLegacyAuthSync}) {
			t.Fatalf("Secrets.ActiveModes = %#v, want normalized modes", cfg.Secrets.ActiveModes)
		}
	})

	t.Run("rejects invalid secret mode with sanitized error", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("Failed to create .hal dir: %v", err)
		}
		yaml := `sandbox:
  secrets:
    requestedModes:
      - token://secret-value
`
		if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(yaml), 0644); err != nil {
			t.Fatalf("Failed to write config.yaml: %v", err)
		}

		_, err := LoadSandboxConfig(dir)
		if err == nil {
			t.Fatal("LoadSandboxConfig() error = nil, want secret mode validation error")
		}
		got := err.Error()
		if !strings.Contains(got, "sandbox.secrets") || !strings.Contains(got, "requestedModes[0]") {
			t.Fatalf("error = %q, want sanitized secret mode location", got)
		}
		if strings.Contains(got, "token://secret-value") {
			t.Fatalf("error = %q leaks rejected secret mode value", got)
		}
	})
}

func TestSandboxConfigPreservesPolicySecretAndReadinessGateMetadata(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("Failed to create .hal dir: %v", err)
	}
	existingYAML := `engine: codex
auto:
  reportsDir: custom/reports
sandbox:
  provider: hetzner
  securityReadinessGatePolicyMode: " Strict "
  env:
    EXISTING: keep
  networkPolicy:
    preset: deny_by_default
  secrets:
    requestedModes:
      - env
`
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(existingYAML), 0644); err != nil {
		t.Fatalf("Failed to write config.yaml: %v", err)
	}

	cfg, err := LoadSandboxConfig(dir)
	if err != nil {
		t.Fatalf("LoadSandboxConfig() unexpected error: %v", err)
	}
	cfg.Env["NEW"] = "value"
	if err := SaveSandboxConfig(dir, cfg); err != nil {
		t.Fatalf("SaveSandboxConfig() unexpected error: %v", err)
	}

	autoCfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if autoCfg.ReportsDir != "custom/reports" {
		t.Fatalf("auto.reportsDir = %q, want custom/reports", autoCfg.ReportsDir)
	}
	loaded, err := LoadSandboxConfig(dir)
	if err != nil {
		t.Fatalf("LoadSandboxConfig() after save unexpected error: %v", err)
	}
	if loaded.Env["EXISTING"] != "keep" || loaded.Env["NEW"] != "value" {
		t.Fatalf("Env = %#v, want existing and new keys preserved", loaded.Env)
	}
	if loaded.NetworkPolicy == nil || loaded.NetworkPolicy.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("NetworkPolicy = %#v, want deny_by_default policy preserved", loaded.NetworkPolicy)
	}
	if loaded.Secrets == nil || !reflect.DeepEqual(loaded.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeEnv}) {
		t.Fatalf("Secrets = %#v, want env request preserved", loaded.Secrets)
	}
	if loaded.SecurityReadinessGatePolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
		t.Fatalf("SecurityReadinessGatePolicyMode = %q, want strict", loaded.SecurityReadinessGatePolicyMode)
	}
}
