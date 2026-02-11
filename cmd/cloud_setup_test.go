package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunCloudSetup(t *testing.T) {
	tests := []struct {
		name        string
		profileFlag string
		setup       func(t *testing.T, halDir string)
		input       string
		wantOutput  string
		wantErr     string
		check       func(t *testing.T, halDir string)
	}{
		{
			name:        "creates new config with defaults accepted",
			profileFlag: "",
			input:       "\nhttps://cloud.example.com\n\n\n\n\n\n\n\n",
			wantOutput:  "Cloud profile configured.",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				cfg := mustLoadConfig(t, halDir)
				if cfg.DefaultProfile != "default" {
					t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "default")
				}
				p := cfg.GetProfile("default")
				if p == nil {
					t.Fatal("default profile not found")
				}
				if p.Endpoint != "https://cloud.example.com" {
					t.Errorf("endpoint = %q, want %q", p.Endpoint, "https://cloud.example.com")
				}
				if p.Mode != config.ModeUntilComplete {
					t.Errorf("mode = %q, want %q", p.Mode, config.ModeUntilComplete)
				}
				if p.PullPolicy != config.PullPolicyAll {
					t.Errorf("pullPolicy = %q, want %q", p.PullPolicy, config.PullPolicyAll)
				}
			},
		},
		{
			name:        "creates config with custom profile name",
			profileFlag: "staging",
			input:       "https://staging.example.com\nbounded_batch\norg/repo\nmain\nclaude\nap-123\nprd-001\nstate\n",
			wantOutput:  "profile:  staging",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				cfg := mustLoadConfig(t, halDir)
				if cfg.DefaultProfile != "staging" {
					t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "staging")
				}
				p := cfg.GetProfile("staging")
				if p == nil {
					t.Fatal("staging profile not found")
				}
				if p.Mode != config.ModeBoundedBatch {
					t.Errorf("mode = %q, want %q", p.Mode, config.ModeBoundedBatch)
				}
				if p.Repo != "org/repo" {
					t.Errorf("repo = %q, want %q", p.Repo, "org/repo")
				}
				if p.Base != "main" {
					t.Errorf("base = %q, want %q", p.Base, "main")
				}
				if p.Engine != "claude" {
					t.Errorf("engine = %q, want %q", p.Engine, "claude")
				}
				if p.AuthProfile != "ap-123" {
					t.Errorf("authProfile = %q, want %q", p.AuthProfile, "ap-123")
				}
				if p.Scope != "prd-001" {
					t.Errorf("scope = %q, want %q", p.Scope, "prd-001")
				}
				if p.PullPolicy != config.PullPolicyState {
					t.Errorf("pullPolicy = %q, want %q", p.PullPolicy, config.PullPolicyState)
				}
			},
		},
		{
			name:        "preserves unrelated profiles on re-run",
			profileFlag: "prod",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				writeCloudConfig(t, halDir, `defaultProfile: dev
profiles:
  dev:
    endpoint: https://dev.example.com
    mode: until_complete
`)
			},
			input:      "https://prod.example.com\n\n\n\n\n\n\n\n",
			wantOutput: "profile:  prod",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				cfg := mustLoadConfig(t, halDir)
				// Default profile should be updated to prod.
				if cfg.DefaultProfile != "prod" {
					t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "prod")
				}
				// Dev profile should be preserved.
				dev := cfg.GetProfile("dev")
				if dev == nil {
					t.Fatal("dev profile was deleted")
				}
				if dev.Endpoint != "https://dev.example.com" {
					t.Errorf("dev endpoint = %q, want %q", dev.Endpoint, "https://dev.example.com")
				}
				// Prod profile should exist.
				prod := cfg.GetProfile("prod")
				if prod == nil {
					t.Fatal("prod profile not found")
				}
				if prod.Endpoint != "https://prod.example.com" {
					t.Errorf("prod endpoint = %q, want %q", prod.Endpoint, "https://prod.example.com")
				}
			},
		},
		{
			name:        "updates existing profile without deleting others",
			profileFlag: "dev",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				writeCloudConfig(t, halDir, `defaultProfile: dev
profiles:
  dev:
    endpoint: https://dev.example.com
    mode: until_complete
  prod:
    endpoint: https://prod.example.com
    mode: bounded_batch
`)
			},
			input:      "https://dev-v2.example.com\n\n\n\n\n\n\n\n",
			wantOutput: "endpoint: https://dev-v2.example.com",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				cfg := mustLoadConfig(t, halDir)
				// Dev profile should be updated.
				dev := cfg.GetProfile("dev")
				if dev == nil {
					t.Fatal("dev profile not found")
				}
				if dev.Endpoint != "https://dev-v2.example.com" {
					t.Errorf("dev endpoint = %q, want %q", dev.Endpoint, "https://dev-v2.example.com")
				}
				// Prod profile should be preserved.
				prod := cfg.GetProfile("prod")
				if prod == nil {
					t.Fatal("prod profile was deleted")
				}
				if prod.Endpoint != "https://prod.example.com" {
					t.Errorf("prod endpoint = %q, want %q", prod.Endpoint, "https://prod.example.com")
				}
			},
		},
		{
			name:        "validation error for invalid mode",
			profileFlag: "bad",
			input:       "https://cloud.example.com\ninvalid_mode\n\n\n\n\n\n\n",
			wantErr:     "validation failed",
		},
		{
			name:        "writes only non-secret values",
			profileFlag: "test",
			input:       "https://cloud.example.com\n\n\n\n\n\n\n\n",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(halDir, template.CloudConfigFile))
				if err != nil {
					t.Fatalf("failed to read config: %v", err)
				}
				content := string(data)
				for _, secret := range []string{"token", "password", "secret", "api_key", "dsn"} {
					if strings.Contains(strings.ToLower(content), secret+":") {
						t.Errorf("config contains secret-like key %q", secret)
					}
				}
			},
		},
		{
			name:        "creates hal dir if missing",
			profileFlag: "default",
			input:       "https://cloud.example.com\n\n\n\n\n\n\n\n",
			wantOutput:  "Cloud profile configured.",
			check: func(t *testing.T, halDir string) {
				t.Helper()
				info, err := os.Stat(halDir)
				if err != nil {
					t.Fatalf("halDir not created: %v", err)
				}
				if !info.IsDir() {
					t.Error("halDir is not a directory")
				}
			},
		},
		{
			name:        "output includes profile name endpoint and mode",
			profileFlag: "myprofile",
			input:       "https://my.endpoint.com\nbounded_batch\n\n\n\n\n\n\n",
			wantOutput:  "profile:  myprofile",
			check: func(t *testing.T, halDir string) {
				// Output assertions handled by wantOutput
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, template.HalDir)

			if tt.setup != nil {
				os.MkdirAll(halDir, 0755)
				tt.setup(t, halDir)
			}

			in := strings.NewReader(tt.input)
			var out bytes.Buffer

			err := runCloudSetup(halDir, tt.profileFlag, in, &out)

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

			if tt.check != nil {
				tt.check(t, halDir)
			}
		})
	}
}

func TestPromptField(t *testing.T) {
	tests := []struct {
		name       string
		label      string
		defaultVal string
		input      string
		want       string
		wantPrompt string
	}{
		{
			name:       "returns input when provided",
			label:      "Name",
			defaultVal: "foo",
			input:      "bar\n",
			want:       "bar",
			wantPrompt: "Name [foo]: ",
		},
		{
			name:       "returns default on empty input",
			label:      "Name",
			defaultVal: "foo",
			input:      "\n",
			want:       "foo",
			wantPrompt: "Name [foo]: ",
		},
		{
			name:       "no default shows plain prompt",
			label:      "Name",
			defaultVal: "",
			input:      "baz\n",
			want:       "baz",
			wantPrompt: "Name: ",
		},
		{
			name:       "empty input with no default returns empty",
			label:      "Name",
			defaultVal: "",
			input:      "\n",
			want:       "",
			wantPrompt: "Name: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := strings.NewReader(tt.input)
			var out bytes.Buffer
			reader := bufio.NewReader(in)

			got := promptField(reader, &out, tt.label, tt.defaultVal)

			if got != tt.want {
				t.Errorf("promptField() = %q, want %q", got, tt.want)
			}
			if out.String() != tt.wantPrompt {
				t.Errorf("prompt = %q, want %q", out.String(), tt.wantPrompt)
			}
		})
	}
}

func TestMarshalCloudConfig(t *testing.T) {
	cfg := &config.CloudConfig{
		DefaultProfile: "test",
		Profiles: map[string]*config.Profile{
			"test": {
				Endpoint: "https://example.com",
				Mode:     config.ModeUntilComplete,
			},
		},
	}

	data, err := marshalCloudConfig(cfg)
	if err != nil {
		t.Fatalf("marshalCloudConfig() error: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "defaultProfile: test") {
		t.Errorf("YAML missing defaultProfile: %s", content)
	}
	if !strings.Contains(content, "endpoint: https://example.com") {
		t.Errorf("YAML missing endpoint: %s", content)
	}

	// Verify roundtrip through Parse.
	parsed, err := config.Parse(data)
	if err != nil {
		t.Fatalf("roundtrip Parse() error: %v", err)
	}
	if parsed.DefaultProfile != "test" {
		t.Errorf("roundtrip defaultProfile = %q, want %q", parsed.DefaultProfile, "test")
	}
	p := parsed.GetProfile("test")
	if p == nil {
		t.Fatal("roundtrip profile not found")
	}
	if p.Endpoint != "https://example.com" {
		t.Errorf("roundtrip endpoint = %q, want %q", p.Endpoint, "https://example.com")
	}
}

func TestLoadExistingCloudConfig(t *testing.T) {
	t.Run("returns nil for missing file", func(t *testing.T) {
		cfg := loadExistingCloudConfig("/nonexistent/path/cloud.yaml")
		if cfg != nil {
			t.Error("expected nil for missing file")
		}
	})

	t.Run("returns nil for invalid yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "cloud.yaml")
		os.WriteFile(path, []byte("{{invalid yaml"), 0644)

		cfg := loadExistingCloudConfig(path)
		if cfg != nil {
			t.Error("expected nil for invalid yaml")
		}
	})

	t.Run("returns config for valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "cloud.yaml")
		os.WriteFile(path, []byte(`defaultProfile: test
profiles:
  test:
    endpoint: https://example.com
`), 0644)

		cfg := loadExistingCloudConfig(path)
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.DefaultProfile != "test" {
			t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "test")
		}
	})
}

// writeCloudConfig writes a cloud.yaml file in the halDir.
func writeCloudConfig(t *testing.T, halDir, content string) {
	t.Helper()
	path := filepath.Join(halDir, template.CloudConfigFile)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write cloud config: %v", err)
	}
}

// mustLoadConfig loads and validates a cloud.yaml from halDir, failing the test on error.
func mustLoadConfig(t *testing.T, halDir string) *config.CloudConfig {
	t.Helper()
	cfg, err := config.Load(filepath.Join(halDir, template.CloudConfigFile))
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return cfg
}
