package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultGlobalConfig(t *testing.T) {
	cfg := DefaultGlobalConfig()

	if cfg.Provider != "daytona" {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, "daytona")
	}
	if !cfg.Defaults.AutoShutdown {
		t.Fatalf("Defaults.AutoShutdown = %v, want %v", cfg.Defaults.AutoShutdown, true)
	}
	if cfg.Defaults.IdleHours != 48 {
		t.Fatalf("Defaults.IdleHours = %d, want %d", cfg.Defaults.IdleHours, 48)
	}
	if cfg.Env == nil {
		t.Fatal("Env should be initialized, got nil")
	}
	if len(cfg.Env) != 0 {
		t.Fatalf("Env length = %d, want %d", len(cfg.Env), 0)
	}
}

func TestLoadGlobalConfig(t *testing.T) {
	tests := []struct {
		name                  string
		yaml                  string
		wantProvider          string
		wantAutoShutdown      bool
		wantIdleHours         int
		wantEnv               map[string]string
		wantTailscaleLockdown bool
		wantDaytonaAPIKey     string
		wantDOSize            string
		wantHetznerImage      string
		wantLightsailAZ       string
	}{
		{
			name:                  "missing file returns defaults",
			wantProvider:          "daytona",
			wantAutoShutdown:      true,
			wantIdleHours:         48,
			wantEnv:               map[string]string{},
			wantTailscaleLockdown: false,
		},
		{
			name: "missing defaults section keeps defaults",
			yaml: `provider: digitalocean
env:
  OPENAI_API_KEY: sk-test
`,
			wantProvider:          "digitalocean",
			wantAutoShutdown:      true,
			wantIdleHours:         48,
			wantEnv:               map[string]string{"OPENAI_API_KEY": "sk-test"},
			wantTailscaleLockdown: false,
		},
		{
			name: "explicit zero values override defaults",
			yaml: `provider: ""
defaults:
  autoShutdown: false
  idleHours: 0
env: {}
`,
			wantProvider:          "",
			wantAutoShutdown:      false,
			wantIdleHours:         0,
			wantEnv:               map[string]string{},
			wantTailscaleLockdown: false,
		},
		{
			name: "loads all provider sections",
			yaml: `provider: lightsail
defaults:
  autoShutdown: false
  idleHours: 72
env:
  GITHUB_TOKEN: ghp_test
tailscaleLockdown: true
daytona:
  apiKey: day-key
  serverURL: https://custom.daytona.io/api
digitalocean:
  sshKey: do-key
  size: s-4vcpu-8gb
hetzner:
  sshKey: hz-key
  serverType: cx32
  image: ubuntu-24.04
lightsail:
  keyPairName: ls-key
  bundle: medium_3_0
  region: us-east-1
  availabilityZone: us-east-1b
`,
			wantProvider:          "lightsail",
			wantAutoShutdown:      false,
			wantIdleHours:         72,
			wantEnv:               map[string]string{"GITHUB_TOKEN": "ghp_test"},
			wantTailscaleLockdown: true,
			wantDaytonaAPIKey:     "day-key",
			wantDOSize:            "s-4vcpu-8gb",
			wantHetznerImage:      "ubuntu-24.04",
			wantLightsailAZ:       "us-east-1b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := setGlobalConfigHome(t)
			if tt.yaml != "" {
				if err := EnsureGlobalDir(); err != nil {
					t.Fatalf("EnsureGlobalDir() failed: %v", err)
				}
				configPath := filepath.Join(home, globalConfigFileName)
				if err := os.WriteFile(configPath, []byte(tt.yaml), 0o600); err != nil {
					t.Fatalf("write global config: %v", err)
				}
			}

			cfg, err := LoadGlobalConfig()
			if err != nil {
				t.Fatalf("LoadGlobalConfig() unexpected error: %v", err)
			}

			if cfg.Provider != tt.wantProvider {
				t.Fatalf("Provider = %q, want %q", cfg.Provider, tt.wantProvider)
			}
			if cfg.Defaults.AutoShutdown != tt.wantAutoShutdown {
				t.Fatalf("Defaults.AutoShutdown = %v, want %v", cfg.Defaults.AutoShutdown, tt.wantAutoShutdown)
			}
			if cfg.Defaults.IdleHours != tt.wantIdleHours {
				t.Fatalf("Defaults.IdleHours = %d, want %d", cfg.Defaults.IdleHours, tt.wantIdleHours)
			}
			if !reflect.DeepEqual(cfg.Env, tt.wantEnv) {
				t.Fatalf("Env = %#v, want %#v", cfg.Env, tt.wantEnv)
			}
			if cfg.TailscaleLockdown != tt.wantTailscaleLockdown {
				t.Fatalf("TailscaleLockdown = %v, want %v", cfg.TailscaleLockdown, tt.wantTailscaleLockdown)
			}
			if cfg.Daytona.APIKey != tt.wantDaytonaAPIKey {
				t.Fatalf("Daytona.APIKey = %q, want %q", cfg.Daytona.APIKey, tt.wantDaytonaAPIKey)
			}
			if cfg.DigitalOcean.Size != tt.wantDOSize {
				t.Fatalf("DigitalOcean.Size = %q, want %q", cfg.DigitalOcean.Size, tt.wantDOSize)
			}
			if cfg.Hetzner.Image != tt.wantHetznerImage {
				t.Fatalf("Hetzner.Image = %q, want %q", cfg.Hetzner.Image, tt.wantHetznerImage)
			}
			if cfg.Lightsail.AvailabilityZone != tt.wantLightsailAZ {
				t.Fatalf("Lightsail.AvailabilityZone = %q, want %q", cfg.Lightsail.AvailabilityZone, tt.wantLightsailAZ)
			}
		})
	}
}

func TestLoadGlobalConfig_InvalidYAML(t *testing.T) {
	home := setGlobalConfigHome(t)
	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() failed: %v", err)
	}

	configPath := filepath.Join(home, globalConfigFileName)
	if err := os.WriteFile(configPath, []byte("provider: ["), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	_, err := LoadGlobalConfig()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parse global sandbox config") {
		t.Fatalf("error = %q, want parse global sandbox config prefix", err.Error())
	}
}

func TestSaveGlobalConfig(t *testing.T) {
	home := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, home)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	cfg := &GlobalConfig{
		Provider: "digitalocean",
		Defaults: GlobalDefaults{
			AutoShutdown: false,
			IdleHours:    12,
		},
		Env: map[string]string{
			"OPENAI_API_KEY": "sk-openai",
			"GITHUB_TOKEN":   "ghp-token",
		},
		TailscaleLockdown: true,
		Daytona: DaytonaGlobalConfig{
			APIKey:    "day-api-key",
			ServerURL: "https://app.daytona.io/api",
		},
		DigitalOcean: DigitalOceanGlobalConfig{
			SSHKey: "aa:bb:cc",
			Size:   "s-2vcpu-4gb",
		},
		Hetzner: HetznerGlobalConfig{
			SSHKey:     "my-key",
			ServerType: "cx22",
			Image:      "ubuntu-24.04",
		},
		Lightsail: LightsailGlobalConfig{
			KeyPairName:      "key-a",
			Bundle:           "small_3_0",
			Region:           "us-east-1",
			AvailabilityZone: "us-east-1a",
		},
	}

	if err := SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("SaveGlobalConfig() unexpected error: %v", err)
	}

	configPath := filepath.Join(home, globalConfigFileName)
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config file perms = %o, want %o", info.Mode().Perm(), 0o600)
	}
	if _, err := os.Stat(configPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary config file should not remain after save")
	}

	if _, err := os.Stat(filepath.Join(home, sandboxesDirName)); err != nil {
		t.Fatalf("expected sandboxes directory to exist: %v", err)
	}

	loaded, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig() after save failed: %v", err)
	}
	if loaded.Provider != cfg.Provider {
		t.Fatalf("loaded provider = %q, want %q", loaded.Provider, cfg.Provider)
	}
	if loaded.Defaults != cfg.Defaults {
		t.Fatalf("loaded defaults = %#v, want %#v", loaded.Defaults, cfg.Defaults)
	}
	if !reflect.DeepEqual(loaded.Env, cfg.Env) {
		t.Fatalf("loaded env = %#v, want %#v", loaded.Env, cfg.Env)
	}
	if loaded.TailscaleLockdown != cfg.TailscaleLockdown {
		t.Fatalf("loaded tailscaleLockdown = %v, want %v", loaded.TailscaleLockdown, cfg.TailscaleLockdown)
	}
	if loaded.DigitalOcean.Size != cfg.DigitalOcean.Size {
		t.Fatalf("loaded digitalocean.size = %q, want %q", loaded.DigitalOcean.Size, cfg.DigitalOcean.Size)
	}
}

func TestSaveGlobalConfig_Nil(t *testing.T) {
	setGlobalConfigHome(t)

	err := SaveGlobalConfig(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "global sandbox config is nil" {
		t.Fatalf("error = %q, want %q", err.Error(), "global sandbox config is nil")
	}
}

func setGlobalConfigHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv(halConfigHomeEnv, home)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())
	return home
}
