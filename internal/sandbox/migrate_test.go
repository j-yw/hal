package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestMigrate_ConfigFile(t *testing.T) {
	tests := []struct {
		name           string
		setupLocal     func(t *testing.T, projectDir string)
		seedGlobal     *GlobalConfig
		wantGlobal     *GlobalConfig
		wantGlobalFile bool
	}{
		{
			name: "copies local sandbox config when global config is missing",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeProjectConfig(t, projectDir, localSandboxConfigYAML)
			},
			wantGlobal:     expectedMigratedGlobalConfig(),
			wantGlobalFile: true,
		},
		{
			name: "keeps existing global config and preserves local config when both exist",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeProjectConfig(t, projectDir, localSandboxConfigYAML)
			},
			seedGlobal:     existingGlobalConfig(),
			wantGlobal:     existingGlobalConfig(),
			wantGlobalFile: true,
		},
		{
			name:           "no-op when local project sandbox config is missing",
			wantGlobalFile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			globalHome := filepath.Join(t.TempDir(), "hal-global")
			t.Setenv(halConfigHomeEnv, globalHome)
			t.Setenv(xdgConfigHomeEnv, "")
			t.Setenv("HOME", t.TempDir())

			projectDir := t.TempDir()
			if tt.setupLocal != nil {
				tt.setupLocal(t, projectDir)
			}
			if tt.seedGlobal != nil {
				if err := SaveGlobalConfig(tt.seedGlobal); err != nil {
					t.Fatalf("SaveGlobalConfig(seed) error: %v", err)
				}
			}

			localPath := filepath.Join(projectDir, template.HalDir, template.ConfigFile)
			localBefore, hadLocal := readFileIfExists(t, localPath)

			if err := Migrate(projectDir, nil); err != nil {
				t.Fatalf("Migrate() unexpected error: %v", err)
			}

			globalPath := filepath.Join(globalHome, globalConfigFileName)
			_, statErr := os.Stat(globalPath)
			if !tt.wantGlobalFile {
				if !errors.Is(statErr, fs.ErrNotExist) {
					t.Fatalf("global config should not exist, stat err = %v", statErr)
				}
			} else {
				if statErr != nil {
					t.Fatalf("expected global config file: %v", statErr)
				}

				got, err := LoadGlobalConfig()
				if err != nil {
					t.Fatalf("LoadGlobalConfig() error: %v", err)
				}
				if !reflect.DeepEqual(got, tt.wantGlobal) {
					t.Fatalf("global config = %#v, want %#v", got, tt.wantGlobal)
				}
			}

			if hadLocal {
				localAfter, err := os.ReadFile(localPath)
				if err != nil {
					t.Fatalf("read local config after migration: %v", err)
				}
				if string(localAfter) != localBefore {
					t.Fatalf("local config should be preserved; before %q after %q", localBefore, string(localAfter))
				}
			}
		})
	}
}

func writeProjectConfig(t *testing.T, projectDir, content string) {
	t.Helper()

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	path := filepath.Join(halDir, template.ConfigFile)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}
}

func readFileIfExists(t *testing.T, path string) (string, bool) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false
		}
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data), true
}

func expectedMigratedGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		Provider: "digitalocean",
		Defaults: GlobalDefaults{
			AutoShutdown: true,
			IdleHours:    48,
		},
		Env: map[string]string{
			"OPENAI_API_KEY": "sk-local",
			"GITHUB_TOKEN":   "gh-local",
		},
		TailscaleLockdown: true,
		Daytona: DaytonaGlobalConfig{
			APIKey:    "local-daytona-key",
			ServerURL: "https://daytona.local/api",
		},
		DigitalOcean: DigitalOceanGlobalConfig{
			SSHKey: "do-local-key",
			Size:   "s-2vcpu-4gb",
		},
		Hetzner: HetznerGlobalConfig{
			SSHKey:     "hz-local-key",
			ServerType: "cx22",
			Image:      "ubuntu-24.04",
		},
		Lightsail: LightsailGlobalConfig{
			Region:           "us-east-1",
			AvailabilityZone: "us-east-1a",
			Bundle:           "small_3_0",
			KeyPairName:      "ls-local-key",
		},
	}
}

func existingGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		Provider: "hetzner",
		Defaults: GlobalDefaults{
			AutoShutdown: false,
			IdleHours:    72,
		},
		Env: map[string]string{
			"OPENAI_API_KEY": "sk-global",
		},
		TailscaleLockdown: false,
		Daytona: DaytonaGlobalConfig{
			APIKey:    "global-daytona-key",
			ServerURL: "https://global.daytona/api",
		},
		DigitalOcean: DigitalOceanGlobalConfig{
			SSHKey: "do-global-key",
			Size:   "s-1vcpu-1gb",
		},
		Hetzner: HetznerGlobalConfig{
			SSHKey:     "hz-global-key",
			ServerType: "cx32",
			Image:      "ubuntu-22.04",
		},
		Lightsail: LightsailGlobalConfig{
			Region:           "us-west-2",
			AvailabilityZone: "us-west-2a",
			Bundle:           "medium_3_0",
			KeyPairName:      "ls-global-key",
		},
	}
}

const localSandboxConfigYAML = `engine: codex
daytona:
  apiKey: local-daytona-key
  serverURL: https://daytona.local/api
sandbox:
  provider: digitalocean
  tailscaleLockdown: true
  env:
    OPENAI_API_KEY: sk-local
    GITHUB_TOKEN: gh-local
  digitalocean:
    sshKey: do-local-key
    size: s-2vcpu-4gb
  hetzner:
    sshKey: hz-local-key
    serverType: cx22
    image: ubuntu-24.04
  lightsail:
    keyPairName: ls-local-key
    bundle: small_3_0
    region: us-east-1
    availabilityZone: us-east-1a
`
