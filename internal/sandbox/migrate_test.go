package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestMigrate_StateFile(t *testing.T) {
	tests := []struct {
		name             string
		setupLocal       func(t *testing.T, projectDir string)
		seedRegistry     func(t *testing.T)
		wantErr          string
		wantLocalDeleted bool
		wantRegistered   bool
		wantOutput       string
		checkRegistry    func(t *testing.T)
	}{
		{
			name: "migrates sandbox.json to global registry and deletes local",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeSandboxJSON(t, projectDir, &SandboxState{
					ID:       "test-id-001",
					Name:     "my-sandbox",
					Provider: "hetzner",
					IP:       "10.0.0.1",
					Status:   StatusRunning,
				})
			},
			wantLocalDeleted: true,
			wantRegistered:   true,
			wantOutput:       `Migrated sandbox "my-sandbox" to global registry`,
			checkRegistry: func(t *testing.T) {
				t.Helper()
				inst, err := LoadInstance("my-sandbox")
				if err != nil {
					t.Fatalf("LoadInstance after migration: %v", err)
				}
				if inst.ID != "test-id-001" {
					t.Errorf("ID = %q, want %q", inst.ID, "test-id-001")
				}
				if inst.Provider != "hetzner" {
					t.Errorf("Provider = %q, want %q", inst.Provider, "hetzner")
				}
				if inst.IP != "10.0.0.1" {
					t.Errorf("IP = %q, want %q", inst.IP, "10.0.0.1")
				}
			},
		},
		{
			name:             "no-op when sandbox.json does not exist",
			wantLocalDeleted: false,
			wantRegistered:   false,
		},
		{
			name: "already migrated removes local file and skips registry write",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeSandboxJSON(t, projectDir, &SandboxState{
					ID:       "test-id-002",
					Name:     "already-there",
					Provider: "daytona",
					Status:   StatusRunning,
				})
			},
			seedRegistry: func(t *testing.T) {
				t.Helper()
				if err := ForceWriteInstance(&SandboxState{
					ID:       "test-id-002",
					Name:     "already-there",
					Provider: "daytona",
					Status:   StatusRunning,
				}); err != nil {
					t.Fatalf("seed registry: %v", err)
				}
			},
			wantLocalDeleted: true,
			wantRegistered:   true,
			wantOutput:       "Removed already-migrated sandbox.json",
		},
		{
			name: "auto-migrates empty provider to daytona",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeSandboxJSON(t, projectDir, &SandboxState{
					ID:       "legacy-id",
					Name:     "legacy-box",
					Provider: "", // empty = legacy daytona
					Status:   StatusRunning,
				})
			},
			wantLocalDeleted: true,
			wantRegistered:   true,
			checkRegistry: func(t *testing.T) {
				t.Helper()
				inst, err := LoadInstance("legacy-box")
				if err != nil {
					t.Fatalf("LoadInstance: %v", err)
				}
				if inst.Provider != "daytona" {
					t.Errorf("Provider = %q, want %q", inst.Provider, "daytona")
				}
			},
		},
		{
			name: "returns error for empty name in sandbox.json",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				writeSandboxJSON(t, projectDir, &SandboxState{
					ID:       "no-name-id",
					Name:     "",
					Provider: "hetzner",
				})
			},
			wantErr:          "empty name",
			wantLocalDeleted: false,
		},
		{
			name: "preserves all SandboxState fields through migration",
			setupLocal: func(t *testing.T, projectDir string) {
				t.Helper()
				now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
				stopped := now.Add(2 * time.Hour)
				writeSandboxJSON(t, projectDir, &SandboxState{
					ID:                "full-id",
					Name:              "full-box",
					Provider:          "digitalocean",
					WorkspaceID:       "drop-123",
					IP:                "1.2.3.4",
					TailscaleIP:       "100.64.0.1",
					TailscaleHostname: "hal-full-box",
					Status:            StatusStopped,
					CreatedAt:         now,
					StoppedAt:         &stopped,
					AutoShutdown:      true,
					IdleHours:         48,
					Size:              "s-2vcpu-4gb",
					Repo:              "org/repo",
					SnapshotID:        "snap-001",
				})
			},
			wantLocalDeleted: true,
			wantRegistered:   true,
			checkRegistry: func(t *testing.T) {
				t.Helper()
				inst, err := LoadInstance("full-box")
				if err != nil {
					t.Fatalf("LoadInstance: %v", err)
				}
				if inst.WorkspaceID != "drop-123" {
					t.Errorf("WorkspaceID = %q, want %q", inst.WorkspaceID, "drop-123")
				}
				if inst.TailscaleIP != "100.64.0.1" {
					t.Errorf("TailscaleIP = %q, want %q", inst.TailscaleIP, "100.64.0.1")
				}
				if inst.Size != "s-2vcpu-4gb" {
					t.Errorf("Size = %q, want %q", inst.Size, "s-2vcpu-4gb")
				}
				if inst.Repo != "org/repo" {
					t.Errorf("Repo = %q, want %q", inst.Repo, "org/repo")
				}
				if inst.SnapshotID != "snap-001" {
					t.Errorf("SnapshotID = %q, want %q", inst.SnapshotID, "snap-001")
				}
			},
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
			if tt.seedRegistry != nil {
				tt.seedRegistry(t)
			}

			var buf bytes.Buffer
			err := Migrate(projectDir, &buf)

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

			// Check local file deleted/preserved.
			localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)
			_, localErr := os.Stat(localPath)
			if tt.wantLocalDeleted {
				if !errors.Is(localErr, fs.ErrNotExist) {
					t.Errorf("expected local sandbox.json deleted, stat err = %v", localErr)
				}
			} else {
				// If no local was set up, it's fine that it doesn't exist.
				if tt.setupLocal != nil && localErr != nil {
					t.Errorf("expected local sandbox.json preserved, stat err = %v", localErr)
				}
			}

			// Check output.
			if tt.wantOutput != "" {
				if !strings.Contains(buf.String(), tt.wantOutput) {
					t.Errorf("output %q does not contain %q", buf.String(), tt.wantOutput)
				}
			}

			// Check registry.
			if tt.checkRegistry != nil {
				tt.checkRegistry(t)
			}
		})
	}
}

func TestMigrate_StateFile_Idempotent(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	writeSandboxJSON(t, projectDir, &SandboxState{
		ID:       "idem-id",
		Name:     "idem-box",
		Provider: "hetzner",
		Status:   StatusRunning,
	})

	// First migration.
	var buf1 bytes.Buffer
	if err := Migrate(projectDir, &buf1); err != nil {
		t.Fatalf("first Migrate() error: %v", err)
	}
	if !strings.Contains(buf1.String(), "Migrated sandbox") {
		t.Fatalf("first migration should emit output, got %q", buf1.String())
	}

	// Verify local file deleted.
	localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)
	if _, err := os.Stat(localPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("local file should be deleted after first migration")
	}

	// Second migration is a no-op.
	var buf2 bytes.Buffer
	if err := Migrate(projectDir, &buf2); err != nil {
		t.Fatalf("second Migrate() error: %v", err)
	}
	if buf2.Len() != 0 {
		t.Errorf("second migration should emit no output, got %q", buf2.String())
	}

	// Registry entry still present.
	inst, err := LoadInstance("idem-box")
	if err != nil {
		t.Fatalf("LoadInstance after second migration: %v", err)
	}
	if inst.ID != "idem-id" {
		t.Errorf("ID = %q, want %q", inst.ID, "idem-id")
	}
}

func TestMigrate_StateFile_NilWriterNoOutput(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	writeSandboxJSON(t, projectDir, &SandboxState{
		ID:       "silent-id",
		Name:     "silent-box",
		Provider: "hetzner",
		Status:   StatusRunning,
	})

	// nil writer — migration emits no output.
	if err := Migrate(projectDir, nil); err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}

	// Verify migration actually happened.
	inst, err := LoadInstance("silent-box")
	if err != nil {
		t.Fatalf("LoadInstance: %v", err)
	}
	if inst.ID != "silent-id" {
		t.Errorf("ID = %q, want %q", inst.ID, "silent-id")
	}

	// Local file deleted.
	localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)
	if _, err := os.Stat(localPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("local sandbox.json should be deleted")
	}
}

func TestMigrate_StateAndConfigTogether(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	writeProjectConfig(t, projectDir, localSandboxConfigYAML)
	writeSandboxJSON(t, projectDir, &SandboxState{
		ID:       "combo-id",
		Name:     "combo-box",
		Provider: "digitalocean",
		Status:   StatusRunning,
	})

	var buf bytes.Buffer
	if err := Migrate(projectDir, &buf); err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Migrated sandbox config") {
		t.Errorf("output should contain config migration message, got %q", output)
	}
	if !strings.Contains(output, "Migrated sandbox \"combo-box\"") {
		t.Errorf("output should contain state migration message, got %q", output)
	}

	// Both config and state should be in global location.
	cfg, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig: %v", err)
	}
	if cfg.Provider != "digitalocean" {
		t.Errorf("config Provider = %q, want %q", cfg.Provider, "digitalocean")
	}

	inst, err := LoadInstance("combo-box")
	if err != nil {
		t.Fatalf("LoadInstance: %v", err)
	}
	if inst.ID != "combo-id" {
		t.Errorf("registry ID = %q, want %q", inst.ID, "combo-id")
	}
}

func TestMigrate_InvalidLocalJSON(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := Migrate(projectDir, nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse legacy sandbox state") {
		t.Errorf("error %q should mention parsing", err.Error())
	}

	// Local file should be preserved on error.
	localPath := filepath.Join(halDir, template.SandboxFile)
	if _, statErr := os.Stat(localPath); statErr != nil {
		t.Errorf("local file should be preserved on error, stat err = %v", statErr)
	}
}

func TestMigrate_StateFile_ExistingRegistryParseError(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	writeSandboxJSON(t, projectDir, &SandboxState{
		ID:       "legacy-id",
		Name:     "legacy-box",
		Provider: "daytona",
		Status:   StatusRunning,
	})

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir: %v", err)
	}
	brokenRegistryPath := filepath.Join(SandboxesDir(), "legacy-box.json")
	if err := os.WriteFile(brokenRegistryPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write broken registry entry: %v", err)
	}

	err := Migrate(projectDir, nil)
	if err == nil {
		t.Fatal("expected migration error, got nil")
	}
	if !strings.Contains(err.Error(), `check existing global sandbox state "legacy-box"`) {
		t.Fatalf("error %q missing existing-state context", err.Error())
	}
	if !strings.Contains(err.Error(), `parse sandbox "legacy-box"`) {
		t.Fatalf("error %q missing parse context", err.Error())
	}

	localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)
	if _, statErr := os.Stat(localPath); statErr != nil {
		t.Fatalf("local sandbox.json should be preserved, stat err = %v", statErr)
	}
}

func TestMigrate_StateFile_ExistingRegistryConflictPreservesLocal(t *testing.T) {
	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv(halConfigHomeEnv, globalHome)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()
	writeSandboxJSON(t, projectDir, &SandboxState{
		ID:          "legacy-id",
		Name:        "legacy-box",
		Provider:    "daytona",
		WorkspaceID: "ws-legacy",
		Status:      StatusRunning,
	})

	if err := ForceWriteInstance(&SandboxState{
		ID:          "global-id",
		Name:        "legacy-box",
		Provider:    "daytona",
		WorkspaceID: "ws-global",
		Status:      StatusRunning,
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	err := Migrate(projectDir, nil)
	if err == nil {
		t.Fatal("expected migration conflict error, got nil")
	}
	if !strings.Contains(err.Error(), `conflicts with existing global sandbox state`) {
		t.Fatalf("error %q missing conflict context", err.Error())
	}

	localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)
	if _, statErr := os.Stat(localPath); statErr != nil {
		t.Fatalf("local sandbox.json should be preserved, stat err = %v", statErr)
	}

	existing, loadErr := LoadInstance("legacy-box")
	if loadErr != nil {
		t.Fatalf("LoadInstance after conflict: %v", loadErr)
	}
	if existing.ID != "global-id" {
		t.Fatalf("existing global entry should be preserved, ID=%q", existing.ID)
	}
}

func writeSandboxJSON(t *testing.T, projectDir string, state *SandboxState) {
	t.Helper()
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal sandbox state: %v", err)
	}
	path := filepath.Join(halDir, template.SandboxFile)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write sandbox.json: %v", err)
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
