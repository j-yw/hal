package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

// Migrate moves legacy project sandbox state to global locations:
//
//  1. Config migration: .hal/config.yaml sandbox/daytona sections → global
//     sandbox-config.yaml (only when global config is missing).
//  2. State migration: .hal/sandbox.json → global registry entry
//     (sandboxes/{name}.json). The local file is deleted only after the global
//     registry save succeeds and a read-back confirms the entry is present.
//
// Migration is idempotent — running it repeatedly after a successful migration
// is a no-op.
//
// When out is non-nil, migration emits one line per action. When out is nil,
// migration emits no output.
func Migrate(projectDir string, out io.Writer) error {
	if err := migrateConfig(projectDir, out); err != nil {
		return err
	}
	if err := migrateState(projectDir, out); err != nil {
		return err
	}
	return nil
}

// migrateConfig handles config migration (.hal/config.yaml → global sandbox-config.yaml).
func migrateConfig(projectDir string, out io.Writer) error {
	globalPath := filepath.Join(GlobalDir(), globalConfigFileName)
	if _, err := os.Stat(globalPath); err == nil {
		return nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat global sandbox config: %w", err)
	}

	cfg, hasLegacyConfig, err := loadLegacyProjectConfig(projectDir)
	if err != nil {
		return err
	}
	if !hasLegacyConfig {
		return nil
	}

	if err := SaveGlobalConfig(cfg); err != nil {
		return fmt.Errorf("save migrated sandbox config: %w", err)
	}

	if out != nil {
		fmt.Fprintf(out, "Migrated sandbox config to %s\n", globalPath)
	}

	return nil
}

// migrateState handles state migration (.hal/sandbox.json → global registry).
//
// Safety contract:
//   - The local .hal/sandbox.json is deleted only after the global registry
//     save succeeds AND a read-back confirms the migrated entry is present.
//   - If read-back verification fails, migration returns an error and the
//     local file remains unchanged.
//   - Uses read→write→verify→delete (no os.Rename) for cross-device safety.
func migrateState(projectDir string, out io.Writer) error {
	localPath := filepath.Join(projectDir, template.HalDir, template.SandboxFile)

	data, err := os.ReadFile(localPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // nothing to migrate
		}
		return fmt.Errorf("read legacy sandbox state: %w", err)
	}

	var state SandboxState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse legacy sandbox state: %w", err)
	}

	if strings.TrimSpace(state.Name) == "" {
		return fmt.Errorf("legacy sandbox state has empty name — cannot migrate")
	}

	// Auto-migrate legacy provider field (same as LoadState).
	if state.Provider == "" {
		state.Provider = "daytona"
	}

	// Check if already migrated (entry exists in global registry).
	if existing, err := LoadInstance(state.Name); err == nil {
		if !equivalentMigrationState(&state, existing) {
			return fmt.Errorf("legacy sandbox state %q conflicts with existing global sandbox state", state.Name)
		}
		// Already in registry — remove local file and return.
		if removeErr := os.Remove(localPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return fmt.Errorf("remove already-migrated local state: %w", removeErr)
		}
		if out != nil {
			fmt.Fprintf(out, "Removed already-migrated %s (entry %q exists in global registry)\n",
				template.SandboxFile, state.Name)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("check existing global sandbox state %q: %w", state.Name, err)
	}

	// Ensure global directory exists before writing.
	if err := EnsureGlobalDir(); err != nil {
		return fmt.Errorf("ensure global dir for state migration: %w", err)
	}

	// Legacy state used "id" for provider lifecycle target. Backfill workspaceId
	// so ConnectInfoFromState remains valid after migration.
	if strings.TrimSpace(state.WorkspaceID) == "" && strings.TrimSpace(state.ID) != "" {
		state.WorkspaceID = strings.TrimSpace(state.ID)
	}

	// Save to global registry (uses atomic temp-file + rename internally).
	if err := ForceWriteInstance(&state); err != nil {
		return fmt.Errorf("save migrated sandbox state: %w", err)
	}

	// Read-back verification: confirm the entry is present and matches.
	readBack, err := LoadInstance(state.Name)
	if err != nil {
		return fmt.Errorf("verify migrated sandbox state: read-back failed for %q: %w", state.Name, err)
	}
	if readBack.Name != state.Name || readBack.ID != state.ID {
		return fmt.Errorf("verify migrated sandbox state: read-back mismatch for %q (name=%q id=%q, expected name=%q id=%q)",
			state.Name, readBack.Name, readBack.ID, state.Name, state.ID)
	}

	// Verification passed — safe to delete local file.
	if err := os.Remove(localPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove local sandbox state after migration: %w", err)
	}

	if out != nil {
		fmt.Fprintf(out, "Migrated sandbox %q to global registry\n", state.Name)
	}

	return nil
}

func equivalentMigrationState(local, global *SandboxState) bool {
	if local == nil || global == nil {
		return false
	}
	return local.Name == global.Name &&
		local.ID == global.ID &&
		local.WorkspaceID == global.WorkspaceID &&
		normalizeMigrationProvider(local.Provider) == normalizeMigrationProvider(global.Provider)
}

func normalizeMigrationProvider(provider string) string {
	if strings.TrimSpace(provider) == "" {
		return "daytona"
	}
	return provider
}

type rawLegacyProjectConfig struct {
	Sandbox *rawLegacySandboxSection `yaml:"sandbox"`
	Daytona *rawLegacyDaytonaSection `yaml:"daytona"`
}

type rawLegacySandboxSection struct {
	Provider          *string                     `yaml:"provider"`
	TailscaleLockdown *bool                       `yaml:"tailscaleLockdown"`
	Env               map[string]string           `yaml:"env"`
	Hetzner           rawLegacyHetznerSection     `yaml:"hetzner"`
	DigitalOcean      rawLegacyDigitalOceanConfig `yaml:"digitalocean"`
	Lightsail         rawLegacyLightsailSection   `yaml:"lightsail"`
}

type rawLegacyDaytonaSection struct {
	APIKey    *string `yaml:"apiKey"`
	ServerURL *string `yaml:"serverURL"`
}

type rawLegacyHetznerSection struct {
	SSHKey     *string `yaml:"sshKey"`
	ServerType *string `yaml:"serverType"`
	Image      *string `yaml:"image"`
}

type rawLegacyDigitalOceanConfig struct {
	SSHKey *string `yaml:"sshKey"`
	Size   *string `yaml:"size"`
}

type rawLegacyLightsailSection struct {
	Region           *string `yaml:"region"`
	AvailabilityZone *string `yaml:"availabilityZone"`
	Bundle           *string `yaml:"bundle"`
	KeyPairName      *string `yaml:"keyPairName"`
}

func loadLegacyProjectConfig(projectDir string) (*GlobalConfig, bool, error) {
	configPath := filepath.Join(projectDir, template.HalDir, template.ConfigFile)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read project sandbox config: %w", err)
	}

	var raw rawLegacyProjectConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parse project sandbox config: %w", err)
	}

	if raw.Sandbox == nil && raw.Daytona == nil {
		return nil, false, nil
	}

	cfg := DefaultGlobalConfig()

	if raw.Sandbox != nil {
		if raw.Sandbox.Provider != nil {
			cfg.Provider = *raw.Sandbox.Provider
		}
		if raw.Sandbox.TailscaleLockdown != nil {
			cfg.TailscaleLockdown = *raw.Sandbox.TailscaleLockdown
		}
		if raw.Sandbox.Env != nil {
			cfg.Env = copyStringMap(raw.Sandbox.Env)
		}
		if raw.Sandbox.Hetzner.SSHKey != nil {
			cfg.Hetzner.SSHKey = *raw.Sandbox.Hetzner.SSHKey
		}
		if raw.Sandbox.Hetzner.ServerType != nil {
			cfg.Hetzner.ServerType = *raw.Sandbox.Hetzner.ServerType
		}
		if raw.Sandbox.Hetzner.Image != nil {
			cfg.Hetzner.Image = *raw.Sandbox.Hetzner.Image
		}
		if raw.Sandbox.DigitalOcean.SSHKey != nil {
			cfg.DigitalOcean.SSHKey = *raw.Sandbox.DigitalOcean.SSHKey
		}
		if raw.Sandbox.DigitalOcean.Size != nil {
			cfg.DigitalOcean.Size = *raw.Sandbox.DigitalOcean.Size
		}
		if raw.Sandbox.Lightsail.Region != nil {
			cfg.Lightsail.Region = *raw.Sandbox.Lightsail.Region
		}
		if raw.Sandbox.Lightsail.AvailabilityZone != nil {
			cfg.Lightsail.AvailabilityZone = *raw.Sandbox.Lightsail.AvailabilityZone
		}
		if raw.Sandbox.Lightsail.Bundle != nil {
			cfg.Lightsail.Bundle = *raw.Sandbox.Lightsail.Bundle
		}
		if raw.Sandbox.Lightsail.KeyPairName != nil {
			cfg.Lightsail.KeyPairName = *raw.Sandbox.Lightsail.KeyPairName
		}
	}

	if raw.Daytona != nil {
		if raw.Daytona.APIKey != nil {
			cfg.Daytona.APIKey = *raw.Daytona.APIKey
		}
		if raw.Daytona.ServerURL != nil {
			cfg.Daytona.ServerURL = *raw.Daytona.ServerURL
		}
	}

	return &cfg, true, nil
}
