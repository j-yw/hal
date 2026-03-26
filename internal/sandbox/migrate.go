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

	legacyID := strings.TrimSpace(state.ID)

	// Legacy provider state only used "id" as a lifecycle target for specific
	// providers. Backfill workspaceId before the existing-entry check so reruns
	// compare normalized state without copying new UUIDv7 sandbox IDs.
	if strings.TrimSpace(state.WorkspaceID) == "" && shouldBackfillLegacyWorkspaceID(state.Provider, legacyID) {
		state.WorkspaceID = legacyID
	}
	if !isUUIDv7(state.ID) {
		state.ID = ""
	}

	// Check if already migrated (entry exists in global registry).
	if existing, err := LoadInstance(state.Name); err == nil {
		if !compatibleMigrationState(&state, existing) {
			return fmt.Errorf("legacy sandbox state %q conflicts with existing global sandbox state", state.Name)
		}

		if merged, changed := mergeMissingMigrationState(existing, &state); changed {
			if err := ForceWriteInstance(merged); err != nil {
				return fmt.Errorf("merge existing global sandbox state %q: %w", state.Name, err)
			}
			existing, err = LoadInstance(state.Name)
			if err != nil {
				return fmt.Errorf("verify migrated sandbox state: read-back failed for %q: %w", state.Name, err)
			}
		}
		if !migrationStatePreserved(&state, existing) {
			return fmt.Errorf("verify migrated sandbox state: existing entry %q is missing persisted legacy fields", state.Name)
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

	if strings.TrimSpace(state.ID) == "" {
		id, err := NewV7()
		if err != nil {
			return fmt.Errorf("generate sandbox id for migrated state: %w", err)
		}
		state.ID = id
	}

	// Save to global registry (uses atomic temp-file + rename internally).
	if err := SaveInstance(&state); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("save migrated sandbox state: sandbox %q already exists", state.Name)
		}
		return fmt.Errorf("save migrated sandbox state: %w", err)
	}

	// Read-back verification: confirm the entry is present and matches.
	readBack, err := LoadInstance(state.Name)
	if err != nil {
		return fmt.Errorf("verify migrated sandbox state: read-back failed for %q: %w", state.Name, err)
	}
	if !migrationStatePreserved(&state, readBack) {
		return fmt.Errorf("verify migrated sandbox state: read-back mismatch for %q", state.Name)
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

func shouldBackfillLegacyWorkspaceID(provider, legacyID string) bool {
	if legacyID == "" || isUUIDv7(legacyID) {
		return false
	}
	return strings.TrimSpace(provider) == "digitalocean" && isLegacyDigitalOceanDropletID(legacyID)
}

func compatibleMigrationState(local, global *SandboxState) bool {
	if local == nil || global == nil {
		return false
	}
	if local.Name != global.Name ||
		!migrationValuesCompatible(local.ID, global.ID) ||
		!migrationValuesCompatible(local.WorkspaceID, global.WorkspaceID) ||
		normalizeMigrationProvider(local.Provider) != normalizeMigrationProvider(global.Provider) {
		return false
	}

	if !migrationValuesCompatible(local.IP, global.IP) {
		return false
	}
	if !migrationValuesCompatible(local.TailscaleIP, global.TailscaleIP) {
		return false
	}
	if !migrationValuesCompatible(local.TailscaleHostname, global.TailscaleHostname) {
		return false
	}
	if !migrationStatusCompatible(local.Status, global.Status) {
		return false
	}
	if !local.CreatedAt.IsZero() && !global.CreatedAt.IsZero() && !global.CreatedAt.Equal(local.CreatedAt) {
		return false
	}
	if local.StoppedAt != nil && global.StoppedAt != nil && !global.StoppedAt.Equal(*local.StoppedAt) {
		return false
	}
	if local.AutoShutdown && !global.AutoShutdown {
		return false
	}
	if local.IdleHours != 0 && global.IdleHours != 0 && global.IdleHours != local.IdleHours {
		return false
	}
	if !migrationValuesCompatible(local.Size, global.Size) {
		return false
	}
	if !migrationValuesCompatible(local.Repo, global.Repo) {
		return false
	}
	if !migrationValuesCompatible(local.SnapshotID, global.SnapshotID) {
		return false
	}

	return true
}

func migrationValuesCompatible(local, global string) bool {
	local = strings.TrimSpace(local)
	global = strings.TrimSpace(global)
	return local == "" || global == "" || local == global
}

func migrationStatePreserved(local, global *SandboxState) bool {
	if !compatibleMigrationState(local, global) {
		return false
	}

	if !migrationValuePreserved(local.ID, global.ID) {
		return false
	}
	if !migrationValuePreserved(local.WorkspaceID, global.WorkspaceID) {
		return false
	}
	if !migrationValuePreserved(local.IP, global.IP) {
		return false
	}
	if !migrationValuePreserved(local.TailscaleIP, global.TailscaleIP) {
		return false
	}
	if !migrationValuePreserved(local.TailscaleHostname, global.TailscaleHostname) {
		return false
	}

	if !migrationStatusPreserved(local.Status, global.Status) {
		return false
	}

	if !local.CreatedAt.IsZero() && (global.CreatedAt.IsZero() || !global.CreatedAt.Equal(local.CreatedAt)) {
		return false
	}
	if local.StoppedAt != nil && (global.StoppedAt == nil || !global.StoppedAt.Equal(*local.StoppedAt)) {
		return false
	}
	if local.AutoShutdown && !global.AutoShutdown {
		return false
	}
	if local.IdleHours != 0 && global.IdleHours != local.IdleHours {
		return false
	}
	if !migrationValuePreserved(local.Size, global.Size) {
		return false
	}
	if !migrationValuePreserved(local.Repo, global.Repo) {
		return false
	}
	if !migrationValuePreserved(local.SnapshotID, global.SnapshotID) {
		return false
	}

	return true
}

func migrationValuePreserved(local, global string) bool {
	local = strings.TrimSpace(local)
	if local == "" {
		return true
	}
	return strings.TrimSpace(global) == local
}

func mergeMissingMigrationState(existing, local *SandboxState) (*SandboxState, bool) {
	if existing == nil || local == nil {
		return existing, false
	}

	merged := *existing
	changed := false

	if strings.TrimSpace(merged.ID) == "" && strings.TrimSpace(local.ID) != "" {
		merged.ID = local.ID
		changed = true
	}
	if strings.TrimSpace(merged.Provider) == "" && strings.TrimSpace(local.Provider) != "" {
		merged.Provider = local.Provider
		changed = true
	}
	if strings.TrimSpace(merged.WorkspaceID) == "" && strings.TrimSpace(local.WorkspaceID) != "" {
		merged.WorkspaceID = local.WorkspaceID
		changed = true
	}
	if strings.TrimSpace(merged.IP) == "" && strings.TrimSpace(local.IP) != "" {
		merged.IP = local.IP
		changed = true
	}
	if strings.TrimSpace(merged.TailscaleIP) == "" && strings.TrimSpace(local.TailscaleIP) != "" {
		merged.TailscaleIP = local.TailscaleIP
		changed = true
	}
	if strings.TrimSpace(merged.TailscaleHostname) == "" && strings.TrimSpace(local.TailscaleHostname) != "" {
		merged.TailscaleHostname = local.TailscaleHostname
		changed = true
	}
	if needsMigrationStatus(merged.Status) && normalizeMigrationStatus(local.Status) != "" {
		merged.Status = normalizeMigrationStatus(local.Status)
		changed = true
	}
	if merged.CreatedAt.IsZero() && !local.CreatedAt.IsZero() {
		merged.CreatedAt = local.CreatedAt
		changed = true
	}
	if merged.StoppedAt == nil && local.StoppedAt != nil {
		stoppedAt := *local.StoppedAt
		merged.StoppedAt = &stoppedAt
		changed = true
	}
	if !merged.AutoShutdown && local.AutoShutdown {
		merged.AutoShutdown = true
		changed = true
	}
	if merged.IdleHours == 0 && local.IdleHours != 0 {
		merged.IdleHours = local.IdleHours
		changed = true
	}
	if strings.TrimSpace(merged.Size) == "" && strings.TrimSpace(local.Size) != "" {
		merged.Size = local.Size
		changed = true
	}
	if strings.TrimSpace(merged.Repo) == "" && strings.TrimSpace(local.Repo) != "" {
		merged.Repo = local.Repo
		changed = true
	}
	if strings.TrimSpace(merged.SnapshotID) == "" && strings.TrimSpace(local.SnapshotID) != "" {
		merged.SnapshotID = local.SnapshotID
		changed = true
	}

	return &merged, changed
}

func needsMigrationStatus(status string) bool {
	status = normalizeMigrationStatus(status)
	return status == "" || status == StatusUnknown
}

func migrationStatusCompatible(local, global string) bool {
	local = normalizeMigrationStatus(local)
	if local == "" || local == StatusUnknown {
		return true
	}

	global = normalizeMigrationStatus(global)
	return global == "" || global == StatusUnknown || global == local
}

func migrationStatusPreserved(local, global string) bool {
	local = normalizeMigrationStatus(local)
	if local == "" || local == StatusUnknown {
		return true
	}
	return normalizeMigrationStatus(global) == local
}

func normalizeMigrationStatus(status string) string {
	return strings.TrimSpace(strings.ToLower(status))
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
