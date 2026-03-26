package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const globalConfigFileName = "sandbox-config.yaml"

var (
	renameGlobalConfigFile = os.Rename
	removeGlobalConfigFile = os.Remove
)

// GlobalConfigPath returns the full path to sandbox-config.yaml in GlobalDir().
func GlobalConfigPath() string {
	path, err := globalConfigPath()
	if err != nil {
		return ""
	}
	return path
}

func globalConfigPath() (string, error) {
	dir, err := resolveGlobalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, globalConfigFileName), nil
}

// GlobalConfig stores sandbox provider settings in the global hal config dir.
type GlobalConfig struct {
	Provider          string                   `yaml:"provider"`
	Defaults          GlobalDefaults           `yaml:"defaults"`
	Env               map[string]string        `yaml:"env"`
	TailscaleLockdown bool                     `yaml:"tailscaleLockdown"`
	Daytona           DaytonaGlobalConfig      `yaml:"daytona"`
	DigitalOcean      DigitalOceanGlobalConfig `yaml:"digitalocean"`
	Hetzner           HetznerGlobalConfig      `yaml:"hetzner"`
	Lightsail         LightsailGlobalConfig    `yaml:"lightsail"`
}

// GlobalDefaults contains default sandbox lifecycle settings.
type GlobalDefaults struct {
	AutoShutdown bool `yaml:"autoShutdown"`
	IdleHours    int  `yaml:"idleHours"`
}

// DaytonaGlobalConfig contains Daytona-specific global settings.
type DaytonaGlobalConfig struct {
	APIKey    string `yaml:"apiKey"`
	ServerURL string `yaml:"serverURL"`
}

// DigitalOceanGlobalConfig contains DigitalOcean-specific global settings.
type DigitalOceanGlobalConfig struct {
	SSHKey string `yaml:"sshKey"`
	Size   string `yaml:"size"`
}

// HetznerGlobalConfig contains Hetzner-specific global settings.
type HetznerGlobalConfig struct {
	SSHKey     string `yaml:"sshKey"`
	ServerType string `yaml:"serverType"`
	Image      string `yaml:"image"`
}

// LightsailGlobalConfig contains AWS Lightsail-specific global settings.
type LightsailGlobalConfig struct {
	Region           string `yaml:"region"`
	AvailabilityZone string `yaml:"availabilityZone"`
	Bundle           string `yaml:"bundle"`
	KeyPairName      string `yaml:"keyPairName"`
}

// rawGlobalConfig uses pointer fields to distinguish missing YAML keys from
// explicitly provided zero values.
type rawGlobalConfig struct {
	Provider          *string                     `yaml:"provider"`
	Defaults          rawGlobalDefaults           `yaml:"defaults"`
	Env               map[string]string           `yaml:"env"`
	TailscaleLockdown *bool                       `yaml:"tailscaleLockdown"`
	Daytona           rawDaytonaGlobalConfig      `yaml:"daytona"`
	DigitalOcean      rawDigitalOceanGlobalConfig `yaml:"digitalocean"`
	Hetzner           rawHetznerGlobalConfig      `yaml:"hetzner"`
	Lightsail         rawLightsailGlobalConfig    `yaml:"lightsail"`
}

type rawGlobalDefaults struct {
	AutoShutdown *bool `yaml:"autoShutdown"`
	IdleHours    *int  `yaml:"idleHours"`
}

type rawDaytonaGlobalConfig struct {
	APIKey    *string `yaml:"apiKey"`
	ServerURL *string `yaml:"serverURL"`
}

type rawDigitalOceanGlobalConfig struct {
	SSHKey *string `yaml:"sshKey"`
	Size   *string `yaml:"size"`
}

type rawHetznerGlobalConfig struct {
	SSHKey     *string `yaml:"sshKey"`
	ServerType *string `yaml:"serverType"`
	Image      *string `yaml:"image"`
}

type rawLightsailGlobalConfig struct {
	Region           *string `yaml:"region"`
	AvailabilityZone *string `yaml:"availabilityZone"`
	Bundle           *string `yaml:"bundle"`
	KeyPairName      *string `yaml:"keyPairName"`
}

// DefaultGlobalConfig returns default sandbox global configuration.
func DefaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
		Provider: "daytona",
		Defaults: GlobalDefaults{
			AutoShutdown: true,
			IdleHours:    48,
		},
		Env: map[string]string{},
	}
}

// LoadGlobalConfig reads sandbox-config.yaml from the global hal config
// directory. Missing files return DefaultGlobalConfig.
func LoadGlobalConfig() (*GlobalConfig, error) {
	path, err := globalConfigPath()
	if err != nil {
		return nil, fmt.Errorf("resolve global sandbox config path: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultGlobalConfig()
			return &cfg, nil
		}
		return nil, fmt.Errorf("read global sandbox config: %w", err)
	}

	var raw rawGlobalConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse global sandbox config: %w", err)
	}

	cfg := DefaultGlobalConfig()

	if raw.Provider != nil {
		cfg.Provider = *raw.Provider
	}
	if raw.Defaults.AutoShutdown != nil {
		cfg.Defaults.AutoShutdown = *raw.Defaults.AutoShutdown
	}
	if raw.Defaults.IdleHours != nil {
		cfg.Defaults.IdleHours = *raw.Defaults.IdleHours
	}
	if raw.Env != nil {
		cfg.Env = copyStringMap(raw.Env)
	}
	if raw.TailscaleLockdown != nil {
		cfg.TailscaleLockdown = *raw.TailscaleLockdown
	}
	if raw.Daytona.APIKey != nil {
		cfg.Daytona.APIKey = *raw.Daytona.APIKey
	}
	if raw.Daytona.ServerURL != nil {
		cfg.Daytona.ServerURL = *raw.Daytona.ServerURL
	}
	if raw.DigitalOcean.SSHKey != nil {
		cfg.DigitalOcean.SSHKey = *raw.DigitalOcean.SSHKey
	}
	if raw.DigitalOcean.Size != nil {
		cfg.DigitalOcean.Size = *raw.DigitalOcean.Size
	}
	if raw.Hetzner.SSHKey != nil {
		cfg.Hetzner.SSHKey = *raw.Hetzner.SSHKey
	}
	if raw.Hetzner.ServerType != nil {
		cfg.Hetzner.ServerType = *raw.Hetzner.ServerType
	}
	if raw.Hetzner.Image != nil {
		cfg.Hetzner.Image = *raw.Hetzner.Image
	}
	if raw.Lightsail.Region != nil {
		cfg.Lightsail.Region = *raw.Lightsail.Region
	}
	if raw.Lightsail.AvailabilityZone != nil {
		cfg.Lightsail.AvailabilityZone = *raw.Lightsail.AvailabilityZone
	}
	if raw.Lightsail.Bundle != nil {
		cfg.Lightsail.Bundle = *raw.Lightsail.Bundle
	}
	if raw.Lightsail.KeyPairName != nil {
		cfg.Lightsail.KeyPairName = *raw.Lightsail.KeyPairName
	}

	return &cfg, nil
}

// SaveGlobalConfig writes sandbox-config.yaml to the global hal config
// directory using an atomic temp-file + rename flow and 0600 permissions.
func SaveGlobalConfig(cfg *GlobalConfig) error {
	if cfg == nil {
		return fmt.Errorf("global sandbox config is nil")
	}
	if err := EnsureGlobalDir(); err != nil {
		return err
	}
	path, err := globalConfigPath()
	if err != nil {
		return fmt.Errorf("resolve global sandbox config path: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal global sandbox config: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write global sandbox config: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = removeGlobalConfigFile(tmpPath)
		return fmt.Errorf("set global sandbox config permissions: %w", err)
	}
	if err := saveGlobalConfigFile(tmpPath, path); err != nil {
		_ = removeGlobalConfigFile(tmpPath)
		return fmt.Errorf("save global sandbox config: %w", err)
	}

	return nil
}

func saveGlobalConfigFile(tmpPath, path string) error {
	if err := renameGlobalConfigFile(tmpPath, path); err == nil {
		return nil
	} else if !isRenameNoReplaceError(err) {
		return err
	}

	backupPath := path + ".bak"
	if err := removeGlobalConfigFile(backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := renameGlobalConfigFile(path, backupPath); err != nil {
		return err
	}
	if err := renameGlobalConfigFile(tmpPath, path); err != nil {
		if restoreErr := renameGlobalConfigFile(backupPath, path); restoreErr != nil {
			return fmt.Errorf("%w (restore failed: %v)", err, restoreErr)
		}
		return err
	}

	_ = removeGlobalConfigFile(backupPath)
	return nil
}

func copyStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
