package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

// Migrate moves legacy project sandbox config from .hal/config.yaml to the
// global sandbox config location when needed.
//
// Rules:
//   - If global sandbox-config.yaml already exists, migration is a no-op.
//   - If project .hal/config.yaml is missing, migration is a no-op.
//   - If project config has sandbox/daytona sections and global config is
//     missing, those sections are copied into global sandbox-config.yaml.
func Migrate(projectDir string) error {
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

	return nil
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
