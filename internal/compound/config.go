package compound

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

// AutoConfig contains configuration for the compound auto pipeline.
type AutoConfig struct {
	ReportsDir    string   `yaml:"reportsDir"`
	BranchPrefix  string   `yaml:"branchPrefix"`
	QualityChecks []string `yaml:"qualityChecks"`
	MaxIterations int      `yaml:"maxIterations"`
}

// rawAutoConfig is used for YAML unmarshaling to distinguish missing keys from explicit empty values.
type rawAutoConfig struct {
	ReportsDir    *string  `yaml:"reportsDir"`
	BranchPrefix  *string  `yaml:"branchPrefix"`
	QualityChecks []string `yaml:"qualityChecks"`
	MaxIterations *int     `yaml:"maxIterations"`
}

// DaytonaConfig contains configuration for Daytona sandbox integration.
type DaytonaConfig struct {
	APIKey    string `yaml:"apiKey"`
	ServerURL string `yaml:"serverURL"`
}

// HetznerConfig contains Hetzner-specific sandbox settings.
type HetznerConfig struct {
	SSHKey     string `yaml:"sshKey"`
	ServerType string `yaml:"serverType"`
	Image      string `yaml:"image"`
}

// DigitalOceanConfig contains DigitalOcean-specific sandbox settings.
type DigitalOceanConfig struct {
	SSHKey string `yaml:"sshKey"`
	Size   string `yaml:"size"`
}

// SandboxConfig contains sandbox configuration including provider selection and env vars.
type SandboxConfig struct {
	Provider     string             `yaml:"provider"`
	Env          map[string]string  `yaml:"env"`
	Hetzner      HetznerConfig      `yaml:"hetzner"`
	DigitalOcean DigitalOceanConfig `yaml:"digitalocean"`
}

// rawDaytonaConfig is used for YAML unmarshaling to distinguish missing keys from explicit values.
type rawDaytonaConfig struct {
	APIKey    *string `yaml:"apiKey"`
	ServerURL *string `yaml:"serverURL"`
}

// RawEngineConfig holds per-engine settings from YAML.
// Pointer fields distinguish "not set" (nil) from "set to empty string".
type RawEngineConfig struct {
	Model    *string `yaml:"model"`
	Provider *string `yaml:"provider"`
	Timeout  *string `yaml:"timeout"`
}

// Config represents the full .hal/config.yaml structure.
type Config struct {
	Engine        string                      `yaml:"engine"`
	MaxIterations int                         `yaml:"maxIterations"`
	RetryDelay    string                      `yaml:"retryDelay"`
	MaxRetries    int                         `yaml:"maxRetries"`
	Engines       map[string]*RawEngineConfig `yaml:"engines"`
	Auto          rawAutoConfig               `yaml:"auto"`
	Daytona       rawDaytonaConfig            `yaml:"daytona"`
}

// DefaultAutoConfig returns sensible defaults for auto configuration.
func DefaultAutoConfig() AutoConfig {
	return AutoConfig{
		ReportsDir:    ".hal/reports",
		BranchPrefix:  "compound/",
		QualityChecks: []string{},
		MaxIterations: 25,
	}
}

// Validate checks that the AutoConfig fields are valid.
func (c *AutoConfig) Validate() error {
	if c.ReportsDir == "" {
		return fmt.Errorf("auto.reportsDir must not be empty")
	}
	if c.BranchPrefix == "" {
		return fmt.Errorf("auto.branchPrefix must not be empty")
	}
	if c.MaxIterations <= 0 {
		return fmt.Errorf("auto.maxIterations must be greater than 0")
	}
	return nil
}

// LoadConfig reads configuration from .hal/config.yaml in the given directory.
// If the config file doesn't exist or the auto section is missing, sensible defaults are returned.
func LoadConfig(dir string) (*AutoConfig, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	// Check if config file exists
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults when config doesn't exist
			config := DefaultAutoConfig()
			return &config, nil
		}
		return nil, err
	}

	// Parse the config file
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Merge with defaults: only apply default when key was not set in YAML
	autoConfig := DefaultAutoConfig()

	if config.Auto.ReportsDir != nil {
		autoConfig.ReportsDir = *config.Auto.ReportsDir
	}
	if config.Auto.BranchPrefix != nil {
		autoConfig.BranchPrefix = *config.Auto.BranchPrefix
	}
	if len(config.Auto.QualityChecks) > 0 {
		autoConfig.QualityChecks = config.Auto.QualityChecks
	}
	if config.Auto.MaxIterations != nil {
		autoConfig.MaxIterations = *config.Auto.MaxIterations
	}

	if err := autoConfig.Validate(); err != nil {
		return nil, err
	}

	return &autoConfig, nil
}

// LoadDefaultEngine reads the top-level engine setting from .hal/config.yaml.
// If the config file does not exist or engine is empty, codex is returned.
func LoadDefaultEngine(dir string) (string, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "codex", nil
		}
		return "", err
	}

	var raw struct {
		Engine string `yaml:"engine"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", err
	}

	engineName := strings.ToLower(strings.TrimSpace(raw.Engine))
	if engineName == "" {
		return "codex", nil
	}

	return engineName, nil
}

// LoadEngineConfig reads per-engine configuration from .hal/config.yaml.
// Returns nil if no engine-specific config is set (engine uses its own defaults).
func LoadEngineConfig(dir, engineName string) *engine.EngineConfig {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil
	}

	if config.Engines == nil {
		return nil
	}

	raw, ok := config.Engines[engineName]
	if !ok || raw == nil {
		return nil
	}

	cfg := &engine.EngineConfig{}
	if raw.Model != nil {
		cfg.Model = *raw.Model
	}
	if raw.Provider != nil {
		cfg.Provider = *raw.Provider
	}
	if raw.Timeout != nil {
		d, err := time.ParseDuration(*raw.Timeout)
		if err == nil && d > 0 {
			cfg.Timeout = d
		}
	}

	// Return nil if nothing was actually configured
	if cfg.Model == "" && cfg.Provider == "" && cfg.Timeout == 0 {
		return nil
	}

	return cfg
}

// DefaultDaytonaConfig returns zero-value defaults for Daytona configuration.
// Both fields default to empty; the SDK uses its own default server URL when empty.
func DefaultDaytonaConfig() DaytonaConfig {
	return DaytonaConfig{}
}

// LoadDaytonaConfig reads the daytona: section from .hal/config.yaml.
// If the file or section is missing, zero-value defaults are returned (no error).
func LoadDaytonaConfig(dir string) (*DaytonaConfig, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultDaytonaConfig()
			return &cfg, nil
		}
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	cfg := DefaultDaytonaConfig()
	if config.Daytona.APIKey != nil {
		cfg.APIKey = *config.Daytona.APIKey
	}
	if config.Daytona.ServerURL != nil {
		cfg.ServerURL = *config.Daytona.ServerURL
	}

	return &cfg, nil
}

// LoadSandboxConfig reads the sandbox: section from .hal/config.yaml.
// If the file or section is missing, a config with Provider defaulting to "daytona" is returned.
func LoadSandboxConfig(dir string) (*SandboxConfig, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &SandboxConfig{Provider: "daytona", Env: map[string]string{}}, nil
		}
		return nil, err
	}

	var raw struct {
		Sandbox struct {
			Provider     *string           `yaml:"provider"`
			Env          map[string]string `yaml:"env"`
			Hetzner      struct {
				SSHKey     *string `yaml:"sshKey"`
				ServerType *string `yaml:"serverType"`
				Image      *string `yaml:"image"`
			} `yaml:"hetzner"`
			DigitalOcean struct {
				SSHKey *string `yaml:"sshKey"`
				Size   *string `yaml:"size"`
			} `yaml:"digitalocean"`
		} `yaml:"sandbox"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if raw.Sandbox.Env == nil {
		raw.Sandbox.Env = map[string]string{}
	}

	cfg := &SandboxConfig{
		Provider: "daytona",
		Env:      raw.Sandbox.Env,
	}

	if raw.Sandbox.Provider != nil && *raw.Sandbox.Provider != "" {
		cfg.Provider = *raw.Sandbox.Provider
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

	return cfg, nil
}

// SaveSandboxConfig merges the given SandboxConfig into .hal/config.yaml without
// clobbering other sections. It preserves existing sandbox.env keys not in the
// new config and round-trips provider and hetzner fields.
func SaveSandboxConfig(dir string, sandbox *SandboxConfig) error {
	halDir := filepath.Join(dir, template.HalDir)
	configPath := filepath.Join(halDir, template.ConfigFile)

	if err := os.MkdirAll(halDir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	existing := make(map[string]interface{})
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading config: %w", err)
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("parsing config: %w", err)
		}
	}

	// Build env map — merge with existing
	envMap := make(map[string]interface{})
	if existingSandbox, ok := existing["sandbox"].(map[string]interface{}); ok {
		if existingEnv, ok := existingSandbox["env"].(map[string]interface{}); ok {
			for k, v := range existingEnv {
				envMap[k] = v
			}
		}
	}
	for k, v := range sandbox.Env {
		envMap[k] = v
	}

	sandboxMap := map[string]interface{}{
		"provider": sandbox.Provider,
		"env":      envMap,
	}

	// Only write hetzner section if any field is set
	if sandbox.Hetzner.SSHKey != "" || sandbox.Hetzner.ServerType != "" || sandbox.Hetzner.Image != "" {
		hetznerMap := map[string]interface{}{}
		if sandbox.Hetzner.SSHKey != "" {
			hetznerMap["sshKey"] = sandbox.Hetzner.SSHKey
		}
		if sandbox.Hetzner.ServerType != "" {
			hetznerMap["serverType"] = sandbox.Hetzner.ServerType
		}
		if sandbox.Hetzner.Image != "" {
			hetznerMap["image"] = sandbox.Hetzner.Image
		}
		sandboxMap["hetzner"] = hetznerMap
	}

	// Only write digitalocean section if any field is set
	if sandbox.DigitalOcean.SSHKey != "" || sandbox.DigitalOcean.Size != "" {
		doMap := map[string]interface{}{}
		if sandbox.DigitalOcean.SSHKey != "" {
			doMap["sshKey"] = sandbox.DigitalOcean.SSHKey
		}
		if sandbox.DigitalOcean.Size != "" {
			doMap["size"] = sandbox.DigitalOcean.Size
		}
		sandboxMap["digitalocean"] = doMap
	}

	existing["sandbox"] = sandboxMap

	out, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, out, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		return fmt.Errorf("setting config permissions: %w", err)
	}

	return nil
}

// SaveConfig merges the given DaytonaConfig into .hal/config.yaml without clobbering
// other sections. It reads the existing file, updates only the daytona: section, and
// writes back the result.
func SaveConfig(dir string, daytona *DaytonaConfig) error {
	halDir := filepath.Join(dir, template.HalDir)
	configPath := filepath.Join(halDir, template.ConfigFile)

	// Ensure .hal directory exists
	if err := os.MkdirAll(halDir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Read existing config as a generic map to preserve all sections
	existing := make(map[string]interface{})
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading config: %w", err)
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("parsing config: %w", err)
		}
	}

	// Update only the daytona section
	existing["daytona"] = map[string]interface{}{
		"apiKey":    daytona.APIKey,
		"serverURL": daytona.ServerURL,
	}

	out, err := yaml.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, out, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	// Ensure existing files are tightened as well (WriteFile does not change mode
	// when truncating an existing file).
	if err := os.Chmod(configPath, 0600); err != nil {
		return fmt.Errorf("setting config permissions: %w", err)
	}

	return nil
}
