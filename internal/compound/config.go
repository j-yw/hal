package compound

import (
	"fmt"
	"os"
	"path/filepath"

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

// RawEngineConfig holds per-engine settings from YAML.
// Pointer fields distinguish "not set" (nil) from "set to empty string".
type RawEngineConfig struct {
	Model    *string `yaml:"model"`
	Provider *string `yaml:"provider"`
}

// Config represents the full .hal/config.yaml structure.
type Config struct {
	Engine        string                      `yaml:"engine"`
	MaxIterations int                         `yaml:"maxIterations"`
	RetryDelay    string                      `yaml:"retryDelay"`
	MaxRetries    int                         `yaml:"maxRetries"`
	Engines       map[string]*RawEngineConfig `yaml:"engines"`
	Auto          rawAutoConfig               `yaml:"auto"`
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
	configPath := filepath.Join(dir, template.HalDir, "config.yaml")

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

// LoadEngineConfig reads per-engine configuration from .hal/config.yaml.
// Returns nil if no engine-specific config is set (engine uses its own defaults).
func LoadEngineConfig(dir, engineName string) *engine.EngineConfig {
	configPath := filepath.Join(dir, template.HalDir, "config.yaml")

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

	// Return nil if nothing was actually configured
	if cfg.Model == "" && cfg.Provider == "" {
		return nil
	}

	return cfg
}
