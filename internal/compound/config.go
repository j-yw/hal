package compound

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AutoConfig contains configuration for the compound auto pipeline.
type AutoConfig struct {
	ReportsDir    string   `yaml:"reportsDir"`
	BranchPrefix  string   `yaml:"branchPrefix"`
	QualityChecks []string `yaml:"qualityChecks"`
	MaxIterations int      `yaml:"maxIterations"`
}

// Config represents the full .hal/config.yaml structure.
type Config struct {
	Engine        string     `yaml:"engine"`
	MaxIterations int        `yaml:"maxIterations"`
	RetryDelay    string     `yaml:"retryDelay"`
	MaxRetries    int        `yaml:"maxRetries"`
	Auto          AutoConfig `yaml:"auto"`
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

// LoadConfig reads configuration from .hal/config.yaml in the given directory.
// If the config file doesn't exist or the auto section is missing, sensible defaults are returned.
func LoadConfig(dir string) (*AutoConfig, error) {
	configPath := filepath.Join(dir, ".hal", "config.yaml")

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

	// Merge with defaults for any missing fields
	autoConfig := DefaultAutoConfig()

	if config.Auto.ReportsDir != "" {
		autoConfig.ReportsDir = config.Auto.ReportsDir
	}
	if config.Auto.BranchPrefix != "" {
		autoConfig.BranchPrefix = config.Auto.BranchPrefix
	}
	if len(config.Auto.QualityChecks) > 0 {
		autoConfig.QualityChecks = config.Auto.QualityChecks
	}
	if config.Auto.MaxIterations > 0 {
		autoConfig.MaxIterations = config.Auto.MaxIterations
	}

	return &autoConfig, nil
}
