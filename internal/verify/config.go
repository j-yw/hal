package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

// DefaultTimeoutSeconds is used when a shell check omits timeoutSeconds.
const DefaultTimeoutSeconds = 300

// Config contains project verification checks from .hal/config.yaml.
type Config struct {
	ProjectRoot string       `yaml:"-"`
	Checks      []ShellCheck `yaml:"checks"`
}

// ShellCheck contains one configured shell verification check.
type ShellCheck struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	Command        string `yaml:"command"`
	WorkDir        string `yaml:"workDir"`
	TimeoutSeconds int    `yaml:"timeoutSeconds"`
	Required       bool   `yaml:"required"`
}

type rawRootConfig struct {
	Verify rawConfig `yaml:"verify"`
}

type rawConfig struct {
	Checks []rawShellCheck `yaml:"checks"`
}

type rawShellCheck struct {
	ID             *string `yaml:"id"`
	Name           *string `yaml:"name"`
	Command        *string `yaml:"command"`
	WorkDir        *string `yaml:"workDir"`
	TimeoutSeconds *int    `yaml:"timeoutSeconds"`
	Required       *bool   `yaml:"required"`
}

// DefaultConfig returns the default verification configuration.
func DefaultConfig() Config {
	return Config{
		Checks: []ShellCheck{},
	}
}

// LoadConfig reads the verify section from .hal/config.yaml in the given project directory.
func LoadConfig(dir string) (*Config, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)
	projectRoot, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			cfg.ProjectRoot = projectRoot
			return &cfg, nil
		}
		return nil, err
	}

	var raw rawRootConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	cfg.ProjectRoot = projectRoot
	cfg.Checks = make([]ShellCheck, 0, len(raw.Verify.Checks))
	for i, rawCheck := range raw.Verify.Checks {
		check, err := normalizeShellCheck(rawCheck, projectRoot)
		if err != nil {
			return nil, fmt.Errorf("verify.checks[%d].%w", i, err)
		}
		cfg.Checks = append(cfg.Checks, check)
	}

	return &cfg, nil
}

func normalizeShellCheck(raw rawShellCheck, projectRoot string) (ShellCheck, error) {
	check := ShellCheck{
		TimeoutSeconds: DefaultTimeoutSeconds,
		Required:       true,
		WorkDir:        projectRoot,
	}

	if raw.ID != nil {
		check.ID = strings.TrimSpace(*raw.ID)
	}
	if raw.Name != nil {
		check.Name = strings.TrimSpace(*raw.Name)
	}
	if raw.Command != nil {
		check.Command = strings.TrimSpace(*raw.Command)
	}
	if raw.TimeoutSeconds != nil {
		check.TimeoutSeconds = *raw.TimeoutSeconds
	}
	if raw.Required != nil {
		check.Required = *raw.Required
	}
	if raw.WorkDir != nil {
		workDir := strings.TrimSpace(*raw.WorkDir)
		if workDir != "" {
			if filepath.IsAbs(workDir) {
				check.WorkDir = filepath.Clean(workDir)
			} else {
				check.WorkDir = filepath.Clean(filepath.Join(projectRoot, workDir))
			}
		}
	}

	if check.ID == "" {
		return ShellCheck{}, fmt.Errorf("id must not be empty")
	}
	if check.Name == "" {
		return ShellCheck{}, fmt.Errorf("name must not be empty")
	}
	if check.Command == "" {
		return ShellCheck{}, fmt.Errorf("command must not be empty")
	}
	if check.TimeoutSeconds <= 0 {
		return ShellCheck{}, fmt.Errorf("timeoutSeconds must be greater than 0")
	}

	return check, nil
}
