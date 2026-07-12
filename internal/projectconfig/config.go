// Package projectconfig loads typed command default settings from
// .hal/config.yaml without depending on command packages.
package projectconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Value carries a typed config value plus whether it was explicitly set in
// .hal/config.yaml.
type Value[T any] struct {
	Value T
	Set   bool
}

// Or returns the configured value when set, otherwise fallback.
func (v Value[T]) Or(fallback T) T {
	if v.Set {
		return v.Value
	}
	return fallback
}

// Config contains command default sections loaded from .hal/config.yaml.
type Config struct {
	Factory FactoryDefaults
	Sandbox SandboxDefaults
	Run     RunDefaults
	Auto    AutoDefaults
	CI      CIDefaults
}

// FactoryDefaults contains defaults shared by factory run/trigger/publish
// wiring.
type FactoryDefaults struct {
	Base           Value[string]
	Executor       Value[string]
	SandboxName    Value[string]
	SandboxHost    Value[string]
	SandboxRuntime Value[string]
	PublishFrom    Value[string]
	SecretEnv      Value[[]string]
}

// SandboxDefaults contains reusable sandbox execution defaults.
type SandboxDefaults struct {
	Name          Value[string]
	Host          Value[string]
	Runtime       Value[string]
	WorkspaceMode Value[string]
	SyncOut       Value[bool]
	Apply         Value[bool]
}

// RunDefaults contains hal run defaults.
type RunDefaults struct {
	Base     Value[string]
	Timeout  Value[time.Duration]
	Parallel Value[int]
}

// AutoDefaults contains hal auto defaults. It intentionally does not model
// compound.AutoConfig settings.
type AutoDefaults struct {
	Base     Value[string]
	Parallel Value[int]
}

// CIDefaults contains CI command defaults grouped by subcommand.
type CIDefaults struct {
	Status CIStatusDefaults
	Fix    CIFixDefaults
	Merge  CIMergeDefaults
}

// CIStatusDefaults contains hal ci status defaults.
type CIStatusDefaults struct {
	Wait          Value[bool]
	Timeout       Value[time.Duration]
	Poll          Value[time.Duration]
	NoChecksGrace Value[time.Duration]
}

// CIFixDefaults contains hal ci fix defaults.
type CIFixDefaults struct {
	MaxAttempts Value[int]
}

// CIMergeDefaults contains hal ci merge defaults.
type CIMergeDefaults struct {
	Strategy      Value[string]
	DeleteBranch  Value[bool]
	AllowNoChecks Value[bool]
}

type rawConfig struct {
	Factory rawFactorySection `yaml:"factory"`
	Sandbox rawSandboxSection `yaml:"sandbox"`
	Run     rawRunDefaults    `yaml:"run"`
	Auto    rawAutoDefaults   `yaml:"auto"`
	CI      rawCIDefaults     `yaml:"ci"`
}

type rawFactorySection struct {
	Defaults rawFactoryDefaults `yaml:"defaults"`
}

type rawFactoryDefaults struct {
	Base           *string  `yaml:"base"`
	Executor       *string  `yaml:"executor"`
	SandboxName    *string  `yaml:"sandboxName"`
	SandboxHost    *string  `yaml:"sandboxHost"`
	SandboxRuntime *string  `yaml:"sandboxRuntime"`
	PublishFrom    *string  `yaml:"publishFrom"`
	SecretEnv      []string `yaml:"secretEnv"`
}

type rawSandboxSection struct {
	Defaults rawSandboxDefaults `yaml:"defaults"`
}

type rawSandboxDefaults struct {
	Name          *string `yaml:"name"`
	Host          *string `yaml:"host"`
	Runtime       *string `yaml:"runtime"`
	WorkspaceMode *string `yaml:"workspaceMode"`
	SyncOut       *bool   `yaml:"syncOut"`
	Apply         *bool   `yaml:"apply"`
}

type rawRunDefaults struct {
	Base     *string `yaml:"base"`
	Timeout  *string `yaml:"timeout"`
	Parallel *int    `yaml:"parallel"`
}

type rawAutoDefaults struct {
	Base     *string `yaml:"base"`
	Parallel *int    `yaml:"parallel"`
}

type rawCIDefaults struct {
	Status rawCIStatusDefaults `yaml:"status"`
	Fix    rawCIFixDefaults    `yaml:"fix"`
	Merge  rawCIMergeDefaults  `yaml:"merge"`
}

type rawCIStatusDefaults struct {
	Wait          *bool   `yaml:"wait"`
	Timeout       *string `yaml:"timeout"`
	Poll          *string `yaml:"poll"`
	NoChecksGrace *string `yaml:"noChecksGrace"`
}

type rawCIFixDefaults struct {
	MaxAttempts *int `yaml:"maxAttempts"`
}

type rawCIMergeDefaults struct {
	Strategy      *string `yaml:"strategy"`
	DeleteBranch  *bool   `yaml:"deleteBranch"`
	AllowNoChecks *bool   `yaml:"allowNoChecks"`
}

// Load reads .hal/config.yaml under dir. Missing config returns an empty
// Config with no set markers.
func Load(dir string) (*Config, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read project config: %w", err)
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse project config: %w", err)
	}

	cfg, err := normalize(raw)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func normalize(raw rawConfig) (*Config, error) {
	var cfg Config

	var err error
	if cfg.Factory, err = normalizeFactoryDefaults(raw.Factory.Defaults); err != nil {
		return nil, err
	}
	if cfg.Sandbox, err = normalizeSandboxDefaults(raw.Sandbox.Defaults); err != nil {
		return nil, err
	}
	if cfg.Run, err = normalizeRunDefaults(raw.Run); err != nil {
		return nil, err
	}
	if cfg.Auto, err = normalizeAutoDefaults(raw.Auto); err != nil {
		return nil, err
	}
	if cfg.CI, err = normalizeCIDefaults(raw.CI); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func normalizeFactoryDefaults(raw rawFactoryDefaults) (FactoryDefaults, error) {
	var cfg FactoryDefaults
	cfg.Base = stringValue(raw.Base)
	cfg.SandboxName = stringValue(raw.SandboxName)
	cfg.SandboxHost = stringValue(raw.SandboxHost)
	cfg.SandboxRuntime = stringValue(raw.SandboxRuntime)

	if raw.Executor != nil {
		executor, err := factory.ValidateExecutorMode(*raw.Executor)
		if err != nil {
			return FactoryDefaults{}, fmt.Errorf("factory.defaults.executor: %w", err)
		}
		cfg.Executor = Value[string]{Value: executor, Set: true}
	}
	if raw.PublishFrom != nil {
		publishFrom, err := factory.ValidatePublishRunner(*raw.PublishFrom)
		if err != nil {
			return FactoryDefaults{}, fmt.Errorf("factory.defaults.publishFrom: %w", err)
		}
		cfg.PublishFrom = Value[string]{Value: publishFrom, Set: true}
	}
	if raw.SandboxRuntime != nil {
		runtime, err := normalizeSandboxRuntime("factory.defaults.sandboxRuntime", *raw.SandboxRuntime)
		if err != nil {
			return FactoryDefaults{}, err
		}
		cfg.SandboxRuntime = Value[string]{Value: runtime, Set: true}
	}
	if raw.SecretEnv != nil {
		secretEnv, err := normalizeSecretEnv(raw.SecretEnv)
		if err != nil {
			return FactoryDefaults{}, err
		}
		cfg.SecretEnv = Value[[]string]{Value: secretEnv, Set: true}
	}

	return cfg, nil
}

func normalizeSandboxDefaults(raw rawSandboxDefaults) (SandboxDefaults, error) {
	var cfg SandboxDefaults
	cfg.Name = stringValue(raw.Name)
	cfg.Host = stringValue(raw.Host)
	cfg.SyncOut = boolValue(raw.SyncOut)
	cfg.Apply = boolValue(raw.Apply)

	if raw.Runtime != nil {
		runtime, err := normalizeSandboxRuntime("sandbox.defaults.runtime", *raw.Runtime)
		if err != nil {
			return SandboxDefaults{}, err
		}
		cfg.Runtime = Value[string]{Value: runtime, Set: true}
	}
	if raw.WorkspaceMode != nil {
		mode, err := normalizeWorkspaceMode("sandbox.defaults.workspaceMode", *raw.WorkspaceMode)
		if err != nil {
			return SandboxDefaults{}, err
		}
		cfg.WorkspaceMode = Value[string]{Value: mode, Set: true}
	}

	return cfg, nil
}

func normalizeRunDefaults(raw rawRunDefaults) (RunDefaults, error) {
	var cfg RunDefaults
	cfg.Base = stringValue(raw.Base)
	if raw.Timeout != nil {
		timeout, err := parseDuration("run.timeout", *raw.Timeout)
		if err != nil {
			return RunDefaults{}, err
		}
		cfg.Timeout = Value[time.Duration]{Value: timeout, Set: true}
	}
	cfg.Parallel = intValue(raw.Parallel)
	return cfg, nil
}

func normalizeAutoDefaults(raw rawAutoDefaults) (AutoDefaults, error) {
	return AutoDefaults{
		Base:     stringValue(raw.Base),
		Parallel: intValue(raw.Parallel),
	}, nil
}

func normalizeCIDefaults(raw rawCIDefaults) (CIDefaults, error) {
	status, err := normalizeCIStatusDefaults(raw.Status)
	if err != nil {
		return CIDefaults{}, err
	}
	merge, err := normalizeCIMergeDefaults(raw.Merge)
	if err != nil {
		return CIDefaults{}, err
	}
	return CIDefaults{
		Status: status,
		Fix: CIFixDefaults{
			MaxAttempts: intValue(raw.Fix.MaxAttempts),
		},
		Merge: merge,
	}, nil
}

func normalizeCIStatusDefaults(raw rawCIStatusDefaults) (CIStatusDefaults, error) {
	var cfg CIStatusDefaults
	cfg.Wait = boolValue(raw.Wait)
	if raw.Timeout != nil {
		timeout, err := parseDuration("ci.status.timeout", *raw.Timeout)
		if err != nil {
			return CIStatusDefaults{}, err
		}
		cfg.Timeout = Value[time.Duration]{Value: timeout, Set: true}
	}
	if raw.Poll != nil {
		poll, err := parseDuration("ci.status.poll", *raw.Poll)
		if err != nil {
			return CIStatusDefaults{}, err
		}
		cfg.Poll = Value[time.Duration]{Value: poll, Set: true}
	}
	if raw.NoChecksGrace != nil {
		grace, err := parseDuration("ci.status.noChecksGrace", *raw.NoChecksGrace)
		if err != nil {
			return CIStatusDefaults{}, err
		}
		cfg.NoChecksGrace = Value[time.Duration]{Value: grace, Set: true}
	}
	return cfg, nil
}

func normalizeCIMergeDefaults(raw rawCIMergeDefaults) (CIMergeDefaults, error) {
	var cfg CIMergeDefaults
	cfg.DeleteBranch = boolValue(raw.DeleteBranch)
	cfg.AllowNoChecks = boolValue(raw.AllowNoChecks)
	if raw.Strategy != nil {
		strategy, err := ci.NormalizeMergeStrategy(*raw.Strategy)
		if err != nil {
			return CIMergeDefaults{}, fmt.Errorf("ci.merge.strategy: %w", err)
		}
		cfg.Strategy = Value[string]{Value: strategy, Set: true}
	}
	return cfg, nil
}

func normalizeSandboxRuntime(field, value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case sandbox.SandboxRuntimeDriverSSHMachine, sandbox.SandboxRuntimeDriverRootlessPodman, sandbox.SandboxRuntimeDriverMicroVM:
		return normalized, nil
	default:
		return "", fmt.Errorf("%s must be one of %s, %s, %s", field, sandbox.SandboxRuntimeDriverSSHMachine, sandbox.SandboxRuntimeDriverRootlessPodman, sandbox.SandboxRuntimeDriverMicroVM)
	}
}

func normalizeWorkspaceMode(field, value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case sandbox.SandboxWorkspaceModeClone:
		return normalized, nil
	case sandbox.SandboxWorkspaceModeCopy:
		return "", fmt.Errorf("%s copy is not currently supported for hal run/auto; use clone", field)
	case sandbox.SandboxWorkspaceModeDirect:
		return "", fmt.Errorf("%s direct is not supported in project config", field)
	default:
		return "", fmt.Errorf("%s must be %s", field, sandbox.SandboxWorkspaceModeClone)
	}
}

func normalizeSecretEnv(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	for i, value := range values {
		name := strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("factory.defaults.secretEnv[%d] must not be empty", i)
		}
		if !envNamePattern.MatchString(name) {
			return nil, fmt.Errorf("factory.defaults.secretEnv[%d] must be an environment variable name", i)
		}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func parseDuration(field, value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("%s must not be empty", field)
	}
	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration", field)
	}
	if duration < 0 {
		return 0, fmt.Errorf("%s must not be negative", field)
	}
	return duration, nil
}

func stringValue(value *string) Value[string] {
	if value == nil {
		return Value[string]{}
	}
	return Value[string]{Value: *value, Set: true}
}

func boolValue(value *bool) Value[bool] {
	if value == nil {
		return Value[bool]{}
	}
	return Value[bool]{Value: *value, Set: true}
}

func intValue(value *int) Value[int] {
	if value == nil {
		return Value[int]{}
	}
	return Value[int]{Value: *value, Set: true}
}
