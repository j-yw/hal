// Package config provides the .hal/cloud.yaml profile schema, loading, and
// validation for non-secret cloud configuration.
//
// resolve.go implements the shared cloud precedence resolver that composes
// runtime config from multiple sources with deterministic precedence:
//
//	CLI flags > process env > .env (non-overriding) > .hal/cloud.yaml > inferred defaults > hard defaults
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// Environment variable names for cloud configuration.
const (
	EnvCloudMode        = "HAL_CLOUD_MODE"
	EnvCloudEndpoint    = "HAL_CLOUD_ENDPOINT"
	EnvCloudRepo        = "HAL_CLOUD_REPO"
	EnvCloudBase        = "HAL_CLOUD_BASE"
	EnvCloudEngine      = "HAL_CLOUD_ENGINE"
	EnvCloudAuthProfile = "HAL_CLOUD_AUTH_PROFILE"
	EnvCloudScope       = "HAL_CLOUD_SCOPE"
	EnvCloudWait        = "HAL_CLOUD_WAIT"
	EnvCloudPullPolicy  = "HAL_CLOUD_PULL_POLICY"
)

// Hard defaults when no other source provides a value.
var hardDefaults = &Profile{
	Mode:       ModeUntilComplete,
	Engine:     "claude",
	Base:       "main",
	PullPolicy: PullPolicyAll,
}

// ResolveInput supplies values from each precedence tier to the resolver.
type ResolveInput struct {
	// CLIFlags holds explicit CLI flag values. Empty strings mean "not set".
	CLIFlags *CLIFlags

	// ProfileName selects which cloud.yaml profile to use (empty = default).
	ProfileName string

	// HalDir is the .hal directory path for loading cloud.yaml.
	// If empty, cloud.yaml loading is skipped.
	HalDir string

	// WorkflowKind is the command being run (run, auto, review).
	WorkflowKind string

	// CloudEnabled indicates whether --cloud was set. When false, the resolver
	// returns cloudEnabled=false with existing local defaults preserved.
	CloudEnabled bool

	// Getenv is the function used to read process environment variables.
	// If nil, os.Getenv is used.
	Getenv func(string) string

	// DotenvPath is the path to a .env file. If empty, ".env" in the current
	// directory is used. Set to a non-existent path to skip .env loading.
	DotenvPath string

	// InferredDefaults holds values inferred from project context (e.g., git
	// remote for repo, current branch for base). Empty strings mean "not inferred".
	InferredDefaults *InferredDefaults
}

// CLIFlags holds explicit CLI flag values. Empty strings mean "not set".
type CLIFlags struct {
	Mode        string
	Endpoint    string
	Repo        string
	Base        string
	Engine      string
	AuthProfile string
	Scope       string
	Wait        *bool // nil = not set
	PullPolicy  string
}

// InferredDefaults holds values inferred from project context.
type InferredDefaults struct {
	Repo string
	Base string
}

// ResolvedConfig is the output of the resolver — a fully resolved runtime
// configuration. The same shape is returned for run, auto, and review inputs.
type ResolvedConfig struct {
	// CloudEnabled indicates whether cloud execution is active.
	CloudEnabled bool `json:"cloudEnabled"`

	// WorkflowKind is the command being run (run, auto, review).
	WorkflowKind string `json:"workflowKind"`

	// Profile fields (fully resolved).
	Mode        string `json:"mode"`
	Endpoint    string `json:"endpoint"`
	Repo        string `json:"repo"`
	Base        string `json:"base"`
	Engine      string `json:"engine"`
	AuthProfile string `json:"authProfile"`
	Scope       string `json:"scope"`
	Wait        bool   `json:"wait"`
	PullPolicy  string `json:"pullPolicy"`
}

// Resolve composes a ResolvedConfig from multiple sources with deterministic
// precedence: CLI > process env > .env (non-overriding) > cloud.yaml > inferred > hard defaults.
//
// When input.CloudEnabled is false, the resolver returns cloudEnabled=false
// and preserves existing local defaults for run/auto/review without loading
// cloud config or environment tiers.
func Resolve(input ResolveInput) (*ResolvedConfig, error) {
	rc := &ResolvedConfig{
		CloudEnabled: input.CloudEnabled,
		WorkflowKind: input.WorkflowKind,
	}

	// When cloud is disabled, return hard defaults only (local mode).
	if !input.CloudEnabled {
		rc.Mode = hardDefaults.Mode
		rc.Engine = hardDefaults.Engine
		rc.Base = hardDefaults.Base
		rc.PullPolicy = hardDefaults.PullPolicy
		rc.Wait = true // local default: wait for completion
		return rc, nil
	}

	getenv := input.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	// Load .env (non-overriding: only sets vars not already in process env).
	loadDotenv(input.DotenvPath)

	// Load cloud.yaml profile.
	var yamlProfile *Profile
	if input.HalDir != "" {
		configPath := filepath.Join(input.HalDir, CloudConfigFile)
		cfg, err := Load(configPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if cfg != nil {
			yamlProfile = cfg.GetProfile(input.ProfileName)
		}
	}

	// Build tiers in precedence order and merge.
	rc.Mode = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Mode }),
		getenv(EnvCloudMode),
		profileVal(yamlProfile, func(p *Profile) string { return p.Mode }),
		"", // no inferred default for mode
		hardDefaults.Mode,
	)

	rc.Endpoint = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Endpoint }),
		getenv(EnvCloudEndpoint),
		profileVal(yamlProfile, func(p *Profile) string { return p.Endpoint }),
		"",
		"",
	)

	rc.Repo = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Repo }),
		getenv(EnvCloudRepo),
		profileVal(yamlProfile, func(p *Profile) string { return p.Repo }),
		inferVal(input.InferredDefaults, func(d *InferredDefaults) string { return d.Repo }),
		"",
	)

	rc.Base = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Base }),
		getenv(EnvCloudBase),
		profileVal(yamlProfile, func(p *Profile) string { return p.Base }),
		inferVal(input.InferredDefaults, func(d *InferredDefaults) string { return d.Base }),
		hardDefaults.Base,
	)

	rc.Engine = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Engine }),
		getenv(EnvCloudEngine),
		profileVal(yamlProfile, func(p *Profile) string { return p.Engine }),
		"",
		hardDefaults.Engine,
	)

	rc.AuthProfile = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.AuthProfile }),
		getenv(EnvCloudAuthProfile),
		profileVal(yamlProfile, func(p *Profile) string { return p.AuthProfile }),
		"",
		"",
	)

	rc.Scope = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.Scope }),
		getenv(EnvCloudScope),
		profileVal(yamlProfile, func(p *Profile) string { return p.Scope }),
		"",
		"",
	)

	rc.PullPolicy = resolveString(
		cliVal(input.CLIFlags, func(f *CLIFlags) string { return f.PullPolicy }),
		getenv(EnvCloudPullPolicy),
		profileVal(yamlProfile, func(p *Profile) string { return p.PullPolicy }),
		"",
		hardDefaults.PullPolicy,
	)

	// Wait has special handling: *bool at CLI and YAML levels, string at env level.
	rc.Wait = resolveWait(input.CLIFlags, getenv, yamlProfile)

	return rc, nil
}

// resolveString returns the first non-empty value from the precedence tiers.
func resolveString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveWait resolves the wait flag with *bool support.
// Precedence: CLI > env > cloud.yaml > hard default (true).
func resolveWait(cli *CLIFlags, getenv func(string) string, yaml *Profile) bool {
	// CLI flag (highest priority).
	if cli != nil && cli.Wait != nil {
		return *cli.Wait
	}

	// Process environment.
	if v := getenv(EnvCloudWait); v != "" {
		return parseBool(v)
	}

	// cloud.yaml profile.
	if yaml != nil && yaml.Wait != nil {
		return *yaml.Wait
	}

	// Hard default: wait for completion.
	return true
}

// parseBool parses a string into a boolean. Accepts "true", "1", "yes" as true.
func parseBool(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return lower == "true" || lower == "1" || lower == "yes"
}

// cliVal extracts a string value from CLIFlags, returning empty if nil.
func cliVal(flags *CLIFlags, getter func(*CLIFlags) string) string {
	if flags == nil {
		return ""
	}
	return getter(flags)
}

// profileVal extracts a string value from a Profile, returning empty if nil.
func profileVal(p *Profile, getter func(*Profile) string) string {
	if p == nil {
		return ""
	}
	return getter(p)
}

// inferVal extracts a string value from InferredDefaults, returning empty if nil.
func inferVal(d *InferredDefaults, getter func(*InferredDefaults) string) string {
	if d == nil {
		return ""
	}
	return getter(d)
}

// loadDotenv loads a .env file non-overriding (does not overwrite existing env vars).
// Errors are silently ignored (missing .env is expected).
func loadDotenv(path string) {
	if path == "" {
		path = ".env"
	}
	// godotenv.Load does NOT override existing env vars.
	_ = godotenv.Load(path)
}
