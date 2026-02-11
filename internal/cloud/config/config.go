// Package config provides the .hal/cloud.yaml profile schema, loading, and
// validation for non-secret cloud configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CloudConfigFile is the filename for cloud configuration.
const CloudConfigFile = "cloud.yaml"

// Valid execution modes.
const (
	ModeUntilComplete = "until_complete"
	ModeBoundedBatch  = "bounded_batch"
)

// Valid pull policies.
const (
	PullPolicyState   = "state"
	PullPolicyReports = "reports"
	PullPolicyAll     = "all"
)

// validModes is the set of accepted mode values.
var validModes = map[string]bool{
	ModeUntilComplete: true,
	ModeBoundedBatch:  true,
}

// validPullPolicies is the set of accepted pull-policy values.
var validPullPolicies = map[string]bool{
	PullPolicyState:   true,
	PullPolicyReports: true,
	PullPolicyAll:     true,
}

// secretFieldNames lists YAML keys that must never appear in cloud.yaml.
var secretFieldNames = []string{
	"token",
	"password",
	"secret",
	"api_key",
	"apiKey",
	"api-key",
	"credentials",
	"private_key",
	"privateKey",
	"private-key",
	"dsn",
}

// Profile holds non-secret defaults for a cloud configuration profile.
type Profile struct {
	// Mode is the execution mode (until_complete or bounded_batch).
	Mode string `yaml:"mode,omitempty"`
	// Endpoint is the cloud orchestration API endpoint URL.
	Endpoint string `yaml:"endpoint,omitempty"`
	// Repo is the repository (owner/repo) for cloud runs.
	Repo string `yaml:"repo,omitempty"`
	// Base is the base branch name for cloud runs.
	Base string `yaml:"base,omitempty"`
	// Engine is the engine to use (e.g., claude, codex, pi).
	Engine string `yaml:"engine,omitempty"`
	// AuthProfile is the auth profile ID for cloud runs.
	AuthProfile string `yaml:"authProfile,omitempty"`
	// Scope is the scope reference (e.g., PRD ID).
	Scope string `yaml:"scope,omitempty"`
	// Wait indicates whether to wait for run completion.
	Wait *bool `yaml:"wait,omitempty"`
	// PullPolicy controls which artifacts to pull after completion.
	PullPolicy string `yaml:"pullPolicy,omitempty"`
}

// rawCloudConfig is the raw YAML unmarshaling target. It uses a map for
// profiles and captures unknown keys for secret detection.
type rawCloudConfig struct {
	DefaultProfile string              `yaml:"defaultProfile"`
	Profiles       map[string]*Profile `yaml:"profiles"`
}

// CloudConfig holds the validated cloud configuration.
type CloudConfig struct {
	// DefaultProfile is the name of the default profile.
	DefaultProfile string
	// Profiles maps profile names to their configuration.
	Profiles map[string]*Profile
}

// ValidationError represents a single schema validation failure with
// field path, rule, and remediation message.
type ValidationError struct {
	Field       string // Dot-separated field path (e.g., "profiles.default.mode")
	Rule        string // Short rule name (e.g., "invalid_value", "secret_field")
	Remediation string // Actionable fix message
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s — %s", e.Field, e.Rule, e.Remediation)
}

// ValidationErrors collects multiple validation failures.
type ValidationErrors []*ValidationError

// Error implements the error interface.
func (errs ValidationErrors) Error() string {
	if len(errs) == 0 {
		return "no validation errors"
	}
	var b strings.Builder
	for i, e := range errs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(e.Error())
	}
	return b.String()
}

// Load reads and validates a cloud.yaml file from the given path.
func Load(path string) (*CloudConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse unmarshals YAML bytes into a validated CloudConfig.
func Parse(data []byte) (*CloudConfig, error) {
	// First pass: check for secret-bearing keys in the raw YAML.
	if errs := detectSecrets(data); len(errs) > 0 {
		return nil, errs
	}

	var raw rawCloudConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse cloud.yaml: %w", err)
	}

	cfg := &CloudConfig{
		DefaultProfile: raw.DefaultProfile,
		Profiles:       raw.Profiles,
	}

	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*Profile)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, errs
	}

	return cfg, nil
}

// Validate checks the CloudConfig for schema violations. Returns a
// ValidationErrors slice (nil if valid).
func (c *CloudConfig) Validate() ValidationErrors {
	var errs ValidationErrors

	// defaultProfile must reference an existing profile if set.
	if c.DefaultProfile != "" && len(c.Profiles) > 0 {
		if _, ok := c.Profiles[c.DefaultProfile]; !ok {
			errs = append(errs, &ValidationError{
				Field:       "defaultProfile",
				Rule:        "unknown_profile",
				Remediation: fmt.Sprintf("defaultProfile %q does not match any profile in profiles; add the profile or change defaultProfile", c.DefaultProfile),
			})
		}
	}

	// Validate each profile.
	for name, p := range c.Profiles {
		prefix := fmt.Sprintf("profiles.%s", name)
		errs = append(errs, validateProfile(prefix, p)...)
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// GetProfile returns the profile for the given name, or the default profile
// if name is empty. Returns nil if not found.
func (c *CloudConfig) GetProfile(name string) *Profile {
	if name == "" {
		name = c.DefaultProfile
	}
	if name == "" {
		return nil
	}
	return c.Profiles[name]
}

// validateProfile checks individual profile fields.
func validateProfile(prefix string, p *Profile) ValidationErrors {
	var errs ValidationErrors

	if p.Mode != "" && !validModes[p.Mode] {
		errs = append(errs, &ValidationError{
			Field:       prefix + ".mode",
			Rule:        "invalid_value",
			Remediation: fmt.Sprintf("mode must be one of: %s; got %q", joinKeys(validModes), p.Mode),
		})
	}

	if p.Endpoint != "" {
		if u, err := url.Parse(p.Endpoint); err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, &ValidationError{
				Field:       prefix + ".endpoint",
				Rule:        "invalid_url",
				Remediation: fmt.Sprintf("endpoint must be a valid URL with scheme and host; got %q", p.Endpoint),
			})
		} else if containsSecretQuery(u) {
			errs = append(errs, &ValidationError{
				Field:       prefix + ".endpoint",
				Rule:        "secret_in_url",
				Remediation: "endpoint URL must not contain secret-bearing query parameters (authToken, token, password, secret); use environment variables for secrets",
			})
		}
	}

	if p.PullPolicy != "" && !validPullPolicies[p.PullPolicy] {
		errs = append(errs, &ValidationError{
			Field:       prefix + ".pullPolicy",
			Rule:        "invalid_value",
			Remediation: fmt.Sprintf("pullPolicy must be one of: %s; got %q", joinKeys(validPullPolicies), p.PullPolicy),
		})
	}

	return errs
}

// detectSecrets inspects raw YAML for secret-bearing top-level or nested keys.
func detectSecrets(data []byte) ValidationErrors {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil // parse errors handled later
	}
	var errs ValidationErrors
	walkSecrets("", raw, &errs)
	return errs
}

// walkSecrets recursively checks map keys and string values for secret-bearing content.
func walkSecrets(prefix string, m map[string]interface{}, errs *ValidationErrors) {
	for key, val := range m {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		if isSecretFieldName(key) {
			*errs = append(*errs, &ValidationError{
				Field:       path,
				Rule:        "secret_field",
				Remediation: fmt.Sprintf("field %q looks like a secret and must not be stored in cloud.yaml; use environment variables or a secrets manager instead", key),
			})
		}

		switch v := val.(type) {
		case map[string]interface{}:
			// Recurse into nested maps.
			walkSecrets(path, v, errs)
		case string:
			// Check string values for secret-bearing URL query parameters.
			if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
				if containsSecretQuery(u) {
					*errs = append(*errs, &ValidationError{
						Field:       path,
						Rule:        "secret_in_url",
						Remediation: fmt.Sprintf("value of %q contains a URL with secret-bearing query parameters (authToken, token, password, secret); use environment variables for secrets", key),
					})
				}
			}
		}
	}
}

// isSecretFieldName checks if a field name matches known secret patterns.
func isSecretFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range secretFieldNames {
		if strings.ToLower(s) == lower {
			return true
		}
	}
	return false
}

// containsSecretQuery checks if a URL contains secret-bearing query parameters.
func containsSecretQuery(u *url.URL) bool {
	secretParams := []string{"authtoken", "token", "password", "secret", "api_key", "apikey"}
	for param := range u.Query() {
		lower := strings.ToLower(param)
		for _, s := range secretParams {
			if lower == s {
				return true
			}
		}
	}
	return false
}

// joinKeys returns a sorted comma-separated list of map keys.
func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple sort for deterministic output.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return strings.Join(keys, ", ")
}
