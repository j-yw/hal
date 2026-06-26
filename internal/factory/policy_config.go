package factory

import (
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
)

type rawPolicyConfig struct {
	SandboxRequired      *bool     `yaml:"sandboxRequired"`
	AllowedEngines       *[]string `yaml:"allowedEngines"`
	MaxRunAttempts       *int      `yaml:"maxRunAttempts"`
	MaxReviewFixAttempts *int      `yaml:"maxReviewFixAttempts"`
	MaxCIFixAttempts     *int      `yaml:"maxCiFixAttempts"`
	VerificationRequired *bool     `yaml:"verificationRequired"`
	PRCreationAllowed    *bool     `yaml:"prCreationAllowed"`
	MergeAllowed         *bool     `yaml:"mergeAllowed"`
	CleanupBehavior      *string   `yaml:"cleanupBehavior"`
}

// LoadPolicyConfig reads factory.policy from .hal/config.yaml and merges any
// configured values over DefaultFactoryPolicy.
func LoadPolicyConfig(dir string) (*FactoryPolicy, error) {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			policy := DefaultFactoryPolicy()
			return &policy, nil
		}
		return nil, err
	}

	var raw struct {
		Factory struct {
			Policy rawPolicyConfig `yaml:"policy"`
		} `yaml:"factory"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	policy := DefaultFactoryPolicy()
	mergePolicyConfig(&policy, raw.Factory.Policy)
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	return &policy, nil
}

func mergePolicyConfig(policy *FactoryPolicy, raw rawPolicyConfig) {
	if raw.SandboxRequired != nil {
		policy.SandboxRequired = *raw.SandboxRequired
	}
	if raw.AllowedEngines != nil {
		policy.AllowedEngines = make([]string, len(*raw.AllowedEngines))
		copy(policy.AllowedEngines, *raw.AllowedEngines)
	}
	if raw.MaxRunAttempts != nil {
		policy.MaxRunAttempts = *raw.MaxRunAttempts
	}
	if raw.MaxReviewFixAttempts != nil {
		policy.MaxReviewFixAttempts = *raw.MaxReviewFixAttempts
	}
	if raw.MaxCIFixAttempts != nil {
		policy.MaxCIFixAttempts = *raw.MaxCIFixAttempts
	}
	if raw.VerificationRequired != nil {
		policy.VerificationRequired = *raw.VerificationRequired
	}
	if raw.PRCreationAllowed != nil {
		policy.PRCreationAllowed = *raw.PRCreationAllowed
	}
	if raw.MergeAllowed != nil {
		policy.MergeAllowed = *raw.MergeAllowed
	}
	if raw.CleanupBehavior != nil {
		policy.CleanupBehavior = *raw.CleanupBehavior
	}
}
