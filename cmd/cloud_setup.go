package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Cloud setup flags.
var (
	cloudSetupProfileFlag string
)

var cloudSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Guided cloud profile configuration",
	Long: `Interactively configure cloud defaults and write .hal/cloud.yaml.

Prompts for profile name, endpoint, mode, and other defaults.
Only non-secret values are written. Re-running setup can update
the selected profile without deleting unrelated profiles.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		halDir := filepath.Join(".", template.HalDir)
		return runCloudSetup(halDir, cloudSetupProfileFlag, os.Stdin, os.Stdout)
	},
}

func init() {
	cloudSetupCmd.Flags().StringVar(&cloudSetupProfileFlag, "profile", "", "Profile name to configure (default: \"default\")")
	cloudCmd.AddCommand(cloudSetupCmd)
}

// runCloudSetup is the testable logic for the cloud setup command.
func runCloudSetup(halDir, profileFlag string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)

	// Ensure .hal/ directory exists.
	if err := os.MkdirAll(halDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", halDir, err)
	}

	// Load existing config if present.
	configPath := filepath.Join(halDir, template.CloudConfigFile)
	existing := loadExistingCloudConfig(configPath)

	// Determine profile name.
	profileName := profileFlag
	if profileName == "" {
		defaultProfile := "default"
		if existing != nil && existing.DefaultProfile != "" {
			defaultProfile = existing.DefaultProfile
		}
		profileName = promptField(reader, out, "Profile name", defaultProfile)
	}

	// Load existing profile defaults for this profile name.
	var defaults *config.Profile
	if existing != nil {
		defaults = existing.GetProfile(profileName)
	}
	if defaults == nil {
		defaults = &config.Profile{}
	}

	// Prompt for each field.
	endpoint := promptField(reader, out, "Endpoint URL", defaults.Endpoint)

	modeDefault := defaults.Mode
	if modeDefault == "" {
		modeDefault = config.ModeUntilComplete
	}
	mode := promptField(reader, out, fmt.Sprintf("Mode (%s, %s)", config.ModeUntilComplete, config.ModeBoundedBatch), modeDefault)

	repo := promptField(reader, out, "Repository (owner/repo)", defaults.Repo)
	base := promptField(reader, out, "Base branch", defaults.Base)
	engine := promptField(reader, out, "Engine (e.g., claude, codex, pi)", defaults.Engine)
	authProfile := promptField(reader, out, "Auth profile ID", defaults.AuthProfile)
	scope := promptField(reader, out, "Scope reference", defaults.Scope)

	pullPolicyDefault := defaults.PullPolicy
	if pullPolicyDefault == "" {
		pullPolicyDefault = config.PullPolicyAll
	}
	pullPolicy := promptField(reader, out, fmt.Sprintf("Pull policy (%s, %s, %s)", config.PullPolicyState, config.PullPolicyReports, config.PullPolicyAll), pullPolicyDefault)

	// Build profile.
	profile := &config.Profile{
		Endpoint:    endpoint,
		Mode:        mode,
		Repo:        repo,
		Base:        base,
		Engine:      engine,
		AuthProfile: authProfile,
		Scope:       scope,
		PullPolicy:  pullPolicy,
	}

	// Preserve Wait from existing profile if set.
	if defaults.Wait != nil {
		profile.Wait = defaults.Wait
	}

	// Build or update config.
	cfg := &config.CloudConfig{
		DefaultProfile: profileName,
		Profiles:       make(map[string]*config.Profile),
	}

	// Preserve existing profiles.
	if existing != nil {
		for name, p := range existing.Profiles {
			cfg.Profiles[name] = p
		}
	}

	// Set/overwrite the target profile.
	cfg.Profiles[profileName] = profile

	// Validate before writing.
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("validation failed: %s", errs.Error())
	}

	// Marshal to YAML.
	yamlData, err := marshalCloudConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write the file.
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Print summary.
	fmt.Fprintf(out, "\nCloud profile configured.\n")
	fmt.Fprintf(out, "  profile:  %s\n", profileName)
	if endpoint != "" {
		fmt.Fprintf(out, "  endpoint: %s\n", endpoint)
	}
	fmt.Fprintf(out, "  mode:     %s\n", mode)
	fmt.Fprintf(out, "  config:   %s\n", configPath)

	return nil
}

// promptField prompts for a single value with an optional default.
func promptField(reader *bufio.Reader, out io.Writer, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Fprintf(out, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(out, "%s: ", label)
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultVal
	}
	return input
}

// loadExistingCloudConfig loads and parses an existing cloud.yaml, returning
// nil if the file doesn't exist or can't be parsed.
func loadExistingCloudConfig(path string) *config.CloudConfig {
	cfg, err := config.Load(path)
	if err != nil {
		return nil
	}
	return cfg
}

// yamlCloudConfig is the YAML serialization target for cloud config.
type yamlCloudConfig struct {
	DefaultProfile string                     `yaml:"defaultProfile"`
	Profiles       map[string]*config.Profile `yaml:"profiles"`
}

// marshalCloudConfig serializes a CloudConfig to YAML bytes.
func marshalCloudConfig(cfg *config.CloudConfig) ([]byte, error) {
	raw := &yamlCloudConfig{
		DefaultProfile: cfg.DefaultProfile,
		Profiles:       cfg.Profiles,
	}
	return yaml.Marshal(raw)
}
