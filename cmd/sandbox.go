package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage sandbox environments",
	Long: `Manage sandbox environments for isolated development.

Supports multiple providers (Daytona, Hetzner, DigitalOcean) — run
'hal sandbox setup' to choose a provider and configure credentials.

Subcommands:
  setup       Configure provider, credentials, and environment
  start       Create and start a sandbox
  stop        Stop a running sandbox
  status      Show sandbox status
  delete      Delete a sandbox
  ssh         Open an interactive shell or run a remote command`,
	Example: `  hal sandbox setup
  hal sandbox start
  hal sandbox status`,
}

var sandboxSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure sandbox credentials and environment",
	Args:  noArgsValidation(),
	Long: `Interactive setup for sandbox credentials and environment variables.

First prompts for a provider:
  (1) Daytona — managed cloud sandbox (prompts for API key, server URL)
  (2) Hetzner — self-managed VPS (prompts for SSH key name, server type, image)
  (3) DigitalOcean — managed VPS via doctl (prompts for SSH key fingerprint, droplet size)
  (4) AWS Lightsail — lightweight VPS via aws CLI (prompts for key pair name, bundle, region)

Then prompts for shared environment variables:
  • API keys (Anthropic, OpenAI) — masked input
  • GitHub token — masked input
  • Git identity (name, email)
  • Tailscale auth key and hostname — for SSH from mobile

All values are saved to .hal/config.yaml. Re-running setup lets you update
individual values — press Enter to keep the current value.

After setup, 'hal sandbox start' injects all configured env vars automatically.`,
	Example: `  hal sandbox setup`,
	RunE:    runSandboxSetupCobra,
}

func init() {
	sandboxCmd.AddCommand(sandboxSetupCmd)
	rootCmd.AddCommand(sandboxCmd)
}

// resolveProviderFromState creates a Provider from the state's provider field
// and the project config. Used by stop, delete, status, and ssh commands.
func resolveProviderFromState(dir string, state *sandbox.SandboxState) (sandbox.Provider, error) {
	halDir := filepath.Join(dir, template.HalDir)
	sandboxCfg, err := compound.LoadSandboxConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("loading sandbox config: %w", err)
	}
	dayCfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("loading daytona config: %w", err)
	}

	provCfg := sandbox.ProviderConfig{
		StateDir: halDir,
	}
	if dayCfg != nil {
		provCfg.DaytonaAPIKey = dayCfg.APIKey
		provCfg.DaytonaServerURL = dayCfg.ServerURL
	}
	if sandboxCfg != nil {
		provCfg.HetznerSSHKey = sandboxCfg.Hetzner.SSHKey
		provCfg.HetznerServerType = sandboxCfg.Hetzner.ServerType
		provCfg.HetznerImage = sandboxCfg.Hetzner.Image
		provCfg.DigitalOceanSSHKey = sandboxCfg.DigitalOcean.SSHKey
		provCfg.DigitalOceanSize = sandboxCfg.DigitalOcean.Size
		provCfg.LightsailRegion = sandboxCfg.Lightsail.Region
		provCfg.LightsailAvailabilityZone = sandboxCfg.Lightsail.AvailabilityZone
		provCfg.LightsailBundle = sandboxCfg.Lightsail.Bundle
		provCfg.LightsailKeyPairName = sandboxCfg.Lightsail.KeyPairName
		provCfg.TailscaleLockdown = sandboxCfg.TailscaleLockdown
	}

	return sandbox.ProviderFromConfig(state.Provider, provCfg)
}

// resolveProviderFromName creates a Provider for delete-by-name paths where no
// matching local sandbox state exists. It uses the configured sandbox provider.
func resolveProviderFromName(dir, _ string) (sandbox.Provider, error) {
	halDir := filepath.Join(dir, template.HalDir)
	sandboxCfg, err := compound.LoadSandboxConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("loading sandbox config: %w", err)
	}
	dayCfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("loading daytona config: %w", err)
	}

	provCfg := sandbox.ProviderConfig{
		StateDir: halDir,
	}
	if dayCfg != nil {
		provCfg.DaytonaAPIKey = dayCfg.APIKey
		provCfg.DaytonaServerURL = dayCfg.ServerURL
	}
	if sandboxCfg != nil {
		provCfg.HetznerSSHKey = sandboxCfg.Hetzner.SSHKey
		provCfg.HetznerServerType = sandboxCfg.Hetzner.ServerType
		provCfg.HetznerImage = sandboxCfg.Hetzner.Image
		provCfg.DigitalOceanSSHKey = sandboxCfg.DigitalOcean.SSHKey
		provCfg.DigitalOceanSize = sandboxCfg.DigitalOcean.Size
		provCfg.LightsailRegion = sandboxCfg.Lightsail.Region
		provCfg.LightsailAvailabilityZone = sandboxCfg.Lightsail.AvailabilityZone
		provCfg.LightsailBundle = sandboxCfg.Lightsail.Bundle
		provCfg.LightsailKeyPairName = sandboxCfg.Lightsail.KeyPairName
		provCfg.TailscaleLockdown = sandboxCfg.TailscaleLockdown
	}

	providerName := sandboxCfg.Provider
	if strings.TrimSpace(providerName) == "" {
		providerName = "daytona"
	}

	return sandbox.ProviderFromConfig(providerName, provCfg)
}

func runSandboxSetupCobra(cmd *cobra.Command, args []string) error {
	return runSandboxSetup(".", os.Stdin, os.Stdout, readPasswordFromTerminal, exec.LookPath)
}

// lookPathFunc checks whether a binary is on PATH. Injected for testability.
type lookPathFunc func(file string) (string, error)

// passwordReader reads a password from the user. The fd parameter is the file
// descriptor of the terminal. Returns the password bytes and any error.
type passwordReader func(fd int) ([]byte, error)

// readPasswordFromTerminal reads a password from stdin with echo disabled.
func readPasswordFromTerminal(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// setupField defines a field to prompt for during sandbox setup.
type setupField struct {
	key      string // env var name or config key
	label    string // display label
	secret   bool   // mask input
	required bool   // cannot be empty
	defVal   string // default if user presses Enter with no existing value
}

// daytona connection fields
var daytonaFields = []setupField{
	{key: "_daytona_api_key", label: "Daytona API key", secret: true, required: true},
	{key: "_daytona_server_url", label: "Server URL", defVal: "https://app.daytona.io/api"},
}

// sandbox env var fields
var sandboxEnvFields = []setupField{
	{key: "ANTHROPIC_API_KEY", label: "Anthropic API key", secret: true},
	{key: "OPENAI_API_KEY", label: "OpenAI API key", secret: true},
	{key: "GITHUB_TOKEN", label: "GitHub token", secret: true},
	{key: "GIT_USER_NAME", label: "Git name"},
	{key: "GIT_USER_EMAIL", label: "Git email"},
	{key: "TAILSCALE_AUTHKEY", label: "Tailscale auth key", secret: true},
	{key: "TAILSCALE_HOSTNAME", label: "Tailscale hostname", defVal: "hal-sandbox"},
}

// hetzner-specific setup fields
var hetznerFields = []setupField{
	{key: "_hetzner_ssh_key", label: "SSH key name", required: true},
	{key: "_hetzner_server_type", label: "Server type", defVal: "cx22"},
	{key: "_hetzner_image", label: "Image", defVal: "ubuntu-24.04"},
}

// digitalocean-specific setup fields
var digitaloceanFields = []setupField{
	{key: "_do_ssh_key", label: "SSH key fingerprint (doctl compute ssh-key list)", required: true},
	{key: "_do_size", label: "Droplet size", defVal: "s-2vcpu-4gb"},
}

// lightsail-specific setup fields
var lightsailFields = []setupField{
	{key: "_ls_key_pair", label: "Key pair name (aws lightsail get-key-pairs)", required: true},
	{key: "_ls_bundle", label: "Bundle", defVal: "small_3_0"},
	{key: "_ls_region", label: "Region", defVal: "us-east-1"},
	{key: "_ls_az", label: "Availability zone", defVal: "us-east-1a"},
}

// runSandboxSetup contains the testable logic for the sandbox setup command.
// dir is the project root directory (containing .hal/).
func runSandboxSetup(dir string, in io.Reader, out io.Writer, readPassword passwordReader, lookPath lookPathFunc) error {
	halDir := filepath.Join(dir, template.HalDir)

	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	reader := bufio.NewReader(in)

	// Load existing config for defaults
	existingDaytona, _ := compound.LoadDaytonaConfig(dir)
	existingSandbox, _ := compound.LoadSandboxConfig(dir)
	if existingDaytona == nil {
		d := compound.DefaultDaytonaConfig()
		existingDaytona = &d
	}
	if existingSandbox == nil {
		existingSandbox = &compound.SandboxConfig{Provider: "daytona", Env: map[string]string{}}
	}

	// ── Provider selection ──
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  ── Select Provider ──")
	fmt.Fprintln(out, "")

	// Determine default provider choice
	defaultChoice := "1"
	switch existingSandbox.Provider {
	case "hetzner":
		defaultChoice = "2"
	case "digitalocean":
		defaultChoice = "3"
	case "lightsail":
		defaultChoice = "4"
	}
	fmt.Fprintf(out, "  (1) Daytona  (2) Hetzner  (3) DigitalOcean  (4) Lightsail [%s]: ", defaultChoice)
	line, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if choice == "" {
		choice = defaultChoice
	}

	var selectedProvider string
	switch choice {
	case "1":
		selectedProvider = "daytona"
	case "2":
		selectedProvider = "hetzner"
	case "3":
		selectedProvider = "digitalocean"
	case "4":
		selectedProvider = "lightsail"
	default:
		return fmt.Errorf("invalid provider choice %q — enter 1, 2, 3, or 4", choice)
	}

	// Check CLI availability before prompting
	if selectedProvider == "digitalocean" {
		if _, err := lookPath("doctl"); err != nil {
			return fmt.Errorf("doctl not found on PATH: install from https://docs.digitalocean.com/reference/doctl/how-to/install/ and run 'doctl auth init'")
		}
	}
	if selectedProvider == "lightsail" {
		if _, err := lookPath("aws"); err != nil {
			return fmt.Errorf("aws CLI not found on PATH: install with 'brew install awscli' and run 'aws configure'")
		}
	}

	// Collect all values
	collected := make(map[string]string)

	// ── Provider-specific credentials ──
	switch selectedProvider {
	case "daytona":
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  ── Daytona ──")
		fmt.Fprintln(out, "")

		// API key
		val, err := promptField(reader, in, out, readPassword, daytonaFields[0], existingDaytona.APIKey)
		if err != nil {
			return err
		}
		collected["_daytona_api_key"] = val

		// Server URL
		currentURL := existingDaytona.ServerURL
		if currentURL == "" {
			currentURL = daytonaFields[1].defVal
		}
		val, err = promptField(reader, in, out, readPassword, daytonaFields[1], currentURL)
		if err != nil {
			return err
		}
		collected["_daytona_server_url"] = val

	case "hetzner":
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  ── Hetzner ──")
		fmt.Fprintln(out, "")

		// SSH key name
		val, err := promptField(reader, in, out, readPassword, hetznerFields[0], existingSandbox.Hetzner.SSHKey)
		if err != nil {
			return err
		}
		collected["_hetzner_ssh_key"] = val

		// Server type
		currentType := existingSandbox.Hetzner.ServerType
		if currentType == "" {
			currentType = hetznerFields[1].defVal
		}
			val, err = promptField(reader, in, out, readPassword, hetznerFields[1], currentType)
			if err != nil {
				return err
			}
			collected["_hetzner_server_type"] = val

			// Image
			currentImage := existingSandbox.Hetzner.Image
			if currentImage == "" {
				currentImage = hetznerFields[2].defVal
			}
			val, err = promptField(reader, in, out, readPassword, hetznerFields[2], currentImage)
			if err != nil {
				return err
			}
			collected["_hetzner_image"] = val

	case "digitalocean":
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  ── DigitalOcean ──")
		fmt.Fprintln(out, "")

		// SSH key fingerprint
		val, err := promptField(reader, in, out, readPassword, digitaloceanFields[0], existingSandbox.DigitalOcean.SSHKey)
		if err != nil {
			return err
		}
		collected["_do_ssh_key"] = val

		// Droplet size
		currentSize := existingSandbox.DigitalOcean.Size
		if currentSize == "" {
			currentSize = digitaloceanFields[1].defVal
		}
		val, err = promptField(reader, in, out, readPassword, digitaloceanFields[1], currentSize)
		if err != nil {
			return err
		}
		collected["_do_size"] = val

	case "lightsail":
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  ── AWS Lightsail ──")
		fmt.Fprintln(out, "")

		// Key pair name
		val, err := promptField(reader, in, out, readPassword, lightsailFields[0], existingSandbox.Lightsail.KeyPairName)
		if err != nil {
			return err
		}
		collected["_ls_key_pair"] = val

		// Bundle
		currentBundle := existingSandbox.Lightsail.Bundle
		if currentBundle == "" {
			currentBundle = lightsailFields[1].defVal
		}
		val, err = promptField(reader, in, out, readPassword, lightsailFields[1], currentBundle)
		if err != nil {
			return err
		}
		collected["_ls_bundle"] = val

		// Region
		currentRegion := existingSandbox.Lightsail.Region
		if currentRegion == "" {
			currentRegion = lightsailFields[2].defVal
		}
		val, err = promptField(reader, in, out, readPassword, lightsailFields[2], currentRegion)
		if err != nil {
			return err
		}
		collected["_ls_region"] = val

		// Availability zone
		currentAZ := existingSandbox.Lightsail.AvailabilityZone
		if currentAZ == "" {
			currentAZ = lightsailFields[3].defVal
		}
		val, err = promptField(reader, in, out, readPassword, lightsailFields[3], currentAZ)
		if err != nil {
			return err
		}
		collected["_ls_az"] = val
	}

	// ── API keys ──
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  ── API Keys ──")
	fmt.Fprintln(out, "")

	for _, f := range sandboxEnvFields[:3] {
		val, err := promptField(reader, in, out, readPassword, f, existingSandbox.Env[f.key])
		if err != nil {
			return err
		}
		if val != "" {
			collected[f.key] = val
		}
	}

	// ── Git identity ──
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  ── Git Identity ──")
	fmt.Fprintln(out, "")

	for _, f := range sandboxEnvFields[3:5] {
		val, err := promptField(reader, in, out, readPassword, f, existingSandbox.Env[f.key])
		if err != nil {
			return err
		}
		if val != "" {
			collected[f.key] = val
		}
	}

	// ── Tailscale ──
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  ── Tailscale (SSH from phone) ──")
	fmt.Fprintln(out, "")

	for _, f := range sandboxEnvFields[5:] {
		current := existingSandbox.Env[f.key]
		if current == "" {
			current = f.defVal
		}
		val, err := promptField(reader, in, out, readPassword, f, current)
		if err != nil {
			return err
		}
		if val != "" {
			collected[f.key] = val
		}
	}

	lockdown := false
	if selectedProvider != "daytona" {
		fmt.Fprintf(out, "  Lock down to Tailscale only? (y/n) [%s]: ", yesNoDefault(existingSandbox.TailscaleLockdown))
		line, _ := reader.ReadString('\n')
		v := strings.ToLower(strings.TrimSpace(strings.TrimRight(line, "\r\n")))
		switch v {
		case "":
			lockdown = existingSandbox.TailscaleLockdown
		case "y", "yes":
			lockdown = true
		case "n", "no":
			lockdown = false
		default:
			return fmt.Errorf("invalid answer %q (expected y or n)", v)
		}
		if lockdown && strings.TrimSpace(collected["TAILSCALE_AUTHKEY"]) == "" {
			return fmt.Errorf("Tailscale auth key required for lockdown")
		}
	}

	// ── Save ──

	// Save provider-specific config
	switch selectedProvider {
	case "daytona":
		daytonaCfg := &compound.DaytonaConfig{
			APIKey:    collected["_daytona_api_key"],
			ServerURL: collected["_daytona_server_url"],
		}
		if err := compound.SaveConfig(dir, daytonaCfg); err != nil {
			return fmt.Errorf("saving daytona config: %w", err)
		}
	}

	// Build and save sandbox config (provider + env + hetzner fields)
	envVars := make(map[string]string)
	for _, f := range sandboxEnvFields {
		if v, ok := collected[f.key]; ok && v != "" {
			envVars[f.key] = v
		}
	}

	sandboxCfg := &compound.SandboxConfig{
		Provider:          selectedProvider,
		TailscaleLockdown: lockdown,
		Env:               envVars,
	}

	if selectedProvider == "hetzner" {
		sandboxCfg.Hetzner = compound.HetznerConfig{
			SSHKey:     collected["_hetzner_ssh_key"],
			ServerType: collected["_hetzner_server_type"],
			Image:      collected["_hetzner_image"],
		}
	}

	if selectedProvider == "digitalocean" {
		sandboxCfg.DigitalOcean = compound.DigitalOceanConfig{
			SSHKey: collected["_do_ssh_key"],
			Size:   collected["_do_size"],
		}
	}

	if selectedProvider == "lightsail" {
		sandboxCfg.Lightsail = compound.LightsailConfig{
			KeyPairName:      collected["_ls_key_pair"],
			Bundle:           collected["_ls_bundle"],
			Region:           collected["_ls_region"],
			AvailabilityZone: collected["_ls_az"],
		}
	}

	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		return fmt.Errorf("saving sandbox config: %w", err)
	}

	// ── Summary ──
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  ── Saved to .hal/config.yaml ──")
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "  Provider:   %s\n", selectedProvider)

	switch selectedProvider {
	case "daytona":
		fmt.Fprintln(out, "  Daytona:    ✓ configured")
	case "hetzner":
		fmt.Fprintf(out, "  Hetzner:    ✓ ssh-key=%s type=%s image=%s\n", collected["_hetzner_ssh_key"], collected["_hetzner_server_type"], collected["_hetzner_image"])
	case "digitalocean":
		fmt.Fprintf(out, "  DigitalOcean: ✓ ssh-key=%s size=%s\n", collected["_do_ssh_key"], collected["_do_size"])
	case "lightsail":
		fmt.Fprintf(out, "  Lightsail:  ✓ key=%s bundle=%s region=%s az=%s\n", collected["_ls_key_pair"], collected["_ls_bundle"], collected["_ls_region"], collected["_ls_az"])
	}

	if selectedProvider != "daytona" {
		if lockdown {
			fmt.Fprintln(out, "  Tailscale:  ✓ locked down (Tailscale-only access)")
		} else {
			fmt.Fprintln(out, "  Tailscale:  configured (public SSH allowed)")
		}
	}

	configuredCount := 0
	for _, f := range sandboxEnvFields {
		if v, ok := collected[f.key]; ok && v != "" {
			configuredCount++
		}
	}
	fmt.Fprintf(out, "  Sandbox:    %d env vars configured\n", configuredCount)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  Run 'hal sandbox start -n dev' to spin up a sandbox.")
	fmt.Fprintln(out, "")

	return nil
}

// promptField prompts the user for a single field value.
// If current is non-empty, it's shown as the default (masked for secrets).
// Returns the new value, or current if the user presses Enter.
func promptField(
	reader *bufio.Reader,
	in io.Reader,
	out io.Writer,
	readPassword passwordReader,
	field setupField,
	current string,
) (string, error) {
	// Build prompt
	hint := ""
	if current != "" {
		if field.secret {
			hint = maskSecret(current)
		} else {
			hint = current
		}
	} else if field.defVal != "" {
		hint = field.defVal
	}

	if hint != "" {
		fmt.Fprintf(out, "  %s [%s]: ", field.label, hint)
	} else {
		fmt.Fprintf(out, "  %s: ", field.label)
	}

	var val string
	if field.secret {
		val = readSecretInput(reader, in, out, readPassword)
	} else {
		line, _ := reader.ReadString('\n')
		val = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	}

	// If empty, use current or default
	if val == "" {
		if current != "" {
			return current, nil
		}
		if field.defVal != "" {
			return field.defVal, nil
		}
		if field.required {
			return "", fmt.Errorf("%s is required", field.label)
		}
		return "", nil
	}

	return val, nil
}

// readSecretInput reads a secret value with masked input when possible.
func readSecretInput(reader *bufio.Reader, in io.Reader, out io.Writer, readPassword passwordReader) string {
	if readPassword != nil {
		if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			pass, err := readPassword(int(f.Fd()))
			fmt.Fprintln(out) // newline after masked input
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(pass))
		}
	}
	// Fallback: plain text (piped input / tests)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.TrimRight(line, "\r\n"))
}

// maskSecret returns a masked version of a secret, showing last 4 chars.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

func yesNoDefault(v bool) string {
	if v {
		return "y"
	}
	return "n"
}
