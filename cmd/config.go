package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ui "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var configJSONFlag bool

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Long: `Show the current Hal configuration.

Displays settings from .hal/config.yaml if present,
otherwise shows default values.

With --json, outputs the configuration as JSON.`,
	Example: `  hal config
  hal config --json
  hal config add-rule testing`,
	RunE: runConfig,
}

var addRuleCmd = &cobra.Command{
	Use:        "add-rule <name>",
	Short:      "Add a rule to config",
	Deprecated: "deprecated in v0.2.0; will be removed in v1.0.0. Use 'hal standards discover' and 'hal standards list' instead.",
	Long: `Add a new rule to the .hal/rules/ directory.

Rules are markdown files that provide additional context or
instructions for task execution.

Example:
  hal config add-rule testing     # Creates .hal/rules/testing.md`,
	Example: `  hal config add-rule testing`,
	Args:    exactArgsValidation(1),
	RunE:    runAddRule,
}

func init() {
	configCmd.Flags().BoolVar(&configJSONFlag, "json", false, "Output configuration as JSON")
	configCmd.AddCommand(addRuleCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := configJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runParentCommand(cmd, args, func() error {
		return runConfigFn(".", jsonMode, out)
	})
}

func runConfigFn(dir string, jsonMode bool, out io.Writer) error {
	if jsonMode {
		return runConfigJSONFn(dir, out)
	}
	return runConfigShowFn(dir, out)
}

func runConfigJSONFn(dir string, out io.Writer) error {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)
	displayPath := filepath.Join(template.HalDir, template.ConfigFile)

	result := map[string]interface{}{
		"exists": false,
	}

	data, err := os.ReadFile(configPath)
	switch {
	case err == nil:
		result["exists"] = true
		result["path"] = displayPath
		result["content"] = string(data)
	case os.IsNotExist(err):
		// Keep exists=false.
	default:
		return fmt.Errorf("failed to read config: %w", err)
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	fmt.Fprintln(out, string(jsonData))
	return nil
}

func runConfigShowFn(dir string, out io.Writer) error {
	configPath := filepath.Join(dir, template.HalDir, template.ConfigFile)
	displayPath := filepath.Join(template.HalDir, template.ConfigFile)

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Fprintf(out, "%s No %s found (using defaults)\n\n", ui.StyleWarning.Render("[!]"), ui.StyleInfo.Render(displayPath))
		fmt.Fprintf(out, "Run %s to create a configuration file.\n\n", ui.StyleInfo.Render("hal init"))
		fmt.Fprintln(out, ui.StyleBold.Render("Default settings:"))
		printDefaults(out)
		return nil
	}

	// Read and display config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	fmt.Fprintln(out, ui.StyleTitle.Render("Configuration"))
	fmt.Fprintf(out, "%s %s\n\n", ui.StyleMuted.Render("Path:"), ui.StyleInfo.Render(displayPath))
	renderConfigContent(out, string(content))

	return nil
}

func renderConfigContent(out io.Writer, content string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		fmt.Fprintln(out, styleConfigLine(line))
	}
}

func styleConfigLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "#") {
		return ui.StyleMuted.Render(line)
	}
	styled, ok := styleTopLevelYAMLKey(line)
	if ok {
		return styled
	}
	return line
}

func styleTopLevelYAMLKey(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !isYAMLKeyLine(trimmed) {
		return "", false
	}

	indent := len(line) - len(strings.TrimLeft(line, " \t"))
	if indent > 0 {
		return line, true
	}

	colonIdx := strings.Index(line, ":")
	if colonIdx <= 0 {
		return "", false
	}

	key := line[:colonIdx]
	rest := line[colonIdx:]
	return ui.StyleInfo.Render(key) + rest, true
}

func isYAMLKeyLine(trimmed string) bool {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
		return false
	}
	idx := strings.Index(trimmed, ":")
	return idx > 0
}

func runAddRule(cmd *cobra.Command, args []string) error {
	ruleName := args[0]
	halDir := template.HalDir
	rulesDir := filepath.Join(halDir, "rules")
	rulePath := filepath.Join(rulesDir, ruleName+".md")

	// Check if .hal exists
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Ensure rules directory exists
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Check if rule already exists
	if _, err := os.Stat(rulePath); err == nil {
		return fmt.Errorf("rule %q already exists at %s", ruleName, rulePath)
	}

	// Create rule template
	ruleContent := fmt.Sprintf(`# Rule: %s

<!--
This rule file provides additional context for task execution.
Add instructions, constraints, or guidance that should apply
to tasks matching this rule.
-->

## Description

Describe what this rule is for.

## Instructions

- Add specific instructions here
- These will be included in task prompts
`, ruleName)

	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %w", err)
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	fmt.Fprintf(out, "%s Created rule: %s\n", ui.StyleSuccess.Render("[OK]"), ui.StyleInfo.Render(rulePath))
	return nil
}

func printDefaults(out io.Writer) {
	fmt.Fprintln(out, "  engine: codex           # Options: claude, codex, pi")
	fmt.Fprintln(out, "  maxIterations: 10")
	fmt.Fprintln(out, "  retryDelay: 30s")
	fmt.Fprintln(out, "  maxRetries: 3")
	fmt.Fprintln(out, "  auto:")
	fmt.Fprintln(out, "    reportsDir: .hal/reports")
	fmt.Fprintln(out, "    branchPrefix: compound/")
	fmt.Fprintln(out, "    maxIterations: 25")
	fmt.Fprintln(out, "    mode: balanced        # fast | balanced | strict")
	fmt.Fprintln(out, "    ciEnabled: true")
	fmt.Fprintln(out, "    reviewEnabled: true")
	fmt.Fprintln(out, "    reviewCleanStreak: 1")
	fmt.Fprintln(out, "    reviewMaxIterations: 10")
	fmt.Fprintln(out, "  engines:                # Per-engine model/provider overrides")
	fmt.Fprintln(out, "    claude:")
	fmt.Fprintln(out, "      model: \"\"          # Use Claude's default")
	fmt.Fprintln(out, "      timeout: 30m        # Per-session timeout")
	fmt.Fprintln(out, "    codex:")
	fmt.Fprintln(out, "      model: \"\"          # Use Codex's default")
	fmt.Fprintln(out, "      timeout: 30m        # Raise for long xhigh reasoning sessions")
	fmt.Fprintln(out, "    pi:")
	fmt.Fprintln(out, "      provider: \"\"       # Use pi's default")
	fmt.Fprintln(out, "      model: \"\"          # Use pi's default")
	fmt.Fprintln(out, "      timeout: 30m        # Per-session timeout")
}
