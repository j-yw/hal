package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Long: `Show the current Hal configuration.

Displays settings from .hal/config.yaml if present,
otherwise shows default values.`,
	RunE: runConfig,
}

var addRuleCmd = &cobra.Command{
	Use:   "add-rule <name>",
	Short: "Add a rule to config",
	Long: `Add a new rule to the .hal/rules/ directory.

Rules are markdown files that provide additional context or
instructions for task execution.

Example:
  hal config add-rule testing     # Creates .hal/rules/testing.md`,
	Args: cobra.ExactArgs(1),
	RunE: runAddRule,
}

func init() {
	configCmd.AddCommand(addRuleCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	configPath := filepath.Join(".hal", "config.yaml")

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("No .hal/config.yaml found (using defaults)")
		fmt.Println()
		fmt.Println("Run 'hal init' to create a configuration file.")
		fmt.Println()
		fmt.Println("Default settings:")
		printDefaults()
		return nil
	}

	// Read and display config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	fmt.Println("Current configuration (.hal/config.yaml):")
	fmt.Println()
	fmt.Println(string(content))

	return nil
}

func runAddRule(cmd *cobra.Command, args []string) error {
	ruleName := args[0]
	rulesDir := filepath.Join(".hal", "rules")
	rulePath := filepath.Join(rulesDir, ruleName+".md")

	// Check if .hal exists
	if _, err := os.Stat(".hal"); os.IsNotExist(err) {
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

	fmt.Printf("Created rule: %s\n", rulePath)
	return nil
}

func printDefaults() {
	fmt.Println("  engine: claude          # Options: claude, codex, pi")
	fmt.Println("  maxIterations: 10")
	fmt.Println("  retryDelay: 30s")
	fmt.Println("  maxRetries: 3")
	fmt.Println("  engines:                # Per-engine model/provider overrides")
	fmt.Println("    claude:")
	fmt.Println("      model: \"\"          # Use Claude's default")
	fmt.Println("    codex:")
	fmt.Println("      model: \"\"          # Use Codex's default")
	fmt.Println("    pi:")
	fmt.Println("      provider: \"\"       # Use pi's default")
	fmt.Println("      model: \"\"          # Use pi's default")
}
