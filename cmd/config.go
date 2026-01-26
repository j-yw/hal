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
	Long: `Show the current GoRalph configuration.

Displays settings from .goralph/config.yaml if present,
otherwise shows default values.`,
	RunE: runConfig,
}

var addRuleCmd = &cobra.Command{
	Use:   "add-rule <name>",
	Short: "Add a rule to config",
	Long: `Add a new rule to the .goralph/rules/ directory.

Rules are markdown files that provide additional context or
instructions for task execution.

Example:
  goralph config add-rule testing     # Creates .goralph/rules/testing.md`,
	Args: cobra.ExactArgs(1),
	RunE: runAddRule,
}

func init() {
	configCmd.AddCommand(addRuleCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	configPath := filepath.Join(".goralph", "config.yaml")

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("No .goralph/config.yaml found (using defaults)")
		fmt.Println()
		fmt.Println("Run 'goralph init' to create a configuration file.")
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

	fmt.Println("Current configuration (.goralph/config.yaml):")
	fmt.Println()
	fmt.Println(string(content))

	return nil
}

func runAddRule(cmd *cobra.Command, args []string) error {
	ruleName := args[0]
	rulesDir := filepath.Join(".goralph", "rules")
	rulePath := filepath.Join(rulesDir, ruleName+".md")

	// Check if .goralph exists
	if _, err := os.Stat(".goralph"); os.IsNotExist(err) {
		return fmt.Errorf(".goralph/ not found - run 'goralph init' first")
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
	fmt.Println("  engine: claude")
	fmt.Println("  execution:")
	fmt.Println("    max_retries: 3")
	fmt.Println("    retry_delay: 5s")
	fmt.Println("  git:")
	fmt.Println("    auto_commit: true")
	fmt.Println("    commit_prefix: \"goralph:\"")
	fmt.Println("  validation:")
	fmt.Println("    run_tests: true")
	fmt.Println("    run_lint: true")
}
