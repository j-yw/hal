package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/jywlabs/goralph/internal/executor"
	"github.com/spf13/cobra"
)

var prdFile string

var rootCmd = &cobra.Command{
	Use:   "goralph",
	Short: "GoRalph - Autonomous PRD task executor using Claude Code",
	Long: `GoRalph is a CLI tool that processes PRD (Product Requirements Document) files
and executes tasks sequentially using Claude Code as the AI engine.

Usage:
  goralph --prd <file>    Process tasks from the specified PRD file`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if prdFile == "" {
			fmt.Println("GoRalph ready. Use --help for available commands.")
			return nil
		}

		// Validate file exists
		info, err := os.Stat(prdFile)
		if os.IsNotExist(err) {
			return fmt.Errorf("PRD file does not exist: %s", prdFile)
		}
		if err != nil {
			return fmt.Errorf("cannot access PRD file: %w", err)
		}

		// Check it's not a directory
		if info.IsDir() {
			return fmt.Errorf("PRD path is a directory, not a file: %s", prdFile)
		}

		// Validate file is readable
		file, err := os.Open(prdFile)
		if err != nil {
			return fmt.Errorf("PRD file is not readable: %w", err)
		}
		file.Close()

		// Execute tasks from PRD file
		exec := executor.New(executor.Config{
			PRDFile:  prdFile,
			RepoPath: ".",
			Logger:   os.Stdout,
		})

		result := exec.Run(context.Background())

		if !result.Success {
			return fmt.Errorf("execution failed: %w", result.Error)
		}

		return nil
	},
}

func init() {
	rootCmd.Flags().StringVar(&prdFile, "prd", "", "Path to PRD markdown file to process")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
