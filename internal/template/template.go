package template

import (
	_ "embed"
)

//go:embed prompt.md
var DefaultPrompt string

//go:embed progress.txt
var DefaultProgress string

//go:embed config.yaml
var DefaultConfig string

// GoralphDir is the name of the goralph configuration directory.
const GoralphDir = ".goralph"

// File name constants for consistent usage across the codebase.
const (
	PRDFile          = "prd.json"          // Manual flow (plan, convert, validate, run)
	AutoPRDFile      = "auto-prd.json"     // Auto flow (auto, explode)
	PromptFile       = "prompt.md"
	ProgressFile     = "progress.txt"      // Manual flow
	AutoProgressFile = "auto-progress.txt" // Auto flow
	ConfigFile       = "config.yaml"
)

// DefaultFiles returns the default files to create in .goralph/
func DefaultFiles() map[string]string {
	return map[string]string{
		PromptFile:   DefaultPrompt,
		ProgressFile: DefaultProgress,
		ConfigFile:   DefaultConfig,
	}
}
