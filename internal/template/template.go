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

// HalDir is the name of the hal configuration directory.
const HalDir = ".hal"

// File name constants for consistent usage across the codebase.
const (
	PRDFile       = "prd.json"      // Manual flow (plan, convert, validate, run)
	AutoPRDFile   = "auto-prd.json" // Auto flow (auto, explode)
	PromptFile    = "prompt.md"
	ProgressFile  = "progress.txt"    // Unified progress for both flows
	AutoStateFile = "auto-state.json" // Auto flow pipeline state
	ConfigFile    = "config.yaml"
	StandardsDir  = "standards" // Project standards directory
	CommandsDir   = "commands"  // Agent commands directory
)

// DefaultFiles returns the default files to create in .hal/
func DefaultFiles() map[string]string {
	return map[string]string{
		PromptFile:   DefaultPrompt,
		ProgressFile: DefaultProgress,
		ConfigFile:   DefaultConfig,
	}
}
