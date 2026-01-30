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

// DefaultFiles returns the default files to create in .goralph/
func DefaultFiles() map[string]string {
	return map[string]string{
		"prompt.md":    DefaultPrompt,
		"progress.txt": DefaultProgress,
		"config.yaml":  DefaultConfig,
	}
}
