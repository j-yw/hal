package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/compound"
)

// sandboxEffectiveEngine returns the engine the sandboxed command will run:
// an explicit --engine value, otherwise the project's configured default.
func sandboxEffectiveEngine(flagEngine string, flagChanged bool, projectDir string) string {
	if name := strings.TrimSpace(flagEngine); flagChanged && name != "" {
		return name
	}
	name, err := compound.LoadDefaultEngine(projectDir)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

// sandboxEngineAuthFilesFor returns the auth files to sync into a sandbox that
// runs engineName.
func sandboxEngineAuthFilesFor(engineName string, base func() []factorySandboxAuthFile) func() []factorySandboxAuthFile {
	return func() []factorySandboxAuthFile {
		if base == nil {
			return nil
		}
		return base()
	}
}
