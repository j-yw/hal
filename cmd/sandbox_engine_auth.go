package cmd

import (
	"os"
	"path/filepath"
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
// runs engineName. Claude credentials are added only for the Claude engine;
// the broad ~/.claude.json state file (MCP tokens, project history) is never
// copied.
func sandboxEngineAuthFilesFor(engineName string, base func() []factorySandboxAuthFile) func() []factorySandboxAuthFile {
	return func() []factorySandboxAuthFile {
		var files []factorySandboxAuthFile
		if base != nil {
			files = base()
		}
		if strings.EqualFold(strings.TrimSpace(engineName), "claude") {
			files = append(files, sandboxClaudeAuthFiles()...)
		}
		return files
	}
}

func sandboxClaudeAuthFiles() []factorySandboxAuthFile {
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil || strings.TrimSpace(home) == "" {
			return nil
		}
	}
	source := filepath.Join(home, ".claude", ".credentials.json")
	if info, err := os.Stat(source); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return []factorySandboxAuthFile{{SourcePath: source, RemotePath: ".claude/.credentials.json"}}
}

// factorySandboxEngineAuthDeps returns deps whose engine auth files match the
// engine the factory run will use inside the sandbox.
func factorySandboxEngineAuthDeps(req factorySandboxExecutorRequest, deps factorySandboxExecutorDeps) factorySandboxExecutorDeps {
	engineName := strings.TrimSpace(req.RemoteAuto.Engine)
	engineName = sandboxEffectiveEngine(engineName, engineName != "", req.RunRecord.RepoPath)
	deps.engineAuthFiles = sandboxEngineAuthFilesFor(engineName, deps.engineAuthFiles)
	return deps
}
