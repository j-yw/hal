package cmd

import (
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"

	// Register available engines.
	_ "github.com/jywlabs/hal/internal/engine/claude"
	_ "github.com/jywlabs/hal/internal/engine/codex"
	_ "github.com/jywlabs/hal/internal/engine/pi"
)

// newEngine creates an engine by name, loading per-engine config from .hal/config.yaml.
func newEngine(name string) (engine.Engine, error) {
	cfg := compound.LoadEngineConfig(".", name)
	return engine.NewWithConfig(name, cfg)
}

// buildHeaderCtx constructs a HeaderContext for command headers.
// It loads model from config and fetches git repo/branch info.
func buildHeaderCtx(engineFlag string) engine.HeaderContext {
	repo, branch := engine.GetGitInfo()
	cfg := compound.LoadEngineConfig(".", engineFlag)
	model := ""
	if cfg != nil {
		model = cfg.Model
	}
	return engine.HeaderContext{
		Engine: engineFlag,
		Model:  model,
		Repo:   repo,
		Branch: branch,
	}
}
