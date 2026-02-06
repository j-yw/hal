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
