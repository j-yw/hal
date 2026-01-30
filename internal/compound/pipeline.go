package compound

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/engine"
)

const stateFileName = "auto-state.json"

// Pipeline orchestrates the compound engineering automation process.
type Pipeline struct {
	config  *AutoConfig
	engine  engine.Engine
	display *engine.Display
	dir     string
}

// NewPipeline creates a new pipeline instance.
func NewPipeline(config *AutoConfig, eng engine.Engine, display *engine.Display, dir string) *Pipeline {
	return &Pipeline{
		config:  config,
		engine:  eng,
		display: display,
		dir:     dir,
	}
}

// statePath returns the full path to the state file.
func (p *Pipeline) statePath() string {
	return filepath.Join(p.dir, ".goralph", stateFileName)
}

// loadState reads the pipeline state from .goralph/auto-state.json.
// Returns nil if the state file doesn't exist.
func (p *Pipeline) loadState() *PipelineState {
	data, err := os.ReadFile(p.statePath())
	if err != nil {
		return nil
	}

	var state PipelineState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}

	return &state
}

// saveState writes the pipeline state to .goralph/auto-state.json atomically.
// It writes to a temp file first, then renames to ensure atomic operation.
func (p *Pipeline) saveState(state *PipelineState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	statePath := p.statePath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		return err
	}

	// Write to temp file first for atomic operation
	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	// Rename temp to final (atomic on most filesystems)
	return os.Rename(tmpPath, statePath)
}

// clearState removes the state file on completion.
func (p *Pipeline) clearState() error {
	err := os.Remove(p.statePath())
	if os.IsNotExist(err) {
		return nil // Not an error if file doesn't exist
	}
	return err
}

// HasState returns true if there is a saved state to resume from.
func (p *Pipeline) HasState() bool {
	return p.loadState() != nil
}
