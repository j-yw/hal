package codex

import (
	"context"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
)

func init() {
	engine.RegisterEngine("codex", func() engine.Engine {
		return New()
	})
}

// Engine executes prompts using OpenAI Codex CLI.
type Engine struct {
	Timeout time.Duration
}

// New creates a new Codex engine.
func New() *Engine {
	return &Engine{
		Timeout: engine.DefaultTimeout,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "codex"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "codex"
}

// BuildArgs returns the CLI arguments for execution.
func (e *Engine) BuildArgs(prompt string) []string {
	return []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
		prompt,
	}
}

// Execute runs the prompt using Codex CLI.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	// TODO: Implement in US-004
	return engine.Result{}
}

// Prompt executes a single prompt and returns the text response.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	// TODO: Implement in US-005
	return "", nil
}

// StreamPrompt executes a prompt with streaming display feedback.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	// TODO: Implement in US-006
	return "", nil
}
