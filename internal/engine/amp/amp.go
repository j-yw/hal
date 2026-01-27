package amp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
)

func init() {
	engine.RegisterEngine("amp", func() engine.Engine {
		return New()
	})
}

// Engine executes prompts using Amp CLI.
type Engine struct {
	Timeout time.Duration
}

// New creates a new Amp engine.
func New() *Engine {
	return &Engine{
		Timeout: engine.DefaultTimeout,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "amp"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "amp"
}

// BuildArgs returns the CLI arguments for execution.
// TODO: Update flags when Amp's actual CLI interface is known.
func (e *Engine) BuildArgs(prompt string) []string {
	return []string{
		"-p",
		prompt,
	}
}

// Execute runs the prompt using Amp CLI.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()

	// Build command
	args := e.BuildArgs(prompt)
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Detach from TTY to suppress interactive UI hints.
	//
	// Some CLI tools display interactive hints when they detect a TTY.
	// By setting Stdin to nil, the child process has no controlling terminal,
	// causing the CLI to skip TTY detection and suppress these hints.
	//
	// This ensures clean, parseable output without interactive UI elements.
	cmd.Stdin = nil

	// Set up output capture with streaming parser
	var stdout, stderr bytes.Buffer
	parser := NewParser()
	streamWriter := &streamHandler{
		parser:  parser,
		display: display,
		buffer:  nil,
	}

	cmd.Stdout = io.MultiWriter(streamWriter, &stdout)
	cmd.Stderr = &stderr

	// Run command
	err := cmd.Run()
	streamWriter.Flush()

	output := stdout.String()
	duration := time.Since(startTime)

	// Handle errors
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return engine.Result{
				Success:  false,
				Output:   output,
				Duration: duration,
				Error:    fmt.Errorf("execution timed out after %s", timeout),
			}
		}
		return engine.Result{
			Success:  false,
			Output:   output,
			Duration: duration,
			Error:    fmt.Errorf("execution failed: %w (stderr: %s)", err, stderr.String()),
		}
	}

	// Check for completion signal
	complete := strings.Contains(output, "<promise>COMPLETE</promise>")

	return engine.Result{
		Success:  true,
		Complete: complete,
		Output:   output,
		Duration: duration,
		Error:    nil,
	}
}

// Prompt executes a single prompt and returns the text response.
// This is a simpler interface for PRD generation, validation, etc.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command
	args := e.BuildArgs(prompt)
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = nil

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("prompt timed out after %s", timeout)
		}
		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// StreamPrompt delegates to Prompt for now since Amp's streaming format is unknown.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	if display != nil {
		display.StartSpinner("thinking...")
		defer display.StopSpinner()
	}
	return e.Prompt(ctx, prompt)
}

// streamHandler processes output line by line.
type streamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
}

func (h *streamHandler) Write(p []byte) (n int, err error) {
	h.buffer = append(h.buffer, p...)

	// Process complete lines
	for {
		idx := bytes.IndexByte(h.buffer, '\n')
		if idx == -1 {
			break
		}

		line := h.buffer[:idx]
		h.buffer = h.buffer[idx+1:]

		event := h.parser.ParseLine(line)
		h.display.ShowEvent(event)
	}

	return len(p), nil
}

func (h *streamHandler) Flush() {
	if len(h.buffer) > 0 {
		event := h.parser.ParseLine(h.buffer)
		h.display.ShowEvent(event)
		h.buffer = nil
	}
}
