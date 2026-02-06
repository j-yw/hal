package pi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func init() {
	engine.RegisterEngine("pi", func(cfg *engine.EngineConfig) engine.Engine {
		return New(cfg)
	})
}

// Engine executes prompts using the pi coding agent CLI.
type Engine struct {
	Timeout  time.Duration
	model    string
	provider string
}

// New creates a new Pi engine.
func New(cfg *engine.EngineConfig) *Engine {
	e := &Engine{
		Timeout: engine.DefaultTimeout,
	}
	if cfg != nil {
		if cfg.Model != "" {
			e.model = cfg.Model
		}
		if cfg.Provider != "" {
			e.provider = cfg.Provider
		}
		if cfg.Timeout > 0 {
			e.Timeout = cfg.Timeout
		}
	}
	return e
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "pi"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "pi"
}

// BuildArgs returns the CLI arguments for streaming JSON execution.
// The prompt is passed via stdin, not as a CLI argument, to avoid
// OS argument length limits and pi's silent truncation of long args.
func (e *Engine) BuildArgs() []string {
	args := []string{
		"-p",
		"--no-session",
		"--mode", "json",
	}
	if e.provider != "" {
		args = append(args, "--provider", e.provider)
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	return args
}

// BuildArgsSimple returns CLI arguments for plain text output.
// The prompt is passed via stdin.
func (e *Engine) BuildArgsSimple() []string {
	args := []string{
		"-p",
		"--no-session",
	}
	if e.provider != "" {
		args = append(args, "--provider", e.provider)
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	return args
}

// Execute runs the prompt using pi CLI with streaming JSON output.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()

	// Build command — prompt is piped via stdin to avoid OS arg length limits.
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Pipe prompt via stdin.
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

	// Set up output capture with streaming parser
	var stdout, stderr bytes.Buffer
	parser := NewParser()
	streamWriter := &streamHandler{
		parser:  parser,
		display: display,
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

	// Parse success and completion from parser state
	success := !parser.HasFailure()
	complete := strings.Contains(output, "<promise>COMPLETE</promise>")

	return engine.Result{
		Success:  success,
		Complete: complete,
		Output:   output,
		Duration: duration,
		Tokens:   parser.TotalTokens(),
		Error:    nil,
	}
}

// Prompt executes a single prompt and returns the text response.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command with plain text output — prompt piped via stdin.
	args := e.BuildArgsSimple()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

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

// StreamPrompt executes a prompt with streaming display feedback.
// It uses JSON mode to show progress via the display while collecting
// the text response for return.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use streaming JSON args — prompt piped via stdin.
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

	var stdout, stderr bytes.Buffer
	parser := NewParser()
	collector := &textCollectingStreamHandler{
		parser:  parser,
		display: display,
	}

	cmd.Stdout = io.MultiWriter(collector, &stdout)
	cmd.Stderr = &stderr

	err := cmd.Run()
	collector.Flush()

	if display != nil {
		display.StopSpinner()
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("prompt timed out after %s", timeout)
		}
		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return collector.Text(), nil
}

// streamHandler processes output line by line for Execute.
type streamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
}

func (h *streamHandler) Write(p []byte) (n int, err error) {
	h.buffer = append(h.buffer, p...)

	for {
		idx := bytes.IndexByte(h.buffer, '\n')
		if idx == -1 {
			break
		}

		line := h.buffer[:idx]
		h.buffer = h.buffer[idx+1:]

		event := h.parser.ParseLine(line)
		if h.display != nil {
			h.display.ShowEvent(event)
		}
	}

	return len(p), nil
}

func (h *streamHandler) Flush() {
	if len(h.buffer) > 0 {
		event := h.parser.ParseLine(h.buffer)
		if h.display != nil {
			h.display.ShowEvent(event)
		}
		h.buffer = nil
	}
}

// textCollectingStreamHandler streams events to the display while
// collecting text content from assistant messages.
type textCollectingStreamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
}

func (h *textCollectingStreamHandler) Write(p []byte) (n int, err error) {
	h.buffer = append(h.buffer, p...)

	for {
		idx := bytes.IndexByte(h.buffer, '\n')
		if idx == -1 {
			break
		}

		line := h.buffer[:idx]
		h.buffer = h.buffer[idx+1:]

		h.processLine(line)
	}

	return len(p), nil
}

func (h *textCollectingStreamHandler) processLine(line []byte) {
	event := h.parser.ParseLine(line)
	if h.display != nil {
		h.display.ShowEvent(event)
	}
}

func (h *textCollectingStreamHandler) Flush() {
	if len(h.buffer) > 0 {
		h.processLine(h.buffer)
		h.buffer = nil
	}
}

func (h *textCollectingStreamHandler) Text() string {
	return h.parser.CollectedText()
}
