package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func init() {
	engine.RegisterEngine("codex", func(cfg *engine.EngineConfig) engine.Engine {
		return New(cfg)
	})
}

// Engine executes prompts using OpenAI Codex CLI.
type Engine struct {
	Timeout time.Duration
	model   string
}

// New creates a new Codex engine.
func New(cfg *engine.EngineConfig) *Engine {
	e := &Engine{
		Timeout: engine.DefaultTimeout,
	}
	if cfg != nil && cfg.Model != "" {
		e.model = cfg.Model
	}
	return e
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
// Prompt is passed via stdin using "-" placeholder.
func (e *Engine) BuildArgs() []string {
	args := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
		"--json",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-") // Read prompt from stdin
	return args
}

// BuildArgsNoJSON returns CLI arguments without JSON flag.
func (e *Engine) BuildArgsNoJSON() []string {
	args := []string{
		"exec",
		"--dangerously-bypass-approvals-and-sandbox",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-") // Read prompt from stdin
	return args
}

// Execute runs the prompt using Codex CLI.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()

	// Build command
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Pass prompt via stdin
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()

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

	// Parse success from output
	success := e.parseSuccess(output)
	complete := strings.Contains(output, "<promise>COMPLETE</promise>")

	return engine.Result{
		Success:  success,
		Complete: complete,
		Output:   output,
		Duration: duration,
		Error:    nil,
	}
}

// parseSuccess checks if the Codex JSON response indicates success.
func (e *Engine) parseSuccess(output string) bool {
	lines := strings.Split(output, "\n")
	parser := NewParser()
	sawResult := false
	lastSuccess := true

	for _, line := range lines {
		event := parser.ParseLine([]byte(line))
		if event != nil && event.Type == engine.EventResult {
			sawResult = true
			lastSuccess = event.Data.Success
		}
	}

	if sawResult {
		return lastSuccess
	}

	if parser.HasFailure() {
		return false
	}

	// If we can't parse, assume success if no error
	return true
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

// Prompt executes a single prompt and returns the text response.
// This is a simpler interface for PRD generation, validation, etc.
func (e *Engine) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command - use stdin for prompt
	args := e.BuildArgsNoJSON()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()

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
// It uses --json flag for JSONL output to show progress via the display
// while collecting text content from assistant messages for return.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use BuildArgs which includes --json flag for streaming, prompt via stdin
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()

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

// textCollectingStreamHandler streams events to the display while
// collecting text content from Codex agent_message events.
type textCollectingStreamHandler struct {
	parser  *Parser
	display *engine.Display
	buffer  []byte
	text    strings.Builder
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
	// Show event on display
	event := h.parser.ParseLine(line)
	if h.display != nil {
		h.display.ShowEvent(event)
	}

	// Also extract text content from agent messages
	h.collectText(line)
}

func (h *textCollectingStreamHandler) collectText(line []byte) {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 {
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return
	}

	eventType, _ := raw["type"].(string)
	// Codex uses item.completed for completed agent messages
	if eventType != "item.completed" {
		return
	}

	item, ok := raw["item"].(map[string]interface{})
	if !ok {
		return
	}

	itemType, _ := item["type"].(string)
	if itemType != "agent_message" {
		return
	}

	// Extract text from agent_message
	if text, _ := item["text"].(string); text != "" {
		h.text.WriteString(text)
	}
}

func (h *textCollectingStreamHandler) Flush() {
	if len(h.buffer) > 0 {
		h.processLine(h.buffer)
		h.buffer = nil
	}
}

func (h *textCollectingStreamHandler) Text() string {
	return h.text.String()
}
