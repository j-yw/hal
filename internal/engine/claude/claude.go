package claude

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
	engine.RegisterEngine("claude", func(cfg *engine.EngineConfig) engine.Engine {
		return New(cfg)
	})
}

// Engine executes prompts using Claude Code CLI.
type Engine struct {
	Timeout time.Duration
	model   string
}

// New creates a new Claude engine.
func New(cfg *engine.EngineConfig) *Engine {
	e := &Engine{
		Timeout: engine.DefaultTimeout,
	}
	if cfg != nil {
		if cfg.Model != "" {
			e.model = cfg.Model
		}
		if cfg.Timeout > 0 {
			e.Timeout = cfg.Timeout
		}
	}
	return e
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return "claude"
}

// CLICommand returns the CLI executable name.
func (e *Engine) CLICommand() string {
	return "claude"
}

// BuildArgs returns the CLI arguments for execution.
// Prompt content is piped via stdin to avoid argument-length issues.
func (e *Engine) BuildArgs() []string {
	args := []string{
		"-p",
		"--dangerously-skip-permissions",
		"--verbose",
		"--output-format", "stream-json",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	return args
}

func contextRunError(ctx context.Context, timeout time.Duration, operation string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if ctxErr == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out after %s", operation, timeout)
		}
		return fmt.Errorf("%s canceled: %w", operation, ctxErr)
	}

	return nil
}

// Execute runs the prompt using Claude Code CLI.
func (e *Engine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()

	// Build command. Prompt is piped via stdin.
	args := e.BuildArgs()
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)

	// Detach from TTY to suppress interactive UI hints.
	//
	// Claude Code CLI displays interactive hints like "ctrl+b to run in background"
	// when it detects a TTY. These are written directly to /dev/tty.
	//
	// To suppress these hints, we:
	// 1. Set Stdin to nil (no input)
	// 2. Create a new session (Setsid) to detach from controlling terminal
	//
	// This ensures clean, parseable output without interactive UI elements.
	// Prompt is sent via stdin instead of argv.
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

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

	// Handle errors.
	if err != nil {
		if runErr := contextRunError(ctx, timeout, "execution"); runErr != nil {
			return engine.Result{
				Success:  false,
				Output:   output,
				Duration: duration,
				Error:    runErr,
			}
		}

		// Some Claude CLI versions may emit a successful result event but still
		// return a non-zero exit code. Trust the structured stream result when present.
		if hasResult, success := e.parseResultStatus(output); hasResult && success {
			complete := strings.Contains(output, "<promise>COMPLETE</promise>")
			return engine.Result{
				Success:  true,
				Complete: complete,
				Output:   output,
				Duration: duration,
				Error:    nil,
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

// parseResultStatus checks the Claude stream for a terminal result event.
func (e *Engine) parseResultStatus(output string) (hasResult bool, success bool) {
	lines := strings.Split(output, "\n")
	parser := NewParser()

	hasResult = false
	success = false
	for _, line := range lines {
		event := parser.ParseLine([]byte(line))
		if event != nil && event.Type == engine.EventResult {
			hasResult = true
			success = event.Data.Success
		}
	}

	return hasResult, success
}

// parseSuccess checks if the Claude JSON response indicates success.
func (e *Engine) parseSuccess(output string) bool {
	hasResult, success := e.parseResultStatus(output)
	if hasResult {
		return success
	}

	// If we can't parse a terminal result, keep legacy optimistic behavior.
	return true
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

	// Build command - similar to Execute but simpler output handling.
	// Prompt is piped via stdin.
	args := []string{
		"-p",
		"--dangerously-skip-permissions",
	}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	cmd := exec.CommandContext(ctx, e.CLICommand(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if runErr := contextRunError(ctx, timeout, "prompt"); runErr != nil {
			return "", runErr
		}

		// Tolerate non-zero exit if Claude still produced a response and no stderr.
		if strings.TrimSpace(stdout.String()) != "" && strings.TrimSpace(stderr.String()) == "" {
			return stdout.String(), nil
		}

		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// StreamPrompt executes a prompt with streaming display feedback.
// It uses stream-json output to show progress via the display while
// collecting the text response for return.
func (e *Engine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = engine.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use same flags as Execute for streaming. Prompt is piped via stdin.
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
		if runErr := contextRunError(ctx, timeout, "prompt"); runErr != nil {
			return "", runErr
		}

		// Some Claude CLI versions may exit non-zero after emitting a successful
		// stream result. If the stream result is success, treat this as success.
		output := stdout.String()
		if hasResult, success := e.parseResultStatus(output); hasResult && success {
			if text := strings.TrimSpace(collector.Text()); text != "" {
				return collector.Text(), nil
			}
			if recovered := collectAssistantTextFromStream(output); strings.TrimSpace(recovered) != "" {
				return recovered, nil
			}
		}

		return "", fmt.Errorf("prompt failed: %w (stderr: %s)", err, stderr.String())
	}

	return collector.Text(), nil
}

// textCollectingStreamHandler streams events to the display while
// collecting text content from assistant messages.
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

	// Also extract text content from assistant messages
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
	if eventType != "assistant" {
		return
	}

	msg, ok := raw["message"].(map[string]interface{})
	if !ok {
		return
	}

	content, ok := msg["content"].([]interface{})
	if !ok {
		return
	}

	for _, item := range content {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if blockType, _ := block["type"].(string); blockType == "text" {
			if text, _ := block["text"].(string); text != "" {
				h.text.WriteString(text)
			}
		}
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

func collectAssistantTextFromStream(output string) string {
	var text strings.Builder
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			continue
		}
		eventType, _ := raw["type"].(string)
		if eventType != "assistant" {
			continue
		}

		msg, ok := raw["message"].(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := msg["content"].([]interface{})
		if !ok {
			continue
		}

		for _, item := range content {
			block, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if blockType, _ := block["type"].(string); blockType == "text" {
				if t, _ := block["text"].(string); t != "" {
					text.WriteString(t)
				}
			}
		}
	}

	return text.String()
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
