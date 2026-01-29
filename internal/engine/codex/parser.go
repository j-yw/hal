package codex

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/goralph/internal/engine"
)

// Parser parses Codex CLI JSONL output format.
type Parser struct {
	commandFailed bool
}

// NewParser creates a new Codex output parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLine parses a single JSON line from Codex's JSONL output.
func (p *Parser) ParseLine(line []byte) *engine.Event {
	line = trimSpace(line)
	if len(line) == 0 {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil
	}

	eventType, _ := raw["type"].(string)

	switch eventType {
	case "thread.started":
		return p.parseThreadStarted(raw)
	case "item.started", "item.completed":
		return p.parseItem(raw)
	case "turn.completed":
		return p.parseTurnCompleted(raw)
	default:
		return nil
	}
}

func (p *Parser) parseThreadStarted(raw map[string]interface{}) *engine.Event {
	return &engine.Event{
		Type: engine.EventInit,
		Data: engine.EventData{
			Model: "codex", // Codex doesn't include model in thread.started
		},
	}
}

func (p *Parser) parseItem(raw map[string]interface{}) *engine.Event {
	item, ok := raw["item"].(map[string]interface{})
	if !ok {
		return nil
	}

	itemType, _ := item["type"].(string)

	switch itemType {
	case "command_execution":
		return p.parseCommandExecution(item, raw["type"].(string))
	case "agent_message":
		return p.parseAgentMessage(item)
	case "reasoning":
		return p.parseReasoning(item)
	default:
		return nil
	}
}

func (p *Parser) parseCommandExecution(item map[string]interface{}, eventType string) *engine.Event {
	command, _ := item["command"].(string)
	status, _ := item["status"].(string)

	// Extract the actual command from bash wrapper
	detail := extractCommand(command)

	event := &engine.Event{
		Type:   engine.EventTool,
		Tool:   "run",
		Detail: truncate(detail, 50),
	}

	// If item.completed with exit_code != 0, it's an error
	if eventType == "item.completed" {
		if exitCode, ok := item["exit_code"].(float64); ok && exitCode != 0 {
			p.commandFailed = true
			event.Type = engine.EventError
			event.Data.Message = "command failed"
		}
	}

	// Include status in detail for in-progress items
	if status == "in_progress" {
		event.Detail = truncate(detail, 45) + "..."
	}

	return event
}

func (p *Parser) parseAgentMessage(item map[string]interface{}) *engine.Event {
	text, _ := item["text"].(string)

	return &engine.Event{
		Type:   engine.EventText,
		Detail: truncate(text, 80),
	}
}

func (p *Parser) parseReasoning(item map[string]interface{}) *engine.Event {
	text, _ := item["text"].(string)

	return &engine.Event{
		Type:   engine.EventText,
		Tool:   "thinking",
		Detail: truncate(text, 60),
	}
}

func (p *Parser) parseTurnCompleted(raw map[string]interface{}) *engine.Event {
	var tokens int

	if usage, ok := raw["usage"].(map[string]interface{}); ok {
		if in, ok := usage["input_tokens"].(float64); ok {
			tokens += int(in)
		}
		if out, ok := usage["output_tokens"].(float64); ok {
			tokens += int(out)
		}
		if cached, ok := usage["cached_input_tokens"].(float64); ok {
			tokens += int(cached)
		}
	}

	success := !p.commandFailed
	p.commandFailed = false

	return &engine.Event{
		Type: engine.EventResult,
		Data: engine.EventData{
			Success: success,
			Tokens:  tokens,
		},
	}
}

// Helper functions

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// extractCommand extracts the actual command from bash wrapper like:
// "/usr/bin/bash -lc 'echo hello world'" -> "echo hello world"
func extractCommand(command string) string {
	// Look for bash -lc pattern
	if idx := strings.Index(command, "-lc '"); idx != -1 {
		start := idx + 5
		if end := strings.LastIndex(command, "'"); end > start {
			return command[start:end]
		}
	}

	// Look for bash -c pattern
	if idx := strings.Index(command, "-c '"); idx != -1 {
		start := idx + 4
		if end := strings.LastIndex(command, "'"); end > start {
			return command[start:end]
		}
	}

	return command
}
