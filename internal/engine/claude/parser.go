package claude

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
)

// Parser parses Claude's stream-json output format.
type Parser struct{}

// NewParser creates a new Claude output parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLine parses a single JSON line from Claude's stream-json output.
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
	case "system":
		return p.parseSystem(raw)
	case "assistant":
		return p.parseAssistant(raw)
	case "result":
		return p.parseResult(raw)
	default:
		return nil
	}
}

func (p *Parser) parseSystem(raw map[string]interface{}) *engine.Event {
	subtype, _ := raw["subtype"].(string)
	if subtype != "init" {
		return nil
	}

	model, _ := raw["model"].(string)
	return &engine.Event{
		Type: engine.EventInit,
		Data: engine.EventData{
			Model: model,
		},
	}
}

func (p *Parser) parseAssistant(raw map[string]interface{}) *engine.Event {
	msg, ok := raw["message"].(map[string]interface{})
	if !ok {
		return nil
	}

	content, ok := msg["content"].([]interface{})
	if !ok {
		return nil
	}

	// Look for tool_use blocks
	for _, item := range content {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		blockType, _ := block["type"].(string)
		if blockType == "tool_use" {
			return p.parseToolUse(block)
		}
	}

	return nil
}

func (p *Parser) parseToolUse(block map[string]interface{}) *engine.Event {
	name, _ := block["name"].(string)
	input, _ := block["input"].(map[string]interface{})

	event := &engine.Event{
		Type: engine.EventTool,
		Tool: strings.ToLower(name),
	}

	// Extract relevant detail based on tool type
	switch name {
	case "Read":
		path, _ := input["file_path"].(string)
		event.Detail = shortPath(path)

	case "Write":
		path, _ := input["file_path"].(string)
		event.Detail = shortPath(path)

	case "Edit":
		path, _ := input["file_path"].(string)
		event.Detail = shortPath(path)

	case "Glob":
		pattern, _ := input["pattern"].(string)
		event.Detail = pattern

	case "Grep":
		pattern, _ := input["pattern"].(string)
		event.Detail = truncate(pattern, 40)

	case "Bash":
		desc, _ := input["description"].(string)
		if desc != "" {
			event.Detail = truncate(desc, 50)
		} else {
			cmd, _ := input["command"].(string)
			event.Detail = truncate(cmd, 50)
		}
		event.Tool = "run"

	case "Task":
		desc, _ := input["description"].(string)
		event.Detail = truncate(desc, 50)
		event.Tool = "task"

	case "WebFetch":
		url, _ := input["url"].(string)
		event.Detail = truncate(url, 50)
		event.Tool = "fetch"

	case "WebSearch":
		query, _ := input["query"].(string)
		event.Detail = truncate(query, 40)
		event.Tool = "search"

	default:
		event.Tool = strings.ToLower(name)
	}

	return event
}

func (p *Parser) parseResult(raw map[string]interface{}) *engine.Event {
	subtype, _ := raw["subtype"].(string)
	durationMs, _ := raw["duration_ms"].(float64)

	// Calculate total tokens
	var tokens int
	if usage, ok := raw["usage"].(map[string]interface{}); ok {
		if in, ok := usage["input_tokens"].(float64); ok {
			tokens += int(in)
		}
		if out, ok := usage["output_tokens"].(float64); ok {
			tokens += int(out)
		}
		if cache, ok := usage["cache_read_input_tokens"].(float64); ok {
			tokens += int(cache)
		}
		if cacheCreate, ok := usage["cache_creation_input_tokens"].(float64); ok {
			tokens += int(cacheCreate)
		}
	}

	return &engine.Event{
		Type: engine.EventResult,
		Data: engine.EventData{
			Success:    subtype == "success",
			DurationMs: durationMs,
			Tokens:     tokens,
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

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return ".../" + strings.Join(parts[len(parts)-2:], "/")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
