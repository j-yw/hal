package engine

import (
	"fmt"
	"strings"
)

// engineConstructors maps engine names to their constructors.
// Engines register themselves via RegisterEngine.
var engineConstructors = make(map[string]func(*EngineConfig) Engine)

// RegisterEngine registers an engine constructor by name.
func RegisterEngine(name string, constructor func(*EngineConfig) Engine) {
	engineConstructors[strings.ToLower(name)] = constructor
}

// New creates an engine by name with default configuration.
func New(name string) (Engine, error) {
	return NewWithConfig(name, nil)
}

// NewWithConfig creates an engine by name with optional configuration.
// If cfg is nil, the engine uses its own defaults.
func NewWithConfig(name string, cfg *EngineConfig) (Engine, error) {
	constructor, ok := engineConstructors[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown engine: %s (supported: %s)", name, strings.Join(Available(), ", "))
	}
	return constructor(cfg), nil
}

// Available returns a list of registered engine names.
func Available() []string {
	names := make([]string, 0, len(engineConstructors))
	for name := range engineConstructors {
		names = append(names, name)
	}
	return names
}
