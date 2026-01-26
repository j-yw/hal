package engine

import (
	"fmt"
	"strings"
)

// engineConstructors maps engine names to their constructors.
// Engines register themselves via RegisterEngine.
var engineConstructors = make(map[string]func() Engine)

// RegisterEngine registers an engine constructor by name.
func RegisterEngine(name string, constructor func() Engine) {
	engineConstructors[strings.ToLower(name)] = constructor
}

// New creates an engine by name.
func New(name string) (Engine, error) {
	constructor, ok := engineConstructors[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown engine: %s (supported: %s)", name, strings.Join(Available(), ", "))
	}
	return constructor(), nil
}

// Available returns a list of registered engine names.
func Available() []string {
	names := make([]string, 0, len(engineConstructors))
	for name := range engineConstructors {
		names = append(names, name)
	}
	return names
}
