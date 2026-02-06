package skills

// EngineLinker handles skill and command installation for a specific engine.
type EngineLinker interface {
	// Name returns the engine identifier (e.g., "claude").
	Name() string

	// SkillsDir returns where the engine looks for skills.
	SkillsDir() string

	// CommandsDir returns where the engine looks for user-invocable commands.
	// Returns "" if the engine doesn't support a commands directory.
	CommandsDir() string

	// Link creates links/copies from .hal/skills/ to engine's skill directory.
	Link(projectDir string, skills []string) error

	// LinkCommands creates a link from .hal/commands/ to engine's commands directory.
	LinkCommands(projectDir string) error

	// Unlink removes links/copies from engine's skill directory.
	Unlink(projectDir string) error
}

// linkers holds registered engine linkers.
var linkers = map[string]EngineLinker{}

// RegisterLinker registers an engine linker by name.
func RegisterLinker(l EngineLinker) {
	linkers[l.Name()] = l
}

// GetLinker returns a linker by name, or nil if not found.
func GetLinker(name string) EngineLinker {
	return linkers[name]
}
