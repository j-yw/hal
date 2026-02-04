package skills

// EngineLinker handles skill installation for a specific engine.
type EngineLinker interface {
	// Name returns the engine identifier (e.g., "claude").
	Name() string

	// SkillsDir returns where the engine looks for skills.
	SkillsDir() string

	// Link creates links/copies from .hal/skills/ to engine's skill directory.
	Link(projectDir string, skills []string) error

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

// AvailableLinkers returns the names of all registered linkers.
func AvailableLinkers() []string {
	names := make([]string, 0, len(linkers))
	for name := range linkers {
		names = append(names, name)
	}
	return names
}
