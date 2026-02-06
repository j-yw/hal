package standards

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/template"
)

// Load reads all .md files from the standards directory and returns
// them concatenated with section headers for prompt injection.
// Returns empty string (not error) if no standards exist.
func Load(halDir string) (string, error) {
	standardsDir := filepath.Join(halDir, template.StandardsDir)

	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		return "", nil
	}

	var sections []section
	err := filepath.WalkDir(standardsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only read .md files, skip index.yml and other non-standard files
		if filepath.Ext(path) != ".md" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read standard %s: %w", path, err)
		}

		trimmed := strings.TrimSpace(string(content))
		if trimmed == "" {
			return nil
		}

		// Use relative path from standards dir as the section key
		rel, _ := filepath.Rel(standardsDir, path)
		// Convert to forward slashes for consistent display
		rel = filepath.ToSlash(rel)
		// Strip .md extension for cleaner headers
		rel = strings.TrimSuffix(rel, ".md")

		sections = append(sections, section{key: rel, content: trimmed})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to load standards: %w", err)
	}

	if len(sections) == 0 {
		return "", nil
	}

	// Sort by key for deterministic output
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].key < sections[j].key
	})

	var b strings.Builder
	b.WriteString("## Project Standards\n\n")
	b.WriteString("You MUST follow these project-specific standards when implementing:\n\n")
	for i, s := range sections {
		if i > 0 {
			b.WriteString("\n\n---\n\n")
		}
		b.WriteString(fmt.Sprintf("### %s\n\n%s", s.key, s.content))
	}

	return b.String(), nil
}

// ListIndex reads the index.yml and returns its raw content.
// Returns empty string if no index exists.
func ListIndex(halDir string) (string, error) {
	indexPath := filepath.Join(halDir, template.StandardsDir, "index.yml")
	data, err := os.ReadFile(indexPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read standards index: %w", err)
	}
	return string(data), nil
}

// Count returns the number of .md standard files.
func Count(halDir string) (int, error) {
	standardsDir := filepath.Join(halDir, template.StandardsDir)
	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		return 0, nil
	}

	count := 0
	err := filepath.WalkDir(standardsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".md" {
			count++
		}
		return nil
	})
	return count, err
}

type section struct {
	key     string
	content string
}
