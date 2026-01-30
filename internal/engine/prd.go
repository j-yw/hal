package engine

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/template"
)

// PRD represents the structure of a prd.json file.
type PRD struct {
	Project     string      `json:"project"`
	BranchName  string      `json:"branchName"`
	Description string      `json:"description"`
	UserStories []UserStory `json:"userStories"`
	Tasks       []UserStory `json:"tasks,omitempty"`
}

// UserStory represents a single user story in the PRD.
type UserStory struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	AcceptanceCriteria []string `json:"acceptanceCriteria"`
	Priority           int      `json:"priority"`
	Passes             bool     `json:"passes"`
	Notes              string   `json:"notes"`
}

// LoadPRD reads and parses the default prd.json file (manual flow).
func LoadPRD(dir string) (*PRD, error) {
	return LoadPRDFile(dir, template.PRDFile)
}

// LoadPRDFile reads and parses a PRD from a specific file.
func LoadPRDFile(dir, filename string) (*PRD, error) {
	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var prd PRD
	if err := json.Unmarshal(data, &prd); err != nil {
		return nil, err
	}

	return &prd, nil
}

// CurrentStory returns the highest priority story that hasn't passed yet.
// Returns nil if all stories have passed.
// Checks UserStories first, then Tasks for backward compatibility.
func (p *PRD) CurrentStory() *UserStory {
	var current *UserStory

	// Check UserStories first (backward compatible)
	for i := range p.UserStories {
		story := &p.UserStories[i]
		if story.Passes {
			continue
		}
		if current == nil || story.Priority < current.Priority {
			current = story
		}
	}

	// If no UserStories found, check Tasks
	if current == nil {
		for i := range p.Tasks {
			story := &p.Tasks[i]
			if story.Passes {
				continue
			}
			if current == nil || story.Priority < current.Priority {
				current = story
			}
		}
	}

	return current
}

// Progress returns (completed, total) story counts.
// Counts both UserStories and Tasks for dual-format support.
func (p *PRD) Progress() (int, int) {
	completed := 0
	total := len(p.UserStories) + len(p.Tasks)

	for _, story := range p.UserStories {
		if story.Passes {
			completed++
		}
	}
	for _, task := range p.Tasks {
		if task.Passes {
			completed++
		}
	}

	return completed, total
}

// FindStoryByID returns a story by its ID, or nil if not found.
// Searches both UserStories and Tasks for dual-format support.
func (p *PRD) FindStoryByID(id string) *UserStory {
	for i := range p.UserStories {
		if p.UserStories[i].ID == id {
			return &p.UserStories[i]
		}
	}
	for i := range p.Tasks {
		if p.Tasks[i].ID == id {
			return &p.Tasks[i]
		}
	}
	return nil
}
