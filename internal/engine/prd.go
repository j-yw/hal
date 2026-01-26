package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// PRD represents the structure of a prd.json file.
type PRD struct {
	Project     string      `json:"project"`
	BranchName  string      `json:"branchName"`
	Description string      `json:"description"`
	UserStories []UserStory `json:"userStories"`
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

// LoadPRD reads and parses a prd.json file.
func LoadPRD(dir string) (*PRD, error) {
	path := filepath.Join(dir, "prd.json")
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
func (p *PRD) CurrentStory() *UserStory {
	var current *UserStory

	for i := range p.UserStories {
		story := &p.UserStories[i]
		if story.Passes {
			continue
		}
		if current == nil || story.Priority < current.Priority {
			current = story
		}
	}

	return current
}

// Progress returns (completed, total) story counts.
func (p *PRD) Progress() (int, int) {
	completed := 0
	for _, story := range p.UserStories {
		if story.Passes {
			completed++
		}
	}
	return completed, len(p.UserStories)
}
