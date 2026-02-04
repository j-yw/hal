package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestPRD_CurrentStory_UserStoriesFormat(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Priority: 2, Passes: false},
			{ID: "US-002", Priority: 1, Passes: false},
			{ID: "US-003", Priority: 3, Passes: true},
		},
	}

	story := prd.CurrentStory()
	if story == nil {
		t.Fatal("expected a story, got nil")
	}
	if story.ID != "US-002" {
		t.Errorf("expected US-002 (lowest priority not passed), got %s", story.ID)
	}
}

func TestPRD_CurrentStory_TasksFormat(t *testing.T) {
	prd := &PRD{
		Tasks: []UserStory{
			{ID: "T-001", Priority: 2, Passes: false},
			{ID: "T-002", Priority: 1, Passes: false},
			{ID: "T-003", Priority: 3, Passes: true},
		},
	}

	story := prd.CurrentStory()
	if story == nil {
		t.Fatal("expected a story, got nil")
	}
	if story.ID != "T-002" {
		t.Errorf("expected T-002 (lowest priority not passed), got %s", story.ID)
	}
}

func TestPRD_CurrentStory_UserStoriesTakesPrecedence(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Priority: 2, Passes: false},
		},
		Tasks: []UserStory{
			{ID: "T-001", Priority: 1, Passes: false},
		},
	}

	story := prd.CurrentStory()
	if story == nil {
		t.Fatal("expected a story, got nil")
	}
	// UserStories should be checked first (backward compatible)
	if story.ID != "US-001" {
		t.Errorf("expected US-001 (UserStories takes precedence), got %s", story.ID)
	}
}

func TestPRD_CurrentStory_AllPassed(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Priority: 1, Passes: true},
		},
		Tasks: []UserStory{
			{ID: "T-001", Priority: 1, Passes: true},
		},
	}

	story := prd.CurrentStory()
	if story != nil {
		t.Errorf("expected nil when all passed, got %s", story.ID)
	}
}

func TestPRD_Progress_UserStoriesFormat(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Passes: true},
			{ID: "US-002", Passes: false},
			{ID: "US-003", Passes: true},
		},
	}

	completed, total := prd.Progress()
	if completed != 2 {
		t.Errorf("expected 2 completed, got %d", completed)
	}
	if total != 3 {
		t.Errorf("expected 3 total, got %d", total)
	}
}

func TestPRD_Progress_TasksFormat(t *testing.T) {
	prd := &PRD{
		Tasks: []UserStory{
			{ID: "T-001", Passes: true},
			{ID: "T-002", Passes: false},
			{ID: "T-003", Passes: true},
		},
	}

	completed, total := prd.Progress()
	if completed != 2 {
		t.Errorf("expected 2 completed, got %d", completed)
	}
	if total != 3 {
		t.Errorf("expected 3 total, got %d", total)
	}
}

func TestPRD_Progress_BothFormats(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Passes: true},
			{ID: "US-002", Passes: false},
		},
		Tasks: []UserStory{
			{ID: "T-001", Passes: true},
			{ID: "T-002", Passes: true},
		},
	}

	completed, total := prd.Progress()
	if completed != 3 {
		t.Errorf("expected 3 completed, got %d", completed)
	}
	if total != 4 {
		t.Errorf("expected 4 total, got %d", total)
	}
}

func TestPRD_FindStoryByID_InUserStories(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Title: "User Story 1"},
			{ID: "US-002", Title: "User Story 2"},
		},
		Tasks: []UserStory{
			{ID: "T-001", Title: "Task 1"},
		},
	}

	story := prd.FindStoryByID("US-002")
	if story == nil {
		t.Fatal("expected to find story, got nil")
	}
	if story.Title != "User Story 2" {
		t.Errorf("expected 'User Story 2', got '%s'", story.Title)
	}
}

func TestPRD_FindStoryByID_InTasks(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Title: "User Story 1"},
		},
		Tasks: []UserStory{
			{ID: "T-001", Title: "Task 1"},
			{ID: "T-002", Title: "Task 2"},
		},
	}

	story := prd.FindStoryByID("T-002")
	if story == nil {
		t.Fatal("expected to find story, got nil")
	}
	if story.Title != "Task 2" {
		t.Errorf("expected 'Task 2', got '%s'", story.Title)
	}
}

func TestPRD_FindStoryByID_NotFound(t *testing.T) {
	prd := &PRD{
		UserStories: []UserStory{
			{ID: "US-001", Title: "User Story 1"},
		},
		Tasks: []UserStory{
			{ID: "T-001", Title: "Task 1"},
		},
	}

	story := prd.FindStoryByID("US-999")
	if story != nil {
		t.Errorf("expected nil for non-existent ID, got %s", story.ID)
	}
}

func TestLoadPRD_UserStoriesFormat(t *testing.T) {
	dir := t.TempDir()
	prdData := `{
		"project": "test",
		"branchName": "test-branch",
		"description": "Test PRD",
		"userStories": [
			{"id": "US-001", "title": "Story 1", "priority": 1, "passes": false}
		]
	}`
	if err := os.WriteFile(filepath.Join(dir, template.PRDFile), []byte(prdData), 0644); err != nil {
		t.Fatal(err)
	}

	prd, err := LoadPRD(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(prd.UserStories) != 1 {
		t.Errorf("expected 1 user story, got %d", len(prd.UserStories))
	}
	if len(prd.Tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(prd.Tasks))
	}
}

func TestLoadPRD_TasksFormat(t *testing.T) {
	dir := t.TempDir()
	prdData := `{
		"project": "test",
		"branchName": "test-branch",
		"description": "Test PRD",
		"tasks": [
			{"id": "T-001", "title": "Task 1", "priority": 1, "passes": false}
		]
	}`
	if err := os.WriteFile(filepath.Join(dir, template.PRDFile), []byte(prdData), 0644); err != nil {
		t.Fatal(err)
	}

	prd, err := LoadPRD(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(prd.UserStories) != 0 {
		t.Errorf("expected 0 user stories, got %d", len(prd.UserStories))
	}
	if len(prd.Tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(prd.Tasks))
	}
}

func TestPRD_JSONSerialization_TasksOmitEmpty(t *testing.T) {
	prd := &PRD{
		Project:     "test",
		BranchName:  "test-branch",
		Description: "Test",
		UserStories: []UserStory{
			{ID: "US-001", Title: "Story 1"},
		},
		// Tasks is empty
	}

	data, err := json.Marshal(prd)
	if err != nil {
		t.Fatal(err)
	}

	// Tasks should not appear in JSON when empty (omitempty)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	if _, exists := result["tasks"]; exists {
		t.Error("expected 'tasks' to be omitted when empty, but it was present")
	}
}
