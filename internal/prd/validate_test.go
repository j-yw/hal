package prd

import (
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestValidateSchedulingDependencies_AllowsStoryAndTaskDependencies(t *testing.T) {
	prd := &engine.PRD{
		UserStories: []engine.UserStory{
			{ID: "US-001"},
		},
		Tasks: []engine.UserStory{
			{ID: "T-001", DependsOn: []string{"US-001"}},
			{ID: "T-002", DependsOn: []string{"T-001"}},
		},
	}

	if issues := ValidateSchedulingDependencies(prd); len(issues) != 0 {
		t.Fatalf("ValidateSchedulingDependencies returned issues: %#v", issues)
	}
}

func TestValidateSchedulingDependencies_DetectsInvalidSchedulingMetadata(t *testing.T) {
	parallelSafe := false
	prd := &engine.PRD{
		UserStories: []engine.UserStory{
			{ID: "US-001", DependsOn: []string{"US-999"}},
			{ID: "US-002", DependsOn: []string{"US-002"}},
			{ID: "US-003", DependsOn: []string{"US-004"}},
			{ID: "US-004", DependsOn: []string{"US-003"}},
			{ID: "US-005", ParallelSafe: &parallelSafe},
			{ID: "US-006", Barrier: true},
			{ID: "US-006"},
		},
	}

	issues := ValidateSchedulingDependencies(prd)
	want := []Issue{
		{
			StoryID:  "US-006",
			Field:    "id",
			Message:  "US-006 duplicates an earlier story/task ID",
			Severity: "error",
		},
		{
			StoryID:  "US-001",
			Field:    "dependsOn",
			Message:  "US-001 depends on unknown story ID US-999",
			Severity: "error",
		},
		{
			StoryID:  "US-002",
			Field:    "dependsOn",
			Message:  "US-002 must not depend on itself",
			Severity: "error",
		},
		{
			StoryID:  "US-003",
			Field:    "dependsOn",
			Message:  "US-003 depends on later story ID US-004",
			Severity: "error",
		},
		{
			StoryID:  "US-005",
			Field:    "parallelReason",
			Message:  "US-005 must include parallelReason when parallelSafe or barrier is set",
			Severity: "error",
		},
		{
			StoryID:  "US-006",
			Field:    "parallelReason",
			Message:  "US-006 must include parallelReason when parallelSafe or barrier is set",
			Severity: "error",
		},
		{
			StoryID:  "US-004",
			Field:    "dependsOn",
			Message:  "dependency cycle detected: US-003 -> US-004 -> US-003",
			Severity: "error",
		},
	}

	if len(issues) != len(want) {
		t.Fatalf("issue count = %d, want %d: %#v", len(issues), len(want), issues)
	}
	for i := range want {
		if issues[i] != want[i] {
			t.Fatalf("issue[%d] = %#v, want %#v", i, issues[i], want[i])
		}
	}
}
