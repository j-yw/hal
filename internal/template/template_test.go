package template

import (
	"strings"
	"testing"
)

func TestDefaultPrompt_CommitsAfterBookkeeping(t *testing.T) {
	prdIdx := strings.Index(DefaultPrompt, "8. Update `.hal/{{PRD_FILE}}` to set `passes: true` for the completed story")
	progressIdx := strings.Index(DefaultPrompt, "9. Append your progress to `.hal/{{PROGRESS_FILE}}`")
	commitIdx := strings.Index(DefaultPrompt, "10. If checks pass, commit ALL changes, including `.hal/{{PRD_FILE}}` and `.hal/{{PROGRESS_FILE}}`")
	if prdIdx == -1 || progressIdx == -1 || commitIdx == -1 {
		t.Fatalf("default prompt missing expected bookkeeping/commit instructions:\n%s", DefaultPrompt)
	}
	if !(prdIdx < progressIdx && progressIdx < commitIdx) {
		t.Fatalf("default prompt should update PRD and progress before commit")
	}
}

func TestDefaultPrompt_StopConditionRequiresCleanCommittedBookkeeping(t *testing.T) {
	required := []string{
		"1. Every story in `.hal/{{PRD_FILE}}` has `passes: true`",
		"2. `git status --short` is empty",
		"3. Your latest commit includes `.hal/{{PRD_FILE}}` and `.hal/{{PROGRESS_FILE}}`",
		"If there are still stories with `passes: false`, end your response normally even if you completed the current story",
	}
	for _, needle := range required {
		if !strings.Contains(DefaultPrompt, needle) {
			t.Fatalf("default prompt should contain %q", needle)
		}
	}
}
