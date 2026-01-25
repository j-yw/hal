package parser

import (
	"strings"
	"testing"
)

func TestParse_PendingTasks(t *testing.T) {
	input := `# My PRD

- [ ] First task
- [ ] Second task
- [ ] Third task
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(tasks))
	}

	expected := []struct {
		desc string
		line int
	}{
		{"First task", 3},
		{"Second task", 4},
		{"Third task", 5},
	}

	for i, exp := range expected {
		if tasks[i].Description != exp.desc {
			t.Errorf("task %d: expected description %q, got %q", i, exp.desc, tasks[i].Description)
		}
		if tasks[i].LineNumber != exp.line {
			t.Errorf("task %d: expected line %d, got %d", i, exp.line, tasks[i].LineNumber)
		}
	}
}

func TestParse_CompletedTasksSkipped(t *testing.T) {
	input := `- [x] Completed task lowercase
- [X] Completed task uppercase
- [ ] Pending task
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 pending task, got %d", len(tasks))
	}

	if tasks[0].Description != "Pending task" {
		t.Errorf("expected 'Pending task', got %q", tasks[0].Description)
	}
	if tasks[0].LineNumber != 3 {
		t.Errorf("expected line 3, got %d", tasks[0].LineNumber)
	}
}

func TestParse_MultiLineDescription(t *testing.T) {
	input := `- [ ] Main task description
  This is a continuation line
  And another continuation
- [ ] Next task
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}

	expectedDesc := "Main task description\nThis is a continuation line\nAnd another continuation"
	if tasks[0].Description != expectedDesc {
		t.Errorf("expected multi-line description %q, got %q", expectedDesc, tasks[0].Description)
	}
	if tasks[0].LineNumber != 1 {
		t.Errorf("expected line 1, got %d", tasks[0].LineNumber)
	}

	if tasks[1].Description != "Next task" {
		t.Errorf("expected 'Next task', got %q", tasks[1].Description)
	}
}

func TestParse_TabIndentedContinuation(t *testing.T) {
	input := `- [ ] Task with tab indent
	Tab indented continuation
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	expectedDesc := "Task with tab indent\nTab indented continuation"
	if tasks[0].Description != expectedDesc {
		t.Errorf("expected %q, got %q", expectedDesc, tasks[0].Description)
	}
}

func TestParse_MixedContent(t *testing.T) {
	input := `# PRD Document

## Overview
Some introductory text.

## Tasks

- [x] Already done
- [ ] First pending task
  with continuation
- Regular list item (ignored)
- [X] Also completed
- [ ] Second pending task

## Notes
More text at the end.
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 2 {
		t.Fatalf("expected 2 pending tasks, got %d", len(tasks))
	}

	if tasks[0].Description != "First pending task\nwith continuation" {
		t.Errorf("unexpected first task: %q", tasks[0].Description)
	}
	if tasks[0].LineNumber != 9 {
		t.Errorf("expected line 9, got %d", tasks[0].LineNumber)
	}

	if tasks[1].Description != "Second pending task" {
		t.Errorf("unexpected second task: %q", tasks[1].Description)
	}
	if tasks[1].LineNumber != 13 {
		t.Errorf("expected line 13, got %d", tasks[1].LineNumber)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	tasks, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
}

func TestParse_NoTasks(t *testing.T) {
	input := `# Document with no tasks

Just some regular markdown content.
- Regular list
- Another item
`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
}

func TestParse_TaskAtEndOfFile(t *testing.T) {
	input := `- [ ] Last task without newline`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	if tasks[0].Description != "Last task without newline" {
		t.Errorf("unexpected description: %q", tasks[0].Description)
	}
}

func TestParse_ContinuationAtEndOfFile(t *testing.T) {
	input := `- [ ] Task with continuation
  continuation at EOF`
	tasks, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	expectedDesc := "Task with continuation\ncontinuation at EOF"
	if tasks[0].Description != expectedDesc {
		t.Errorf("expected %q, got %q", expectedDesc, tasks[0].Description)
	}
}
