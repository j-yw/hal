package parser

import (
	"bufio"
	"io"
	"strings"
)

// Task represents a pending task extracted from a PRD markdown file
type Task struct {
	Description string // Full task description including any continuation lines
	LineNumber  int    // 1-based line number where the task starts
}

// Parse reads a markdown PRD and extracts all pending tasks.
// It looks for lines starting with "- [ ]" (unchecked checkbox).
// Lines starting with "- [x]" or "- [X]" are treated as completed and skipped.
// Multi-line task descriptions are supported via indented continuation lines.
func Parse(r io.Reader) ([]Task, error) {
	var tasks []Task
	scanner := bufio.NewScanner(r)
	lineNum := 0

	var currentTask *Task

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for pending task (unchecked checkbox)
		if strings.HasPrefix(line, "- [ ] ") {
			// Save any previous task
			if currentTask != nil {
				tasks = append(tasks, *currentTask)
			}
			// Start new pending task
			description := strings.TrimPrefix(line, "- [ ] ")
			currentTask = &Task{
				Description: description,
				LineNumber:  lineNum,
			}
			continue
		}

		// Check for completed task (checked checkbox) - skip it
		if strings.HasPrefix(line, "- [x] ") || strings.HasPrefix(line, "- [X] ") {
			// Save any previous pending task
			if currentTask != nil {
				tasks = append(tasks, *currentTask)
				currentTask = nil
			}
			continue
		}

		// Check for continuation line (indented)
		// Continuation lines start with whitespace (space or tab)
		if currentTask != nil && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Append to current task description
			currentTask.Description += "\n" + strings.TrimLeft(line, " \t")
			continue
		}

		// Non-continuation, non-task line ends the current task
		if currentTask != nil {
			tasks = append(tasks, *currentTask)
			currentTask = nil
		}
	}

	// Don't forget the last task if file ends with one
	if currentTask != nil {
		tasks = append(tasks, *currentTask)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tasks, nil
}
