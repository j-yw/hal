package prompt

import "fmt"

// Build constructs a prompt string for Claude to execute a given task.
// The prompt includes:
// - The task description
// - Instruction to implement the task and commit changes
// - Instruction not to modify the PRD file
func Build(taskDescription string) string {
	return fmt.Sprintf(`## Task

%s

## Instructions

1. Implement the task described above
2. Make the necessary code changes to complete the task
3. Stage and commit your changes with a descriptive commit message
4. DO NOT modify the PRD file - the orchestrator will handle marking tasks complete

Focus on completing the task correctly and thoroughly.`, taskDescription)
}
