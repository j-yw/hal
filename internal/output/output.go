package output

import (
	"fmt"
	"io"
)

// Printer handles formatted output for the CLI.
type Printer struct {
	w io.Writer
}

// New creates a new Printer that writes to the given writer.
func New(w io.Writer) *Printer {
	return &Printer{w: w}
}

// TaskCount prints the initial task count message.
// Format: "Found N pending tasks"
func (p *Printer) TaskCount(count int) {
	if count == 1 {
		fmt.Fprintf(p.w, "Found 1 pending task\n")
	} else {
		fmt.Fprintf(p.w, "Found %d pending tasks\n", count)
	}
}

// TaskStart prints the current task being processed.
// Format: "Task 1/N: <description>"
func (p *Printer) TaskStart(current, total int, description string) {
	fmt.Fprintf(p.w, "Task %d/%d: %s\n", current, total, description)
}

// TaskSuccess prints a success message with checkmark.
// Format: "✓ Task completed"
func (p *Printer) TaskSuccess() {
	fmt.Fprintf(p.w, "✓ Task completed\n")
}

// TaskFailure prints a failure message with x.
// Format: "✗ Task failed: <reason>"
func (p *Printer) TaskFailure(reason string) {
	fmt.Fprintf(p.w, "✗ Task failed: %s\n", reason)
}

// Retry prints a retry message.
// Format: "Retrying in Xs... (attempt N/M)"
func (p *Printer) Retry(delaySeconds int, attempt, maxAttempts int) {
	fmt.Fprintf(p.w, "Retrying in %ds... (attempt %d/%d)\n", delaySeconds, attempt, maxAttempts)
}

// Summary prints the final summary.
// Format: "Completed X/N tasks"
func (p *Printer) Summary(completed, total int) {
	fmt.Fprintf(p.w, "Completed %d/%d tasks\n", completed, total)
}
