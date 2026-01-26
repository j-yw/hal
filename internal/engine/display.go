package engine

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Spinner frames using braille characters
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Progress bar characters
const (
	barFilled = "█"
	barEmpty  = "░"
	barWidth  = 20
)

// Display handles terminal output with spinners and formatted status.
type Display struct {
	out       io.Writer
	mu        sync.Mutex
	spinning  bool
	spinStop  chan struct{}
	spinDone  chan struct{}
	lastTool  string
	startTime time.Time
	loopStart time.Time

	// Stats tracking
	totalTokens    int
	totalCost      float64
	iterationCount int
	maxIterations  int
}

// NewDisplay creates a new display writer.
func NewDisplay(out io.Writer) *Display {
	now := time.Now()
	return &Display{
		out:       out,
		startTime: now,
		loopStart: now,
	}
}

// StartSpinner begins the loading spinner with a message.
func (d *Display) StartSpinner(msg string) {
	d.mu.Lock()
	if d.spinning {
		d.mu.Unlock()
		return
	}
	d.spinning = true
	d.spinStop = make(chan struct{})
	d.spinDone = make(chan struct{})
	d.mu.Unlock()

	go func() {
		defer close(d.spinDone)
		frame := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-d.spinStop:
				fmt.Fprintf(d.out, "\r%s\r", strings.Repeat(" ", 60))
				return
			case <-ticker.C:
				elapsed := time.Since(d.startTime).Round(time.Second)
				fmt.Fprintf(d.out, "\r   %s %s (%s)", spinnerFrames[frame], msg, elapsed)
				frame = (frame + 1) % len(spinnerFrames)
			}
		}
	}()
}

// StopSpinner stops the loading spinner.
func (d *Display) StopSpinner() {
	d.mu.Lock()
	if !d.spinning {
		d.mu.Unlock()
		return
	}
	d.spinning = false
	close(d.spinStop)
	d.mu.Unlock()
	<-d.spinDone
}

// ShowEvent displays a normalized event.
func (d *Display) ShowEvent(e *Event) {
	if e == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	switch e.Type {
	case EventInit:
		if e.Data.Model != "" {
			fmt.Fprintf(d.out, "   model: %s\n", e.Data.Model)
		}

	case EventTool:
		// Avoid duplicate consecutive tool messages
		toolKey := e.Tool + e.Detail
		if toolKey == d.lastTool {
			return
		}
		d.lastTool = toolKey

		detail := e.Detail
		if detail != "" {
			detail = " " + detail
		}
		fmt.Fprintf(d.out, "   ==> %s%s\n", e.Tool, detail)

	case EventResult:
		status := "[ok]"
		if !e.Data.Success {
			status = "[!!]"
		}
		duration := int(e.Data.DurationMs / 1000)
		fmt.Fprintf(d.out, "   %s %ds", status, duration)
		if e.Data.Tokens > 0 {
			d.totalTokens += e.Data.Tokens
			fmt.Fprintf(d.out, " | %s tokens", formatTokens(e.Data.Tokens))
		}
		fmt.Fprintln(d.out)

	case EventError:
		fmt.Fprintf(d.out, "   [!!] %s\n", e.Data.Message)

	case EventText:
		// Text events are usually the final response, we don't show them inline
	}
}

// ShowLoopHeader displays the initial loop information.
func (d *Display) ShowLoopHeader(engineName string, maxIterations int) {
	d.maxIterations = maxIterations
	d.loopStart = time.Now()

	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(d.out, "│  Ralph Loop                                         │\n")
	fmt.Fprintf(d.out, "│  Engine: %-43s│\n", engineName)
	fmt.Fprintf(d.out, "│  Max iterations: %-34d│\n", maxIterations)
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n\n")
}

// StoryInfo holds information about the current story being worked on.
type StoryInfo struct {
	ID    string
	Title string
}

// ShowIterationHeader displays the iteration banner with progress bar.
func (d *Display) ShowIterationHeader(current, max int, story *StoryInfo) {
	d.iterationCount = current
	d.maxIterations = max
	d.startTime = time.Now()
	d.lastTool = "" // Reset for new iteration

	// Calculate progress
	progress := float64(current-1) / float64(max)
	filled := int(progress * barWidth)
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat(barFilled, filled) + strings.Repeat(barEmpty, barWidth-filled)
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintf(d.out, "───────────────────────────────────────────────────────\n")
	fmt.Fprintf(d.out, "  Iteration %d/%d  [%s]  %s elapsed\n", current, max, bar, elapsed)
	if story != nil {
		storyLine := fmt.Sprintf("  >>> %s: %s", story.ID, story.Title)
		fmt.Fprintf(d.out, "%s\n", truncate(storyLine, 55))
	}
	fmt.Fprintf(d.out, "───────────────────────────────────────────────────────\n")
}

// ShowIterationComplete displays iteration completion status.
func (d *Display) ShowIterationComplete(current int) {
	fmt.Fprintf(d.out, "   --- iteration %d complete ---\n\n", current)
}

// ShowSuccess displays a success message with final stats.
func (d *Display) ShowSuccess(msg string) {
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(d.out, "│  [ok] %-46s│\n", msg)
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(d.out, "│  Iterations: %-38d│\n", d.iterationCount)
	fmt.Fprintf(d.out, "│  Total time: %-38s│\n", elapsed)
	fmt.Fprintf(d.out, "│  Total tokens: %-36s│\n", formatTokens(d.totalTokens))
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n")
}

// ShowError displays an error message.
func (d *Display) ShowError(msg string) {
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(d.out, "│  [!!] Error                                         │\n")
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(d.out, "│  %s\n", truncateBox(msg, 51))
	fmt.Fprintf(d.out, "│  After %d iterations (%s)%s│\n", d.iterationCount, elapsed, strings.Repeat(" ", 30-len(elapsed.String())))
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n")
}

// ShowMaxIterations displays max iterations reached message.
func (d *Display) ShowMaxIterations() {
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(d.out, "│  [--] Max iterations reached                        │\n")
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(d.out, "│  Completed: %d/%d iterations%-24s│\n", d.iterationCount, d.maxIterations, "")
	fmt.Fprintf(d.out, "│  Total time: %-38s│\n", elapsed)
	fmt.Fprintf(d.out, "│  Total tokens: %-36s│\n", formatTokens(d.totalTokens))
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n")
}

// ShowInfo displays an info message.
func (d *Display) ShowInfo(format string, args ...interface{}) {
	fmt.Fprintf(d.out, format, args...)
}

// ShowRetry displays retry information.
func (d *Display) ShowRetry(attempt, max int, delay time.Duration) {
	fmt.Fprintf(d.out, "   ... retrying in %s (attempt %d/%d)\n", delay, attempt, max)
}

// Helper functions

func formatTokens(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return ".../" + strings.Join(parts[len(parts)-2:], "/")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func truncateBox(s string, max int) string {
	if len(s) <= max {
		return s + strings.Repeat(" ", max-len(s)) + "│"
	}
	return s[:max-3] + "...│"
}
