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

// Flusher is an optional interface for writers that support flushing.
type Flusher interface {
	Sync() error
}

// Display handles terminal output with spinners and formatted status.
type Display struct {
	out       io.Writer
	mu        sync.Mutex
	spinMu    sync.Mutex // Separate mutex for spinner to avoid deadlock
	spinning  bool
	spinStop  chan struct{}
	spinDone  chan struct{}
	spinMsg   string
	lastTool  string
	startTime time.Time
	loopStart time.Time
	toolStart time.Time // Track when current tool started

	// Stats tracking
	totalTokens    int
	iterationCount int
	maxIterations  int
}

// flush attempts to flush the output if it supports it.
func (d *Display) flush() {
	if f, ok := d.out.(Flusher); ok {
		f.Sync()
	}
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
	d.spinMu.Lock()
	if d.spinning {
		d.spinMu.Unlock()
		return
	}
	d.spinning = true
	d.spinMsg = msg
	d.spinStop = make(chan struct{})
	d.spinDone = make(chan struct{})
	d.spinMu.Unlock()

	go func() {
		defer close(d.spinDone)
		frame := 0
		first := true
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-d.spinStop:
				// Move up, clear line, stay there for next output
				fmt.Fprintf(d.out, "\033[1A\r\033[K")
				d.flush()
				return
			case <-ticker.C:
				elapsed := formatElapsed(time.Since(d.toolStart))
				if first {
					// First frame: print spinner + newline (cursor goes below)
					fmt.Fprintf(d.out, "   %s %s (%s)\n", spinnerFrames[frame], d.spinMsg, elapsed)
					first = false
				} else {
					// Subsequent frames: move up, clear line, reprint + newline
					fmt.Fprintf(d.out, "\033[1A\r\033[K   %s %s (%s)\n", spinnerFrames[frame], d.spinMsg, elapsed)
				}
				d.flush()
				frame = (frame + 1) % len(spinnerFrames)
			}
		}
	}()
}

// StopSpinner stops the loading spinner.
func (d *Display) StopSpinner() {
	d.spinMu.Lock()
	if !d.spinning {
		d.spinMu.Unlock()
		return
	}
	d.spinning = false
	close(d.spinStop)
	d.spinMu.Unlock()
	<-d.spinDone
}

// ShowEvent displays a normalized event.
func (d *Display) ShowEvent(e *Event) {
	if e == nil {
		return
	}

	// Stop any running spinner before showing new event
	d.StopSpinner()

	d.mu.Lock()

	var startSpinnerMsg string

	switch e.Type {
	case EventInit:
		if e.Data.Model != "" {
			fmt.Fprintf(d.out, "   model: %s\n", e.Data.Model)
		}
		d.toolStart = time.Now()
		startSpinnerMsg = "thinking..."

	case EventTool:
		// Avoid duplicate consecutive tool messages
		toolKey := e.Tool + e.Detail
		if toolKey == d.lastTool {
			d.mu.Unlock()
			return
		}
		d.lastTool = toolKey
		d.toolStart = time.Now()

		detail := e.Detail
		if detail != "" {
			detail = " " + detail
		}
		fmt.Fprintf(d.out, "   ▶ %s%s\n", e.Tool, detail)

		// Start spinner while tool executes
		startSpinnerMsg = truncate(e.Tool+detail, 40)

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
		// But start a spinner to show we're still working
		startSpinnerMsg = "working..."
	}

	d.mu.Unlock()

	// Start spinner after releasing lock (if needed)
	if startSpinnerMsg != "" {
		d.StartSpinner(startSpinnerMsg)
	}
}

// ShowLoopHeader displays the initial loop information.
func (d *Display) ShowLoopHeader(engineName string, maxIterations int) {
	d.maxIterations = maxIterations
	d.loopStart = time.Now()

	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprint(d.out, boxLine("Ralph Loop"))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Engine: %s", engineName)))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Max iterations: %d", maxIterations)))
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
	d.StopSpinner()
	fmt.Fprintf(d.out, "   --- iteration %d complete ---\n\n", current)
}

// ShowSuccess displays a success message with final stats.
func (d *Display) ShowSuccess(msg string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("[ok] %s", msg)))
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Iterations: %d", d.iterationCount)))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Total time: %s", elapsed)))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))))
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n")
}

// ShowError displays an error message.
func (d *Display) ShowError(msg string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprint(d.out, boxLine("[!!] Error"))
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprint(d.out, boxLine(msg))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("After %d iterations (%s)", d.iterationCount, elapsed)))
	fmt.Fprintf(d.out, "└─────────────────────────────────────────────────────┘\n")
}

// ShowMaxIterations displays max iterations reached message.
func (d *Display) ShowMaxIterations() {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprint(d.out, boxLine("[--] Max iterations reached"))
	fmt.Fprintf(d.out, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Completed: %d/%d iterations", d.iterationCount, d.maxIterations)))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Total time: %s", elapsed)))
	fmt.Fprint(d.out, boxLine(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))))
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

// Box drawing constants
const boxWidth = 53 // Inner width between │ symbols

// boxLine creates a properly padded box line: │  content  │
func boxLine(content string) string {
	// Pad or truncate to fit box width
	if len(content) > boxWidth-2 {
		content = content[:boxWidth-5] + "..."
	}
	padding := boxWidth - 2 - len(content)
	if padding < 0 {
		padding = 0
	}
	return fmt.Sprintf("│  %s%s│\n", content, strings.Repeat(" ", padding))
}

// formatElapsed formats duration with fixed width (always 6 chars like " 1.04s")
func formatElapsed(d time.Duration) string {
	secs := d.Seconds()
	if secs < 10 {
		return fmt.Sprintf("%5.2fs", secs) // " 1.04s"
	} else if secs < 100 {
		return fmt.Sprintf("%5.1fs", secs) // " 10.0s"
	}
	return fmt.Sprintf("%5.0fs", secs) // "  100s"
}

func formatTokens(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
