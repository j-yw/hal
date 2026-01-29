package engine

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Display handles terminal output with spinners and formatted status.
type Display struct {
	out        io.Writer
	mu         sync.Mutex
	spinMu     sync.Mutex // Separate mutex for spinner to avoid deadlock
	spinning   bool
	spinCtx    context.Context
	spinCancel context.CancelFunc
	spinDone   chan struct{}
	spinMsg    string
	lastTool   string
	startTime  time.Time
	loopStart  time.Time

	// Stats tracking
	totalTokens    int
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

// StartSpinner begins a gradient color-cycling spinner.
func (d *Display) StartSpinner(msg string) {
	d.spinMu.Lock()
	if d.spinning {
		d.spinMu.Unlock()
		return
	}
	d.spinning = true
	d.spinMsg = msg
	d.spinCtx, d.spinCancel = context.WithCancel(context.Background())
	d.spinDone = make(chan struct{})
	d.spinMu.Unlock()

	go func() {
		defer close(d.spinDone)

		frame := 0
		colorIdx := 0
		first := true
		ticker := time.NewTicker(66 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-d.spinCtx.Done():
				// Clear the spinner line
				fmt.Fprint(d.out, "\033[2K\r")
				return
			case <-ticker.C:
				// Get current gradient color
				color := SpinnerGradient[colorIdx%len(SpinnerGradient)]
				spinnerStyle := lipgloss.NewStyle().Foreground(color).Bold(true)
				spinChar := spinnerStyle.Render(SpinnerFrames[frame%len(SpinnerFrames)])

				// Render message with muted style
				msgText := StyleMuted.Render(msg)

				line := fmt.Sprintf("   %s %s", spinChar, msgText)

				if first {
					fmt.Fprint(d.out, line)
					first = false
				} else {
					// Move to start of line, clear, and reprint
					fmt.Fprintf(d.out, "\r\033[2K%s", line)
				}

				frame++
				colorIdx++
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
	d.spinCancel()
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
			modelText := StyleMuted.Render(fmt.Sprintf("   model: %s", e.Data.Model))
			fmt.Fprintln(d.out, modelText)
		}
		startSpinnerMsg = "thinking..."

	case EventTool:
		// Avoid duplicate consecutive tool messages
		toolKey := e.Tool + e.Detail
		if toolKey == d.lastTool {
			d.mu.Unlock()
			return
		}
		d.lastTool = toolKey

		detail := e.Detail
		if detail != "" {
			detail = " " + detail
		}

		// Color-code based on tool type
		arrow := StyleToolArrow.Render()
		var toolLine string
		switch e.Tool {
		case "read", "Read":
			toolLine = StyleToolRead.Render(e.Tool + detail)
		case "write", "Write", "Edit":
			toolLine = StyleToolWrite.Render(e.Tool + detail)
		case "bash", "Bash":
			toolLine = StyleToolBash.Render(e.Tool + detail)
		default:
			toolLine = StyleInfo.Render(e.Tool + detail)
		}
		fmt.Fprintf(d.out, "   %s %s\n", arrow, toolLine)

		// Start spinner while tool executes
		startSpinnerMsg = truncate(e.Tool+detail, GetTerminalWidth()/2)

	case EventResult:
		duration := int(e.Data.DurationMs / 1000)
		var statusBadge string
		if e.Data.Success {
			statusBadge = StyleSuccess.Render("✓")
		} else {
			statusBadge = StyleError.Render("✗")
		}

		timeText := StyleMuted.Render(fmt.Sprintf("%ds", duration))
		fmt.Fprintf(d.out, "   %s %s", statusBadge, timeText)

		if e.Data.Tokens > 0 {
			d.totalTokens += e.Data.Tokens
			tokenText := StyleMuted.Render(fmt.Sprintf(" │ %s tokens", formatTokens(e.Data.Tokens)))
			fmt.Fprint(d.out, tokenText)
		}
		fmt.Fprintln(d.out)

	case EventError:
		errorBadge := StyleError.Render("✗")
		errorMsg := StyleError.Render(e.Data.Message)
		fmt.Fprintf(d.out, "   %s %s\n", errorBadge, errorMsg)

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

	icon := StyleCommandIcon.Render()
	title := StyleBold.Render("Ralph Loop")
	details := StyleMuted.Render(fmt.Sprintf("%s  •  max %d iterations", engineName, maxIterations))

	content := fmt.Sprintf("%s %s\n%s", icon, title, details)
	box := HeaderBox().Render(content)

	fmt.Fprintln(d.out, box)
	fmt.Fprintln(d.out)
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

	barWidth := IterationBarWidth

	// Calculate progress
	progress := float64(current-1) / float64(max)
	filled := int(progress * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}

	// Build styled progress bar
	filledBar := StyleProgressFilled.Render(strings.Repeat("█", filled))
	emptyBar := StyleProgressEmpty.Render(strings.Repeat("░", barWidth-filled))
	bar := filledBar + emptyBar

	iterLabel := StyleBold.Render(fmt.Sprintf("[%d/%d]", current, max))

	storyText := ""
	if story != nil {
		storyText = fmt.Sprintf("  %s: %s",
			StyleInfo.Render(story.ID),
			truncate(story.Title, GetTerminalWidth()/2))
	}

	fmt.Fprintf(d.out, "%s %s%s\n", iterLabel, bar, storyText)
}

// ShowIterationComplete displays iteration completion status.
func (d *Display) ShowIterationComplete(current int) {
	d.StopSpinner()
	fmt.Fprintln(d.out) // Blank line separates iterations
}

// ShowSuccess displays a success message with final stats.
func (d *Display) ShowSuccess(msg string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	successBadge := StyleSuccess.Render("✓")
	title := StyleSuccess.Bold(true).Render(fmt.Sprintf("%s %s", successBadge, msg))

	stats := []string{
		StyleMuted.Render(fmt.Sprintf("Iterations: %d", d.iterationCount)),
		StyleMuted.Render(fmt.Sprintf("Total time: %s", elapsed)),
		StyleMuted.Render(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))),
	}

	content := title + "\n" + strings.Join(stats, "  •  ")
	box := SuccessBox().Render(content)

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowError displays an error message.
func (d *Display) ShowError(msg string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	errorBadge := StyleError.Render("✗")
	title := StyleError.Bold(true).Render(fmt.Sprintf("%s Error", errorBadge))

	errorMsg := msg
	if len(errorMsg) > 50 {
		errorMsg = errorMsg[:47] + "..."
	}

	lines := []string{
		title,
		errorMsg,
		StyleMuted.Render(fmt.Sprintf("After %d iterations (%s)", d.iterationCount, elapsed)),
	}

	content := strings.Join(lines, "\n")
	box := ErrorBox().Render(content)

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowMaxIterations displays max iterations reached message.
func (d *Display) ShowMaxIterations() {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	warnBadge := StyleWarning.Render("⚠")
	title := StyleWarning.Bold(true).Render(fmt.Sprintf("%s Max iterations reached", warnBadge))

	stats := []string{
		StyleMuted.Render(fmt.Sprintf("Completed: %d/%d iterations", d.iterationCount, d.maxIterations)),
		StyleMuted.Render(fmt.Sprintf("Total time: %s", elapsed)),
		StyleMuted.Render(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))),
	}

	content := title + "\n" + strings.Join(stats, "  •  ")
	box := WarningBox().Render(content)

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowInfo displays an info message.
func (d *Display) ShowInfo(format string, args ...interface{}) {
	fmt.Fprintf(d.out, format, args...)
}

// ShowRetry displays retry information.
func (d *Display) ShowRetry(attempt, max int, delay time.Duration) {
	retryText := StyleWarning.Render(fmt.Sprintf("... retrying in %s (attempt %d/%d)", delay, attempt, max))
	fmt.Fprintf(d.out, "   %s\n", retryText)
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// QuestionOption represents a selectable option for a question.
type QuestionOption struct {
	Letter      string
	Label       string
	Recommended bool
}

// ShowCommandHeader displays a boxed header for any command.
// title: "Plan", "Convert", "Validate"
// context: "user auth", "tasks/prd.md → prd.json"
// engineName: "claude"
func (d *Display) ShowCommandHeader(title, context, engineName string) {
	d.loopStart = time.Now()
	d.totalTokens = 0

	icon := StyleCommandIcon.Render()
	titleText := StyleBold.Render(title)
	details := StyleMuted.Render(fmt.Sprintf("%s  •  %s engine", context, engineName))

	content := fmt.Sprintf("%s %s\n%s", icon, titleText, details)
	box := HeaderBox().Render(content)

	fmt.Fprintln(d.out, box)
	fmt.Fprintln(d.out)
}

// ShowPhase displays a phase indicator like [1/2] Phase: Questions
func (d *Display) ShowPhase(current, total int, label string) {
	d.StopSpinner()

	phaseLabel := StyleBold.Render(fmt.Sprintf("[%d/%d]", current, total))
	phaseText := StyleMuted.Render(fmt.Sprintf("Phase: %s", label))
	fmt.Fprintf(d.out, "%s %s\n", phaseLabel, phaseText)
}

// ShowQuestion displays a styled question box with options.
func (d *Display) ShowQuestion(number int, text string, options []QuestionOption) {
	d.StopSpinner()

	// Build question content with number prefix
	var content strings.Builder
	content.WriteString(StyleBold.Render(fmt.Sprintf("Q%d: ", number)))
	content.WriteString(text)
	content.WriteString("\n")

	for _, opt := range options {
		label := opt.Label
		if opt.Recommended {
			label += " (Recommended)"
		}
		content.WriteString(fmt.Sprintf("\n   %s. %s", opt.Letter, label))
	}

	box := QuestionBox().Render(content.String())

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowCommandSuccess displays a success result box.
// title: "PRD created", "Conversion complete", "PRD is valid"
// details: "Path: ... • Duration: 23s"
func (d *Display) ShowCommandSuccess(title, details string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	successBadge := StyleSuccess.Render("✓")
	titleText := StyleSuccess.Bold(true).Render(fmt.Sprintf("%s %s", successBadge, title))

	var contentLines []string
	contentLines = append(contentLines, titleText)

	if details != "" {
		detailText := StyleMuted.Render(fmt.Sprintf("%s  •  Duration: %s", details, elapsed))
		contentLines = append(contentLines, detailText)
	} else {
		detailText := StyleMuted.Render(fmt.Sprintf("Duration: %s", elapsed))
		contentLines = append(contentLines, detailText)
	}

	if d.totalTokens > 0 {
		tokenText := StyleMuted.Render(fmt.Sprintf("Tokens: %s", formatTokens(d.totalTokens)))
		contentLines[len(contentLines)-1] += "  •  " + tokenText
	}

	content := strings.Join(contentLines, "\n")
	box := SuccessBox().Render(content)

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ValidationIssue represents a validation error or warning for display.
type ValidationIssue struct {
	StoryID string
	Field   string
	Message string
}

// ShowCommandError displays an error result box with structured errors and warnings.
func (d *Display) ShowCommandError(title string, errors, warnings []ValidationIssue) {
	d.StopSpinner()

	errorBadge := StyleError.Render("✗")
	titleText := StyleError.Bold(true).Render(fmt.Sprintf("%s %s", errorBadge, title))

	summary := StyleMuted.Render(fmt.Sprintf("%d errors  •  %d warnings", len(errors), len(warnings)))

	var content strings.Builder
	content.WriteString(titleText)
	content.WriteString("\n")
	content.WriteString(summary)

	if len(errors) > 0 {
		content.WriteString("\n\n")
		content.WriteString(StyleError.Render("Errors:"))
		for _, e := range errors {
			if e.StoryID != "" {
				content.WriteString(fmt.Sprintf("\n  %s  %-10s %s",
					StyleMuted.Render(e.StoryID),
					StyleMuted.Render(e.Field),
					e.Message))
			} else {
				content.WriteString(fmt.Sprintf("\n  %s", e.Message))
			}
		}
	}

	if len(warnings) > 0 {
		content.WriteString("\n\n")
		content.WriteString(StyleWarning.Render("Warnings:"))
		for _, w := range warnings {
			if w.StoryID != "" {
				content.WriteString(fmt.Sprintf("\n  %s  %-10s %s",
					StyleMuted.Render(w.StoryID),
					StyleMuted.Render(w.Field),
					w.Message))
			} else {
				content.WriteString(fmt.Sprintf("\n  %s", w.Message))
			}
		}
	}

	box := ErrorBox().Render(content.String())

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowNextSteps displays next step hints.
func (d *Display) ShowNextSteps(steps []string) {
	if len(steps) == 0 {
		return
	}

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, StyleMuted.Render("Next:"))
	for _, step := range steps {
		fmt.Fprintf(d.out, "  %s\n", step)
	}
}


