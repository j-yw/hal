package engine

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// HAL personality words with trailing ... for measured speech
var HalThinkingWords = []string{
	"processing...", "observing...", "analyzing...", "computing...",
	"considering...", "reasoning...", "calculating...", "monitoring...",
	"evaluating...", "assessing...",
}

var HalWorkingWords = []string{
	"executing...", "operating...", "performing...",
}

func randomHalWord(words []string) string {
	return words[rand.Intn(len(words))]
}

// HeaderContext holds engine/model/git info for command and loop headers.
type HeaderContext struct {
	Engine string // "pi", "claude", "codex"
	Model  string // from config, may be empty
	Repo   string // git repo basename, may be empty
	Branch string // git branch, may be empty
}

// Display handles terminal output with spinners and formatted status.
type Display struct {
	out        io.Writer
	isTTY      bool // Whether output is a real terminal (supports ANSI escapes)
	mu         sync.Mutex
	spinMu     sync.Mutex // Separate mutex for spinner to avoid deadlock
	spinning   bool
	spinCtx    context.Context
	spinCancel context.CancelFunc
	spinDone   chan struct{}
	spinMsg    string
	fsm        *SpinnerFSM
	startTime  time.Time
	loopStart  time.Time

	// Stats tracking
	totalTokens    int
	iterationCount int
	maxIterations  int

	// Model tracking — suppresses duplicate model lines after first EventInit
	modelShown bool
}

// NewDisplay creates a new display writer.
func NewDisplay(out io.Writer) *Display {
	now := time.Now()
	isTTY := false
	if f, ok := out.(*os.File); ok {
		isTTY = term.IsTerminal(f.Fd())
	}
	return &Display{
		out:       out,
		isTTY:     isTTY,
		fsm:       NewSpinnerFSM(),
		startTime: now,
		loopStart: now,
	}
}

// StartSpinner begins a gradient color-cycling spinner.
// When output is not a TTY (e.g., piped to another process), the spinner
// is suppressed to avoid dumping ANSI escape sequences into captured output.
func (d *Display) StartSpinner(msg string) {
	d.spinMu.Lock()
	if d.spinning {
		// Spinner already running: just update the message in place.
		d.spinMsg = msg
		d.spinMu.Unlock()
		return
	}
	d.spinning = true
	d.spinMsg = msg

	// Non-TTY: mark as spinning but don't animate. StopSpinner handles cleanup.
	if !d.isTTY {
		d.spinMu.Unlock()
		return
	}

	d.spinCtx, d.spinCancel = context.WithCancel(context.Background())
	d.spinDone = make(chan struct{})
	d.spinMu.Unlock()

	go func() {
		defer close(d.spinDone)

		frame := 0
		first := true
		ticker := time.NewTicker(80 * time.Millisecond) // HAL smooth breathing
		defer ticker.Stop()

		bracketStyle := lipgloss.NewStyle().Foreground(SpinnerBracketColor)

		for {
			select {
			case <-d.spinCtx.Done():
				// Clear the spinner line
				d.mu.Lock()
				fmt.Fprint(d.out, "\033[2K\r")
				d.mu.Unlock()
				return
			case <-ticker.C:
				d.mu.Lock()
				// HAL eye on the loading line: static brackets, pulsing red iris.
				accent := SpinnerGradient[frame%len(SpinnerGradient)]
				dotStyle := lipgloss.NewStyle().Foreground(accent).Bold(true)
				spinChar := bracketStyle.Render("[") + dotStyle.Render("●") + bracketStyle.Render("]")

				// Build the display message and apply a subtle shimmer.
				baseMsg := d.currentSpinnerMessage()
				displayMsg := d.spinnerDisplayMessage(baseMsg)
				msgText := renderAnimatedSpinnerText(displayMsg, frame)

				line := fmt.Sprintf("   %s %s", spinChar, msgText)

				if first {
					fmt.Fprint(d.out, line)
					first = false
				} else {
					// Move to start of line, clear, and reprint
					fmt.Fprintf(d.out, "\r\033[2K%s", line)
				}
				d.mu.Unlock()

				frame++
			}
		}
	}()
}

// isThinkingSpinnerActive reports whether a spinner is currently active.
// It synchronizes on spinMu internally and does not require d.mu.
func (d *Display) isThinkingSpinnerActive() bool {
	d.spinMu.Lock()
	active := d.spinning
	d.spinMu.Unlock()
	return active
}

func (d *Display) currentSpinnerMessage() string {
	d.spinMu.Lock()
	msg := d.spinMsg
	d.spinMu.Unlock()
	return msg
}

func (d *Display) clearThinkingState() {
	if d.fsm.State() == StateThinking {
		d.fsm.Reset()
	}
}

// spinnerDisplayMessage returns the message shown on the spinner line.
// Caller must hold d.mu.
func (d *Display) spinnerDisplayMessage(base string) string {
	if elapsed := d.fsm.ThinkingElapsed(); elapsed > 0 {
		return fmt.Sprintf("%s %s", base, elapsed.Truncate(time.Second))
	}

	return base
}

// StopSpinner stops the loading spinner.
func (d *Display) StopSpinner() {
	d.spinMu.Lock()
	if !d.spinning {
		d.spinMu.Unlock()
		return
	}
	d.spinning = false

	// Non-TTY: no goroutine was started, just clear state.
	if !d.isTTY {
		d.spinMu.Unlock()
		return
	}

	d.spinCancel()
	d.spinMu.Unlock()
	<-d.spinDone
}

// ShowEvent displays a normalized event.
func (d *Display) ShowEvent(e *Event) {
	if e == nil {
		return
	}

	// FSM-driven spinner continuity: keep spinner active when the incoming
	// event will transition to a spinner-continuing state (ToolActivity or
	// Thinking delta). Stop for terminal states (Completion, Error, Idle).
	switch {
	case e.Type == EventTool, e.Type == EventThinking && e.Data.Message == "delta":
		// Spinner stays active — these events update message in-place.
	default:
		d.StopSpinner()
	}

	d.mu.Lock()

	var startSpinnerMsg string

	switch e.Type {
	case EventInit:
		// Reset FSM to clean state, then transition to Thinking
		d.fsm.Reset()
		if e.Data.Model != "" && !d.modelShown {
			modelText := StyleMuted.Render(fmt.Sprintf("   model: %s", e.Data.Model))
			fmt.Fprintln(d.out, modelText)
			d.modelShown = true
		}
		msg := randomHalWord(HalThinkingWords)
		_ = d.fsm.GoTo(StateThinking, msg)
		startSpinnerMsg = d.fsm.Message()

	case EventTool:
		// Avoid duplicate consecutive tool messages
		toolKey := e.Tool + e.Detail
		if toolKey == d.fsm.LastTool() {
			d.mu.Unlock()
			return
		}
		d.fsm.SetLastTool(toolKey)

		detail := e.Detail
		if detail != "" {
			detail = " " + detail
		}

		// Transition FSM to ToolActivity state
		toolMsg := truncate(e.Tool+detail, GetTerminalWidth()/2)
		if err := d.fsm.GoTo(StateToolActivity, toolMsg); err != nil {
			// Edge case: FSM in unexpected state (e.g., Idle) — reset and proceed
			d.fsm.Reset()
		}

		if d.isTTY && d.isThinkingSpinnerActive() {
			// Clear active spinner line before writing immutable tool history line.
			fmt.Fprint(d.out, "\r\033[2K")
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
		startSpinnerMsg = toolMsg

	case EventResult:
		// Transition through Completion state, then reset to Idle
		if err := d.fsm.GoTo(StateCompletion, ""); err != nil {
			d.fsm.Reset()
		}
		d.fsm.Reset()
		duration := int(e.Data.DurationMs / 1000)
		var statusBadge string
		if e.Data.Success {
			statusBadge = StyleSuccess.Render("[OK]")
		} else {
			statusBadge = StyleError.Render("[!!]")
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
		// Transition through Error state, then reset to Idle
		if err := d.fsm.GoTo(StateError, e.Data.Message); err != nil {
			d.fsm.Reset()
		}
		d.fsm.Reset()
		errorBadge := StyleError.Render("[!!]")
		errorMsg := StyleError.Render(e.Data.Message)
		fmt.Fprintf(d.out, "   %s %s\n", errorBadge, errorMsg)

	case EventThinking:
		switch e.Data.Message {
		case "start":
			d.fsm.Reset() // Ensure clean state before starting thinking
			_ = d.fsm.GoTo(StateThinking, randomHalWord(HalThinkingWords))
			startSpinnerMsg = d.fsm.Message()
		case "delta":
			// Keep thinking state active — the spinner already shows elapsed time.
			// If spinner isn't running (e.g., first delta), start it.
			if !d.isThinkingSpinnerActive() {
				startSpinnerMsg = randomHalWord(HalThinkingWords)
			}
		case "end":
			thinkMsg := StyleMuted.Render(formatThinkingComplete(d.fsm.thinkingStart))
			// Transition through Completion state, then reset to Idle
			_ = d.fsm.GoTo(StateCompletion, "")
			d.fsm.Reset()
			// Keep tool/completion history lines on the angled marker.
			fmt.Fprintf(d.out, "   %s %s\n", StyleToolArrow.Render(), thinkMsg)
		}

	case EventText:
		// Transition FSM to ToolActivity state for working indicator
		workingMsg := randomHalWord(HalWorkingWords)
		if err := d.fsm.GoTo(StateToolActivity, workingMsg); err != nil {
			// Edge case: FSM in unexpected state — reset and proceed
			d.fsm.Reset()
		}
		// Text events are usually the final response, we don't show them inline
		// But start a spinner to show we're still working
		startSpinnerMsg = workingMsg
	}

	d.mu.Unlock()

	// Start spinner after releasing lock (if needed)
	if startSpinnerMsg != "" {
		d.StartSpinner(startSpinnerMsg)
	}
}

// ShowLoopHeader displays the initial loop information.
func (d *Display) ShowLoopHeader(hctx HeaderContext, maxIterations int) {
	d.maxIterations = maxIterations
	d.loopStart = time.Now()

	icon := StyleCommandIcon.Render()
	title := StyleTitle.Render("Hal Loop")

	// Detail line: engine: X · model: Y │ max N iterations
	detail := "engine: " + hctx.Engine
	if hctx.Model != "" {
		detail += " · model: " + hctx.Model
		d.modelShown = true
	}
	detail += fmt.Sprintf(" │ max %d iterations", maxIterations)
	detailLine := StyleMuted.Render(detail)

	content := fmt.Sprintf("%s %s\n%s", icon, title, detailLine)

	// Repo/branch line
	if repoBranch := formatRepoBranch(hctx.Repo, hctx.Branch); repoBranch != "" {
		content += "\n" + StyleMuted.Render(repoBranch)
	}

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
	d.fsm.Reset() // Reset for new iteration

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

	successBadge := StyleSuccess.Render("[OK]")
	title := StyleSuccess.Bold(true).Render(fmt.Sprintf("%s %s", successBadge, msg))

	stats := []string{
		StyleMuted.Render(fmt.Sprintf("Iterations: %d", d.iterationCount)),
		StyleMuted.Render(fmt.Sprintf("Total time: %s", elapsed)),
		StyleMuted.Render(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))),
	}

	content := title + "\n" + strings.Join(stats, " │ ")
	box := SuccessBox().Render(content)

	fmt.Fprintln(d.out)
	fmt.Fprintln(d.out, box)
}

// ShowError displays an error message.
func (d *Display) ShowError(msg string) {
	d.StopSpinner()
	elapsed := time.Since(d.loopStart).Round(time.Second)

	errorBadge := StyleError.Render("[!!]")
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

	warnBadge := StyleWarning.Render("[!]")
	title := StyleWarning.Bold(true).Render(fmt.Sprintf("%s Max iterations reached", warnBadge))

	stats := []string{
		StyleMuted.Render(fmt.Sprintf("Completed: %d/%d iterations", d.iterationCount, d.maxIterations)),
		StyleMuted.Render(fmt.Sprintf("Total time: %s", elapsed)),
		StyleMuted.Render(fmt.Sprintf("Total tokens: %s", formatTokens(d.totalTokens))),
	}

	content := title + "\n" + strings.Join(stats, " │ ")
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

func formatThinkingComplete(start time.Time) string {
	if start.IsZero() {
		return "reasoning complete"
	}

	elapsed := time.Since(start).Truncate(time.Second)
	if elapsed < 0 {
		return "reasoning complete"
	}

	return fmt.Sprintf("reasoning complete %s", elapsed)
}

func renderAnimatedSpinnerText(msg string, frame int) string {
	runes := []rune(msg)
	if len(runes) == 0 {
		return ""
	}

	highlightIdx := frame % len(runes)
	glowStyle := lipgloss.NewStyle().Foreground(SpinnerTextGlowColor)
	highlightStyle := lipgloss.NewStyle().Foreground(SpinnerTextHighlightColor).Bold(true)

	var b strings.Builder
	for i, r := range runes {
		ch := string(r)
		switch absInt(i - highlightIdx) {
		case 0:
			b.WriteString(highlightStyle.Render(ch))
		case 1:
			b.WriteString(glowStyle.Render(ch))
		default:
			b.WriteString(StyleMuted.Render(ch))
		}
	}

	return b.String()
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
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
// hctx: engine/model/repo/branch context
func (d *Display) ShowCommandHeader(title, context string, hctx HeaderContext) {
	d.loopStart = time.Now()
	d.totalTokens = 0

	icon := StyleCommandIcon.Render()
	titleText := StyleTitle.Render(title)

	// Detail line: context │ engine: X · model: Y
	detail := context + " │ engine: " + hctx.Engine
	if hctx.Model != "" {
		detail += " · model: " + hctx.Model
		d.modelShown = true
	}
	detailLine := StyleMuted.Render(detail)

	content := fmt.Sprintf("%s %s\n%s", icon, titleText, detailLine)

	// Repo/branch line
	if repoBranch := formatRepoBranch(hctx.Repo, hctx.Branch); repoBranch != "" {
		content += "\n" + StyleMuted.Render(repoBranch)
	}

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

	successBadge := StyleSuccess.Render("[OK]")
	titleText := StyleSuccess.Bold(true).Render(fmt.Sprintf("%s %s", successBadge, title))

	var contentLines []string
	contentLines = append(contentLines, titleText)

	if details != "" {
		detailText := StyleMuted.Render(fmt.Sprintf("%s │ Duration: %s", details, elapsed))
		contentLines = append(contentLines, detailText)
	} else {
		detailText := StyleMuted.Render(fmt.Sprintf("Duration: %s", elapsed))
		contentLines = append(contentLines, detailText)
	}

	if d.totalTokens > 0 {
		tokenText := StyleMuted.Render(fmt.Sprintf("Tokens: %s", formatTokens(d.totalTokens)))
		contentLines[len(contentLines)-1] += " │ " + tokenText
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

	errorBadge := StyleError.Render("[!!]")
	titleText := StyleError.Bold(true).Render(fmt.Sprintf("%s %s", errorBadge, title))

	summary := StyleMuted.Render(fmt.Sprintf("%d errors │ %d warnings", len(errors), len(warnings)))

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

// formatRepoBranch builds the "repo: X · branch: Y" line.
// Returns empty string if both are empty; omits individual segments when empty.
func formatRepoBranch(repo, branch string) string {
	var parts []string
	if repo != "" {
		parts = append(parts, "repo: "+repo)
	}
	if branch != "" {
		parts = append(parts, "branch: "+branch)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ")
}

// Writer returns the underlying io.Writer for the display.
func (d *Display) Writer() io.Writer {
	return d.out
}
