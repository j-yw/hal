package engine

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// Color palette
var (
	ColorSuccess = lipgloss.Color("#00D787")
	ColorError   = lipgloss.Color("#FF5F87")
	ColorWarning = lipgloss.Color("#FFAF00")
	ColorInfo    = lipgloss.Color("#5FAFFF")
	ColorMuted   = lipgloss.Color("#8C8C8C") // Brightened for readability
	ColorAccent  = lipgloss.Color("#AF87FF")
)

// Text styles
var (
	StyleSuccess = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	StyleError   = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	StyleWarning = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)
	StyleInfo    = lipgloss.NewStyle().Foreground(ColorInfo)
	StyleMuted   = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleAccent  = lipgloss.NewStyle().Foreground(ColorAccent)
	StyleBold    = lipgloss.NewStyle().Bold(true)
)

// Command header styles
var (
	// StyleCommandIcon is the ◆ symbol used in command headers
	StyleCommandIcon = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).SetString("◆")
)

// Box styles - now dynamic functions for responsive width

// GetTerminalWidth returns the current terminal width, or a default fallback.
func GetTerminalWidth() int {
	width, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || width <= 0 {
		return 80 // sensible default
	}
	return width
}

// BoxStyle creates a box style with the given border color and responsive width.
func BoxStyle(borderColor lipgloss.Color) lipgloss.Style {
	width := GetTerminalWidth() - 2 // leave margin
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Width(width)
}

// HeaderBox returns a header box style with responsive width.
func HeaderBox() lipgloss.Style { return BoxStyle(ColorInfo) }

// SuccessBox returns a success box style with responsive width.
func SuccessBox() lipgloss.Style { return BoxStyle(ColorSuccess) }

// ErrorBox returns an error box style with responsive width.
func ErrorBox() lipgloss.Style { return BoxStyle(ColorError) }

// WarningBox returns a warning box style with responsive width.
func WarningBox() lipgloss.Style { return BoxStyle(ColorWarning) }

// Progress bar styles
var (
	StyleProgressFilled = lipgloss.NewStyle().Foreground(ColorInfo)
	StyleProgressEmpty  = lipgloss.NewStyle().Foreground(ColorMuted)
)

// Tool event styles
var (
	StyleToolRead  = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleToolWrite = lipgloss.NewStyle().Foreground(ColorSuccess)
	StyleToolBash  = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleToolArrow = lipgloss.NewStyle().Foreground(ColorAccent).SetString("▶")
)

// Layout constants
const (
	IterationBarWidth = 10 // Width of progress bar in iteration headers
)

// SpinnerGradient defines colors for the gradient spinner (cyan → purple → pink → cyan)
var SpinnerGradient = []lipgloss.Color{
	lipgloss.Color("#00D7FF"), // cyan
	lipgloss.Color("#00AFFF"),
	lipgloss.Color("#5F87FF"),
	lipgloss.Color("#875FFF"), // purple
	lipgloss.Color("#AF5FFF"),
	lipgloss.Color("#D75FAF"),
	lipgloss.Color("#FF5F87"), // pink
	lipgloss.Color("#FF87AF"),
	lipgloss.Color("#D75FAF"),
	lipgloss.Color("#AF5FFF"),
	lipgloss.Color("#875FFF"), // back to purple
	lipgloss.Color("#5F87FF"),
	lipgloss.Color("#00AFFF"),
}

// SpinnerFrames are braille characters for smooth animation
var SpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// QuestionBox returns a styled box for Q&A.
func QuestionBox() lipgloss.Style {
	width := GetTerminalWidth() - 2
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorInfo).
		BorderTop(true).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		Padding(0, 1).
		Width(width)
}
