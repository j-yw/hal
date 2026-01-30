package engine

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// Color palette
var (
	ColorSuccess = lipgloss.Color("#00D787") // Green
	ColorError   = lipgloss.Color("#FF5F87") // Pink
	ColorWarning = lipgloss.Color("#FFAF00") // Yellow
	ColorInfo    = lipgloss.Color("#5FAFFF") // Blue
	ColorMuted   = lipgloss.Color("#888888") // Mid gray (readable)
	ColorAccent  = lipgloss.Color("#AF87FF") // Purple
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
	StyleTitle   = lipgloss.NewStyle().Foreground(ColorInfo).Bold(true) // Blue headers
)

// Command header styles
var (
	// StyleCommandIcon is the ○ symbol used in command headers (HAL eye)
	StyleCommandIcon = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).SetString("○")
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
		Border(lipgloss.NormalBorder()). // Sharp geometric corners
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

// Progress bar styles - HAL red for filled
var (
	StyleProgressFilled = lipgloss.NewStyle().Foreground(ColorAccent)  // HAL red
	StyleProgressEmpty  = lipgloss.NewStyle().Foreground(ColorMuted)   // Dim gray
)

// Tool event styles
var (
	StyleToolRead  = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleToolWrite = lipgloss.NewStyle().Foreground(ColorSuccess)
	StyleToolBash  = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleToolArrow = lipgloss.NewStyle().Foreground(ColorMuted).SetString(">") // Minimal arrow
)

// Layout constants
const (
	IterationBarWidth = 10 // Width of progress bar in iteration headers
)

// SpinnerGradient defines colors for the gradient spinner (HAL 9000 smooth red pulse)
var SpinnerGradient = []lipgloss.Color{
	"#300000", // very dark
	"#400000",
	"#500000",
	"#600000",
	"#700000",
	"#800000",
	"#900000",
	"#A00000",
	"#B00000",
	"#C00000",
	"#D00000",
	"#E00000",
	"#F00000",
	"#FF0000", // bright red
	"#FF1111",
	"#FF2222",
	"#FF3333",
	"#FF4444",
	"#FF5555",
	"#FF6666", // peak
	"#FF5555",
	"#FF4444",
	"#FF3333",
	"#FF2222",
	"#FF1111",
	"#FF0000",
	"#F00000",
	"#E00000",
	"#D00000",
	"#C00000",
	"#B00000",
	"#A00000",
	"#900000",
	"#800000",
	"#700000",
	"#600000",
	"#500000",
	"#400000",
}

// SpinnerBracketColor is the static dim red for HAL eye brackets
var SpinnerBracketColor = lipgloss.Color("#882222")

// SpinnerFrames are HAL eye dots only (brackets rendered separately)
var SpinnerFrames = []string{"·", "•", "●", "•", "·"}

// QuestionBox returns a styled box for Q&A.
func QuestionBox() lipgloss.Style {
	width := GetTerminalWidth() - 2
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()). // Sharp geometric corners
		BorderForeground(ColorInfo).
		BorderTop(true).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		Padding(0, 1).
		Width(width)
}
