package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// Color palette shared by human-facing command renderers.
var (
	ColorSuccess = lipgloss.Color("#00D787")
	ColorError   = lipgloss.Color("#FF5F87")
	ColorWarning = lipgloss.Color("#FFAF00")
	ColorInfo    = lipgloss.Color("#5FAFFF")
	ColorMuted   = lipgloss.Color("#888888")
	ColorAccent  = lipgloss.Color("#AF87FF")
)

// Text styles.
var (
	StyleSuccess = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	StyleError   = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	StyleWarning = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleInfo    = lipgloss.NewStyle().Foreground(ColorInfo)
	StyleMuted   = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleAccent  = lipgloss.NewStyle().Foreground(ColorAccent)
	StyleBold    = lipgloss.NewStyle().Bold(true)
	StyleTitle   = lipgloss.NewStyle().Foreground(ColorInfo).Bold(true)
)

var StyleCommandIcon = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).SetString("○")

// GetTerminalWidth returns the current terminal width, or a default fallback.
func GetTerminalWidth() int {
	width, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

// BoxStyle creates a box style with the given border color and responsive width.
func BoxStyle(borderColor lipgloss.Color) lipgloss.Style {
	width := GetTerminalWidth() - 2
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Width(width)
}

func HeaderBox() lipgloss.Style  { return BoxStyle(ColorInfo) }
func SuccessBox() lipgloss.Style { return BoxStyle(ColorSuccess) }
func ErrorBox() lipgloss.Style   { return BoxStyle(ColorError) }
func WarningBox() lipgloss.Style { return BoxStyle(ColorWarning) }

var (
	StyleProgressFilled = lipgloss.NewStyle().Foreground(ColorAccent)
	StyleProgressEmpty  = lipgloss.NewStyle().Foreground(ColorMuted)
)

var (
	StyleToolRead  = lipgloss.NewStyle().Foreground(ColorMuted)
	StyleToolWrite = lipgloss.NewStyle().Foreground(ColorSuccess)
	StyleToolBash  = lipgloss.NewStyle().Foreground(ColorWarning)
	StyleToolArrow = lipgloss.NewStyle().Foreground(ColorMuted).SetString(">")
)

const IterationBarWidth = 10

var SpinnerGradient = []lipgloss.Color{
	"#300000",
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
	"#FF0000",
	"#FF1111",
	"#FF2222",
	"#FF3333",
	"#FF4444",
	"#FF5555",
	"#FF6666",
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

var SpinnerBracketColor = lipgloss.Color("#882222")
var SpinnerTextGlowColor = lipgloss.Color("#8F6666")
var SpinnerTextHighlightColor = lipgloss.Color("#B87777")

// QuestionBox returns a styled box for Q&A.
func QuestionBox() lipgloss.Style {
	width := GetTerminalWidth() - 2
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorInfo).
		BorderTop(true).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		Padding(0, 1).
		Width(width)
}
