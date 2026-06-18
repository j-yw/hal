package engine

import (
	"github.com/charmbracelet/lipgloss"
	ui "github.com/jywlabs/hal/internal/ui"
)

var (
	ColorSuccess = ui.ColorSuccess
	ColorError   = ui.ColorError
	ColorWarning = ui.ColorWarning
	ColorInfo    = ui.ColorInfo
	ColorMuted   = ui.ColorMuted
	ColorAccent  = ui.ColorAccent
)

var (
	StyleSuccess = ui.StyleSuccess
	StyleError   = ui.StyleError
	StyleWarning = ui.StyleWarning
	StyleInfo    = ui.StyleInfo
	StyleMuted   = ui.StyleMuted
	StyleAccent  = ui.StyleAccent
	StyleBold    = ui.StyleBold
	StyleTitle   = ui.StyleTitle
)

var StyleCommandIcon = ui.StyleCommandIcon

func GetTerminalWidth() int { return ui.GetTerminalWidth() }

func BoxStyle(borderColor lipgloss.Color) lipgloss.Style { return ui.BoxStyle(borderColor) }

func HeaderBox() lipgloss.Style  { return ui.HeaderBox() }
func SuccessBox() lipgloss.Style { return ui.SuccessBox() }
func ErrorBox() lipgloss.Style   { return ui.ErrorBox() }
func WarningBox() lipgloss.Style { return ui.WarningBox() }

var (
	StyleProgressFilled = ui.StyleProgressFilled
	StyleProgressEmpty  = ui.StyleProgressEmpty
)

var (
	StyleToolRead  = ui.StyleToolRead
	StyleToolWrite = ui.StyleToolWrite
	StyleToolBash  = ui.StyleToolBash
	StyleToolArrow = ui.StyleToolArrow
)

const IterationBarWidth = ui.IterationBarWidth

var SpinnerGradient = ui.SpinnerGradient
var SpinnerBracketColor = ui.SpinnerBracketColor
var SpinnerTextGlowColor = ui.SpinnerTextGlowColor
var SpinnerTextHighlightColor = ui.SpinnerTextHighlightColor

func QuestionBox() lipgloss.Style { return ui.QuestionBox() }
