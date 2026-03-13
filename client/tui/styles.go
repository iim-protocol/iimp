package tui

import (
	"charm.land/lipgloss/v2"
)

// styles
var (
	senderStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	ownStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))
	timestampStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	editedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Italic(true)
	attachStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	pendingStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	errorStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	selectedStyle  = lipgloss.NewStyle().Background(lipgloss.Color("8"))
	modalStyle     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Margin(1, 2).Align(lipgloss.Center)
	headerStyle    = lipgloss.NewStyle().Bold(true).Padding(0, 1)
)
