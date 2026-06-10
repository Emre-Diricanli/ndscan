package tui

import "github.com/charmbracelet/lipgloss"

var (
	accent  = lipgloss.Color("#22d3ee") // cyan
	subtle  = lipgloss.Color("#6b7280") // gray
	green   = lipgloss.Color("#34d399")
	red     = lipgloss.Color("#f87171")
	yellow  = lipgloss.Color("#fbbf24")
	fgLight = lipgloss.Color("#e5e7eb")

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0b1120")).
			Background(accent).
			Bold(true).
			Padding(0, 1)

	appBar = lipgloss.NewStyle().
		Foreground(subtle).
		Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Padding(1, 2)

	labelStyle        = lipgloss.NewStyle().Foreground(fgLight).Bold(true)
	labelFocusedStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)
	valueStyle        = lipgloss.NewStyle().Foreground(fgLight)
	hintStyle         = lipgloss.NewStyle().Foreground(subtle)
	helpStyle         = lipgloss.NewStyle().Foreground(subtle).Padding(1, 0, 0, 0)

	okStyle    = lipgloss.NewStyle().Foreground(green)
	errStyle   = lipgloss.NewStyle().Foreground(red)
	warnStyle  = lipgloss.NewStyle().Foreground(yellow)
	accentText = lipgloss.NewStyle().Foreground(accent)

	buttonStyle = lipgloss.NewStyle().
			Foreground(fgLight).
			Background(lipgloss.Color("#374151")).
			Padding(0, 2)

	buttonFocusedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#0b1120")).
				Background(accent).
				Bold(true).
				Padding(0, 2)
)

func checkbox(on bool) string {
	if on {
		return okStyle.Render("[✔]")
	}
	return hintStyle.Render("[ ]")
}

// sevStyle maps a risk severity string to its display style.
func sevStyle(severity string) lipgloss.Style {
	switch severity {
	case "high":
		return errStyle
	case "warn":
		return warnStyle
	case "info":
		return accentText
	default:
		return valueStyle
	}
}
