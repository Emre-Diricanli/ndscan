package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Palette. One source of truth for every screen — the form, the running view,
// results, overlays, and the map — so nothing looks bolted on.
var (
	accent  = lipgloss.Color("#22d3ee") // cyan — focus, selection, structure
	accent2 = lipgloss.Color("#818cf8") // indigo — secondary emphasis
	subtle  = lipgloss.Color("#6b7280") // gray — hints, chrome
	faint   = lipgloss.Color("#374151") // darker gray — dividers, inactive
	green   = lipgloss.Color("#34d399")
	red     = lipgloss.Color("#f87171")
	yellow  = lipgloss.Color("#fbbf24")
	fgLight = lipgloss.Color("#e5e7eb")
	bgDark  = lipgloss.Color("#0b1120") // page background, used as inverse text

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
				Foreground(bgDark).
				Background(accent).
				Bold(true).
				Padding(0, 2)

	// Shared vocabulary used across screens.

	// sectionStyle heads a group of related fields or rows.
	sectionStyle = lipgloss.NewStyle().Foreground(accent2).Bold(true)
	// dividerStyle draws the thin rules that separate regions.
	dividerStyle = lipgloss.NewStyle().Foreground(faint)
	// badgeStyle is an inverse chip, for counts and states.
	badgeStyle = lipgloss.NewStyle().Foreground(bgDark).Background(accent2).Padding(0, 1).Bold(true)
	// keyStyle renders a keybinding so hints read consistently everywhere.
	keyStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

// divider returns a horizontal rule of the given width.
func divider(w int) string {
	if w < 1 {
		return ""
	}
	return dividerStyle.Render(strings.Repeat("─", w))
}

// keyHint renders "key action" pairs in one consistent style, joined by
// separators — used by every screen's footer.
func keyHint(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, keyStyle.Render(p[0])+" "+hintStyle.Render(p[1]))
	}
	return strings.Join(parts, hintStyle.Render(" · "))
}

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
