package ui

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/text"
)

// Interactive is true when stderr is attached to a terminal; spinners and the
// banner are suppressed otherwise (e.g. when output is piped or redirected).
var Interactive = isTTY(os.Stderr)

func init() {
	// Keep piped/redirected stdout free of ANSI escape codes.
	if !isTTY(os.Stdout) {
		text.DisableColors()
	}
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

var (
	cAccent = text.Colors{text.FgHiCyan}
	cDim    = text.Colors{text.FgHiBlack}
	cOK     = text.Colors{text.FgHiGreen}
	cWarn   = text.Colors{text.FgHiYellow}
	cErr    = text.Colors{text.FgHiRed}
	cBold   = text.Colors{text.Bold}
	cTitle  = text.Colors{text.FgHiCyan, text.Bold}
)

// Banner prints the app header to stderr so stdout stays clean for results.
func Banner(version string) {
	if !Interactive {
		return
	}
	line := func(s string) { fmt.Fprintln(os.Stderr, s) }
	line(cAccent.Sprint("╭──────────────────────────────────────────────╮"))
	line(cAccent.Sprint("│") + cTitle.Sprint("   ndscan ") + cDim.Sprintf(" ·  fast network scanner  ·  v%-5s", version) + cAccent.Sprint(" │"))
	line(cAccent.Sprint("╰──────────────────────────────────────────────╯"))
}

// Warnf prints a yellow warning line to stderr.
func Warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", cWarn.Sprint("!"), fmt.Sprintf(format, a...))
}

// Infof prints a dim info line to stderr.
func Infof(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s\n", cDim.Sprint(fmt.Sprintf(format, a...)))
}
