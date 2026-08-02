package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/notify"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

type screen int

const (
	screenForm screen = iota
	screenRunning
	screenResults
)

type resultView int

const (
	viewTable resultView = iota
	viewTree
	viewTopology
	resultViewCount
)

func (v resultView) String() string {
	return [...]string{"table", "tree", "map"}[v]
}

// mode is a modal overlay layered on top of the current screen.
type mode int

const (
	modeNone mode = iota
	modeHelp
	modeDetail
	modeFilter
	modeProfileName
	modeProfilePicker
	modeDiscover
)

type sortKey int

const (
	sortIP sortKey = iota
	sortHost
	sortPorts
	sortUp
	sortKeyCount
)

func (s sortKey) String() string {
	return [...]string{"ip", "host", "ports", "up"}[s]
}

var presets = []string{"quick", "default", "udp", "deep"}

// form field indices
const (
	fTargets = iota
	fPreset
	fPorts
	fShowMac
	fShowVendors
	fRootScan
	fSudo
	fConcurrency
	fHostTimeout
	fStart
	fieldCount
)

// rowView pairs a result row with its change badge for display.
type rowView struct {
	row   ui.Row
	diff  config.HostDiff
	gone  bool
	badge string
}

type watchTickMsg struct{ gen int }

// notifyDoneMsg is returned after a desktop notification attempt completes.
type notifyDoneMsg struct{}

// Model is the root Bubble Tea model for the ndscan TUI.
type Model struct {
	version string
	width   int
	height  int

	screen screen
	mode   mode
	focus  int // active form field
	err    error
	notice string // transient feedback (exports, profile saves)

	// form inputs
	targetsIn textinput.Model
	portsIn   textinput.Model
	concurIn  textinput.Model
	timeoutIn textinput.Model
	presetIdx int
	showMac   bool
	showVend  bool
	rootScan  bool
	sudo      bool

	// profiles
	profiles      []config.Profile
	profileIdx    int
	profileNameIn textinput.Model

	// running state
	spin       spinner.Model
	phase      string
	phaseDone  int
	phaseTotal int
	events     <-chan tea.Msg
	cancel     context.CancelFunc
	params     scanParams

	// results
	rows     []ui.Row // authoritative rows (streamed during run, final on done)
	diff     map[string]config.HostDiff
	visible  []rowView // rows after filter/sort, aligned with table cursor
	view     resultView
	tbl      table.Model
	treeVP   viewport.Model // scrollable container for the tree view
	treeRdy  bool           // treeVP has been sized at least once
	summary  string
	failed   int
	filterIn textinput.Model
	sortBy   sortKey

	// discover: a focused deep scan of a single host, shown in an overlay
	disco discoverState

	// topology: the machine's own networks, read once at startup. Passive —
	// no probing — so the map can render before any scan has run.
	netLocals  []netinfo.Network
	netGateway netinfo.Gateway
	mapVP      viewport.Model // scrollable container for the map view
	mapRdy     bool

	// watch mode
	watch       bool
	watchEvery  time.Duration
	watchLeft   int
	watchGen    int
	notify      bool // desktop notifications on watch-mode changes
	watchRescan bool // the in-flight scan was triggered by a watch tick
}

// New constructs the initial model, restoring saved settings when present.
func New(version string) Model {
	mkInput := func(placeholder, val string, width int) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.SetValue(val)
		ti.CharLimit = 256
		ti.Width = width
		ti.Prompt = ""
		return ti
	}

	t := mkInput("192.168.1.0/24  (or  user@host 192.168.1.0/24)", "", 48)
	t.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(accent)

	fl := mkInput("filter…", "", 32)

	m := Model{
		version:       version,
		screen:        screenForm,
		focus:         fTargets,
		targetsIn:     t,
		portsIn:       mkInput("e.g. 22,80,443 or 1-1024 (optional)", "", 48),
		concurIn:      mkInput("64", "64", 8),
		timeoutIn:     mkInput("20", "20", 8),
		profileNameIn: mkInput("profile name", "", 32),
		presetIdx:     0,
		spin:          sp,
		view:          viewTable,
		filterIn:      fl,
		watchEvery:    60 * time.Second,
		notify:        notify.Available(),
	}

	// Read the machine's own networks up front: passive, instant, and it lets
	// the map show attached networks even before the first scan.
	m.netLocals = netinfo.Locals()
	m.netGateway = netinfo.DefaultGateway()

	cf := config.Load()
	m.profiles = cf.Profiles
	if cf.Last != nil {
		m.applySettings(*cf.Last)
	} else if cidr := localCIDR(); cidr != "" {
		m.targetsIn.SetValue(cidr)
	}
	return m
}

// currentSettings snapshots the form into a persistable Settings.
func (m Model) currentSettings() config.Settings {
	return config.Settings{
		Targets:     m.targetsIn.Value(),
		Preset:      presets[m.presetIdx],
		Ports:       m.portsIn.Value(),
		ShowMac:     m.showMac,
		ShowVendors: m.showVend,
		RootScan:    m.rootScan,
		Sudo:        m.sudo,
		Concurrency: m.concurIn.Value(),
		HostTimeout: m.timeoutIn.Value(),
	}
}

// applySettings restores the form from a saved Settings.
func (m *Model) applySettings(s config.Settings) {
	m.targetsIn.SetValue(s.Targets)
	m.portsIn.SetValue(s.Ports)
	if s.Concurrency != "" {
		m.concurIn.SetValue(s.Concurrency)
	}
	if s.HostTimeout != "" {
		m.timeoutIn.SetValue(s.HostTimeout)
	}
	m.showMac = s.ShowMac
	m.showVend = s.ShowVendors
	m.rootScan = s.RootScan
	m.sudo = s.Sudo
	for i, p := range presets {
		if p == s.Preset {
			m.presetIdx = i
		}
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

// Run starts the TUI program.
func Run(version string) error {
	p := tea.NewProgram(New(version), tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.screen == screenResults || m.screen == screenRunning {
			m.rebuildTable()
		}
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		// modal overlays grab keys first
		if m.mode != modeNone {
			return m.updateMode(msg)
		}
		switch m.screen {
		case screenForm:
			return m.updateForm(msg)
		case screenRunning:
			return m.updateRunning(msg)
		case screenResults:
			return m.updateResults(msg)
		}

	case tea.MouseMsg:
		// Mouse-wheel scrolls the active results view. The table scrolls
		// itself; the tree scrolls its viewport.
		if m.mode == modeNone && m.screen == screenResults {
			if m.view == viewTree {
				var cmd tea.Cmd
				m.treeVP, cmd = m.treeVP.Update(msg)
				return m, cmd
			}
			if m.view == viewTopology {
				var cmd tea.Cmd
				m.mapVP, cmd = m.mapVP.Update(msg)
				return m, cmd
			}
			var cmd tea.Cmd
			m.tbl, cmd = m.tbl.Update(msg)
			return m, cmd
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case phaseMsg:
		m.phase = msg.phase
		m.phaseDone = msg.done
		m.phaseTotal = msg.total
		return m, listen(m.events)

	case hostRowMsg:
		m.rows = append(m.rows, msg.rows...)
		m.rebuildTable()
		return m, listen(m.events)

	case doneMsg:
		m.screen = screenResults
		m.cancel = nil
		m.rows = msg.rows
		m.diff = msg.diff
		m.failed = msg.failed
		hostsUp, openPorts := 0, 0
		for _, r := range msg.rows {
			if r.Up {
				hostsUp++
			}
			openPorts += len(r.Ports)
		}
		m.summary = fmt.Sprintf("%d host(s) up · %d port(s) open · %s in %s",
			hostsUp, openPorts, map[bool]string{true: "cancelled", false: "done"}[msg.cancelled],
			msg.elapsed.Round(10*time.Millisecond))
		m.rebuildTable()

		var cmds []tea.Cmd
		// On a watch-mode rescan, alert on any change via desktop notification.
		if m.watchRescan && m.notify && !msg.cancelled {
			if title, body, ok := notifySummary(m.diff, m.rows); ok {
				cmds = append(cmds, notifyCmd(title, body))
			}
		}
		m.watchRescan = false
		if m.watch {
			m.watchLeft = int(m.watchEvery.Seconds())
			cmds = append(cmds, m.watchTick())
		}
		return m, tea.Batch(cmds...)

	case errMsg:
		m.err = msg.err
		m.screen = screenForm
		m.cancel = nil
		m.watch = false
		return m, nil

	case sudoPrimedMsg:
		if msg.err != nil {
			m.sudo = false
			m.err = fmt.Errorf("sudo authentication failed")
		} else {
			m.sudo = true
			m.notice = "sudo enabled — thorough ARP/SYN scans active"
		}
		return m, nil

	case watchTickMsg:
		if msg.gen != m.watchGen || !m.watch || m.screen != screenResults {
			return m, nil
		}
		m.watchLeft--
		if m.watchLeft <= 0 {
			m.watchRescan = true
			return m.startWithParams(m.params)
		}
		return m, m.watchTick()

	case notifyDoneMsg:
		return m, nil

	case discoverDoneMsg:
		// Ignore a stale result if the user moved on to another host.
		if m.mode != modeDiscover || msg.ip != m.disco.ip {
			return m, nil
		}
		m.disco.scanning = false
		m.disco.row = msg.row
		m.disco.err = msg.err
		m.disco.elapsed = msg.elapsed
		m.disco.cancel = nil
		return m, nil
	}

	return m, nil
}

func (m *Model) watchTick() tea.Cmd {
	gen := m.watchGen
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return watchTickMsg{gen: gen} })
}

// ----- MODAL OVERLAYS -----

func (m Model) updateMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeHelp:
		m.mode = modeNone
		return m, nil

	case modeDetail:
		switch msg.String() {
		case "esc", "enter", "q":
			m.mode = modeNone
		}
		return m, nil

	case modeFilter:
		switch msg.String() {
		case "enter":
			m.mode = modeNone
			return m, nil
		case "esc":
			m.filterIn.SetValue("")
			m.mode = modeNone
			m.rebuildTable()
			return m, nil
		}
		var cmd tea.Cmd
		m.filterIn, cmd = m.filterIn.Update(msg)
		m.rebuildTable()
		return m, cmd

	case modeProfileName:
		switch msg.String() {
		case "enter":
			name := strings.TrimSpace(m.profileNameIn.Value())
			if name == "" {
				return m, nil
			}
			if err := config.UpsertProfile(name, m.currentSettings()); err != nil {
				m.err = err
			} else {
				m.notice = fmt.Sprintf("saved profile %q", name)
				m.profiles = config.Load().Profiles
			}
			m.mode = modeNone
			return m, nil
		case "esc":
			m.mode = modeNone
			return m, nil
		}
		var cmd tea.Cmd
		m.profileNameIn, cmd = m.profileNameIn.Update(msg)
		return m, cmd

	case modeProfilePicker:
		switch msg.String() {
		case "esc", "q":
			m.mode = modeNone
		case "up", "k":
			if m.profileIdx > 0 {
				m.profileIdx--
			}
		case "down", "j":
			if m.profileIdx < len(m.profiles)-1 {
				m.profileIdx++
			}
		case "d":
			if len(m.profiles) > 0 {
				name := m.profiles[m.profileIdx].Name
				_ = config.DeleteProfile(name)
				m.profiles = config.Load().Profiles
				if m.profileIdx >= len(m.profiles) && m.profileIdx > 0 {
					m.profileIdx--
				}
				m.notice = fmt.Sprintf("deleted profile %q", name)
			}
		case "enter":
			if len(m.profiles) > 0 {
				m.applySettings(m.profiles[m.profileIdx].Settings)
				m.notice = fmt.Sprintf("loaded profile %q", m.profiles[m.profileIdx].Name)
			}
			m.mode = modeNone
		}
		return m, nil

	case modeDiscover:
		switch msg.String() {
		case "esc", "q":
			if m.disco.cancel != nil {
				m.disco.cancel()
				m.disco.cancel = nil
			}
			m.mode = modeNone
			return m, nil
		case "r":
			// rescan this host (ignored while a scan is in flight)
			if !m.disco.scanning {
				return m, m.startDiscover(m.disco.ip)
			}
			return m, nil
		case "o":
			if !m.disco.scanning {
				m.disco.notice = m.openWeb()
			}
			return m, nil
		}
		return m, nil
	}
	return m, nil
}

// ----- FORM -----

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m, tea.Quit
	case "ctrl+s":
		m.profileNameIn.SetValue("")
		m.profileNameIn.Focus()
		m.mode = modeProfileName
		return m, textinput.Blink
	case "ctrl+p":
		m.profiles = config.Load().Profiles
		m.profileIdx = 0
		m.mode = modeProfilePicker
		return m, nil
	case "tab", "down":
		m.focus = (m.focus + 1) % fieldCount
		return m.syncFocus()
	case "shift+tab", "up":
		m.focus = (m.focus - 1 + fieldCount) % fieldCount
		return m.syncFocus()
	case "left", "right":
		if m.focus == fPreset {
			if msg.String() == "right" {
				m.presetIdx = (m.presetIdx + 1) % len(presets)
			} else {
				m.presetIdx = (m.presetIdx - 1 + len(presets)) % len(presets)
			}
			return m, nil
		}
	case "?":
		// only when not typing in a text field
		if !m.focusIsTextField() {
			m.mode = modeHelp
			return m, nil
		}
	case " ":
		switch m.focus {
		case fShowMac:
			m.showMac = !m.showMac
			return m, nil
		case fShowVendors:
			m.showVend = !m.showVend
			return m, nil
		case fRootScan:
			m.rootScan = !m.rootScan
			return m, nil
		case fSudo:
			return m.toggleSudo()
		}
	case "enter":
		switch m.focus {
		case fPreset:
			m.presetIdx = (m.presetIdx + 1) % len(presets)
			return m, nil
		case fShowMac:
			m.showMac = !m.showMac
			return m, nil
		case fShowVendors:
			m.showVend = !m.showVend
			return m, nil
		case fRootScan:
			m.rootScan = !m.rootScan
			return m, nil
		case fSudo:
			return m.toggleSudo()
		case fStart:
			return m.startScan()
		default:
			m.focus = (m.focus + 1) % fieldCount
			return m.syncFocus()
		}
	}

	var cmd tea.Cmd
	switch m.focus {
	case fTargets:
		m.targetsIn, cmd = m.targetsIn.Update(msg)
	case fPorts:
		m.portsIn, cmd = m.portsIn.Update(msg)
	case fConcurrency:
		m.concurIn, cmd = m.concurIn.Update(msg)
	case fHostTimeout:
		m.timeoutIn, cmd = m.timeoutIn.Update(msg)
	}
	return m, cmd
}

// sudoPrimedMsg reports the result of an interactive sudo authentication.
type sudoPrimedMsg struct{ err error }

// toggleSudo flips the sudo flag. Turning it on when sudo isn't already
// authenticated suspends the TUI to run an interactive `sudo -v` on the real
// terminal (the only place a password prompt is visible), then resumes.
func (m Model) toggleSudo() (tea.Model, tea.Cmd) {
	if scan.IsRoot() {
		m.sudo = false
		m.notice = "already running as root — sudo not needed"
		return m, nil
	}
	if m.sudo {
		m.sudo = false
		return m, nil
	}
	if !scan.SudoAvailable() {
		m.err = fmt.Errorf("sudo not found on PATH")
		return m, nil
	}
	if scan.SudoPrimed() {
		m.sudo = true
		return m, nil
	}
	// suspend alt-screen, prompt for the password, resume
	prime := exec.Command("sudo", "-v")
	prime.Stdin, prime.Stdout, prime.Stderr = os.Stdin, os.Stdout, os.Stderr
	return m, tea.ExecProcess(prime, func(err error) tea.Msg {
		return sudoPrimedMsg{err: err}
	})
}

func (m Model) focusIsTextField() bool {
	switch m.focus {
	case fTargets, fPorts, fConcurrency, fHostTimeout:
		return true
	}
	return false
}

// syncFocus blurs every input then focuses the one matching m.focus.
func (m Model) syncFocus() (tea.Model, tea.Cmd) {
	m.targetsIn.Blur()
	m.portsIn.Blur()
	m.concurIn.Blur()
	m.timeoutIn.Blur()
	var cmd tea.Cmd
	switch m.focus {
	case fTargets:
		cmd = m.targetsIn.Focus()
	case fPorts:
		cmd = m.portsIn.Focus()
	case fConcurrency:
		cmd = m.concurIn.Focus()
	case fHostTimeout:
		cmd = m.timeoutIn.Focus()
	}
	return m, cmd
}

func (m Model) startScan() (tea.Model, tea.Cmd) {
	ssh, targets := parseTargets(m.targetsIn.Value())
	if len(targets) == 0 {
		m.err = fmt.Errorf("enter at least one target (IP or CIDR)")
		return m, nil
	}
	if !nmapAvailable(ssh) {
		m.err = fmt.Errorf("nmap not found — install it with: brew install nmap")
		return m, nil
	}
	m.err = nil
	m.notice = ""

	concur, err := strconv.Atoi(strings.TrimSpace(m.concurIn.Value()))
	if err != nil || concur < 1 {
		concur = 32
	}
	tmo, err := strconv.Atoi(strings.TrimSpace(m.timeoutIn.Value()))
	if err != nil || tmo < 1 {
		tmo = 20
	}

	_ = config.SaveLast(m.currentSettings()) // best-effort persistence

	return m.startWithParams(scanParams{
		sshTarget:   ssh,
		targets:     targets,
		preset:      presets[m.presetIdx],
		ports:       strings.TrimSpace(m.portsIn.Value()),
		showMac:     m.showMac,
		showVendors: m.showVend,
		rootScan:    m.rootScan,
		sudo:        m.sudo,
		concurrency: concur,
		hostTimeout: time.Duration(tmo) * time.Second,
	})
}

// startWithParams kicks off a scan; used by Start and watch-mode rescans.
func (m Model) startWithParams(p scanParams) (tea.Model, tea.Cmd) {
	m.params = p
	m.rows = nil
	m.diff = nil
	m.failed = 0
	m.events, m.cancel = runScan(p)
	m.screen = screenRunning
	m.phase = "discover"
	m.phaseDone, m.phaseTotal = 0, 0
	m.rebuildTable()
	return m, tea.Batch(m.spin.Tick, listen(m.events))
}

// ----- RUNNING -----

func (m Model) updateRunning(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		// cancel the scan; the goroutine flushes a cancelled doneMsg
		if m.cancel != nil {
			m.cancel()
		}
		return m, nil
	case "?":
		m.mode = modeHelp
		return m, nil
	}
	return m, nil
}

// ----- RESULTS -----

func (m Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "?":
		m.mode = modeHelp
		return m, nil
	case "n", "r":
		m.watch = false
		m.screen = screenForm
		m.err = nil
		m.notice = ""
		return m.syncFocus()
	case "t":
		m.view = (m.view + 1) % resultViewCount
		m.rebuildTable()
		return m, nil
	case "/":
		m.filterIn.Focus()
		m.mode = modeFilter
		return m, textinput.Blink
	case "s":
		// In the map, sorting is meaningless — "s" scans the first attached
		// network that hasn't been covered yet, which is what the map offers.
		if m.view == viewTopology {
			if cidr, ok := m.firstUnscannedNetwork(); ok {
				p := m.params
				p.sshTarget = ""
				p.targets = []string{cidr}
				return m.startWithParams(p)
			}
			m.notice = "every attached network has been scanned"
			return m, nil
		}
		m.sortBy = (m.sortBy + 1) % sortKeyCount
		m.rebuildTable()
		return m, nil
	case "enter":
		// Enter on a host runs a focused deep scan (Discover). Falls back to
		// the static detail pane for synthetic GONE rows.
		if m.view == viewTable {
			if rv := m.selectedRow(); rv != nil {
				if rv.gone {
					m.mode = modeDetail
					return m, nil
				}
				return m, m.startDiscover(rv.row.IP)
			}
		}
		return m, nil
	case "e":
		m.notice = m.export("json")
		return m, nil
	case "c":
		m.notice = m.export("csv")
		return m, nil
	case "m":
		m.notice = m.export("md")
		return m, nil
	case "h":
		m.notice = m.export("html")
		return m, nil
	case "w":
		m.watch = !m.watch
		m.watchGen++
		if m.watch {
			m.watchLeft = int(m.watchEvery.Seconds())
			return m, m.watchTick()
		}
		return m, nil
	case "b":
		if !notify.Available() {
			m.notice = "desktop notifications unavailable on this system"
			return m, nil
		}
		m.notify = !m.notify
		if m.notify {
			m.notice = "watch notifications on"
		} else {
			m.notice = "watch notifications off"
		}
		return m, nil
	case "+", "=":
		m.watchEvery += 15 * time.Second
		m.watchLeft = int(m.watchEvery.Seconds())
		return m, nil
	case "-":
		if m.watchEvery > 15*time.Second {
			m.watchEvery -= 15 * time.Second
		}
		m.watchLeft = int(m.watchEvery.Seconds())
		return m, nil
	}
	if m.view == viewTable {
		before := m.tbl.Cursor()
		var cmd tea.Cmd
		m.tbl, cmd = m.tbl.Update(msg)
		// Keep the "discover →" affordance on the now-selected row.
		if m.tbl.Cursor() != before {
			m.tbl.SetRows(m.tableRows(m.tbl.Cursor()))
		}
		return m, cmd
	}
	// Tree and map views: forward navigation keys (↑↓, j/k, PgUp/PgDn, g/G) to
	// the active scrollable viewport.
	var cmd tea.Cmd
	if m.view == viewTopology {
		m.mapVP, cmd = m.mapVP.Update(msg)
		return m, cmd
	}
	m.treeVP, cmd = m.treeVP.Update(msg)
	return m, cmd
}

// selectedRow returns the rowView under the table cursor, if any.
func (m Model) selectedRow() *rowView {
	i := m.tbl.Cursor()
	if i < 0 || i >= len(m.visible) {
		return nil
	}
	return &m.visible[i]
}

// ----- VISIBLE ROWS (filter + sort + diff badges) -----

func (m *Model) buildVisible() {
	filter := strings.ToLower(strings.TrimSpace(m.filterIn.Value()))
	match := func(r ui.Row) bool {
		if filter == "" {
			return true
		}
		hay := strings.ToLower(strings.Join(append([]string{r.IP, r.Host, r.MAC, r.Vendor, r.OS}, r.Ports...), " "))
		return strings.Contains(hay, filter)
	}

	vis := make([]rowView, 0, len(m.rows)+4)
	for _, r := range m.rows {
		if !match(r) {
			continue
		}
		rv := rowView{row: r}
		if d, ok := m.diff[r.IP]; ok {
			rv.diff = d
			rv.badge = diffBadge(d)
		}
		vis = append(vis, rv)
	}
	// hosts that disappeared since the previous scan
	for ip, d := range m.diff {
		if d.Gone && (filter == "" || strings.Contains(ip, filter)) {
			vis = append(vis, rowView{row: ui.Row{IP: ip}, diff: d, gone: true, badge: "GONE"})
		}
	}

	less := func(a, b rowView) bool { return ipLess(a.row.IP, b.row.IP) }
	switch m.sortBy {
	case sortHost:
		less = func(a, b rowView) bool {
			if a.row.Host != b.row.Host {
				return a.row.Host < b.row.Host
			}
			return ipLess(a.row.IP, b.row.IP)
		}
	case sortPorts:
		less = func(a, b rowView) bool {
			if len(a.row.Ports) != len(b.row.Ports) {
				return len(a.row.Ports) > len(b.row.Ports) // most ports first
			}
			return ipLess(a.row.IP, b.row.IP)
		}
	case sortUp:
		less = func(a, b rowView) bool {
			if a.row.Up != b.row.Up {
				return a.row.Up
			}
			return ipLess(a.row.IP, b.row.IP)
		}
	}
	sort.SliceStable(vis, func(i, j int) bool { return less(vis[i], vis[j]) })
	m.visible = vis
}

func diffBadge(d config.HostDiff) string {
	if d.New {
		return "NEW"
	}
	if d.Gone {
		return "GONE"
	}
	var parts []string
	for _, p := range d.PortsOpened {
		parts = append(parts, "+"+p)
	}
	for _, p := range d.PortsClosed {
		parts = append(parts, "-"+p)
	}
	return strings.Join(parts, " ")
}

// ipLess orders IPv4/IPv6 numerically, falling back to string compare. It
// delegates to ui.IPLess so the TUI and the CLI printers sort identically.
func ipLess(a, b string) bool { return ui.IPLess(a, b) }

func (m *Model) rebuildTable() {
	m.buildVisible()

	hasDiff := len(m.diff) > 0
	var cols []table.Column
	add := func(title string, w int) {
		cols = append(cols, table.Column{Title: title, Width: w})
	}
	// Column set is chosen so the most-asked questions — who is this, what is
	// it running, is any of it risky — are answerable without opening a host.
	add("IP", 16)
	add("Host", 18)
	if m.params.showMac {
		add("MAC", 18)
		add("Vendor", 14)
	}
	add("Up", 4)
	add("!", 3)
	add("Ports", 24)
	add("Latency", 9)
	if hasDiff {
		add("Δ", 10)
	}
	add("", 12) // discover affordance, header left blank

	cursor := m.tbl.Cursor()
	rows := m.tableRows(cursor)

	h := m.height - 12
	if h < 5 {
		h = 5
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(h),
	)
	st := table.DefaultStyles()
	st.Header = st.Header.BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(accent).BorderBottom(true).Bold(true).Foreground(accentText.GetForeground())
	st.Selected = st.Selected.Foreground(bgDark).Background(accent).Bold(true)
	t.SetStyles(st)
	if cursor > 0 && cursor < len(rows) {
		t.SetCursor(cursor)
	}
	m.tbl = t

	m.refreshTree()
}

// tableRows builds the table cell rows. The Discover column shows an arrow only
// on the row at `cursor`, so the affordance follows the selection; pass -1 for
// none. Column set must stay in sync with rebuildTable.
func (m Model) tableRows(cursor int) []table.Row {
	hasDiff := len(m.diff) > 0
	rows := make([]table.Row, 0, len(m.visible))
	for i, rv := range m.visible {
		r := rv.row
		up := "✗"
		if r.Up {
			up = "✓"
		}
		if rv.gone {
			up = "✗"
		}
		name := r.Host
		if name == "" {
			name = r.Vendor
		}
		cells := []string{r.IP, dash(name)}
		if m.params.showMac {
			cells = append(cells, dash(r.MAC), dash(r.Vendor))
		}
		cells = append(cells, up, riskGlyph(r), dash(portSummary(r)), dash(r.RTT))
		if hasDiff {
			cells = append(cells, rv.badge)
		}
		discover := ""
		if i == cursor && !rv.gone {
			discover = "discover →"
		}
		cells = append(cells, discover)
		rows = append(rows, table.Row(cells))
	}
	return rows
}

// riskGlyph renders the highest severity among a host's open ports as a single
// compact marker for the results table.
func riskGlyph(r ui.Row) string {
	worst := ""
	for _, p := range r.PortDetails {
		if rankSeverity(p.Severity) > rankSeverity(worst) {
			worst = p.Severity
		}
	}
	switch worst {
	case "high":
		return "!!"
	case "warn":
		return "▲"
	case "info":
		return "·"
	default:
		return ""
	}
}

// treeViewportHeight returns the visible row budget for the scrollable tree,
// matching the table's height reservation so both views fill the same space.
func (m Model) treeViewportHeight() int {
	h := m.height - 12
	if h < 5 {
		h = 5
	}
	return h
}

// refreshTree re-renders the tree content into the scrollable viewport and
// sizes it to the current window, preserving the scroll position.
func (m *Model) refreshTree() {
	w := m.width
	if w == 0 {
		w = 100
	}
	h := m.treeViewportHeight()
	if !m.treeRdy {
		m.treeVP = viewport.New(w, h)
		m.treeRdy = true
	} else {
		m.treeVP.Width = w
		m.treeVP.Height = h
	}
	m.treeVP.SetContent(m.treeView())
	m.refreshMap()
}

// refreshMap re-renders the topology map into its scrollable viewport.
func (m *Model) refreshMap() {
	w := m.width
	if w == 0 {
		w = 100
	}
	h := m.treeViewportHeight()
	if !m.mapRdy {
		m.mapVP = viewport.New(w, h)
		m.mapRdy = true
	} else {
		m.mapVP.Width = w
		m.mapVP.Height = h
	}
	m.mapVP.SetContent(m.topologyView())
}

// shortHostname returns this machine's hostname without any domain suffix.
func shortHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// rankSeverity orders severity strings so we can find the highest on a host.
func rankSeverity(s string) int {
	switch s {
	case "high":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// notifyCmd fires a desktop notification off the main loop. It returns a
// notifyDoneMsg so the model can surface delivery state without blocking.
func notifyCmd(title, body string) tea.Cmd {
	return func() tea.Msg {
		_ = notify.Send(notify.Notification{
			Title:    "ndscan",
			Subtitle: title,
			Message:  body,
		})
		return notifyDoneMsg{}
	}
}

// notifySummary condenses a watch-mode diff into a notification title + body.
// It returns ok=false when nothing meaningfully changed (so no alert fires).
// rows supplies host context (vendor/hostname) for friendlier new-host lines.
func notifySummary(diff map[string]config.HostDiff, rows []ui.Row) (title, body string, ok bool) {
	if len(diff) == 0 {
		return "", "", false
	}
	rowByIP := make(map[string]ui.Row, len(rows))
	for _, r := range rows {
		rowByIP[r.IP] = r
	}

	var newHosts, goneHosts []string
	newCount, goneCount, opened, closed := 0, 0, 0, 0
	for ip, d := range diff {
		switch {
		case d.New:
			newCount++
			newHosts = append(newHosts, hostLabel(ip, rowByIP[ip]))
		case d.Gone:
			goneCount++
			goneHosts = append(goneHosts, ip)
		}
		opened += len(d.PortsOpened)
		closed += len(d.PortsClosed)
	}
	if newCount == 0 && goneCount == 0 && opened == 0 && closed == 0 {
		return "", "", false
	}
	sort.Strings(newHosts)
	sort.Strings(goneHosts)

	// Title: the single most important change, prioritizing new hosts.
	switch {
	case newCount == 1 && goneCount == 0 && opened == 0:
		title = "New host: " + newHosts[0]
	case newCount > 0:
		title = fmt.Sprintf("%d new host(s) on the network", newCount)
	case goneCount > 0:
		title = fmt.Sprintf("%d host(s) went offline", goneCount)
	case opened > 0:
		title = fmt.Sprintf("%d port(s) opened", opened)
	default:
		title = "Network changed"
	}

	// Body: a compact breakdown of everything that changed.
	var parts []string
	if len(newHosts) > 0 {
		parts = append(parts, "+ "+strings.Join(clip(newHosts, 3), ", "))
	}
	if len(goneHosts) > 0 {
		parts = append(parts, "- "+strings.Join(clip(goneHosts, 3), ", "))
	}
	if opened > 0 {
		parts = append(parts, fmt.Sprintf("%d port(s) opened", opened))
	}
	if closed > 0 {
		parts = append(parts, fmt.Sprintf("%d port(s) closed", closed))
	}
	return title, strings.Join(parts, " · "), true
}

// hostLabel renders an IP with its hostname or vendor in parens when known.
func hostLabel(ip string, r ui.Row) string {
	switch {
	case r.Host != "":
		return ip + " (" + r.Host + ")"
	case r.Vendor != "":
		return ip + " (" + r.Vendor + ")"
	default:
		return ip
	}
}

// clip caps a slice for display, appending "+N more" when truncated.
func clip(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("+%d more", len(s)-n))
}

// exposureNote is the summary line shown when a host has notable open ports.
func exposureNote(severity string) string {
	if severity == "high" {
		return "high-risk service exposed — review whether this should be open"
	}
	return "notable service exposed on this host"
}
