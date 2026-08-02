package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func keyRunes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func typeString(m tea.Model, s string) tea.Model {
	for _, r := range s {
		m, _ = m.Update(keyRunes(string(r)))
	}
	return m
}

// resultsModel fabricates a model sitting on the results screen.
func resultsModel(t *testing.T) Model {
	t.Helper()
	m := New("test")
	m.width, m.height = 120, 40
	m.screen = screenResults
	m.rows = []ui.Row{
		{IP: "10.0.0.2", Host: "beta", Up: true, Ports: []string{"22/tcp ssh", "80/tcp http nginx"}},
		{IP: "10.0.0.10", Host: "alpha", Up: true, Ports: []string{"443/tcp https"}},
		{IP: "10.0.0.1", Host: "router", Up: true, Ports: []string{}},
	}
	m.diff = map[string]config.HostDiff{
		"10.0.0.10": {New: true},
		"10.0.0.99": {Gone: true},
	}
	m.summary = "3 host(s) up"
	m.rebuildTable()
	return m
}

func TestTreeViewScrolls(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.width, m.height = 100, 16 // short window so content overflows
	m.screen = screenResults
	// many hosts -> tree taller than the viewport
	for i := 0; i < 40; i++ {
		m.rows = append(m.rows, ui.Row{
			IP: "10.0.0." + strconv.Itoa(i), Up: true,
			Ports: []string{"22/tcp ssh"},
		})
	}
	m.summary = "40 host(s) up"
	m.rebuildTable()

	var tm tea.Model = m
	tm, _ = tm.Update(keyRunes("t")) // switch to tree view
	if tm.(Model).view != viewTree {
		t.Fatal("t should switch to tree view")
	}
	before := tm.(Model).treeVP.YOffset

	// keyboard down + mouse wheel down should both advance the viewport
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyDown})
	tm, _ = tm.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	after := tm.(Model).treeVP.YOffset
	if after <= before {
		t.Fatalf("tree viewport should scroll down: offset %d -> %d", before, after)
	}
}

func TestFilterNarrowsRows(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	var tm tea.Model = m
	tm, _ = tm.Update(keyRunes("/"))
	if tm.(Model).mode != modeFilter {
		t.Fatal("/ should enter filter mode")
	}
	tm = typeString(tm, "nginx")
	got := tm.(Model).visible
	if len(got) != 1 || got[0].row.IP != "10.0.0.2" {
		t.Fatalf("filter 'nginx' should leave only 10.0.0.2, got %d rows", len(got))
	}
	// esc clears the filter
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if n := len(tm.(Model).visible); n != 4 { // 3 rows + 1 GONE
		t.Fatalf("esc should clear filter, got %d visible", n)
	}
}

func TestDiscoverArrowFollowsCursor(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t) // 3 live rows + 1 gone
	m.rebuildTable()

	discoverIdx := func(rows []table.Row) int {
		for i, r := range rows {
			if r[len(r)-1] != "" { // Discover is the last column
				return i
			}
		}
		return -1
	}

	if got := discoverIdx(m.tableRows(0)); got != 0 {
		t.Fatalf("discover arrow should be on row 0, got %d", got)
	}

	var tm tea.Model = m
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyDown})
	mm := tm.(Model)
	if got := discoverIdx(mm.tableRows(mm.tbl.Cursor())); got != mm.tbl.Cursor() {
		t.Fatalf("discover arrow should follow cursor to %d, got %d", mm.tbl.Cursor(), got)
	}
	if mm.tbl.Cursor() == 0 {
		t.Fatal("cursor should have moved off row 0")
	}
}

func TestSortCyclesAndIPOrder(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	// default: numeric IP order (.1, .2, .10, then gone .99)
	ips := func() []string {
		var out []string
		for _, rv := range m.visible {
			out = append(out, rv.row.IP)
		}
		return out
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.99"}
	if got := ips(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ip sort wrong: %v", got)
	}
	var tm tea.Model = m
	tm, _ = tm.Update(keyRunes("s")) // -> host
	m = tm.(Model)
	if m.sortBy != sortHost {
		t.Fatal("s should cycle to host sort")
	}
	if m.visible[0].row.Host != "" && m.visible[0].row.Host != "alpha" {
		// gone row has empty host and sorts first; alpha is first named
		t.Fatalf("host sort wrong: first=%q", m.visible[0].row.Host)
	}
	tm, _ = tm.Update(keyRunes("s")) // -> ports (most first)
	m = tm.(Model)
	if m.visible[0].row.IP != "10.0.0.2" {
		t.Fatalf("ports sort should put 10.0.0.2 (2 ports) first, got %s", m.visible[0].row.IP)
	}
}

func TestDetailPaneShowsFingerprint(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	m.rows = []ui.Row{{
		IP: "10.0.0.5", Host: "router", Up: true,
		OS: "Linux 5.X", OSAccuracy: 92, OSCPE: "cpe:/o:linux:linux_kernel:5",
		RTT: "1.2ms",
		PortDetails: []ui.PortInfo{{
			Port: 8443, Proto: "tcp", Service: "http", Product: "nginx", Version: "1.25",
			ExtraInfo: "Ubuntu", CPE: "cpe:/a:igor_sysoev:nginx:1.25", TLS: true,
			HTTPTitle: "Admin Console", Cert: "Acme — exp 2027-01-02",
			Severity: "info", Risk: "admin panel",
		}},
	}}
	m.rebuildTable()
	m.mode = modeDetail // the static detail pane (used for GONE rows)

	v := m.View()
	for _, want := range []string{"92%", "cpe:/o:linux", "tls", "Admin Console", "Acme — exp 2027-01-02", "Ubuntu"} {
		if !strings.Contains(v, want) {
			t.Errorf("detail view missing %q", want)
		}
	}
}

func TestEnterStartsDiscover(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	var tm tea.Model = m
	// Enter on a live host opens the Discover overlay in its scanning state.
	tm, cmd := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mm := tm.(Model)
	if mm.mode != modeDiscover {
		t.Fatalf("enter should open Discover, got mode %d", mm.mode)
	}
	if !mm.disco.scanning || mm.disco.ip == "" {
		t.Fatalf("discover should be scanning a host, got %+v", mm.disco)
	}
	if cmd == nil {
		t.Fatal("enter should return a scan command")
	}
	if v := tm.View(); !strings.Contains(v, "Discover") {
		t.Fatal("discover panel not rendered")
	}

	// A completed scan populates the panel.
	row := &ui.Row{IP: mm.disco.ip, Up: true, OS: "Linux", RTT: "2ms",
		PortDetails: []ui.PortInfo{{Port: 80, Proto: "tcp", Service: "http"}}}
	tm, _ = tm.Update(discoverDoneMsg{ip: mm.disco.ip, row: row, elapsed: time.Second})
	mm = tm.(Model)
	if mm.disco.scanning {
		t.Fatal("discover should no longer be scanning after done")
	}
	if v := mm.View(); !strings.Contains(v, "Open ports") || !strings.Contains(v, "80/tcp") {
		t.Fatal("discover panel should show scanned ports")
	}

	// esc closes the overlay.
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if tm.(Model).mode != modeNone {
		t.Fatal("esc should close discover")
	}
}

func TestHelpOverlay(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	var tm tea.Model = m
	tm, _ = tm.Update(keyRunes("?"))
	if tm.(Model).mode != modeHelp {
		t.Fatal("? should open help")
	}
	if v := tm.View(); !strings.Contains(v, "Keybindings") {
		t.Fatal("help view missing")
	}
}

func TestDiffBadgesShown(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	var newBadge, goneBadge bool
	for _, rv := range m.visible {
		if rv.row.IP == "10.0.0.10" && rv.badge == "NEW" {
			newBadge = true
		}
		if rv.row.IP == "10.0.0.99" && rv.gone && rv.badge == "GONE" {
			goneBadge = true
		}
	}
	if !newBadge || !goneBadge {
		t.Fatalf("badges missing: new=%v gone=%v", newBadge, goneBadge)
	}
	if v := m.View(); !strings.Contains(v, "new host") {
		t.Fatal("diff summary line missing")
	}
}

func TestWatchToggleAndTick(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	var tm tea.Model = m
	tm, cmd := tm.Update(keyRunes("w"))
	mm := tm.(Model)
	if !mm.watch || cmd == nil {
		t.Fatal("w should enable watch and schedule a tick")
	}
	left := mm.watchLeft
	tm, _ = tm.Update(watchTickMsg{gen: mm.watchGen})
	if got := tm.(Model).watchLeft; got != left-1 {
		t.Fatalf("tick should decrement countdown: %d -> %d", left, got)
	}
	// stale generation is ignored
	tm, _ = tm.Update(watchTickMsg{gen: mm.watchGen - 1})
	if got := tm.(Model).watchLeft; got != left-1 {
		t.Fatal("stale tick should be ignored")
	}
	tm, _ = tm.Update(keyRunes("w")) // off
	if tm.(Model).watch {
		t.Fatal("w should disable watch")
	}
}

func TestNotifyToggle(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	m.notify = true // force a known starting state regardless of platform
	var tm tea.Model = m
	tm, _ = tm.Update(keyRunes("b"))
	mm := tm.(Model)
	// On systems with a notifier, b toggles off; without one, it stays off
	// and explains why. Either way it must not be left on after one press.
	if mm.notify {
		t.Fatal("b should toggle notifications off")
	}
	if mm.notice == "" {
		t.Fatal("b should set a notice")
	}
}

func TestWatchRescanFiresNotifyCmd(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := resultsModel(t)
	m.watch = true
	m.watchRescan = true
	m.notify = true // bypass platform availability for the command path

	done := doneMsg{
		rows: []ui.Row{{IP: "10.0.0.9", Up: true}},
		diff: map[string]config.HostDiff{"10.0.0.9": {New: true}},
	}
	var tm tea.Model = m
	out, cmd := tm.Update(done)
	if cmd == nil {
		t.Fatal("watch rescan with a diff should batch a notify command")
	}
	// watchRescan must reset so a later manual scan doesn't re-alert.
	if out.(Model).watchRescan {
		t.Fatal("watchRescan flag should clear after the rescan completes")
	}
}

func TestExportJSONAndCSV(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("NDSCAN_NO_OPEN", "1") // don't spawn a browser in tests
	dir := t.TempDir()
	t.Setenv("NDSCAN_EXPORT_DIR", dir)

	m := resultsModel(t)
	notice := m.export("json")
	if !strings.Contains(notice, "wrote 3 row(s)") {
		t.Fatalf("json export notice: %s", notice)
	}
	notice = m.export("csv")
	if !strings.Contains(notice, "wrote 3 row(s)") {
		t.Fatalf("csv export notice: %s", notice)
	}
	if notice := m.export("md"); !strings.Contains(notice, "wrote 3 row(s)") {
		t.Fatalf("md export notice: %s", notice)
	}
	if notice := m.export("html"); !strings.Contains(notice, "wrote 3 row(s)") {
		t.Fatalf("html export notice: %s", notice)
	}

	// Exports land in a dated subfolder under the export dir.
	files, _ := filepath.Glob(filepath.Join(dir, "*", "ndscan-*"))
	if len(files) != 4 {
		t.Fatalf("expected 4 export files, got %v", files)
	}
	for _, f := range files {
		switch {
		case strings.HasSuffix(f, ".json"):
			b, _ := os.ReadFile(f)
			var rows []ui.Row
			if err := json.Unmarshal(b, &rows); err != nil || len(rows) != 3 {
				t.Fatalf("bad json export: err=%v rows=%d", err, len(rows))
			}
		case strings.HasSuffix(f, ".md"):
			b, _ := os.ReadFile(f)
			if !strings.Contains(string(b), "# Network scan") {
				t.Error("md export missing report header")
			}
		case strings.HasSuffix(f, ".html"):
			b, _ := os.ReadFile(f)
			if !strings.HasPrefix(string(b), "<!doctype html>") {
				t.Error("html export not a full document")
			}
		}
	}
}

func TestProfileSaveAndLoadFlow(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.targetsIn.SetValue("10.1.2.0/24")
	m.presetIdx = 3 // deep
	var tm tea.Model = m

	// ctrl+s -> name overlay -> type name -> enter
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	if tm.(Model).mode != modeProfileName {
		t.Fatal("ctrl+s should open profile name input")
	}
	tm = typeString(tm, "lab")
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mm := tm.(Model)
	if mm.mode != modeNone || len(mm.profiles) != 1 {
		t.Fatalf("profile not saved: mode=%v profiles=%d", mm.mode, len(mm.profiles))
	}

	// mutate the form, then load the profile back via picker
	mm.targetsIn.SetValue("changed")
	mm.presetIdx = 0
	tm = mm
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if tm.(Model).mode != modeProfilePicker {
		t.Fatal("ctrl+p should open picker")
	}
	tm, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mm = tm.(Model)
	if mm.targetsIn.Value() != "10.1.2.0/24" || presets[mm.presetIdx] != "deep" {
		t.Fatalf("profile load failed: targets=%q preset=%q", mm.targetsIn.Value(), presets[mm.presetIdx])
	}
}

func TestSettingsPersistAcrossNew(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if err := config.SaveLast(config.Settings{Targets: "172.16.0.0/16", Preset: "udp", ShowMac: true}); err != nil {
		t.Fatal(err)
	}
	m := New("test")
	if m.targetsIn.Value() != "172.16.0.0/16" || presets[m.presetIdx] != "udp" || !m.showMac {
		t.Fatalf("New() did not restore last settings: %q %q %v",
			m.targetsIn.Value(), presets[m.presetIdx], m.showMac)
	}
}

func TestNmapMissingFriendlyError(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	t.Setenv("PATH", t.TempDir()) // hide nmap
	m := New("test")
	m.targetsIn.SetValue("127.0.0.1")
	tm, _ := m.startScan()
	err := tm.(Model).err
	if err == nil || !strings.Contains(err.Error(), "brew install nmap") {
		t.Fatalf("expected friendly nmap error, got %v", err)
	}
}

// ----- live integration tests (need nmap + localhost) -----

func TestScanStreamsAndDiffsE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("needs nmap")
	}
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	run := func() (streamed int, done doneMsg) {
		ch, cancel := runScan(scanParams{
			targets:     []string{"127.0.0.1"},
			preset:      "quick",
			ports:       "22,80,443",
			concurrency: 8,
			hostTimeout: 20 * time.Second,
		})
		defer cancel()
		deadline := time.After(60 * time.Second)
		for {
			select {
			case msg := <-ch:
				switch v := msg.(type) {
				case hostRowMsg:
					streamed += len(v.rows)
				case doneMsg:
					return streamed, v
				case errMsg:
					t.Fatalf("scan error: %v", v.err)
				}
			case <-deadline:
				t.Fatal("scan timed out")
			}
		}
	}

	streamed, done1 := run()
	if streamed == 0 || len(done1.rows) == 0 {
		t.Fatalf("expected streamed rows, got streamed=%d final=%d", streamed, len(done1.rows))
	}
	if done1.diff != nil {
		t.Fatalf("first scan should have nil diff, got %v", done1.diff)
	}
	_, done2 := run()
	if done2.diff == nil {
		t.Fatal("second scan of same signature should produce a (possibly empty) diff map")
	}
	if len(done2.diff) != 0 {
		t.Logf("note: localhost changed between runs: %v", done2.diff)
	}
}

// Drives the actual Model through a real scan: start via the form, pump every
// channel message through Update, and assert rows streamed into the table
// before landing on the results screen.
func TestModelFullScanLoopE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("needs nmap")
	}
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	m := New("test")
	m.width, m.height = 120, 40
	m.targetsIn.SetValue("127.0.0.1")
	m.portsIn.SetValue("22,80,443")
	tm, _ := m.startScan()
	mm := tm.(Model)
	if mm.screen != screenRunning || mm.cancel == nil {
		t.Fatalf("startScan: screen=%v cancel=%v", mm.screen, mm.cancel)
	}

	sawStream := false
	deadline := time.After(60 * time.Second)
	for mm.screen != screenResults {
		select {
		case msg := <-mm.events:
			if _, ok := msg.(hostRowMsg); ok {
				sawStream = true
			}
			tm, _ = tm.Update(msg)
			mm = tm.(Model)
		case <-deadline:
			t.Fatal("never reached results screen")
		}
	}
	if !sawStream {
		t.Fatal("no hostRowMsg streamed during scan")
	}
	if len(mm.visible) == 0 {
		t.Fatal("results table empty")
	}
	if !strings.Contains(mm.View(), "host(s) up") {
		t.Fatal("results view missing summary")
	}
}

func TestCancelMidScanE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("needs nmap")
	}
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	// discovering a /16 takes far longer than the cancel delay, so the
	// cancel reliably lands mid-discovery
	ch, cancel := runScan(scanParams{
		targets:     []string{"10.123.0.0/16"},
		preset:      "quick",
		concurrency: 4,
		hostTimeout: 120 * time.Second,
	})
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case msg := <-ch:
			if d, ok := msg.(doneMsg); ok {
				if !d.cancelled {
					t.Fatal("expected cancelled doneMsg")
				}
				return
			}
		case <-deadline:
			t.Fatal("cancel did not produce a doneMsg within 30s")
		}
	}
}
