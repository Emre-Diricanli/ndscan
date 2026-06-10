package tui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// export writes the currently visible rows (excluding synthetic GONE entries)
// to a timestamped file in the working directory and returns a notice string.
func (m Model) export(format string) string {
	rows := make([]ui.Row, 0, len(m.visible))
	for _, rv := range m.visible {
		if !rv.gone {
			rows = append(rows, rv.row)
		}
	}
	now := time.Now()
	name := fmt.Sprintf("ndscan-%s.%s", now.Format("20060102-150405"), format)

	var err error
	switch format {
	case "csv":
		err = writeCSV(name, rows)
	case "md", "html":
		rep := report.Report{
			Targets:   strings.Join(m.params.targets, ", "),
			Preset:    m.params.preset,
			Generated: now.Format("2006-01-02 15:04:05"),
			Rows:      rows,
		}
		content := rep.Markdown()
		if format == "html" {
			content = rep.HTML()
		}
		err = os.WriteFile(name, []byte(content), 0o644)
	default:
		err = writeJSON(name, rows)
	}
	if err != nil {
		return "export failed: " + err.Error()
	}
	return fmt.Sprintf("wrote %d row(s) to %s", len(rows), name)
}

func writeJSON(path string, rows []ui.Row) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func writeCSV(path string, rows []ui.Row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"ip", "hostname", "mac", "vendor", "os", "up", "ports"}); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{r.IP, r.Host, r.MAC, r.Vendor, r.OS, strconv.FormatBool(r.Up), strings.Join(r.Ports, "; ")}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return nil
}
