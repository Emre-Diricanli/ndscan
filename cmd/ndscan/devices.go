package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// newDevicesCmd exposes the device inventory ndscan has been building.
//
// Every scan has been recording device identity and a timeline of what those
// devices did, and until now none of it was reachable: a user could not see
// their inventory, could not name anything, and could not ask when a host first
// appeared or when a port opened. Those are the questions the recording exists
// to answer, so this is the surface that makes the record worth keeping.
//
// Like ndscan diff, nothing here scans. It reads what earlier scans wrote.
func newDevicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "List, inspect, and name the devices ndscan has seen — reads recorded state only, never scans",
		Long: `Show the device inventory built from previous scans.

A device is identified by its hardware address where one is visible, so it stays
the same device across DHCP leases. Hosts on a routed subnet have no visible MAC
— ARP does not cross a router — so those are identified by address instead and
marked as such; they cannot be followed across a lease change.

This command never scans. It sends no traffic and needs no privileges.`,
	}
	cmd.AddCommand(newDevicesListCmd(), newDevicesShowCmd(), newDevicesNameCmd())
	return cmd
}

func newDevicesListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every device ndscan has recorded",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listDevices(cmd.OutOrStdout(), jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON to stdout")
	return cmd
}

func listDevices(w io.Writer, jsonOut bool) error {
	// TODO(merge): delegate/kimi makes device.Load error-returning so a corrupt
	// store is refused rather than read as empty. Take the erroring form here
	// at integration — a user asking to see their devices must be told the file
	// is unreadable, not shown an empty list.
	devices := device.Load()
	if len(devices) == 0 {
		fmt.Fprintln(w, "no devices recorded yet — run a scan first:")
		fmt.Fprintln(w, "  ndscan scan <targets>")
		return nil
	}

	recs := sortedDevices(devices)
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(recs)
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Device", "Address", "MAC", "Vendor", "First seen", "Last seen"})
	for _, r := range recs {
		t.AppendRow(table.Row{
			r.Label(), currentAddress(r), dashIfEmpty(r.MAC), dashIfEmpty(r.Vendor),
			shortTime(r.FirstSeen), shortTime(r.LastSeen),
		})
	}
	t.Render()

	// Ephemeral identities cannot be followed across a lease, so saying how many
	// there are is more honest than a list that implies they are all equal.
	if n := countEphemeral(recs); n > 0 {
		ui.Infof("%d device(s) identified by address only — no MAC is visible for them, so they cannot be tracked across a DHCP lease", n)
	}
	return nil
}

func newDevicesShowCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show <device-key>",
		Short: "Show one device's history: addresses it has held, and when its ports opened or closed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showDevice(cmd.OutOrStdout(), args[0], jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON to stdout")
	return cmd
}

// deviceDetail is one device plus everything the timeline remembers about it.
type deviceDetail struct {
	Device device.Record    `json:"device"`
	First  *time.Time       `json:"firstSeen,omitempty"`
	Last   *time.Time       `json:"lastSeen,omitempty"`
	Events []timeline.Event `json:"events,omitempty"`
}

func showDevice(w io.Writer, key string, jsonOut bool) error {
	devices := device.Load() // TODO(merge): erroring form, see listDevices
	rec, ok := devices[key]
	if !ok {
		return fmt.Errorf("no device recorded with key %q — run 'ndscan devices list' to see the keys", key)
	}

	detail := deviceDetail{Device: rec}
	if first, ok, err := timeline.FirstSeen(key); err == nil && ok {
		detail.First = &first
	}
	if last, ok, err := timeline.LastSeen(key); err == nil && ok {
		detail.Last = &last
	}
	if events, err := timeline.History(key); err == nil {
		detail.Events = events
	}

	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(detail)
	}

	fmt.Fprintf(w, "%s\n", rec.Label())
	fmt.Fprintf(w, "  key       %s\n", rec.Key)
	fmt.Fprintf(w, "  mac       %s\n", dashIfEmpty(rec.MAC))
	fmt.Fprintf(w, "  vendor    %s\n", dashIfEmpty(rec.Vendor))
	fmt.Fprintf(w, "  addresses %s\n", joinOrDash(rec.Addresses))
	if len(rec.Hostnames) > 0 {
		fmt.Fprintf(w, "  names     %s\n", joinOrDash(rec.Hostnames))
	}
	fmt.Fprintf(w, "  first     %s\n", shortTime(rec.FirstSeen))
	fmt.Fprintf(w, "  last      %s\n", shortTime(rec.LastSeen))

	if len(detail.Events) == 0 {
		fmt.Fprintln(w, "\nno recorded events for this device yet")
		return nil
	}
	fmt.Fprintln(w)
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"When", "What", "Address"})
	for _, ev := range detail.Events {
		t.AppendRow(table.Row{shortTime(ev.Timestamp), eventLabel(ev), ev.IP})
	}
	t.Render()
	return nil
}

func newDevicesNameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "name <device-key> <name>",
		Short: "Give a device a name of your own",
		Long: `Assign a name to a device.

The name you choose always wins over whatever the device advertises about
itself, so a host that starts announcing a different name will not overwrite
what you called it.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := device.Rename(args[0], args[1]); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no device recorded with key %q — run 'ndscan devices list' to see the keys", args[0])
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "named %s → %s\n", args[0], args[1])
			return nil
		},
	}
}

// ----- helpers -----

func sortedDevices(devices map[string]device.Record) []device.Record {
	out := make([]device.Record, 0, len(devices))
	for _, r := range devices {
		out = append(out, r)
	}
	// Most recently seen first: the devices on the network now are the ones a
	// person is usually looking for.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func currentAddress(r device.Record) string {
	if len(r.Addresses) == 0 {
		return "-"
	}
	return r.Addresses[0]
}

func countEphemeral(recs []device.Record) int {
	n := 0
	for _, r := range recs {
		if r.MAC == "" {
			n++
		}
	}
	return n
}

func eventLabel(ev timeline.Event) string {
	switch ev.Type {
	case timeline.EventHostSeen:
		return "appeared"
	case timeline.EventHostGone:
		return "left"
	case timeline.EventPortOpened:
		return fmt.Sprintf("port %d opened", ev.Port)
	case timeline.EventPortClosed:
		return fmt.Sprintf("port %d closed", ev.Port)
	}
	return string(ev.Type)
}

func shortTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinOrDash(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	out := list[0]
	for _, s := range list[1:] {
		out += ", " + s
	}
	return out
}
