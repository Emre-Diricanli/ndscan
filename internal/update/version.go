// Package update implements ndscan's self-update: checking GitHub for a
// newer release, downloading and verifying it, and replacing the running
// binary. Everything here fails safe — a check error never blocks scanning,
// and the old binary is only replaced after the new one is verified.
package update

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareVersions compares two semver-ish versions ("0.1.10", "v0.2.0"),
// returning -1 if current < latest, 0 if equal, +1 if current > latest.
func CompareVersions(current, latest string) (int, error) {
	c, err := parseVersion(current)
	if err != nil {
		return 0, fmt.Errorf("current version %q: %w", current, err)
	}
	l, err := parseVersion(latest)
	if err != nil {
		return 0, fmt.Errorf("latest version %q: %w", latest, err)
	}
	for i := 0; i < 3; i++ {
		switch {
		case c[i] < l[i]:
			return -1, nil
		case c[i] > l[i]:
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(s string) ([3]int, error) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("expected MAJOR.MINOR.PATCH")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid numeric segment %q", p)
		}
		v[i] = n
	}
	return v, nil
}
