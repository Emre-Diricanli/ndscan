package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// The web UI can start network scans, so a page in the user's browser must not
// be able to drive it. Three separate attacks are in scope, and each needs its
// own defence:
//
//   - DNS rebinding: an attacker's domain re-resolves to 127.0.0.1, so the
//     browser happily talks to us. The connection is genuinely local, so
//     binding to loopback does not help. It is defeated by checking the Host
//     header, which still carries the attacker's domain.
//   - CSRF: a cross-origin page POSTs to us. Defeated by requiring an Origin we
//     recognise, plus a JSON content type that simple form posts cannot set.
//   - Argument injection: a target string reaching the scan engine as an argv
//     entry. Defeated by validating every target as an IP or CIDR up front.

// allowedHosts returns the Host header values acceptable for a server bound to
// addr. For a loopback bind that is the loopback names; for an explicit wider
// bind it is the address the user chose, since they opted into that.
func allowedHosts(addr string) map[string]bool {
	out := map[string]bool{}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return out
	}
	add := func(h string) { out[net.JoinHostPort(h, port)] = true }

	if isLoopbackHost(host) || host == "" || host == "0.0.0.0" || host == "::" {
		// A wildcard bind is still reachable on loopback, and the browser will
		// use whichever name the user typed.
		add("127.0.0.1")
		add("localhost")
		add("::1")
	}
	if host != "" {
		add(host)
	}
	return out
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return a.IsLoopback()
	}
	return false
}

// guard wraps the API with Host, Origin, and content-type checks.
func guard(next http.Handler, addr string) http.Handler {
	allowed := allowedHosts(addr)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Host check — closes DNS rebinding. The browser sends the attacker's
		// hostname even after it rebinds to 127.0.0.1, so this rejects the
		// request that a loopback bind alone would have accepted.
		if len(allowed) > 0 && !allowed[normalizeHost(r.Host, addr)] {
			http.Error(w, "unexpected Host header — refusing request", http.StatusMisdirectedRequest)
			return
		}

		// 2. Origin check — closes CSRF for any request the browser labels.
		// A missing Origin is allowed for GETs (curl, direct navigation) but
		// never for state-changing methods.
		origin := r.Header.Get("Origin")
		if origin != "" && !originAllowed(origin, allowed) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodPost {
			if origin == "" && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
				// No Origin and no same-site signal: could be a form post from
				// another page. Non-browser clients can still set Origin.
				http.Error(w, "state-changing request requires an Origin header", http.StatusForbidden)
				return
			}
			// 3. Content-type — a cross-origin HTML form can only send
			// urlencoded/plain/multipart, never application/json.
			ct := r.Header.Get("Content-Type")
			if ct != "" {
				if mt, _, err := mimeType(ct); err != nil || mt != "application/json" {
					http.Error(w, "POST requires Content-Type: application/json", http.StatusUnsupportedMediaType)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// normalizeHost fills in the port when a client omits it, so comparisons
// against the allowlist are consistent.
func normalizeHost(host, addr string) string {
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(host, port)
	}
	return host
}

func originAllowed(origin string, allowed map[string]bool) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return allowed[u.Host]
}

// mimeType extracts the bare media type from a Content-Type header.
func mimeType(ct string) (string, map[string]string, error) {
	mt, rest, _ := strings.Cut(ct, ";")
	mt = strings.TrimSpace(strings.ToLower(mt))
	if mt == "" {
		return "", nil, fmt.Errorf("empty media type")
	}
	_ = rest
	return mt, nil, nil
}

// validateTargets rejects anything that is not a literal IPv4/IPv6 address or
// CIDR before it can reach the scan engine.
//
// The engine passes targets to nmap as argv entries on some paths, so a value
// like "--script=..." or a shell metacharacter must never get that far. Parsing
// strictly here means the API cannot be used to smuggle scanner flags,
// regardless of what any individual downstream call does with the string.
func validateTargets(targets []string) error {
	const maxTargets = 64
	if len(targets) == 0 {
		return fmt.Errorf("targets must not be empty")
	}
	if len(targets) > maxTargets {
		return fmt.Errorf("too many targets (%d, max %d)", len(targets), maxTargets)
	}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			return fmt.Errorf("empty target")
		}
		if _, err := netip.ParseAddr(t); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(t); err == nil {
			continue
		}
		return fmt.Errorf("invalid target %q: must be an IP address or CIDR", t)
	}
	return nil
}
