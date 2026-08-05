package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post builds a request that a legitimate same-origin fetch would send.
func post(url, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Host = "127.0.0.1:8080"
	return r
}

func serve(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	NewServer("test").Handler("127.0.0.1:8080").ServeHTTP(w, r)
	return w
}

// DNS rebinding: the connection really is to 127.0.0.1, so a loopback bind
// doesn't help — the Host header is what gives the attack away.
func TestGuard_RejectsRebindingHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.Host = "evil.example.com:8080"
	if w := serve(t, r); w.Code != http.StatusMisdirectedRequest {
		t.Errorf("rebinding Host = %d, want 421", w.Code)
	}
}

func TestGuard_AllowsLoopbackHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		r.Host = host
		if w := serve(t, r); w.Code != http.StatusOK {
			t.Errorf("Host %s = %d, want 200", host, w.Code)
		}
	}
}

// A cross-origin page must not be able to start a scan.
func TestGuard_RejectsCrossOriginPost(t *testing.T) {
	r := post("/api/scan", `{"targets":["127.0.0.1"]}`)
	r.Header.Set("Origin", "http://evil.example.com")
	if w := serve(t, r); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", w.Code)
	}
}

// A form-post CSRF cannot set application/json, so requiring it blocks the
// classic no-Origin form attack.
func TestGuard_RejectsNonJSONPost(t *testing.T) {
	r := post("/api/scan", `{"targets":["127.0.0.1"]}`)
	r.Header.Set("Content-Type", "text/plain")
	if w := serve(t, r); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST = %d, want 415", w.Code)
	}
}

// A POST with neither Origin nor a same-site signal is refused.
func TestGuard_RejectsOriginlessPost(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"targets":["127.0.0.1"]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Host = "127.0.0.1:8080"
	if w := serve(t, r); w.Code != http.StatusForbidden {
		t.Errorf("origin-less POST = %d, want 403", w.Code)
	}
}

// A legitimate same-origin request still works.
func TestGuard_AllowsSameOriginPost(t *testing.T) {
	r := post("/api/scan", `{"targets":["127.0.0.1"]}`)
	if w := serve(t, r); w.Code != http.StatusAccepted {
		t.Errorf("same-origin POST = %d, want 202 (body: %s)", w.Code, w.Body.String())
	}
}

// GETs without an Origin are fine — curl, direct navigation.
func TestGuard_AllowsOriginlessGet(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.Host = "127.0.0.1:8080"
	if w := serve(t, r); w.Code != http.StatusOK {
		t.Errorf("origin-less GET = %d, want 200", w.Code)
	}
}

// Targets must never be able to smuggle scanner flags or shell tokens.
func TestValidateTargets(t *testing.T) {
	ok := []string{"127.0.0.1", "192.168.1.0/24", "10.0.0.5/32", "::1", "fd00::/64"}
	for _, target := range ok {
		if err := validateTargets([]string{target}); err != nil {
			t.Errorf("validateTargets(%q) = %v, want nil", target, err)
		}
	}

	bad := []string{
		"--script=http-vuln",            // nmap flag injection
		"-oN/tmp/pwned",                 // output redirection
		"192.168.1.1; touch /tmp/pwned", // shell metacharacter
		"$(whoami)",                     // command substitution
		"`id`",                          // backtick substitution
		"192.168.1.1 --privileged",      // trailing flag
		"example.com",                   // hostnames not accepted
		"",                              // empty
		"   ",                           // whitespace
	}
	for _, target := range bad {
		if err := validateTargets([]string{target}); err == nil {
			t.Errorf("validateTargets(%q) = nil, want an error", target)
		}
	}

	if err := validateTargets(nil); err == nil {
		t.Error("empty target list should error")
	}

	// A flood of targets is capped.
	many := make([]string, 200)
	for i := range many {
		many[i] = "127.0.0.1"
	}
	if err := validateTargets(many); err == nil {
		t.Error("oversized target list should error")
	}
}

// The scan endpoint must reject an injection attempt end to end, not just in
// the validator.
func TestScan_RejectsInjectionTargets(t *testing.T) {
	r := post("/api/scan", `{"targets":["--script=http-vuln"]}`)
	w := serve(t, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("injection target = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid target") {
		t.Errorf("error should name the bad target: %s", w.Body.String())
	}
}

func TestAllowedHosts_WiderBindAllowsChosenAddress(t *testing.T) {
	// When the user explicitly binds wider, that address must be accepted —
	// they opted in — but a random attacker host still must not be.
	allowed := allowedHosts("192.168.1.5:9000")
	if !allowed["192.168.1.5:9000"] {
		t.Error("explicit bind address should be allowed")
	}
	if allowed["evil.example.com:9000"] {
		t.Error("arbitrary host must not be allowed")
	}
}
