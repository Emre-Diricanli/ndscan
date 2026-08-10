package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func servedFrontend(t *testing.T) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	frontendHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	if contentType := w.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("GET / content-type = %q, want text/html", contentType)
	}
	body := w.Body.String()
	if strings.Contains(body, "frontend is not built into this binary") {
		t.Fatal("GET / served the missing-frontend fallback")
	}
	return body
}

func TestFrontendAccessibilityAffordances(t *testing.T) {
	body := servedFrontend(t)
	cases := []struct {
		name string
		want string
	}{
		// These attributes keep topology actions available without a mouse.
		{"node tabindex", `g.setAttribute("tabindex", "0")`},
		{"node button role", `g.setAttribute("role", "button")`},
		{"node accessible name", `g.setAttribute("aria-label", nodeLabel(`},
		{"node keyboard listener", `g.addEventListener("keydown"`},
		{"node Enter activation", `ev.key === "Enter"`},
		{"node Space activation", `ev.key === " "`},

		// Scan updates must remain perceivable when the visual bar cannot be seen.
		{"scan status role", `id="scan-status" class="sr-only" role="status"`},
		{"polite scan announcements", `aria-live="polite"`},
		{"progressbar role", `id="progress-bar" role="progressbar"`},
		{"progressbar value", `bar.setAttribute("aria-valuenow"`},

		// Modal semantics and focus containment must not drift apart.
		{"sweep modal semantics", `id="sweep-dialog" role="dialog" aria-modal="true"`},
		{"disconnected modal semantics", `id="disconnected" role="dialog" aria-modal="true"`},
		{"disconnected focus target", `id="disconnected-panel"`},

		// Errors must be announced without requiring the banner to be noticed visually.
		{"error alert role", `id="error-banner" role="alert"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(body, c.want) {
				t.Errorf("served frontend missing %q", c.want)
			}
		})
	}
}

func TestFrontendVisuallyHiddenStatusRemainsAccessible(t *testing.T) {
	body := servedFrontend(t)
	start := strings.Index(body, ".sr-only {")
	if start == -1 {
		t.Fatal("served frontend missing .sr-only rule")
	}
	end := strings.Index(body[start:], "}")
	if end == -1 {
		t.Fatal("served frontend has unterminated .sr-only rule")
	}
	rule := body[start : start+end]

	// Either property would remove status updates from the accessibility tree.
	for _, forbidden := range []string{"display:none", "display: none", "visibility:hidden", "visibility: hidden"} {
		if strings.Contains(rule, forbidden) {
			t.Errorf(".sr-only rule contains %q", forbidden)
		}
	}
}

func TestFrontendDialogsManageFocus(t *testing.T) {
	body := servedFrontend(t)
	cases := []struct {
		name  string
		start string
		end   string
		want  string
	}{
		{"disconnected opens trap", "function setDisconnectedMode", "function updateOperationControls", `trapFocus($("disconnected-panel"))`},
		{"disconnected closes trap", "function setDisconnectedMode", "function updateOperationControls", "releaseFocus()"},
		{"sweep opens trap", "function openSweepModal", "function closeSweepModal", `trapFocus($("sweep-dialog"))`},
		// Anchored on the next function rather than the comment banner that
		// currently follows: rewording a comment must not fail a test about
		// focus behaviour.
		{"sweep closes trap", "function closeSweepModal", "function trapFocus", "releaseFocus()"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := strings.Index(body, c.start)
			if start == -1 {
				t.Fatalf("served frontend missing %q", c.start)
			}
			end := strings.Index(body[start:], c.end)
			if end == -1 {
				t.Fatalf("served frontend missing %q after %q", c.end, c.start)
			}
			if scope := body[start : start+end]; !strings.Contains(scope, c.want) {
				t.Errorf("%s does not contain %q", c.start, c.want)
			}
		})
	}
}
