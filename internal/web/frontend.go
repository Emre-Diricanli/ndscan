package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// staticFS holds the browser frontend, compiled into the binary so `ndscan web`
// stays a single self-contained executable with no runtime asset paths.
//
//go:embed static
var staticFS embed.FS

// frontendHandler serves the embedded single-page app.
//
// The frontend is authored separately (internal/web/static/index.html). When it
// hasn't been built into this binary, the handler says so plainly instead of
// returning a blank 404 — the JSON API is still fully usable, and a developer
// hitting this needs to know which of the two situations they are in.
func frontendHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return http.HandlerFunc(frontendMissing)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return http.HandlerFunc(frontendMissing)
	}
	return http.FileServer(http.FS(sub))
}

func frontendMissing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>ndscan</title>
<body style="font:14px/1.6 system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>ndscan</h1>
<p>The browser frontend is not built into this binary, but the JSON API is running.
<p>Try <code>GET /api/state</code>, or see <code>docs/web-api-contract.md</code>.
`))
}
