// Example 04: serve user-authored pages safely.
//
// Sanitization is the first layer, not the only one. This is the
// whole path end to end: accept content, sanitize it, store only the
// sanitized form, and serve it with the security headers the profile
// implies.
//
//	go run ./examples/04-http-server
//	curl -s localhost:8090/                 # the editor
//	curl -si localhost:8090/r/demo | head   # the served page + headers
//
// Note what is *not* here: no authentication on the write path. That
// is deliberate — the real page service refuses saves until you give
// it a SaveAuthorizer, and this example wires one that only accepts a
// fixed token, so the shape is visible.
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/render"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

var addr = flag.String("addr", ":8090", "listen address")

// saveToken stands in for whatever your dashboard authenticates
// with. A real deployment would check a session or a signed request,
// and would also check that the caller owns the page being written.
const saveToken = "example-token-not-for-production"

// store keeps only sanitized output. Raw input is worth keeping for
// re-sanitization when the policy changes, but it must never be the
// thing you serve.
type store struct {
	mu    sync.RWMutex
	pages map[string]page
}

type page struct {
	HTML string
	CSS  string
}

func (s *store) get(slug string) (page, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pages[slug]
	return p, ok
}

func (s *store) put(slug string, p page) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pages[slug] = p
}

func main() {
	flag.Parse()

	sanitizer, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		log.Fatal(err)
	}
	db := &store{pages: map[string]page{}}

	// Seed a page so there is something to look at immediately. It
	// goes through exactly the same path an author's content would.
	seedHTML, _, _ := sanitizer.SanitizeHTML(
		`<h1>Demo page</h1><p>Authored by an untrusted user.</p>` +
			`<script>alert('this never survives')</script>` +
			`<a href="/about" >a link</a>`)
	seedCSS, _, _ := sanitizer.SanitizeCSS(`h1 { color: navy } p { line-height: 1.6 }`)
	db.put("demo", page{HTML: seedHTML, CSS: seedCSS})

	mux := http.NewServeMux()
	mux.HandleFunc("/", editorPage)
	mux.HandleFunc("/save", handleSave(sanitizer, db))
	mux.HandleFunc("/r/", handleRender(sanitizer, db))

	log.Printf("editor:      http://localhost%s/", *addr)
	log.Printf("served page: http://localhost%s/r/demo", *addr)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// handleSave sanitizes and stores. Note the ordering: authorize,
// then sanitize, then store. Nothing unsanitized ever reaches the
// store, and a sanitizer error aborts the write.
func handleSave(s *usercontent.Sanitizer, db *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Constant-time compare so the token cannot be recovered a
		// byte at a time.
		got := r.Header.Get("X-Save-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(saveToken)) != 1 {
			http.Error(w, "not authorized", http.StatusForbidden)
			return
		}
		// Bound the body before buffering it. The profile's own byte
		// limits are enforced afterwards, on the decoded fields.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		slug := r.FormValue("slug")
		if slug == "" || !validSlug(slug) {
			http.Error(w, "slug must be 1-64 chars of [a-z0-9-]", http.StatusBadRequest)
			return
		}

		html, htmlReport, err := s.SanitizeHTML(r.FormValue("html"))
		if err != nil {
			http.Error(w, "html: "+err.Error(), http.StatusBadRequest)
			return
		}
		css, cssReport, err := s.SanitizeCSS(r.FormValue("css"))
		if err != nil {
			http.Error(w, "css: "+err.Error(), http.StatusBadRequest)
			return
		}
		db.put(slug, page{HTML: html, CSS: css})

		// text/plain with nosniff, and slug has already been
		// restricted to [a-z0-9-]. The removal values echoed below
		// came from the author's input, which is why the content type
		// matters: they are reported, never rendered as markup.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// #nosec G705 -- text/plain + nosniff; slug is [a-z0-9-] only
		fmt.Fprintf(w, "saved /r/%s\n%d html item(s) and %d css item(s) removed\n",
			slug, len(htmlReport.Removed), len(cssReport.Removed))
		for _, rem := range append(htmlReport.Removed, cssReport.Removed...) {
			// #nosec G705 -- text/plain + nosniff, see above
			fmt.Fprintf(w, "  %s %q: %s\n", rem.Kind, rem.Value, rem.Reason)
		}
	}
}

// handleRender serves a stored page inside the trusted shell.
func handleRender(s *usercontent.Sanitizer, db *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.URL.Path[len("/r/"):]
		p, ok := db.get(slug)
		if !ok {
			http.NotFound(w, r)
			return
		}

		// The profile decides the headers, so policy and headers can
		// never drift apart. CSPHeaders() also carries Referrer-Policy,
		// X-Content-Type-Options, Permissions-Policy and COOP.
		for k, v := range s.CSPHeaders() {
			w.Header().Set(k, v)
		}

		doc, err := render.SafeRender(
			slug, "A user-authored page",
			render.CanonicalURL(r.Host, slug), "",
			p.HTML, p.CSS, s.Profile().Name,
		)
		if err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// #nosec G705 -- doc is render.SafeRender's output: a trusted
		// shell whose only user-controlled inputs are the sanitizer's
		// own verified HTML and CSS.
		_, _ = w.Write([]byte(doc))
	}
}

func validSlug(s string) bool {
	if len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// editorPage is the dashboard side. It is a trusted page of our own,
// so html/template escaping is all it needs — user content is never
// rendered here, only posted from here.
var editorTmpl = template.Must(template.New("editor").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Editor</title>
<style>body{font:14px system-ui;margin:2rem;max-width:48rem}
textarea{width:100%;font-family:ui-monospace,monospace}label{display:block;margin-top:1rem}</style>
</head><body>
<h1>Editor</h1>
<p>Anything you paste is sanitized before it is stored. Try a
&lt;script&gt; tag, an onerror handler, or <code>&lt;/style&gt;</code> in the CSS.</p>
<form method="post" action="/save">
  <label>slug <input name="slug" value="demo"></label>
  <label>HTML <textarea name="html" rows="8">{{.HTML}}</textarea></label>
  <label>CSS <textarea name="css" rows="6">{{.CSS}}</textarea></label>
  <p><em>This demo form cannot send the save token; use the curl command in the README.</em></p>
  <button type="submit">Save</button>
</form>
<p><a href="/r/demo">view /r/demo</a></p>
</body></html>`))

func editorPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = editorTmpl.Execute(w, struct{ HTML, CSS string }{
		HTML: "<h1>Hello</h1>\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>",
		CSS:  "h1 { color: navy }\n</style><b>oops</b>",
	})
}
