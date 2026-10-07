// Package handlers contains the HTTP handlers for the page
// service. Routes:
//
//	GET /r/:slug           - public page render
//	GET /preview/:slug     - draft preview (requires ?token=...)
//	POST /api/save         - save & sanitize (editor -> service)
//
// The save endpoint mutates stored content, so it is refused
// unless the Server has an Authorizer wired to it. The public
// endpoints are unauthenticated by design: they serve content
// from an origin that holds no session credentials.
package handlers

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/drafts"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/render"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// MaxSaveBytes bounds the JSON body POST /api/save will read. It
// is generous relative to the profile's own MaxHTMLBytes /
// MaxCSSBytes limits, which are enforced afterwards on the decoded
// fields; this limit exists so an oversized body is rejected
// before it is buffered in memory.
const MaxSaveBytes = 2 << 20 // 2 MiB

// SaveAuthorizer decides whether an incoming save may proceed.
// It runs after the body is decoded and before anything is
// sanitized or stored, so it can authorize on the page's owner,
// host and slug as well as on the HTTP request.
//
// Returning a non-nil error rejects the request with 403.
type SaveAuthorizer interface {
	AuthorizeSave(r *http.Request, req SaveRequest) error
}

// SaveAuthorizerFunc adapts a function to SaveAuthorizer.
type SaveAuthorizerFunc func(r *http.Request, req SaveRequest) error

// AuthorizeSave implements SaveAuthorizer.
func (f SaveAuthorizerFunc) AuthorizeSave(r *http.Request, req SaveRequest) error {
	return f(r, req)
}

// ErrUnauthorized is the error an authorizer should return (or
// wrap) to reject a save.
var ErrUnauthorized = errors.New("handlers: save not authorized")

// AllowAllSaveAuthorizer authorizes every save.
//
// It exists for local development, the playground and tests. Do
// not wire it into anything reachable from a network you do not
// control: /api/save overwrites page content by ID, host and
// slug, all of which come from the request body.
func AllowAllSaveAuthorizer() SaveAuthorizer {
	return SaveAuthorizerFunc(func(*http.Request, SaveRequest) error { return nil })
}

// Server bundles the dependencies the handlers need.
type Server struct {
	Store        storage.Store
	Signer       *drafts.Signer
	Sanitizer    *usercontent.Sanitizer
	Profile      usercontent.Profile
	AllowedHosts []string

	// Authorizer gates POST /api/save. When nil, every save is
	// refused: an unauthenticated write endpoint on the
	// user-content origin would let anyone replace any page.
	Authorizer SaveAuthorizer

	// Logger receives server-side failures that are not reported
	// to the client verbatim. Nil means the standard logger.
	Logger *log.Logger

	allowedHosts map[string]bool
}

// NewServer creates a Server with the given dependencies. The
// returned Server has no Authorizer, so POST /api/save is refused
// until one is set.
func NewServer(store storage.Store, signer *drafts.Signer, profile usercontent.Profile, hosts ...string) (*Server, error) {
	if store == nil {
		return nil, errors.New("handlers: store is nil")
	}
	if signer == nil {
		return nil, errors.New("handlers: signer is nil")
	}
	s, err := usercontent.New(profile)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}
	return &Server{
		Store:        store,
		Signer:       signer,
		Sanitizer:    s,
		Profile:      s.Profile(),
		AllowedHosts: hosts,
		allowedHosts: allowed,
	}, nil
}

// logf writes a server-side diagnostic. Values interpolated here
// include request-controlled strings (page IDs, slugs), so line
// breaks are collapsed: a crafted ID must not be able to forge
// additional log lines.
func (s *Server) logf(format string, args ...any) {
	msg := logLineReplacer.Replace(fmt.Sprintf(format, args...))
	if s.Logger != nil {
		s.Logger.Print(msg) // #nosec G706 -- newlines stripped above
		return
	}
	log.Print(msg) // #nosec G706 -- newlines stripped above
}

var logLineReplacer = strings.NewReplacer("\n", " ", "\r", " ")

// SaveRequest is the editor's POST /api/save payload.
type SaveRequest struct {
	ID         string `json:"id"`
	OwnerID    string `json:"owner_id"`
	Product    string `json:"product"`
	Host       string `json:"host"`
	Slug       string `json:"slug"`
	HTML       string `json:"html"`
	CSS        string `json:"css"`
	Publish    bool   `json:"publish"`
	ReSanitize bool   `json:"resanitize"`
}

// SaveResponse is the editor's POST /api/save response.
type SaveResponse struct {
	Page          *storage.Page      `json:"page"`
	Report        usercontent.Report `json:"report"`
	SanitizedHTML string             `json:"sanitized_html"`
	SanitizedCSS  string             `json:"sanitized_css"`
	DraftToken    string             `json:"draft_token,omitempty"`
}

// HandleSave handles POST /api/save. It authorizes the request,
// sanitizes the input, and stores the result.
func (s *Server) HandleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.Authorizer == nil {
		s.logf("handlers: refusing save: no Authorizer configured on Server")
		http.Error(w, "save endpoint is not configured", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxSaveBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req SaveRequest
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.validateSaveRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Authorizer.AuthorizeSave(r, req); err != nil {
		s.logf("handlers: save denied for page %q: %v", req.ID, err)
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	// Sanitize. A non-nil error always comes with empty output, so
	// there is nothing here that could be stored by accident.
	htmlOut, hReport, err := s.Sanitizer.SanitizeHTML(req.HTML)
	if err != nil {
		http.Error(w, "html: "+err.Error(), http.StatusBadRequest)
		return
	}
	cssOut, cReport, err := s.Sanitizer.SanitizeCSS(req.CSS)
	if err != nil {
		http.Error(w, "css: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Build the page record.
	p := &storage.Page{
		ID:               req.ID,
		OwnerID:          req.OwnerID,
		Product:          req.Product,
		Host:             strings.ToLower(req.Host),
		Slug:             req.Slug,
		RawHTML:          req.HTML,
		RawCSS:           req.CSS,
		SanitizedHTML:    htmlOut,
		SanitizedCSS:     cssOut,
		SanitizerVersion: s.Profile.Version,
		ProfileName:      s.Profile.Name,
	}
	if req.Publish {
		p.Status = "published"
	} else {
		p.Status = "draft"
	}

	tok := s.Signer.Sign(p.ID)

	if err := s.Store.Put(r.Context(), p); err != nil {
		s.logf("handlers: store put %q: %v", p.ID, err)
		http.Error(w, "could not store page", http.StatusInternalServerError)
		return
	}

	// Combined report.
	report := hReport
	report.Removed = append(report.Removed, cReport.Removed...)
	report.InputBytes = len(req.HTML) + len(req.CSS)
	report.OutputBytes = len(htmlOut) + len(cssOut)
	report.Modified = len(report.Removed) > 0

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(SaveResponse{
		Page:          p,
		Report:        report,
		SanitizedHTML: htmlOut,
		SanitizedCSS:  cssOut,
		DraftToken:    tok,
	}); err != nil {
		s.logf("handlers: encode save response: %v", err)
	}
}

// validateSaveRequest checks the structural fields of a save.
// Content limits are enforced by the sanitizer itself.
func (s *Server) validateSaveRequest(req SaveRequest) error {
	if req.ID == "" || req.Host == "" || req.Slug == "" {
		return errors.New("id, host, slug required")
	}
	if !validSlug(req.Slug) {
		return errors.New("slug must be 1-128 characters of [a-z0-9._-]")
	}
	if len(s.allowedHosts) > 0 && !s.allowedHosts[strings.ToLower(req.Host)] {
		return fmt.Errorf("host %q is not served by this instance", req.Host)
	}
	return nil
}

// validSlug reports whether a slug is safe to use as a path
// segment and as a storage key.
func validSlug(slug string) bool {
	if slug == "" || len(slug) > 128 {
		return false
	}
	if slug == "." || slug == ".." {
		return false
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// HandleRender handles GET /r/:slug. Serves the rendered page.
func (s *Server) HandleRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.TrimPrefix(r.URL.Path, "/r/")
	if !validSlug(slug) {
		http.NotFound(w, r)
		return
	}
	host := stripPort(r.Host)
	p, err := s.Store.GetByHostSlug(r.Context(), host, slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if p.Status != "published" {
		http.NotFound(w, r)
		return
	}

	// Lazily re-sanitize on serve if the policy version moved. A
	// failure here must never fall through to serving content the
	// current policy has not approved.
	if p.SanitizerVersion < s.Profile.Version {
		if err := s.resanitize(r, p); err != nil {
			s.logf("handlers: re-sanitize page %q: %v", p.ID, err)
			http.Error(w, "page unavailable", http.StatusInternalServerError)
			return
		}
	}

	s.writePage(w, r, p, p.Slug, "User-authored page")
}

// resanitize re-runs the sanitizer over the page's raw content and
// persists the result. p is a caller-owned copy, so mutating it
// cannot race with another request.
func (s *Server) resanitize(r *http.Request, p *storage.Page) error {
	htmlOut, _, err := s.Sanitizer.SanitizeHTML(p.RawHTML)
	if err != nil {
		return fmt.Errorf("html: %w", err)
	}
	cssOut, _, err := s.Sanitizer.SanitizeCSS(p.RawCSS)
	if err != nil {
		return fmt.Errorf("css: %w", err)
	}
	p.SanitizedHTML = htmlOut
	p.SanitizedCSS = cssOut
	p.SanitizerVersion = s.Profile.Version
	p.ProfileName = s.Profile.Name
	if err := s.Store.Put(r.Context(), p); err != nil {
		// The refreshed content is still safe to serve even if we
		// could not persist it; the next request simply redoes the
		// work.
		s.logf("handlers: persist re-sanitized page %q: %v", p.ID, err)
	}
	return nil
}

// HandlePreview handles GET /preview/:slug?token=... Draft preview
// with no-store, noindex, and referrer-policy headers.
func (s *Server) HandlePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.TrimPrefix(r.URL.Path, "/preview/")
	if !validSlug(slug) {
		http.NotFound(w, r)
		return
	}
	tok := r.URL.Query().Get("token")
	if tok == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	t, err := s.Signer.Verify(tok)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, drafts.ErrExpired) {
			status = http.StatusGone
		}
		http.Error(w, "token: "+err.Error(), status)
		return
	}
	page, err := s.Store.GetByID(r.Context(), t.PageID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if page.Slug != slug || !strings.EqualFold(page.Host, stripPort(r.Host)) {
		http.NotFound(w, r)
		return
	}

	// Draft-specific headers, applied before the shared ones so a
	// draft is never cached or indexed.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")

	s.writePage(w, r, page, "[DRAFT] "+page.Slug, "Draft preview")
}

// writePage applies the security headers and writes the rendered
// shell for a page.
func (s *Server) writePage(w http.ResponseWriter, r *http.Request, p *storage.Page, title, description string) {
	for k, v := range s.Sanitizer.CSPHeaders() {
		w.Header().Set(k, v)
	}

	doc, err := render.SafeRender(
		title,
		description,
		render.CanonicalURL(p.Host, p.Slug),
		"",
		p.SanitizedHTML,
		p.SanitizedCSS,
		p.ProfileName,
	)
	if err != nil {
		s.logf("handlers: render page %q: %v", p.ID, err)
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	// #nosec G705 -- doc is render.SafeRender's output: a trusted
	// shell template whose only user-controlled inputs are the
	// sanitizer's own verified HTML and CSS.
	_, _ = w.Write([]byte(doc))
}

// HandleReport handles GET /report. Renders a small "report
// abuse" page. (Shell-owned component, not user input.)
func (s *Server) HandleReport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Report</title></head>
<body><h1>Report this page</h1>
<p>If this page contains inappropriate content, please report it
to the platform team. Include the URL of the page.</p>
</body></html>`))
}

// stripPort removes the :port from a Host header.
func stripPort(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return strings.ToLower(host[:i])
	}
	return strings.ToLower(host)
}

// NewWithProfile is a convenience constructor: it builds a signer
// from the given secret and returns a server for the profile. The
// caller must set Authorizer before POST /api/save will accept
// anything.
func NewWithProfile(profile usercontent.Profile, store storage.Store, secret []byte, hosts ...string) (*Server, error) {
	signer, err := drafts.NewSigner(secret, 0)
	if err != nil {
		return nil, err
	}
	return NewServer(store, signer, profile, hosts...)
}

// DefaultServer returns a Server with the production full-page
// profile, in-memory storage, and a random 32-byte signing key.
//
// It is intended for development and testing only, and wires
// AllowAllSaveAuthorizer: every save is accepted. Production
// callers should use NewServer or NewWithProfile and supply their
// own store, key and Authorizer.
func DefaultServer() (*Server, error) {
	store := storage.NewMemoryStore()
	key := make([]byte, drafts.MinKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("handlers: read entropy: %w", err)
	}
	srv, err := NewWithProfile(profiles.ProfileFullPage(), store, key, "pages.go-beaver.com", "localhost")
	if err != nil {
		return nil, err
	}
	srv.Authorizer = AllowAllSaveAuthorizer()
	return srv, nil
}
