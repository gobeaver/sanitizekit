package editor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
)

// Editor is the interface the dashboard implements to talk to the
// page service. It is split into two pieces: the editor's own
// state (no untrusted rendering) and the iframe preview, which
// points at the isolated origin.
type Editor struct {
	// SaveEndpoint is the URL of the page service's POST /api/save.
	SaveEndpoint string

	// PreviewOrigin is the user-content hostname to embed in the
	// iframe. Must be a separate origin from the dashboard.
	PreviewOrigin string

	// ReportOrigin is the dashboard origin for the "report" link.
	ReportOrigin string

	// HTTPClient is the HTTP client used to talk to the page
	// service. It must NOT send the editor's session cookie to
	// the page service; the page service strips credentials, but
	// the client should not send them in the first place.
	HTTPClient *http.Client

	// SaveToken is the bearer token presented to the page
	// service's write API. The write API refuses saves without
	// it (see pageservice.Config.SaveToken).
	SaveToken string
}

// MaxSaveResponseBytes bounds the response body Save will read,
// so a misbehaving or hostile page service cannot exhaust the
// dashboard's memory.
const MaxSaveResponseBytes = 8 << 20 // 8 MiB

// NewEditor constructs an Editor with sane defaults.
func NewEditor(saveEndpoint, previewOrigin, reportOrigin string) *Editor {
	return &Editor{
		SaveEndpoint:  saveEndpoint,
		PreviewOrigin: previewOrigin,
		ReportOrigin:  reportOrigin,
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

// SaveRequest is the payload the editor sends to the page service.
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

// SaveResponse mirrors the page service's SaveResponse.
type SaveResponse struct {
	Page          *storage.Page `json:"page"`
	SanitizedHTML string        `json:"sanitized_html"`
	SanitizedCSS  string        `json:"sanitized_css"`
	DraftToken    string        `json:"draft_token"`
}

// Save sends the editor's HTML/CSS to the page service.
func (e *Editor) Save(ctx context.Context, req SaveRequest) (*SaveResponse, error) {
	if e.SaveEndpoint == "" {
		return nil, fmt.Errorf("editor: SaveEndpoint not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.SaveEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.SaveToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.SaveToken)
	}
	resp, err := e.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("save: status %d", resp.StatusCode)
	}
	var out SaveResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxSaveResponseBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewURL builds the iframe src for the editor preview. The
// result is an https URL on the user-content origin, with a
// short-lived signed token.
func (e *Editor) PreviewURL(slug, token string) string {
	u := &url.URL{
		Scheme:   "https",
		Host:     e.PreviewOrigin,
		Path:     "/preview/" + slug,
		RawQuery: "token=" + url.QueryEscape(token),
	}
	return u.String()
}

// IframeHTML returns the HTML for the sandboxed preview iframe.
// The iframe has no allow-scripts or allow-same-origin — the
// preview page runs the page's own CSP in addition to the
// sandbox, but the sandbox is the dashboard's strongest defense.
//
// The src is HTML-escaped rather than Go-quoted: %q would escape
// a quote as \" , which is a Go escape and not an HTML one.
func (e *Editor) IframeHTML(slug, token string) string {
	src := stdhtml.EscapeString(e.PreviewURL(slug, token))
	return `<iframe sandbox="" src="` + src + `" loading="lazy" style="border:0;width:100%;height:80vh"></iframe>`
}

// ReportURL is the URL the page shell links to for abuse reports.
func (e *Editor) ReportURL(pageURL string) string {
	u := &url.URL{
		Scheme:   "https",
		Host:     e.ReportOrigin,
		Path:     "/report",
		RawQuery: "url=" + url.QueryEscape(pageURL),
	}
	return u.String()
}

// RenderTemplate is the dashboard's HTML shell fragment for the
// "Custom Code" editor. It embeds the iframe preview and shows
// the sanitizer report inline.
type RenderTemplate struct {
	PreviewIframe string
	Report        string
	RawHTML       string
	RawCSS        string
	SanitizedHTML string
	SanitizedCSS  string
}

// RenderEditor takes the editor's current state and returns the
// HTML template fields. The dashboard renders this inside its
// own trusted shell.
func (e *Editor) RenderEditor(slug, token, rawHTML, rawCSS, sanitizedHTML, sanitizedCSS, report string) RenderTemplate {
	return RenderTemplate{
		PreviewIframe: e.IframeHTML(slug, token),
		Report:        report,
		RawHTML:       rawHTML,
		RawCSS:        rawCSS,
		SanitizedHTML: sanitizedHTML,
		SanitizedCSS:  sanitizedCSS,
	}
}
