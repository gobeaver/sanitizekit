// Package storage defines the interface the page service uses to
// persist user_pages. The default implementation is in-memory;
// production deployments wire a real database.
package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Page is the persisted record for a single user-authored page.
// raw_* is editor-only; sanitized_* is the only thing served.
type Page struct {
	ID      string
	OwnerID string
	Product string
	Host    string
	Slug    string
	RawHTML string
	RawCSS  string

	// Sanitized output. This is the only content ever served.
	SanitizedHTML string
	SanitizedCSS  string

	// SanitizerVersion is the version of the sanitizer that
	// produced the sanitized content. The render path re-sanitizes
	// lazily when stored < current.
	SanitizerVersion int

	// ProfileName is the sanitizer profile used.
	ProfileName string

	// Status is "draft", "published", or "archived".
	Status string

	// Tokens: the most recent draft token, used for preview URLs.
	// Multiple tokens are kept so old previews stay valid until
	// they expire.
	DraftTokens []string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Sentinel errors.
var (
	ErrNotFound = errors.New("storage: not found")
	ErrConflict = errors.New("storage: conflict")
)

// Clone returns a deep copy of the page. Stores hand out clones
// rather than their own pointers so a caller that mutates a page
// cannot race with, or silently corrupt, the stored record.
func (p *Page) Clone() *Page {
	if p == nil {
		return nil
	}
	c := *p
	if p.DraftTokens != nil {
		c.DraftTokens = append([]string(nil), p.DraftTokens...)
	}
	return &c
}

// Store is the abstract persistence layer. Methods are
// context-aware so the page service can use request cancellation
// and deadlines.
//
// Implementations must return pages that the caller may freely
// mutate: either freshly built values or Clone()d copies. They
// must likewise not retain the caller's pointer in Put.
type Store interface {
	GetByID(ctx context.Context, id string) (*Page, error)
	GetByHostSlug(ctx context.Context, host, slug string) (*Page, error)
	GetByDraftToken(ctx context.Context, token string) (*Page, error)
	Put(ctx context.Context, p *Page) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, ownerID string) ([]*Page, error)
}

// CurrentDraftToken returns the most recent draft token, or "" if
// the page has no draft tokens.
func (p *Page) CurrentDraftToken() string {
	if len(p.DraftTokens) == 0 {
		return ""
	}
	return p.DraftTokens[len(p.DraftTokens)-1]
}

// NewDraftToken generates a new token, appends it to the page,
// and returns it. The token is URL-safe and unpredictable.
//
// It returns an error if the system entropy source fails. There
// is deliberately no fallback: a predictable draft token would
// expose every unpublished page, so failing the request is the
// only safe outcome.
func (p *Page) NewDraftToken() (string, error) {
	t, err := generateToken()
	if err != nil {
		return "", err
	}
	p.DraftTokens = append(p.DraftTokens, t)
	return t, nil
}

// generateToken returns a 128-bit URL-safe random token.
func generateToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("storage: read entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
