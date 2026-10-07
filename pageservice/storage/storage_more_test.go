package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
)

func newPage(id, host, slug string) *storage.Page {
	return &storage.Page{ID: id, Host: host, Slug: slug, Status: "published"}
}

func TestMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	s := storage.NewMemoryStore()

	if _, err := s.GetByID(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetByID on empty store: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetByHostSlug(ctx, "h", "s"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetByHostSlug on empty store: want ErrNotFound, got %v", err)
	}
	if err := s.Put(ctx, &storage.Page{}); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("Put with no ID: want ErrConflict, got %v", err)
	}
	if err := s.Delete(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Delete missing: want ErrNotFound, got %v", err)
	}

	p := newPage("p1", "h", "s")
	if err := s.Put(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetByHostSlug(ctx, "h", "s")
	if err != nil || got.ID != "p1" {
		t.Fatalf("GetByHostSlug: %+v %v", got, err)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("Put did not stamp timestamps")
	}

	if err := s.Delete(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByID(ctx, "p1"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("after Delete: want ErrNotFound, got %v", err)
	}
}

// Re-slugging a page must not leave the old (host, slug) pointing
// at it: a stale index entry would keep serving content at a URL
// its owner believes they have moved away from.
func TestMemoryStore_ReindexOnSlugChange(t *testing.T) {
	ctx := context.Background()
	s := storage.NewMemoryStore()
	if err := s.Put(ctx, newPage("p1", "h", "old")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, newPage("p1", "h", "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByHostSlug(ctx, "h", "old"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("old slug still resolves after rename: %v", err)
	}
	if _, err := s.GetByHostSlug(ctx, "h", "new"); err != nil {
		t.Errorf("new slug does not resolve: %v", err)
	}
}

// The same slug on different hosts must be different pages; the
// host gate is what keeps tenants apart.
func TestMemoryStore_HostScoping(t *testing.T) {
	ctx := context.Background()
	s := storage.NewMemoryStore()
	if err := s.Put(ctx, newPage("a", "one.example", "same")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, newPage("b", "two.example", "same")); err != nil {
		t.Fatal(err)
	}
	for host, wantID := range map[string]string{"one.example": "a", "two.example": "b"} {
		got, err := s.GetByHostSlug(ctx, host, "same")
		if err != nil || got.ID != wantID {
			t.Errorf("host %s: got %+v err %v, want id %s", host, got, err, wantID)
		}
	}
}

func TestMemoryStore_DraftTokenIndexAndList(t *testing.T) {
	ctx := context.Background()
	s := storage.NewMemoryStore()

	p := newPage("p1", "h", "s")
	p.OwnerID = "owner-1"
	tok, err := p.NewDraftToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 16 {
		t.Errorf("draft token looks too short: %q", tok)
	}
	if p.CurrentDraftToken() != tok {
		t.Error("CurrentDraftToken did not return the newest token")
	}
	if err := s.Put(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByDraftToken(ctx, tok)
	if err != nil || got.ID != "p1" {
		t.Fatalf("GetByDraftToken: %+v %v", got, err)
	}
	if _, err := s.GetByDraftToken(ctx, "not-a-token"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown token: want ErrNotFound, got %v", err)
	}

	other := newPage("p2", "h", "s2")
	other.OwnerID = "owner-2"
	if err := s.Put(ctx, other); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "p1" {
		t.Errorf("List(owner-1) = %+v, want just p1", list)
	}
	if empty, _ := s.List(ctx, "nobody"); len(empty) != 0 {
		t.Errorf("List for an unknown owner returned %d pages", len(empty))
	}
}

// Two tokens generated back to back must differ; a predictable
// token exposes every unpublished page.
func TestNewDraftToken_Unpredictable(t *testing.T) {
	seen := map[string]bool{}
	p := &storage.Page{ID: "p"}
	for i := 0; i < 64; i++ {
		tok, err := p.NewDraftToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("duplicate draft token %q on iteration %d", tok, i)
		}
		if strings.Contains(tok, "fallback") {
			t.Fatalf("token looks like a constant fallback: %q", tok)
		}
		seen[tok] = true
	}
	if len(p.DraftTokens) != 64 {
		t.Errorf("expected 64 accumulated tokens, got %d", len(p.DraftTokens))
	}
}

func TestPage_CloneIsDeep(t *testing.T) {
	p := &storage.Page{ID: "p", DraftTokens: []string{"a", "b"}}
	c := p.Clone()
	c.DraftTokens[0] = "mutated"
	c.ID = "other"
	if p.DraftTokens[0] != "a" || p.ID != "p" {
		t.Errorf("Clone aliased the original: %+v", p)
	}
	if (*storage.Page)(nil).Clone() != nil {
		t.Error("Clone of nil must be nil")
	}
}

func TestPage_CurrentDraftTokenEmpty(t *testing.T) {
	if got := (&storage.Page{}).CurrentDraftToken(); got != "" {
		t.Errorf("CurrentDraftToken with no tokens = %q, want empty", got)
	}
}
