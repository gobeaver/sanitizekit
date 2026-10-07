package storage

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store suitable for development and
// tests. It is safe for concurrent use: readers get their own copy
// of a page, and Put stores a copy of what it is given, so no
// caller ever shares a Page pointer with the store. It does not
// persist across restarts.
type MemoryStore struct {
	mu      sync.RWMutex
	pages   map[string]*Page            // by ID
	bySlug  map[string]map[string]*Page // host -> slug -> page
	byToken map[string]*Page            // draft token -> page
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pages:   make(map[string]*Page),
		bySlug:  make(map[string]map[string]*Page),
		byToken: make(map[string]*Page),
	}
}

// GetByID returns the page with the given ID.
func (m *MemoryStore) GetByID(_ context.Context, id string) (*Page, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.pages[id]; ok {
		return p.Clone(), nil
	}
	return nil, ErrNotFound
}

// GetByHostSlug returns the published page for a (host, slug) pair.
func (m *MemoryStore) GetByHostSlug(_ context.Context, host, slug string) (*Page, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h, ok := m.bySlug[host]; ok {
		if p, ok := h[slug]; ok {
			return p.Clone(), nil
		}
	}
	return nil, ErrNotFound
}

// GetByDraftToken returns the page associated with a draft token.
func (m *MemoryStore) GetByDraftToken(_ context.Context, token string) (*Page, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.byToken[token]; ok {
		return p.Clone(), nil
	}
	return nil, ErrNotFound
}

// Put upserts a page.
func (m *MemoryStore) Put(_ context.Context, p *Page) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" {
		return ErrConflict
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	// Remove old index entries if updating.
	if existing, ok := m.pages[p.ID]; ok {
		if h, ok := m.bySlug[existing.Host]; ok {
			delete(h, existing.Slug)
		}
		for _, t := range existing.DraftTokens {
			if t != "" {
				delete(m.byToken, t)
			}
		}
	}
	stored := p.Clone()
	m.pages[stored.ID] = stored
	if m.bySlug[stored.Host] == nil {
		m.bySlug[stored.Host] = make(map[string]*Page)
	}
	m.bySlug[stored.Host][stored.Slug] = stored
	for _, t := range stored.DraftTokens {
		if t != "" {
			m.byToken[t] = stored
		}
	}
	return nil
}

// Delete removes a page by ID.
func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pages[id]
	if !ok {
		return ErrNotFound
	}
	if h, ok := m.bySlug[p.Host]; ok {
		delete(h, p.Slug)
	}
	for _, t := range p.DraftTokens {
		if t != "" {
			delete(m.byToken, t)
		}
	}
	delete(m.pages, id)
	return nil
}

// List returns all pages owned by ownerID.
func (m *MemoryStore) List(_ context.Context, ownerID string) ([]*Page, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Page, 0, len(m.pages))
	for _, p := range m.pages {
		if p.OwnerID == ownerID {
			out = append(out, p.Clone())
		}
	}
	return out, nil
}
