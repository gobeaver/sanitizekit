package storage

import (
	"context"
	"testing"
)

func TestMemoryStore(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	p := &Page{ID: "p1", Host: "example.com", Slug: "test"}
	if err := s.Put(ctx, p); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	got, err := s.GetByID(ctx, "p1")
	if err != nil || got.ID != "p1" {
		t.Fatalf("GetByID failed: %v", err)
	}
}
