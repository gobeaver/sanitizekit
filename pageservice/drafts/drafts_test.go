package drafts

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	return []byte(strings.Repeat("k", MinKeyLen))
}

func newTestSigner(t *testing.T, ttl time.Duration) *Signer {
	t.Helper()
	s, err := NewSigner(testKey(t), ttl)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	return s
}

func TestSignAndVerify(t *testing.T) {
	s := newTestSigner(t, 1*time.Hour)
	tok := s.Sign("page-1")
	result, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.PageID != "page-1" {
		t.Errorf("expected pageID page-1, got %s", result.PageID)
	}
}

func TestExpiredToken(t *testing.T) {
	s := newTestSigner(t, 1*time.Millisecond)
	tok := s.SignAt("page-1", time.Now().Add(-1*time.Hour))
	_, err := s.Verify(tok)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	s := newTestSigner(t, 1*time.Hour)
	for _, tok := range []string{"garbage", "", ".", "a.b", "v1:abc:123.notbase64!"} {
		if _, err := s.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("Verify(%q): expected ErrInvalid, got %v", tok, err)
		}
	}
}

// A page ID containing the payload separator must still round-trip:
// the ID is base64url-encoded precisely so it cannot collide with it.
func TestPageIDWithSeparator(t *testing.T) {
	s := newTestSigner(t, 1*time.Hour)
	for _, id := range []string{"tenant:page:1", "a.b.c", "with spaces", "ünïcode"} {
		got, err := s.Verify(s.Sign(id))
		if err != nil {
			t.Fatalf("Verify for id %q: %v", id, err)
		}
		if got.PageID != id {
			t.Errorf("round trip: want %q, got %q", id, got.PageID)
		}
	}
}

// A token signed by one key must not verify under another.
func TestSignatureIsKeyBound(t *testing.T) {
	a := newTestSigner(t, time.Hour)
	b, err := NewSigner([]byte(strings.Repeat("x", MinKeyLen)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(a.Sign("page-1")); !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid across keys, got %v", err)
	}
}

// Tampering with any part of the payload must fail verification.
func TestTamperedPayloadRejected(t *testing.T) {
	s := newTestSigner(t, time.Hour)
	tok := s.Sign("page-1")
	dot := strings.LastIndexByte(tok, '.')
	payload, sig := tok[:dot], tok[dot+1:]

	// Re-point the token at a different page, keeping the signature.
	other := s.Sign("page-2")
	otherPayload := other[:strings.LastIndexByte(other, '.')]
	if _, err := s.Verify(otherPayload + "." + sig); !errors.Is(err, ErrInvalid) {
		t.Errorf("swapped payload: expected ErrInvalid, got %v", err)
	}

	// Extend the expiry by a digit, keeping the signature.
	if _, err := s.Verify(payload + "0." + sig); !errors.Is(err, ErrInvalid) {
		t.Errorf("extended expiry: expected ErrInvalid, got %v", err)
	}
}

func TestWeakKeyRejected(t *testing.T) {
	for _, key := range [][]byte{nil, {}, []byte("short"), make([]byte, MinKeyLen-1)} {
		if _, err := NewSigner(key, time.Hour); !errors.Is(err, ErrWeakKey) {
			t.Errorf("NewSigner(%d bytes): expected ErrWeakKey, got %v", len(key), err)
		}
	}
	if _, err := NewSigner(make([]byte, MinKeyLen), time.Hour); err != nil {
		t.Errorf("NewSigner with %d bytes: unexpected error %v", MinKeyLen, err)
	}
}

// The signer must not alias the caller's key slice.
func TestSignerCopiesKey(t *testing.T) {
	key := []byte(strings.Repeat("k", MinKeyLen))
	s, err := NewSigner(key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok := s.Sign("page-1")
	for i := range key {
		key[i] = 'z'
	}
	if _, err := s.Verify(tok); err != nil {
		t.Errorf("token stopped verifying after caller mutated its key slice: %v", err)
	}
}

func TestDefaultTTL(t *testing.T) {
	s, err := NewSigner(testKey(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.TTL(), 7*24*time.Hour; got != want {
		t.Errorf("default TTL: got %v, want %v", got, want)
	}
}
