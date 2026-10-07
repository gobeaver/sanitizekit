// Package drafts handles short-lived signed draft tokens used by
// the editor preview. Each token authorizes the editor (or any
// recipient of a preview link) to view a specific page in draft
// state on the public user-content origin.
package drafts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrExpired = errors.New("drafts: token expired")
	ErrInvalid = errors.New("drafts: token invalid")
	ErrWeakKey = errors.New("drafts: signing key too short")
)

// MinKeyLen is the shortest signing key NewSigner accepts. A
// draft token is the only thing standing between an unpublished
// page and the public internet, so the key must carry at least as
// much entropy as the HMAC-SHA256 output it produces.
const MinKeyLen = 32

// tokenVersion is mixed into every signed payload so a token can
// never be replayed against a future format with different
// semantics.
const tokenVersion = "v1"

// Token is a signed, expiring string identifying a draft preview.
//
// Wire format: <version>:<base64url(pageID)>:<expiryUnix>.<base64url(signature)>
//
// The page ID is base64url-encoded so that it cannot contain the
// ':' separator, whatever the caller's ID scheme looks like.
type Token struct {
	PageID string
	Expiry time.Time
}

// Signer creates and verifies tokens.
type Signer struct {
	key []byte
	ttl time.Duration
}

// NewSigner returns a Signer with the given secret key and token
// TTL. ttl==0 means use 7 days. The key must be at least
// MinKeyLen bytes; a shorter one is rejected with ErrWeakKey
// rather than silently producing forgeable tokens.
func NewSigner(key []byte, ttl time.Duration) (*Signer, error) {
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrWeakKey, len(key), MinKeyLen)
	}
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	if ttl < 0 {
		return nil, errors.New("drafts: ttl must not be negative")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k, ttl: ttl}, nil
}

// TTL returns the configured token lifetime.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Sign returns a new token for the given pageID, valid for the
// configured TTL.
func (s *Signer) Sign(pageID string) string {
	return s.SignAt(pageID, time.Now())
}

// SignAt is Sign evaluated at a given time. Useful for tests.
func (s *Signer) SignAt(pageID string, now time.Time) string {
	payload := tokenVersion + ":" +
		base64.RawURLEncoding.EncodeToString([]byte(pageID)) + ":" +
		strconv.FormatInt(now.Add(s.ttl).Unix(), 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload))
}

// Verify parses and validates a token. It returns ErrInvalid if
// the token is malformed or the signature doesn't match, and
// ErrExpired if it is well formed but past its expiry.
func (s *Signer) Verify(token string) (Token, error) {
	return s.verifyAt(token, time.Now())
}

// VerifyAt is Verify evaluated at a given time. Useful for tests.
func (s *Signer) VerifyAt(token string, now time.Time) (Token, error) {
	return s.verifyAt(token, now)
}

func (s *Signer) verifyAt(token string, now time.Time) (Token, error) {
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		return Token{}, ErrInvalid
	}
	payload, sig := token[:dot], token[dot+1:]

	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Token{}, ErrInvalid
	}
	// Authenticate before parsing: nothing downstream should ever
	// look at an unverified payload.
	if !hmac.Equal(s.mac(payload), mac) {
		return Token{}, ErrInvalid
	}

	parts := strings.Split(payload, ":")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return Token{}, ErrInvalid
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Token{}, ErrInvalid
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Token{}, ErrInvalid
	}
	if now.Unix() > exp {
		return Token{}, ErrExpired
	}
	return Token{PageID: string(id), Expiry: time.Unix(exp, 0)}, nil
}

func (s *Signer) mac(payload string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(payload))
	return h.Sum(nil)
}
