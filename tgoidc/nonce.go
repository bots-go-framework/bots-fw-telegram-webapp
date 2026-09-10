package tgoidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	nonceMinKeyLen = 32
	nonceRandLen   = 12
	nonceMACLen    = 16
	noncePayload   = 8 + nonceRandLen
	nonceLen       = noncePayload + nonceMACLen
	nonceDomain    = "tgoidc-nonce-v1"
)

// NonceIssuer issues and checks stateless nonces: an expiry time and random
// bytes, signed with HMAC-SHA256. The server hands one to the page, the page
// passes it to Telegram.Login, and Telegram echoes it in the id_token, so a
// token minted for another site or session is rejected.
//
// Being stateless, a nonce can be presented more than once until it expires;
// keep the TTL short. Single-use enforcement needs server-side storage.
type NonceIssuer struct {
	key  []byte
	ttl  time.Duration
	now  func() time.Time
	rand io.Reader
}

// NewNonceIssuer returns an issuer signing with key (at least 32 bytes) whose
// nonces are valid for ttl.
func NewNonceIssuer(key []byte, ttl time.Duration) (*NonceIssuer, error) {
	if len(key) < nonceMinKeyLen {
		return nil, ErrNonceKeyTooShort
	}
	if ttl <= 0 {
		return nil, ErrNonceTTL
	}
	return &NonceIssuer{key: append([]byte(nil), key...), ttl: ttl, now: time.Now, rand: rand.Reader}, nil
}

// Issue returns a new nonce: 48 URL-safe base64 characters.
func (n *NonceIssuer) Issue() (string, error) {
	buf := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(buf[:8], uint64(n.now().Add(n.ttl).Unix()))
	if _, err := io.ReadFull(n.rand, buf[8:noncePayload]); err != nil {
		return "", fmt.Errorf("tgoidc: read random bytes for nonce: %w", err)
	}
	copy(buf[noncePayload:], n.mac(buf[:noncePayload]))
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Check returns nil if nonce was issued by this issuer's key and has not
// expired. Its signature matches Verifier.Verify's nonce check.
func (n *NonceIssuer) Check(nonce string) error {
	buf, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(buf) != nonceLen {
		return ErrNonceMalformed
	}
	if !hmac.Equal(buf[noncePayload:], n.mac(buf[:noncePayload])) {
		return ErrNonceInvalid
	}
	expiry := time.Unix(int64(binary.BigEndian.Uint64(buf[:8])), 0)
	if !n.now().Before(expiry) {
		return ErrNonceExpired
	}
	return nil
}

func (n *NonceIssuer) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, n.key)
	h.Write([]byte(nonceDomain))
	h.Write(payload)
	return h.Sum(nil)[:nonceMACLen]
}
