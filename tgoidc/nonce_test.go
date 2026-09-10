package tgoidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var testNonceKey = []byte(strings.Repeat("k", 32))

func newIssuer(t *testing.T, now *time.Time) *NonceIssuer {
	t.Helper()
	n, err := NewNonceIssuer(testNonceKey, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	n.now = func() time.Time { return *now }
	return n
}

func TestNonceRoundTrip(t *testing.T) {
	now := testNow
	n := newIssuer(t, &now)
	nonce, err := n.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 48 {
		t.Errorf("len(nonce) = %d; want 48", len(nonce))
	}
	if err = n.Check(nonce); err != nil {
		t.Errorf("fresh nonce rejected: %v", err)
	}
	other, _ := n.Issue()
	if other == nonce {
		t.Error("two nonces are identical")
	}
}

func TestNonceRejects(t *testing.T) {
	now := testNow
	n := newIssuer(t, &now)
	nonce, _ := n.Issue()
	tampered := []byte(nonce)
	if tampered[20] == 'A' {
		tampered[20] = 'B'
	} else {
		tampered[20] = 'A'
	}
	otherKey, _ := NewNonceIssuer([]byte(strings.Repeat("x", 32)), 10*time.Minute)
	otherKey.now = n.now
	foreign, _ := otherKey.Issue()

	for name, tc := range map[string]struct {
		nonce string
		want  error
	}{
		"not base64":  {"!!!", ErrNonceMalformed},
		"wrong size":  {"AAAA", ErrNonceMalformed},
		"tampered":    {string(tampered), ErrNonceInvalid},
		"foreign key": {foreign, ErrNonceInvalid},
	} {
		if err := n.Check(tc.nonce); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v; want %v", name, err, tc.want)
		}
	}

	now = testNow.Add(10 * time.Minute)
	if err := n.Check(nonce); !errors.Is(err, ErrNonceExpired) {
		t.Errorf("expired nonce: err = %v; want ErrNonceExpired", err)
	}
}

func TestNewNonceIssuerValidates(t *testing.T) {
	if _, err := NewNonceIssuer([]byte("short"), time.Minute); !errors.Is(err, ErrNonceKeyTooShort) {
		t.Errorf("short key: err = %v", err)
	}
	if _, err := NewNonceIssuer(testNonceKey, 0); !errors.Is(err, ErrNonceTTL) {
		t.Errorf("zero ttl: err = %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestNonceIssueFailsWithoutEntropy(t *testing.T) {
	now := testNow
	n := newIssuer(t, &now)
	n.rand = failingReader{}
	if _, err := n.Issue(); err == nil {
		t.Error("Issue succeeded without entropy")
	}
}

// TestVerifyWithNonceIssuer is the intended wiring: the server issues a nonce,
// Telegram echoes it in the token, Verify hands it to NonceIssuer.Check.
func TestVerifyWithNonceIssuer(t *testing.T) {
	k, _ := keys(t)
	now := testNow
	n := newIssuer(t, &now)
	nonce, _ := n.Issue()
	claims := validClaims()
	claims["nonce"] = nonce
	c, err := newVerifier(t).Verify(context.Background(), sign(t, jose.RS256, k, claims, ""), n.Check)
	if err != nil || c.UserID != 987654321 {
		t.Fatalf("UserID=%d err=%v", c.UserID, err)
	}
	claims["nonce"] = "forged"
	if _, err = newVerifier(t).Verify(context.Background(), sign(t, jose.RS256, k, claims, ""), n.Check); !errors.Is(err, ErrNonceRejected) {
		t.Errorf("forged nonce: err = %v; want ErrNonceRejected", err)
	}
}
