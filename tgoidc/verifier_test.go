package tgoidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testClientID = "6042661328"

var (
	testNow  = time.Unix(1_700_000_000, 0)
	rsaOnce  sync.Once
	rsaKey   *rsa.PrivateKey
	rsaKey2  *rsa.PrivateKey
	ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

func keys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rsaKey2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return rsaKey, rsaKey2
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":                Issuer,
		"aud":                testClientID,
		"sub":                "1234123412341234123",
		"iat":                testNow.Unix(),
		"exp":                testNow.Add(time.Hour).Unix(),
		"id":                 987654321,
		"name":               "John Doe",
		"given_name":         "John",
		"family_name":        "Doe",
		"preferred_username": "johndoe",
		"picture":            "https://cdn4.telesco.pe/file/x.jpg",
		"nonce":              "n-1",
	}
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, claims map[string]any, kid string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newVerifier(t *testing.T, opts ...Option) *Verifier {
	t.Helper()
	k, _ := keys(t)
	base := []Option{WithPublicKeys(&k.PublicKey, &ecKey.PublicKey), WithClock(func() time.Time { return testNow })}
	v, err := NewVerifier(context.Background(), testClientID, append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func acceptNonce(want string) func(string) error {
	return func(got string) error {
		if got != want {
			return errors.New("unexpected nonce " + got)
		}
		return nil
	}
}

func TestVerifyValidToken(t *testing.T) {
	k, _ := keys(t)
	raw := sign(t, jose.RS256, k, validClaims(), "")
	c, err := newVerifier(t).Verify(context.Background(), raw, acceptNonce("n-1"))
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != 987654321 || c.Subject != "1234123412341234123" {
		t.Errorf("UserID=%d Subject=%q; want 987654321 and the distinct sub", c.UserID, c.Subject)
	}
	if c.Name != "John Doe" || c.GivenName != "John" || c.FamilyName != "Doe" || c.PreferredUsername != "johndoe" || c.Picture == "" {
		t.Errorf("profile claims not mapped: %+v", c)
	}
	if c.Nonce != "n-1" || !c.IssuedAt.Equal(testNow) || !c.Expiry.Equal(testNow.Add(time.Hour)) {
		t.Errorf("nonce/iat/exp not mapped: %+v", c)
	}
}

func TestVerifyAcceptsES256(t *testing.T) {
	raw := sign(t, jose.ES256, ecKey, validClaims(), "")
	if _, err := newVerifier(t).Verify(context.Background(), raw, acceptNonce("n-1")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyUserIDAsString(t *testing.T) {
	k, _ := keys(t)
	claims := validClaims()
	claims["id"] = "987654321"
	c, err := newVerifier(t).Verify(context.Background(), sign(t, jose.RS256, k, claims, ""), acceptNonce("n-1"))
	if err != nil || c.UserID != 987654321 {
		t.Fatalf("UserID=%d err=%v; want 987654321", c.UserID, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	k, other := keys(t)
	mutate := func(f func(map[string]any)) string {
		c := validClaims()
		f(c)
		return sign(t, jose.RS256, k, c, "")
	}
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"wrong audience", mutate(func(c map[string]any) { c["aud"] = "111" }), ErrInvalidIDToken},
		{"wrong issuer", mutate(func(c map[string]any) { c["iss"] = "https://evil.example" }), ErrInvalidIDToken},
		{"expired", mutate(func(c map[string]any) { c["exp"] = testNow.Add(-time.Minute).Unix() }), ErrInvalidIDToken},
		{"signed by another key", sign(t, jose.RS256, other, validClaims(), ""), ErrInvalidIDToken},
		{"algorithm not allowed", sign(t, jose.PS256, k, validClaims(), ""), ErrInvalidIDToken},
		{"not a JWT", "not-a-jwt", ErrInvalidIDToken},
		{"no id claim", mutate(func(c map[string]any) { delete(c, "id") }), ErrMissingUserID},
		{"null id claim", mutate(func(c map[string]any) { c["id"] = nil }), ErrMissingUserID},
		{"zero id claim", mutate(func(c map[string]any) { c["id"] = 0 }), ErrMissingUserID},
		{"non-numeric id", mutate(func(c map[string]any) { c["id"] = "abc" }), ErrInvalidIDToken},
		{"id of wrong type", mutate(func(c map[string]any) { c["id"] = true }), ErrInvalidIDToken},
		{"no nonce", mutate(func(c map[string]any) { delete(c, "nonce") }), ErrMissingNonce},
		{"foreign nonce", mutate(func(c map[string]any) { c["nonce"] = "someone-else" }), ErrNonceRejected},
		{"bad claim type", mutate(func(c map[string]any) { c["name"] = 42 }), ErrInvalidIDToken},
	}
	v := newVerifier(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tt.raw, acceptNonce("n-1")); !errors.Is(err, tt.want) {
				t.Errorf("err = %v; want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyNonceCheckIsRequired(t *testing.T) {
	k, _ := keys(t)
	if _, err := newVerifier(t).Verify(context.Background(), sign(t, jose.RS256, k, validClaims(), ""), nil); !errors.Is(err, ErrNonceCheckRequired) {
		t.Errorf("err = %v; want ErrNonceCheckRequired", err)
	}
}

func TestVerifyNonceRejectionKeepsCause(t *testing.T) {
	k, _ := keys(t)
	cause := errors.New("replayed")
	_, err := newVerifier(t).Verify(context.Background(), sign(t, jose.RS256, k, validClaims(), ""), func(string) error { return cause })
	if !errors.Is(err, ErrNonceRejected) || !errors.Is(err, cause) {
		t.Errorf("err = %v; want both ErrNonceRejected and the cause", err)
	}
}

func TestWithSigningAlgsOverridesDefaults(t *testing.T) {
	raw := sign(t, jose.ES256, ecKey, validClaims(), "")
	if _, err := newVerifier(t, WithSigningAlgs("RS256")).Verify(context.Background(), raw, acceptNonce("n-1")); !errors.Is(err, ErrInvalidIDToken) {
		t.Errorf("ES256 token accepted with RS256-only config: err = %v", err)
	}
}

func TestNewVerifierRequiresClientID(t *testing.T) {
	if _, err := NewVerifier(context.Background(), ""); !errors.Is(err, ErrMissingClientID) {
		t.Errorf("err = %v; want ErrMissingClientID", err)
	}
}

func TestVerifyFetchesRemoteKeySet(t *testing.T) {
	k, _ := keys(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer srv.Close()
	v, err := NewVerifier(context.Background(), testClientID,
		WithJWKSURL(srv.URL), WithHTTPClient(srv.Client()), WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(context.Background(), sign(t, jose.RS256, k, validClaims(), "k1"), acceptNonce("n-1"))
	if err != nil || c.UserID != 987654321 {
		t.Fatalf("UserID=%d err=%v", c.UserID, err)
	}
	if hits == 0 {
		t.Error("key set was never fetched")
	}
}

var _ crypto.PublicKey = (*rsa.PublicKey)(nil)
