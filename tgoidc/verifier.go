// Package tgoidc verifies ID tokens issued by Telegram's "Log In With Telegram"
// OpenID Connect provider (https://core.telegram.org/bots/telegram-login).
//
// The telegram-login.js popup hands an id_token straight to the page, which
// posts it to the server; the server calls Verifier.Verify. Verification checks
// the signature against Telegram's published keys, the issuer, the audience (the
// bot's Client ID from @BotFather) and expiry, then passes the token's nonce to
// a check the caller must supply, so replay protection cannot be forgotten.
// NonceIssuer provides a stateless implementation of that check.
//
// The numeric Telegram user ID is the "id" claim, which Telegram returns only
// when the profile scope was requested. It is not "sub": Telegram documents
// "sub" as a separate unique identifier.
//
// This package does not need the client secret. The secret is only used by the
// redirect-based code flow, to exchange a code at the token endpoint.
package tgoidc

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	// Issuer is the "iss" claim of every Telegram ID token.
	Issuer = "https://oauth.telegram.org"

	// JWKSURL publishes the keys Telegram signs ID tokens with.
	JWKSURL = "https://oauth.telegram.org/.well-known/jwks.json"
)

// DefaultSigningAlgs are accepted unless WithSigningAlgs overrides them.
// Telegram signs with RS256 unless changed in @BotFather, and also offers ES256.
// EdDSA and ES256K are left out on purpose: Telegram restricts them to the
// openid scope, so their tokens never carry the "id" claim Verify requires.
var DefaultSigningAlgs = []string{oidc.RS256, oidc.ES256}

// Verifier verifies Telegram ID tokens for one bot.
type Verifier struct {
	verifier *oidc.IDTokenVerifier
}

type options struct {
	jwksURL    string
	publicKeys []crypto.PublicKey
	algs       []string
	now        func() time.Time
	httpClient *http.Client
}

// Option configures a Verifier.
type Option func(*options)

// WithJWKSURL overrides where signing keys are fetched from. Tests use it.
func WithJWKSURL(url string) Option { return func(o *options) { o.jwksURL = url } }

// WithPublicKeys verifies against fixed keys instead of fetching Telegram's key
// set. Tests use it.
func WithPublicKeys(keys ...crypto.PublicKey) Option {
	return func(o *options) { o.publicKeys = keys }
}

// WithSigningAlgs replaces DefaultSigningAlgs.
func WithSigningAlgs(algs ...string) Option { return func(o *options) { o.algs = algs } }

// WithClock overrides the time source used for the expiry check.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithHTTPClient sets the client used to fetch the key set.
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.httpClient = c } }

// NewVerifier returns a Verifier for the bot whose @BotFather Client ID is
// clientID. Keys are fetched lazily and cached; ctx governs those fetches for
// the Verifier's whole lifetime, so pass a long-lived context, not a request's.
func NewVerifier(ctx context.Context, clientID string, opts ...Option) (*Verifier, error) {
	if clientID == "" {
		return nil, ErrMissingClientID
	}
	o := options{jwksURL: JWKSURL, algs: DefaultSigningAlgs}
	for _, opt := range opts {
		opt(&o)
	}
	if o.httpClient != nil {
		ctx = oidc.ClientContext(ctx, o.httpClient)
	}
	var keySet oidc.KeySet
	if len(o.publicKeys) > 0 {
		keySet = &oidc.StaticKeySet{PublicKeys: o.publicKeys}
	} else {
		keySet = oidc.NewRemoteKeySet(ctx, o.jwksURL)
	}
	return &Verifier{verifier: oidc.NewVerifier(Issuer, keySet, &oidc.Config{
		ClientID:             clientID,
		SupportedSigningAlgs: o.algs,
		Now:                  o.now,
	})}, nil
}

// Verify verifies rawIDToken and returns its claims. checkNonce receives the
// token's nonce and must return an error unless this server issued it and it is
// still valid; NonceIssuer.Check is a ready-made implementation.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string, checkNonce func(nonce string) error) (Claims, error) {
	if checkNonce == nil {
		return Claims{}, ErrNonceCheckRequired
	}
	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}
	if token.Nonce == "" {
		return Claims{}, ErrMissingNonce
	}
	if err = checkNonce(token.Nonce); err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrNonceRejected, err)
	}
	var raw rawClaims
	if err = token.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: decode claims: %w", ErrInvalidIDToken, err)
	}
	userID, err := parseUserID(raw.ID)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}
	if userID == 0 {
		return Claims{}, ErrMissingUserID
	}
	return Claims{
		Subject:             token.Subject,
		UserID:              userID,
		Name:                raw.Name,
		GivenName:           raw.GivenName,
		FamilyName:          raw.FamilyName,
		PreferredUsername:   raw.PreferredUsername,
		Picture:             raw.Picture,
		PhoneNumber:         raw.PhoneNumber,
		PhoneNumberVerified: raw.PhoneNumberVerified,
		Nonce:               token.Nonce,
		IssuedAt:            token.IssuedAt,
		Expiry:              token.Expiry,
	}, nil
}
