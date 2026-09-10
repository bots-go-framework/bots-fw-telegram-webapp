package tgoidc

import "errors"

var (
	// ErrInvalidIDToken wraps any failure of the signature, issuer, audience or
	// expiry checks. The underlying go-oidc error is joined for diagnostics.
	ErrInvalidIDToken = errors.New("tgoidc: invalid id_token")

	// ErrNonceCheckRequired is returned when Verify is called without a nonce
	// check. Replay protection is not optional.
	ErrNonceCheckRequired = errors.New("tgoidc: a nonce check is required")

	// ErrMissingNonce is returned when a valid token carries no nonce claim,
	// i.e. the page did not pass a nonce to Telegram.Login.
	ErrMissingNonce = errors.New("tgoidc: id_token carries no nonce")

	// ErrNonceRejected wraps the error returned by the caller's nonce check.
	ErrNonceRejected = errors.New("tgoidc: nonce rejected")

	// ErrMissingUserID is returned when the token has no numeric Telegram user
	// ID in its "id" claim. Telegram returns it only for the profile scope.
	ErrMissingUserID = errors.New(`tgoidc: id_token has no numeric Telegram user id in the "id" claim; request the profile scope`)

	// ErrMissingClientID is returned by NewVerifier when no client ID is given.
	ErrMissingClientID = errors.New("tgoidc: client ID is required")

	// ErrNonceMalformed is returned by NonceIssuer.Check for input that is not a
	// nonce this package issued.
	ErrNonceMalformed = errors.New("tgoidc: malformed nonce")

	// ErrNonceInvalid is returned by NonceIssuer.Check when the signature does
	// not match, e.g. a forged nonce or one issued with a different key.
	ErrNonceInvalid = errors.New("tgoidc: nonce signature mismatch")

	// ErrNonceExpired is returned by NonceIssuer.Check for a nonce past its TTL.
	ErrNonceExpired = errors.New("tgoidc: nonce expired")

	// ErrNonceKeyTooShort is returned by NewNonceIssuer for keys under 32 bytes.
	ErrNonceKeyTooShort = errors.New("tgoidc: nonce key must be at least 32 bytes")

	// ErrNonceTTL is returned by NewNonceIssuer for a non-positive TTL.
	ErrNonceTTL = errors.New("tgoidc: nonce TTL must be positive")
)
