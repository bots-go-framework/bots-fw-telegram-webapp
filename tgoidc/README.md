# tgoidc

Verifies ID tokens from Telegram's **Log In With Telegram** OpenID Connect
provider ([docs](https://core.telegram.org/bots/telegram-login)), the successor
to the legacy Login Widget in [`tgloginwidget`](../tgloginwidget).

The `telegram-login.js` popup returns an `id_token` to the page. The page posts
it to your server, which verifies it with this package. No client secret is
needed: the secret is only for the redirect-based code flow.

```go
nonces, _ := tgoidc.NewNonceIssuer(key, 10*time.Minute) // key: ≥32 secret bytes
verifier, _ := tgoidc.NewVerifier(context.Background(), clientID) // @BotFather Client ID

// GET: hand the page a nonce to pass to Telegram.Login.auth({client_id, nonce, scope: ["profile"]}).
nonce, _ := nonces.Issue()

// POST: verify the id_token the popup returned.
claims, err := verifier.Verify(ctx, idToken, nonces.Check)
// claims.UserID is the numeric Telegram user ID.
```

What `Verify` checks: the signature against Telegram's JWKS (RS256 or ES256),
`iss` is `https://oauth.telegram.org`, `aud` is your Client ID, the token has
not expired, and the caller's nonce check passes (it is required).

**The user ID is the `id` claim, not `sub`.** Telegram returns `id` only for the
`profile` scope; without it `Verify` fails with `ErrMissingUserID`. `sub` is a
separate identifier, kept in `Claims.Subject`.

`NonceIssuer` nonces are stateless (an HMAC-signed expiry), so one can be
presented repeatedly until it expires. Keep the TTL short, or enforce single
use with server-side storage.
