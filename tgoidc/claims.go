package tgoidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Claims are the user claims of a verified Telegram ID token.
type Claims struct {
	// Subject is the "sub" claim. Telegram documents it as a unique user
	// identifier, distinct from the numeric Telegram user ID in UserID.
	Subject string

	// UserID is the numeric Telegram user ID from the "id" claim — the same ID
	// bots see in updates. Verify guarantees it is non-zero.
	UserID int64

	Name                string
	GivenName           string
	FamilyName          string
	PreferredUsername   string
	Picture             string
	PhoneNumber         string
	PhoneNumberVerified bool

	Nonce    string
	IssuedAt time.Time
	Expiry   time.Time
}

type rawClaims struct {
	ID                  json.RawMessage `json:"id"`
	Name                string          `json:"name"`
	GivenName           string          `json:"given_name"`
	FamilyName          string          `json:"family_name"`
	PreferredUsername   string          `json:"preferred_username"`
	Picture             string          `json:"picture"`
	PhoneNumber         string          `json:"phone_number"`
	PhoneNumberVerified bool            `json:"phone_number_verified"`
}

// parseUserID accepts the "id" claim as a JSON number or a numeric string.
// It returns 0 when the claim is absent or null.
func parseUserID(raw json.RawMessage) (int64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, nil
	}
	s := string(raw)
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("tgoidc: id claim: %w", err)
		}
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tgoidc: id claim %q is not an integer: %w", s, err)
	}
	return id, nil
}
