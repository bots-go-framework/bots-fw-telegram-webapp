package tgwidget

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrBotTokenRequired = errors.New("bot token is required")
var ErrHashIsNotValidHex = errors.New("provided hash is a not valid hex string")
var ErrHashMismatch = errors.New("provided hash does not match computed hash")

type AuthData struct {
	ID        int64  `json:"id"`
	AuthDate  int64  `json:"auth_date"`
	Username  string `json:"username,omitempty"`
	Hash      string `json:"hash"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	PhotoURL  string `json:"photo_url,omitempty"`
}

func (v AuthData) Validate() error {
	if v.ID == 0 {
		return errors.New("missing required field: id")
	}
	if v.AuthDate == 0 {
		return errors.New("missing required field: auth_date")
	}
	if v.Hash == "" {
		return errors.New("missing required field: hash")
	}
	if _, err := hex.DecodeString(v.Hash); err != nil {
		return ErrHashIsNotValidHex
	}
	return nil
}

func (v AuthData) String() string {
	return fmt.Sprintf("AuthData{ID:%d, Username:%s, FirstName:%s, LastName:%s, AuthDate:%d, PhotoURL:%s}",
		v.ID, v.Username, v.FirstName, v.LastName, v.AuthDate, v.PhotoURL,
	)
}

func (v AuthData) StringToCheck() string {
	vs := make([]string, 0, 6)
	vs = append(vs, "auth_date="+strconv.FormatInt(v.AuthDate, 10))

	if v.FirstName != "" {
		vs = append(vs, "first_name="+v.FirstName)
	}

	vs = append(vs, "id="+strconv.FormatInt(v.ID, 10))

	if v.LastName != "" {
		vs = append(vs, "last_name="+v.LastName)
	}

	if v.PhotoURL != "" {
		vs = append(vs, "photo_url="+v.PhotoURL)
	}

	if v.Username != "" {
		vs = append(vs, "username="+v.Username)
	}

	return strings.Join(vs, "\n")
}

// GetHash returns hash of v.StringToCheck() with token
func (v AuthData) GetHash(token string) string {
	stringToCheck := v.StringToCheck()
	sha256hash := hashSHA256([]byte(token))
	hash := hashHMAC([]byte(stringToCheck), sha256hash, sha256.New)
	return hex.EncodeToString(hash)
}

// Check validates SHA256 of v.StringToCheck() matches v.Hash
func (v AuthData) Check(botToken string) (err error) {
	if strings.TrimSpace(botToken) == "" {
		return ErrBotTokenRequired
	}

	computedHash := v.GetHash(botToken)

	// Compare the computed hash with the provided hash
	if subtle.ConstantTimeCompare([]byte(v.Hash), []byte(computedHash)) != 1 {
		return ErrHashMismatch
	}
	return nil
}
