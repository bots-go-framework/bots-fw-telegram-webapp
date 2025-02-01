package twainitdata

import "errors"

var (
	ErrInitDataIsMissing = errors.New("telegram web app init data is missing")
	ErrAuthTokenRequired = errors.New("telegram bot token is required")
	ErrAuthDateMissing   = errors.New("telegram web app auth_date is missing")
	ErrAuthHashIsMissing = errors.New("telegram web app auth hash missing")
	ErrAuthHashIsInvalid = errors.New("telegram web app auth hash is invalid")
	ErrUnexpectedFormat  = errors.New("telegram web app init data has unexpected format")
	ErrExpired           = errors.New("telegram web app init data hash expired")
)
