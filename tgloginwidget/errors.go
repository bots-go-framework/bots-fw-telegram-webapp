package tgloginwidget

import "errors"

var ErrBotTokenRequired = errors.New("bot token is required")
var ErrHashIsNotValidHex = errors.New("provided hash is a not valid hex string")
var ErrHashMismatch = errors.New("provided hash does not match computed hash")
