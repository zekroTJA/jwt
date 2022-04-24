package jwt

import "errors"

var (
	ErrInvalidTokenFormat = errors.New("invalid token format")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrTokenExpired       = errors.New("token has expired (invalid exp)")
	ErrNotValidYet        = errors.New("token is not valid yet (invalid nbf)")
)
