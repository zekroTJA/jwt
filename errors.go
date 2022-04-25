package jwt

var (
	ErrInvalidTokenFormat = wrapError("invalid token format")
	ErrInvalidSignature   = wrapError("invalid signature")
	ErrTokenExpired       = wrapError("token has expired (invalid exp)")
	ErrNotValidYet        = wrapError("token is not valid yet (invalid nbf)")
)

type JWTError struct {
	msg string
}

func (t JWTError) Error() string {
	return t.msg
}

func IsJWTError(err error) bool {
	_, ok := err.(JWTError)
	return ok
}

func wrapError(msg string) JWTError {
	return JWTError{msg: msg}
}
