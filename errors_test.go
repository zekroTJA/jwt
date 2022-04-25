package jwt

import (
	"errors"
	"testing"
)

func TestIsJWTError(t *testing.T) {
	if !IsJWTError(ErrInvalidSignature) {
		t.Fatal("JWTError was not recognized as such")
	}

	if IsJWTError(errors.New("test123")) {
		t.Fatal("Non JWTError was falsely recognized as such")
	}
}
