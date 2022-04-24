package jwt

import (
	"testing"
	"time"
)

func TestValidateExp(t *testing.T) {
	var claims PublicClaims
	now := time.Now()

	claims.Exp = 0
	if !claims.ValidateExp(now) {
		t.Fatal("ValidateExp returned false when empty")
	}

	claims.Exp = now.Add(1 * time.Minute).Unix()
	if !claims.ValidateExp(now) {
		t.Fatal("ValidateExp returned false")
	}

	claims.Exp = now.Add(-1 * time.Minute).Unix()
	if claims.ValidateExp(now) {
		t.Fatal("ValidateExp returned true")
	}
}

func TestValidateNbf(t *testing.T) {
	var claims PublicClaims
	now := time.Now()

	claims.Nbf = 0
	if !claims.ValidateNbf(now) {
		t.Fatal("ValidateNbf returned false when empty")
	}

	claims.Nbf = now.Add(1 * time.Minute).Unix()
	if claims.ValidateNbf(now) {
		t.Fatal("ValidateNbf returned true")
	}

	claims.Nbf = now.Add(-1 * time.Minute).Unix()
	if !claims.ValidateNbf(now) {
		t.Fatal("ValidateNbf returned false")
	}
}
