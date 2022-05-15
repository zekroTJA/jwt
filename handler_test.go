package jwt

import (
	"sync"
	"testing"
	"time"
)

const testKey = "testkey"

func TestEncodeAndSign(t *testing.T) {
	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	var claims PublicClaims
	claims.Iss = "jwt testing"
	claims.Exp = int64(1516239022)
	token, err := alg.EncodeAndSign(claims)
	if err != nil {
		t.Fatal(err)
	}
	expectedToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3QgdGVzdGluZyIsImV4cCI6MTUxNjIzOTAyMn0.GALxzaFGfbggUvAigJlp_tU4S-Oejui6GPHP2edEE8Y"
	if token != expectedToken {
		t.Fatalf("Result token differs:\n\texpected: %s\n\tis:       %s",
			expectedToken, token)
	}
}

func TestDecode(t *testing.T) {
	const invalidToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3QgdGVzdGluZyIsImV4cCI6MTUxNjIzOT"
	const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3QgdGVzdGluZyIsImV4cCI6MTUxNjIzOTAyMn0.GALxzaFGfbggUvAigJlp_tU4S-Oejui6GPHP2edEE8Y"

	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	_, err := alg.Decode(invalidToken)
	if err != ErrInvalidTokenFormat {
		t.Fatalf("Resulting error differs:\n\texpected: %s\n\tis:       %s",
			ErrInvalidTokenFormat.Error(), err.Error())
	}

	claims, err := alg.Decode(token)
	if err != nil {
		t.Fatal(err)
	}

	var expectedClaims PublicClaims
	expectedClaims.Iss = "jwt testing"
	expectedClaims.Exp = int64(1516239022)

	if claims.Iss != expectedClaims.Iss {
		t.Fatalf("Claims 'iss' value differs:\n\texpected: %s\n\tis:       %s",
			expectedClaims.Iss, claims.Iss)
	}
	if claims.Exp != expectedClaims.Exp {
		t.Fatalf("Claims 'exp' value differs:\n\texpected: %d\n\tis:       %d",
			expectedClaims.Exp, claims.Exp)
	}
}

func TestValidateSignature(t *testing.T) {
	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	var claims PublicClaims
	claims.Iss = "jwt testing"

	token, err := alg.EncodeAndSign(claims)
	if err != nil {
		t.Fatal(err)
	}

	err = alg.ValidateSignature(token)
	if err != nil {
		t.Fatalf("valid signature was falsely detected as invalid (%s)", err.Error())
	}

	alg = NewHandler[PublicClaims](NewHmacSha256([]byte("invalid key")))

	err = alg.ValidateSignature(token)
	if err != ErrInvalidSignature {
		t.Fatal("invalid signature was not detected")
	}
}

func TestDecodeAndValidate_Signature(t *testing.T) {
	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	var claims PublicClaims
	claims.Iss = "jwt testing"

	token, err := alg.EncodeAndSign(claims)
	if err != nil {
		t.Fatal(err)
	}

	_, err = alg.DecodeAndValidate(token)
	if err != nil {
		t.Fatalf("valid signature was falsely detected as invalid (%s)", err.Error())
	}

	alg = NewHandler[PublicClaims](NewHmacSha256([]byte("invalid key")))

	_, err = alg.DecodeAndValidate(token)
	if err != ErrInvalidSignature {
		t.Fatal("invalid signature was not detected")
	}
}

func TestDecodeAndValidate_ExpNbf(t *testing.T) {
	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	var claims PublicClaims
	claims.Exp = time.Now().Add(2 * time.Second).Unix()
	claims.Nbf = time.Now().Add(1 * time.Second).Unix()

	token, err := alg.EncodeAndSign(claims)
	if err != nil {
		t.Fatal(err)
	}

	_, err = alg.DecodeAndValidate(token)
	if err != ErrNotValidYet {
		t.Fatal("invalid token was incorrectly validated against NBF")
	}

	time.Sleep(1 * time.Second)
	_, err = alg.DecodeAndValidate(token)
	if err != nil {
		t.Fatalf("valid token was incorrectly validated with error: %s", err.Error())
	}

	time.Sleep(1 * time.Second)
	_, err = alg.DecodeAndValidate(token)
	if err != ErrTokenExpired {
		t.Fatal("invalid token was incorrectly validated against EXP")
	}
}

func TestTestEncodeAndSign_RaceCondition(t *testing.T) {
	alg := NewHandler[PublicClaims](NewHmacSha256([]byte(testKey)))

	n := 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			alg.EncodeAndSign(PublicClaims{
				Iss: "test",
				Sub: "test",
			})
			wg.Done()
		}()
	}

	wg.Wait()
}
