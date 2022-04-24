package jwt

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Handler provides functionalities to encode, sign,
// decode and verify JWT tokens using a given algorithm.
//
// TPayload specifies the type of the payload data.
type Handler[TPayload any] struct {
	algorithm IAlgorithm
}

// NewHandler returns a new handler using the given
// hashing algorithm.
func NewHandler[TPayload any](algorithm IAlgorithm) Handler[TPayload] {
	return Handler[TPayload]{
		algorithm: algorithm,
	}
}

// EncodeAndSign takes a given payload, encodes it into
// a JWT and signs it using the chosen algorithm.
//
// Returns the signed JWT.
func (t Handler[TPayload]) EncodeAndSign(payload TPayload) (string, error) {
	encodedHeader, err := b64JsonEncode(t.header())
	if err != nil {
		return "", err
	}

	encodedPayload, err := b64JsonEncode(payload)
	if err != nil {
		return "", err
	}

	tokenData := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature, err := t.sign(tokenData)

	return fmt.Sprintf("%s.%s", tokenData, signature), nil
}

// Decode takes a JWT and unmarshals the contained data
// without validation of the payload or signature.
func (t Handler[TPayload]) Decode(token string) (p TPayload, err error) {
	_, payload, _, err := t.elements(token)
	if err != nil {
		return p, err
	}

	err = b64JsonDecode(payload, &p)
	return p, err
}

// ValidateSignature takes a given token and validates the
// signature using the registered algorithm.
//
// Returns ErrInvalidSignature when signature does not match.
func (t Handler[TPayload]) ValidateSignature(token string) error {
	header, payload, signature, err := t.elements(token)
	if err != nil {
		return err
	}
	return t.validateSignature(header, payload, signature)
}

// DecodeAndValidate decodes the tokens payload and validates
// the signature as well as 'exp' and 'nbf', if set in the
// payload.
//
// Returns the unmarshaled payload when successful or an error
// if the validation failed.
func (t Handler[TPayload]) DecodeAndValidate(token string) (p TPayload, err error) {
	header, payload, signature, err := t.elements(token)
	if err != nil {
		return p, err
	}

	if err = t.validateSignature(header, payload, signature); err != nil {
		return p, err
	}

	err = b64JsonDecode(payload, &p)
	if err != nil {
		return p, err
	}

	var pa any = p
	now := time.Now()
	if expClaims, ok := pa.(IValidateExp); ok && !expClaims.ValidateExp(now) {
		return p, ErrTokenExpired
	}
	if nbfClaims, ok := pa.(IValidateNbf); ok && !nbfClaims.ValidateNbf(now) {
		return p, ErrNotValidYet
	}

	return p, nil
}

func (t Handler[TPayload]) header() Header {
	return Header{
		Typ: "JWT",
		Alg: t.algorithm.Name(),
	}
}

func (t Handler[TPayload]) elements(token string) (header, payload, signature string, err error) {
	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) != 3 {
		return "", "", "", ErrInvalidTokenFormat
	}

	return tokenSplit[0], tokenSplit[1], tokenSplit[2], nil
}

func (t Handler[TPayload]) sign(data string) (string, error) {
	sum, err := t.algorithm.Sum([]byte(data))
	if err != nil {
		return "", nil
	}

	return base64.RawURLEncoding.EncodeToString(sum), nil
}

func (t Handler[TPayload]) validateSignature(header, payload, signature string) error {
	tokenData := fmt.Sprintf("%s.%s", header, payload)
	newSignature, err := t.sign(tokenData)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(newSignature), []byte(signature)) {
		return ErrInvalidSignature
	}

	return nil
}
