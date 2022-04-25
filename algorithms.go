package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

// IAlgorithm describes a hash algorithm used to
// generate hash sums from given data.
type IAlgorithm interface {
	// Name returns the name of the algorithm.
	// The name must be all uppercase.
	Name() string
	// Sum takes any data and returns the hashed
	// sum of the given data.
	Sum(data []byte) ([]byte, error)
}

type Algorithm struct {
	name   string
	hasher hash.Hash
}

func (t Algorithm) Name() string {
	return t.name
}

func (t Algorithm) Sum(data []byte) ([]byte, error) {
	_, err := t.hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}

	sum := t.hasher.Sum(nil)
	t.hasher.Reset()

	return sum, nil
}

// NewAlgorithmWithKey returns a new algorithm using the
// given hash implementation with the given name and
// a key used to sign the hash with.
func NewAlgorithmWithKey(name string, hasher func() hash.Hash, key []byte) Algorithm {
	return Algorithm{
		name:   name,
		hasher: hmac.New(hasher, key),
	}
}

// NewHmacSha256 returns a new algorithm using HS256.
func NewHmacSha256(key []byte) Algorithm {
	return NewAlgorithmWithKey("HS256", sha256.New, key)
}

// NewHmacSha512 returns a new algorithm using HS512.
func NewHmacSha512(key []byte) Algorithm {
	return NewAlgorithmWithKey("HS512", sha512.New, key)
}

func NewHmacSha384(key []byte) Algorithm {
	return NewAlgorithmWithKey("HS384", sha3.New384, key)
}
