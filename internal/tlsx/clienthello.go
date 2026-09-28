package tlsx

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// NewX25519Key generates a new X25519 private key using a cryptographically
// secure random number generator (rand.Reader).
//
// On success, it returns a pointer to the generated ecdh.PrivateKey.
// If random byte generation fails, it returns nil and a wrapped error.
func NewX25519Key() (*ecdh.PrivateKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	return key, nil
}
