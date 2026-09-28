package tlsx

import (
	"bytes"
	"testing"
)

func TestNewX25519KeyLength(t *testing.T) {
	key, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key: %v", err)
	}

	pub := key.PublicKey().Bytes()
	if len(pub) != 32 {
		t.Fatalf("public key length = %d, want 32", len(pub))
	}
}

func TestNewX25519KeyUnique(t *testing.T) {
	k1, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key #1: %v", err)
	}
	k2, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key #2: %v", err)
	}

	if bytes.Equal(k1.PublicKey().Bytes(), k2.PublicKey().Bytes()) {
		t.Fatal("two calls produced the same public key")
	}
}
