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

type reader struct {
	buf []byte
	pos int
}

func (r *reader) u8() (uint8, bool) {
	if len(r.buf)-r.pos < 1 {
		return 0, false
	}
	v := r.buf[r.pos]
	r.pos++
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(r.buf)-r.pos < 2 {
		return 0, false
	}
	v := uint16(r.buf[r.pos])<<8 | uint16(r.buf[r.pos+1])
	r.pos += 2
	return v, true
}

func (r *reader) u24() (uint32, bool) {
	if len(r.buf)-r.pos < 3 {
		return 0, false
	}
	v := uint32(r.buf[r.pos])<<16 | uint32(r.buf[r.pos+1])<<8 | uint32(r.buf[r.pos+2])
	r.pos += 3
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || len(r.buf)-r.pos < n {
		return nil, false
	}
	v := r.buf[r.pos : r.pos+n : r.pos+n]
	r.pos += n
	return v, true
}

func (r *reader) vec8() ([]byte, bool) {
	start := r.pos
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	v, ok := r.bytes(int(n))
	if !ok {
		r.pos = start
		return nil, false
	}
	return v, true
}

func (r *reader) vec16() ([]byte, bool) {
	start := r.pos
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	v, ok := r.bytes(int(n))
	if !ok {
		r.pos = start
		return nil, false
	}
	return v, true
}

func appendU8(b []byte, v uint8) []byte {
	return append(b, v)
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU24(b []byte, v uint32) ([]byte, bool) {
	if v > 0xFFFFFF {
		return b, false
	}
	return append(b, byte(v>>16), byte(v>>8), byte(v)), true
}

func appendVec8(b []byte, v []byte) ([]byte, bool) {
	if len(v) > 0xFF {
		return b, false
	}
	b = appendU8(b, uint8(len(v)))
	return append(b, v...), true
}

func appendVec16(b []byte, v []byte) ([]byte, bool) {
	if len(v) > 0xFFFF {
		return b, false
	}
	b = appendU16(b, uint16(len(v)))
	return append(b, v...), true
}
