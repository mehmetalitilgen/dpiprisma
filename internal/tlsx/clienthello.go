package tlsx

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
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

// Errors returned by ParseSNI. Callers should check them with errors.Is.
var (
	ErrNotHandshake   = errors.New("tlsx: not a handshake record")
	ErrNotClientHello = errors.New("tlsx: not a client hello")
	ErrTruncated      = errors.New("tlsx: truncated record")
	ErrNoSNI          = errors.New("tlsx: no server_name extension")
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extensionServerName      = 0x0000
	serverNameTypeHostName   = 0x00
)

// ParseSNI returns the host name from the server_name extension of the
// ClientHello carried in record. The whole ClientHello must fit in this
// single TLS record.
func ParseSNI(record []byte) (string, error) {
	r := reader{buf: record}

	contentType, ok := r.u8()
	if !ok {
		return "", ErrTruncated
	}
	if contentType != recordTypeHandshake {
		return "", ErrNotHandshake
	}

	if _, ok := r.u16(); !ok { // legacy_record_version
		return "", ErrTruncated
	}

	fragment, ok := r.vec16()
	if !ok {
		return "", ErrTruncated
	}

	hs := reader{buf: fragment}

	msgType, ok := hs.u8()
	if !ok {
		return "", ErrTruncated
	}
	if msgType != handshakeTypeClientHello {
		return "", ErrNotClientHello
	}

	bodyLen, ok := hs.u24()
	if !ok {
		return "", ErrTruncated
	}

	body, ok := hs.bytes(int(bodyLen))
	if !ok {
		return "", ErrTruncated
	}

	return parseClientHello(body)
}

func parseClientHello(body []byte) (string, error) {
	ch := reader{buf: body}

	if _, ok := ch.u16(); !ok { // legacy_version
		return "", ErrTruncated
	}
	if _, ok := ch.bytes(32); !ok { // random
		return "", ErrTruncated
	}
	if _, ok := ch.vec8(); !ok { // session_id
		return "", ErrTruncated
	}
	if _, ok := ch.vec16(); !ok { // cipher_suites
		return "", ErrTruncated
	}
	if _, ok := ch.vec8(); !ok { // compression_methods
		return "", ErrTruncated
	}

	if len(ch.buf)-ch.pos == 0 {
		return "", ErrNoSNI // the extensions block is optional before TLS 1.3
	}

	exts, ok := ch.vec16()
	if !ok {
		return "", ErrTruncated
	}

	ex := reader{buf: exts}
	for len(ex.buf)-ex.pos > 0 {
		extType, ok := ex.u16()
		if !ok {
			return "", ErrTruncated
		}
		extData, ok := ex.vec16()
		if !ok {
			return "", ErrTruncated
		}
		if extType == extensionServerName {
			return parseServerName(extData)
		}
	}

	return "", ErrNoSNI
}

func parseServerName(data []byte) (string, error) {
	sni := reader{buf: data}

	list, ok := sni.vec16()
	if !ok {
		return "", ErrTruncated
	}

	names := reader{buf: list}
	for len(names.buf)-names.pos > 0 {
		nameType, ok := names.u8()
		if !ok {
			return "", ErrTruncated
		}
		name, ok := names.vec16()
		if !ok {
			return "", ErrTruncated
		}
		if nameType == serverNameTypeHostName && len(name) > 0 {
			return string(name), nil
		}
	}

	return "", ErrNoSNI
}
