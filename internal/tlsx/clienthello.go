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

	serverNameTypeHostName = 0x00
)

const (
	extensionServerName          uint16 = 0x0000
	extensionSupportedGroups     uint16 = 0x000a
	extensionSignatureAlgorithms uint16 = 0x000d
	extensionSupportedVersions   uint16 = 0x002b
	extensionKeyShare            uint16 = 0x0033
	extensionALPN                uint16 = 0x0010
)

const groupX25519 uint16 = 0x001d

const versionTLS13 uint16 = 0x0304

const (
	sigECDSAP256SHA256 uint16 = 0x0403 // ecdsa_secp256r1_sha256
	sigRSAPSSSHA256    uint16 = 0x0804 // rsa_pss_rsae_sha256
	sigRSAPSSSHA384    uint16 = 0x0805 // rsa_pss_rsae_sha384
	sigRSAPSSSHA512    uint16 = 0x0806 // rsa_pss_rsae_sha512
	sigRSAPKCS1SHA256  uint16 = 0x0401 // rsa_pkcs1_sha256
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

// ErrEmptySNI is returned by BuildClientHello when HelloOptions.SNI is empty.
var ErrEmptySNI = errors.New("tlsx: empty SNI")

// errFieldTooLong reports a value that does not fit its length prefix.
var errFieldTooLong = errors.New("tlsx: field too long")

// HelloOptions controls the ClientHello built by BuildClientHello.
type HelloOptions struct {
	SNI  string   // host name sent in the server_name extension
	ALPN []string // optional application protocols, e.g. "h2"
}

// builder appends TLS wire data to buf and remembers the first error.
// Once err is set, every method is a no-op.
type builder struct {
	buf []byte
	err error
}

func (b *builder) u8(v uint8) {
	if b.err != nil {
		return
	}

	b.buf = appendU8(b.buf, v)

}

func (b *builder) u16(v uint16) {
	if b.err != nil {
		return
	}

	b.buf = appendU16(b.buf, v)

}

func (b *builder) raw(p []byte) {
	if b.err != nil {
		return
	}
	b.buf = append(b.buf, p...)
}

func (b *builder) bytes8(p []byte) {
	if b.err != nil {
		return
	}

	nb, ok := appendVec8(b.buf, p)

	if !ok {
		b.err = errFieldTooLong
		return
	}

	b.buf = nb

}

func (b *builder) bytes16(p []byte) {
	if b.err != nil {
		return
	}
	nb, ok := appendVec16(b.buf, p)
	if !ok {
		b.err = errFieldTooLong
		return
	}
	b.buf = nb
}

// extension writes an extension of type typ whose data f writes.
func (b *builder) extension(typ uint16, f func(*builder)) {
	b.u16(typ)
	b.vec16(f)
}

// vec writes a size-byte length prefix followed by the content f writes.
// It reserves the prefix first and fills it in once the content is known.
func (b *builder) vec(size, max int, f func(*builder)) {
	if b.err != nil {
		return
	}
	start := len(b.buf)
	for range size { // placeholder for the length
		b.buf = append(b.buf, 0)
	}
	f(b)
	if b.err != nil {
		return
	}
	n := len(b.buf) - start - size
	if n > max {
		b.err = errFieldTooLong
		return
	}
	for i := size - 1; i >= 0; i-- { // big-endian
		b.buf[start+i] = byte(n)
		n >>= 8
	}
}

func (b *builder) vec8(f func(*builder))  { b.vec(1, 0xFF, f) }
func (b *builder) vec16(f func(*builder)) { b.vec(2, 0xFFFF, f) }
func (b *builder) vec24(f func(*builder)) { b.vec(3, 0xFFFFFF, f) }

// BuildClientHello returns a complete TLS record holding a TLS 1.3
// ClientHello for opts.SNI, offering X25519 and the TLS 1.3 cipher suites.
// Each call uses a fresh random, session ID and key share.
func BuildClientHello(opts HelloOptions) ([]byte, error) {
	if opts.SNI == "" {
		return nil, ErrEmptySNI
	}
	random := make([]byte, 32)
	sessionID := make([]byte, 32)

	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("build client hello: random: %w", err)
	}
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("build client hello: session_id: %w", err)
	}

	key, err := NewX25519Key()
	if err != nil {
		return nil, fmt.Errorf("build client hello: key share: %w", err)
	}
	pub := key.PublicKey().Bytes() // 32 bytes

	var b builder
	b.u8(recordTypeHandshake)
	b.u16(0x0301) // legacy_record_version: frozen at TLS 1.0
	b.vec16(func(b *builder) {
		b.u8(handshakeTypeClientHello)
		b.vec24(func(b *builder) {
			b.u16(0x0303) // legacy_version: frozen at TLS 1.2
			b.raw(random)
			b.bytes8(sessionID)        // non-empty for middlebox compatibility (RFC 8446 D.4)
			b.vec16(func(b *builder) { // cipher_suites
				b.u16(0x1301) // TLS_AES_128_GCM_SHA256
				b.u16(0x1302) // TLS_AES_256_GCM_SHA384
				b.u16(0x1303) // TLS_CHACHA20_POLY1305_SHA256
			})
			b.bytes8([]byte{0x00}) // compression_methods: null only

			b.vec16(func(b *builder) { // extensions
				b.extension(extensionServerName, func(b *builder) {
					b.vec16(func(b *builder) {
						b.u8(serverNameTypeHostName)
						b.bytes16([]byte(opts.SNI))
					})
				})

				if len(opts.ALPN) > 0 {
					b.extension(extensionALPN, func(b *builder) {
						b.vec16(func(b *builder) { // protocol_name_list
							for _, p := range opts.ALPN {
								b.bytes8([]byte(p))
							}
						})
					})
				}

				b.extension(extensionSupportedGroups, func(b *builder) {
					b.vec16(func(b *builder) {
						b.u16(groupX25519)
					})
				})

				b.extension(extensionSignatureAlgorithms, func(b *builder) {
					b.vec16(func(b *builder) {
						b.u16(sigECDSAP256SHA256)
						b.u16(sigRSAPSSSHA256)
						b.u16(sigRSAPSSSHA384)
						b.u16(sigRSAPSSSHA512)
						b.u16(sigRSAPKCS1SHA256)
					})
				})

				b.extension(extensionSupportedVersions, func(b *builder) {
					b.vec8(func(b *builder) { // note: a one-byte length, unlike the others
						b.u16(versionTLS13)
					})
				})

				b.extension(extensionKeyShare, func(b *builder) {
					b.vec16(func(b *builder) { // client_shares
						b.u16(groupX25519)
						b.bytes16(pub)
					})
				})
			})
		})
	})

	if b.err != nil {
		return nil, fmt.Errorf("build client hello: %w", b.err)
	}
	return b.buf, nil
}
