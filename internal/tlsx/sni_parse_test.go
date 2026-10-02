package tlsx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// clientHelloBody builds a minimal ClientHello body whose extensions block
// is exts. A nil exts omits the extensions block entirely.
func clientHelloBody(exts []byte) []byte {
	body := appendU16(nil, 0x0303)                  // legacy_version
	body = append(body, make([]byte, 32)...)        // random
	body, _ = appendVec8(body, nil)                 // legacy_session_id
	body, _ = appendVec16(body, []byte{0x13, 0x01}) // cipher_suites
	body, _ = appendVec8(body, []byte{0x00})        // legacy_compression_methods
	if exts != nil {
		body, _ = appendVec16(body, exts)
	}
	return body
}

// handshakeRecord wraps body in a handshake message of msgType and that in a
// handshake record, with correct lengths at both levels.
func handshakeRecord(msgType uint8, body []byte) []byte {
	hs := appendU8(nil, msgType)
	hs, _ = appendU24(hs, uint32(len(body)))
	return record(append(hs, body...))
}

// record wraps fragment in a handshake record header.
func record(fragment []byte) []byte {
	rec := appendU8(nil, 0x16)   // handshake
	rec = appendU16(rec, 0x0301) // legacy_record_version
	rec, _ = appendVec16(rec, fragment)
	return rec
}

func clientHelloRecord(exts []byte) []byte {
	return handshakeRecord(0x01, clientHelloBody(exts))
}

// extension encodes a single extension: type followed by vec16 data.
func extension(typ uint16, data []byte) []byte {
	b := appendU16(nil, typ)
	b, _ = appendVec16(b, data)
	return b
}

// serverName encodes server_name extension data with one entry.
func serverName(nameType uint8, name string) []byte {
	entry := appendU8(nil, nameType)
	entry, _ = appendVec16(entry, []byte(name))
	b, _ := appendVec16(nil, entry)
	return b
}

// withByte returns a copy of b with b[i] set to v.
func withByte(b []byte, i int, v byte) []byte {
	c := append([]byte(nil), b...)
	c[i] = v
	return c
}

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

var (
	sniExample      = extension(0x0000, serverName(0x00, "example.com"))
	supportedGroups = extension(0x000a, []byte{0x00, 0x02, 0x00, 0x1d})
)

func TestParseSNI(t *testing.T) {
	valid := clientHelloRecord(sniExample)

	tests := []struct {
		name    string
		record  []byte
		want    string
		wantErr error
	}{
		{"sni only", valid, "example.com", nil},
		{"sni after other extension", clientHelloRecord(concat(supportedGroups, sniExample)), "example.com", nil},

		{"no extensions block", clientHelloRecord(nil), "", ErrNoSNI},
		{"empty extensions block", clientHelloRecord([]byte{}), "", ErrNoSNI},
		{"other extensions only", clientHelloRecord(supportedGroups), "", ErrNoSNI},
		{"no host_name entry", clientHelloRecord(extension(0x0000, serverName(0x01, "x"))), "", ErrNoSNI},

		{"application data record", withByte(valid, 0, 0x17), "", ErrNotHandshake},
		{"server hello", withByte(valid, 5, 0x02), "", ErrNotClientHello},

		// Truncation at the record and handshake header level.
		{"empty input", nil, "", ErrTruncated},
		{"record version short", valid[:2], "", ErrTruncated},
		{"header only", valid[:5], "", ErrTruncated},
		{"record one byte short", valid[:len(valid)-1], "", ErrTruncated},
		{"empty fragment", record([]byte{}), "", ErrTruncated},
		{"handshake length short", record([]byte{0x01, 0x00}), "", ErrTruncated},
		{"handshake length overruns", record([]byte{0x01, 0x00, 0x00, 0x10}), "", ErrTruncated},

		// Outer lengths are consistent; the extension contents are malformed.
		{"extension type short", clientHelloRecord([]byte{0x00}), "", ErrTruncated},
		{"extension overruns block", clientHelloRecord([]byte{0x00, 0x00, 0x00, 0x10, 'a'}), "", ErrTruncated},
		{"server_name list length short", clientHelloRecord(extension(0x0000, []byte{0x00})), "", ErrTruncated},
		{"host_name overruns list", clientHelloRecord(extension(0x0000, []byte{0x00, 0x04, 0x00, 0x00, 0x05, 'a'})), "", ErrTruncated},
		{"empty host_name skipped", clientHelloRecord(extension(0x0000, serverName(0x00, ""))), "", ErrNoSNI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSNI(tt.record)
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Errorf("ParseSNI() = (%q, %v); want (%q, %v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// TestParseSNITruncatedBody cuts the ClientHello body at every offset and
// fixes up the outer lengths, so every truncation branch inside the body runs.
func TestParseSNITruncatedBody(t *testing.T) {
	body := clientHelloBody(sniExample)
	extStart := len(clientHelloBody(nil))

	for i := range len(body) {
		want := ErrTruncated
		if i == extStart {
			want = ErrNoSNI // looks like a ClientHello without an extensions block
		}
		t.Run(fmt.Sprintf("cut at %d", i), func(t *testing.T) {
			got, err := ParseSNI(handshakeRecord(0x01, body[:i]))
			if !errors.Is(err, want) || got != "" {
				t.Errorf("ParseSNI() = (%q, %v); want (\"\", %v)", got, err, want)
			}
		})
	}
}

// captureClientHello returns the first TLS record crypto/tls sends as a
// client configured with serverName.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		// Handshake fails once server is closed; only the ClientHello matters.
		_ = tls.Client(client, &tls.Config{ServerName: serverName}).Handshake()
		client.Close()
	}()

	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(server, hdr); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read record body: %v", err)
	}
	return append(hdr, body...)
}

func TestParseSNIRealClientHello(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		want       string
		wantErr    error
	}{
		{"host name", "example.com", "example.com", nil},
		{"ip address sends no sni", "127.0.0.1", "", ErrNoSNI}, // RFC 6066: IP addresses are not sent as SNI
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSNI(captureClientHello(t, tt.serverName))
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Errorf("ParseSNI() = (%q, %v); want (%q, %v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// go test runs in the package directory (internal/tlsx); testdata is at the repo root.
func TestParseSNIGolden(t *testing.T) {
	data, err := os.ReadFile("../../testdata/clienthello_golden.bin")
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseSNI(data)
	if err != nil || got != "example.com" {
		t.Errorf("ParseSNI() = (%q, %v); want (%q, nil)", got, err, "example.com")
	}
}

func FuzzParseSNI(f *testing.F) {
	golden, err := os.ReadFile("../../testdata/clienthello_golden.bin")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(golden) // seed: the fuzzer mutates this real ClientHello

	f.Fuzz(func(t *testing.T, data []byte) {
		name, err := ParseSNI(data)
		// A panic fails the fuzz run on its own; also check the result invariant.
		if err == nil && name == "" {
			t.Errorf("ParseSNI(%x) = (\"\", nil); want non-empty name when err is nil", data)
		}
	})
}
