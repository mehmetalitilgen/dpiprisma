package packet

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChecksum(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint16
	}{
		// The example IPv4 header from Wikipedia, checksum field zeroed.
		{"ipv4 header", "450000730000400040110000c0a80001c0a800c7", 0xb861},
		// The same header with its checksum filled in sums to zero.
		{"verify", "45000073000040004011b861c0a80001c0a800c7", 0x0000},
		{"carry folds back", "ffffffff", 0x0000},
		{"odd length pads with zero", "01", 0xfeff},
		{"empty", "", 0xffff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Checksum(mustHex(t, tt.in)); got != tt.want {
				t.Errorf("Checksum(%s) = %#04x; want %#04x", tt.in, got, tt.want)
			}
		})
	}
}

var hexDecode = hex.DecodeString
