package packet

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestMarshalData(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:50000")
	dst := netip.MustParseAddrPort("198.51.100.7:443")

	tests := []struct {
		payload string
		wantHex string
	}{
		{"hi", "c35001bb000003e8000007d05018faf08f7000006869"},
		{"hello", "c35001bb000003e8000007d05018faf0b404000068656c6c6f"},
	}
	for _, tt := range tests {
		got := MarshalData(src, dst, 1000, 2000, []byte(tt.payload))
		if gotHex := hex.EncodeToString(got); gotHex != tt.wantHex {
			t.Errorf("MarshalData(%q) =\n  %s\nwant\n  %s", tt.payload, gotHex, tt.wantHex)
		}
	}
}

// The checksum must cover the payload: flipping a payload byte must change it.
func TestMarshalDataChecksumCoversPayload(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:50000")
	dst := netip.MustParseAddrPort("198.51.100.7:443")
	a := MarshalData(src, dst, 1, 1, []byte("A"))
	b := MarshalData(src, dst, 1, 1, []byte("B"))
	if a[16] == b[16] && a[17] == b[17] {
		t.Error("checksum did not change when the payload changed")
	}
}
