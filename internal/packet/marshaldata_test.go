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

func TestMarshalRST(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:50000")
	dst := netip.MustParseAddrPort("198.51.100.7:443")

	got := MarshalRST(src, dst, 1000, 2000)
	const want = "c35001bb000003e8000007d050140000f2d00000"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Errorf("MarshalRST =\n  %s\nwant\n  %s", gotHex, want)
	}

	// Recompute: a valid segment folds its checksum to the stored value.
	stored := [2]byte{got[16], got[17]}
	got[16], got[17] = 0, 0
	cs := TCPChecksum(src.Addr(), dst.Addr(), got)
	if byte(cs>>8) != stored[0] || byte(cs) != stored[1] {
		t.Errorf("MarshalRST checksum %#04x does not verify", cs)
	}
}
