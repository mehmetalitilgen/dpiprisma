package packet

import (
	"errors"
	"net/netip"
	"testing"
)

// rstPacket is a 40-byte IPv4 + TCP RST/ACK from 93.184.215.14:443 to
// 192.168.1.10:50000 with TTL 55 and IP-ID 0x1234.
const rstPacket = "4500002812344000370600005db8d70ec0a8010a01bbc35000000001000000005014000000000000"

func TestParseIPv4(t *testing.T) {
	h, payload, err := ParseIPv4(mustHex(t, rstPacket))
	if err != nil {
		t.Fatal(err)
	}
	want := IPv4Header{TTL: 55, ID: 0x1234, Protocol: 6,
		Src: netip.MustParseAddr("93.184.215.14"), Dst: netip.MustParseAddr("192.168.1.10")}
	if h != want {
		t.Errorf("ParseIPv4 header = %+v; want %+v", h, want)
	}
	if len(payload) != 20 {
		t.Errorf("payload length = %d; want 20", len(payload))
	}
}

func TestParseIPv4Options(t *testing.T) {
	// IHL 6: a 24-byte header with 4 bytes of options, then 4 bytes of payload.
	b := mustHex(t, "4600001c00010000400600000a0000010a00000201020304aabbccdd")
	_, payload, err := ParseIPv4(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "\xaa\xbb\xcc\xdd" {
		t.Errorf("payload = %x; want aabbccdd", payload)
	}
}

func TestParseIPv4IgnoresTrailingBytes(t *testing.T) {
	b := append(mustHex(t, rstPacket), 0xde, 0xad) // e.g. Ethernet padding
	_, payload, err := ParseIPv4(b)
	if err != nil || len(payload) != 20 {
		t.Errorf("ParseIPv4 = (%d-byte payload, %v); want 20 bytes, nil", len(payload), err)
	}
}

func TestParseIPv4Errors(t *testing.T) {
	valid := mustHex(t, rstPacket)
	with := func(i int, v byte) []byte {
		c := append([]byte(nil), valid...)
		c[i] = v
		return c
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"19 bytes", valid[:19], ErrTruncated},
		{"IPv6", with(0, 0x65), ErrNotIPv4},
		{"header length below 20", with(0, 0x44), ErrBadHeader},
		{"total length below header", with(3, 10), ErrBadHeader},
		{"total length beyond data", with(3, 60), ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseIPv4(tt.in); !errors.Is(err, tt.want) {
				t.Errorf("ParseIPv4 error = %v; want %v", err, tt.want)
			}
		})
	}
}

func TestParseTCP(t *testing.T) {
	_, payload, err := ParseIPv4(mustHex(t, rstPacket))
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseTCP(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := TCPHeader{SrcPort: 443, DstPort: 50000, Seq: 1, Ack: 0, Flags: FlagRST | FlagACK, Window: 0}
	if h != want {
		t.Errorf("ParseTCP = %+v; want %+v", h, want)
	}
	if h.Flags&FlagSYN != 0 || h.Flags&FlagRST == 0 {
		t.Errorf("flags %#02x: want RST set and SYN clear", h.Flags)
	}
}

func TestParseTCPErrors(t *testing.T) {
	_, valid, err := ParseIPv4(mustHex(t, rstPacket))
	if err != nil {
		t.Fatal(err)
	}
	withOffset := func(words byte) []byte {
		c := append([]byte(nil), valid...)
		c[12] = words << 4
		return c
	}
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"19 bytes", valid[:19]},
		{"data offset below 20", withOffset(4)},
		{"data offset beyond data", withOffset(6)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseTCP(tt.in); !errors.Is(err, ErrTruncated) {
				t.Errorf("ParseTCP error = %v; want ErrTruncated", err)
			}
		})
	}
}

// FuzzParse feeds random bytes through both parsers; neither may panic.
func FuzzParse(f *testing.F) {
	f.Add(mustHexF(f, rstPacket))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, payload, err := ParseIPv4(b)
		if err == nil {
			ParseTCP(payload)
		}
		ParseTCP(b)
	})
}

func mustHexF(f *testing.F, s string) []byte {
	b, err := hexDecode(s)
	if err != nil {
		f.Fatal(err)
	}
	return b
}
