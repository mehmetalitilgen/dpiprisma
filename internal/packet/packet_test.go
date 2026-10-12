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

// synPacket is the TCP SYN that MarshalSYN builds from 192.168.1.10:50000 to
// 93.184.215.14:443 with sequence number 1 (checksum 0xf96b).
const synPacket = "c35001bb00000001000000005002faf0f96b0000"

// timeExceeded is the ICMP time exceeded message a router sends back for
// synPacket sent with TTL 1: an 8-byte ICMP header, the quoted 20-byte IPv4
// header and the first 8 bytes of the TCP header.
const timeExceeded = "0b002ff30000000045000028123400000106b123c0a8010a5db8d70ec35001bb00000001"

var (
	synSrc = netip.MustParseAddrPort("192.168.1.10:50000")
	synDst = netip.MustParseAddrPort("93.184.215.14:443")
)

func TestMarshalSYN(t *testing.T) {
	got := MarshalSYN(synSrc, synDst, 1)
	if want := mustHex(t, synPacket); string(got) != string(want) {
		t.Errorf("MarshalSYN = %x; want %x", got, want)
	}
}

func TestMarshalSYNRoundTrip(t *testing.T) {
	h, err := ParseTCP(MarshalSYN(synSrc, synDst, 0xdeadbeef))
	if err != nil {
		t.Fatal(err)
	}
	want := TCPHeader{SrcPort: 50000, DstPort: 443, Seq: 0xdeadbeef, Flags: FlagSYN, Window: 64240}
	if h != want {
		t.Errorf("ParseTCP(MarshalSYN(...)) = %+v; want %+v", h, want)
	}
}

func TestTCPChecksum(t *testing.T) {
	syn := mustHex(t, synPacket)
	if got := TCPChecksum(synSrc.Addr(), synDst.Addr(), syn); got != 0 {
		t.Errorf("TCPChecksum over a filled-in segment = %#04x; want 0", got)
	}
	// The pseudo-header binds the checksum to the addresses: the same segment
	// to another destination must not verify.
	other := netip.MustParseAddr("93.184.215.15")
	if got := TCPChecksum(synSrc.Addr(), other, syn); got == 0 {
		t.Error("TCPChecksum verified with the wrong destination address")
	}
	// Odd-length data (a 1-byte payload) is padded, not dropped.
	seg := append(mustHex(t, synPacket), 'x')
	seg[16], seg[17] = 0, 0
	cs := TCPChecksum(synSrc.Addr(), synDst.Addr(), seg)
	seg[16], seg[17] = byte(cs>>8), byte(cs)
	if got := TCPChecksum(synSrc.Addr(), synDst.Addr(), seg); got != 0 {
		t.Errorf("odd-length segment does not verify: %#04x", got)
	}
}

func TestParseTimeExceeded(t *testing.T) {
	te, err := ParseTimeExceeded(mustHex(t, timeExceeded))
	if err != nil {
		t.Fatal(err)
	}
	want := TimeExceeded{OrigSrc: synSrc.Addr(), OrigDst: synDst.Addr(),
		OrigSrcPort: 50000, OrigDstPort: 443, OrigSeq: 1}
	if te != want {
		t.Errorf("ParseTimeExceeded = %+v; want %+v", te, want)
	}
}

func TestParseTimeExceededQuotedOptions(t *testing.T) {
	// The quoted IPv4 header has IHL 6 (4 bytes of options): the TCP bytes
	// start 4 bytes later.
	b := mustHex(t, timeExceeded)
	b = append(b[:28:28], append([]byte{1, 1, 1, 1}, b[28:]...)...)
	b[8] = 0x46
	te, err := ParseTimeExceeded(b)
	if err != nil {
		t.Fatal(err)
	}
	if te.OrigSrcPort != 50000 || te.OrigDstPort != 443 || te.OrigSeq != 1 {
		t.Errorf("ParseTimeExceeded = %+v; want ports 50000→443, seq 1", te)
	}
}

func TestParseTimeExceededErrors(t *testing.T) {
	valid := mustHex(t, timeExceeded)
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
		{"35 bytes", valid[:35], ErrTruncated},
		{"echo reply", with(0, 0), ErrNotTimeExceeded},
		{"destination unreachable", with(0, 3), ErrNotTimeExceeded},
		{"quoted IPv6", with(8, 0x65), ErrNotIPv4},
		{"quoted header length below 20", with(8, 0x44), ErrBadHeader},
		{"quoted options cut off the TCP bytes", with(8, 0x46), ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseTimeExceeded(tt.in); !errors.Is(err, tt.want) {
				t.Errorf("ParseTimeExceeded error = %v; want %v", err, tt.want)
			}
		})
	}
}

// FuzzParse feeds random bytes through every parser; none may panic.
func FuzzParse(f *testing.F) {
	f.Add(mustHexF(f, rstPacket))
	f.Add(mustHexF(f, timeExceeded))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, payload, err := ParseIPv4(b)
		if err == nil {
			ParseTCP(payload)
			ParseTimeExceeded(payload)
		}
		ParseTCP(b)
		ParseTimeExceeded(b)
	})
}

func mustHexF(f *testing.F, s string) []byte {
	b, err := hexDecode(s)
	if err != nil {
		f.Fatal(err)
	}
	return b
}
