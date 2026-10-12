// Package packet parses raw IPv4 and TCP headers and computes the internet
// checksum, for inspecting packets captured from the network.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Errors returned by the parsers.
var (
	ErrTruncated       = errors.New("packet: truncated packet")
	ErrNotIPv4         = errors.New("packet: not an IPv4 packet")
	ErrBadHeader       = errors.New("packet: invalid header length")
	ErrNotTimeExceeded = errors.New("packet: not an ICMP time exceeded message")
)

// IPv4Header holds the IPv4 header fields dpiprisma inspects.
type IPv4Header struct {
	TTL      uint8      // time to live; forged packets often carry an unusual one
	ID       uint16     // identification (IP-ID)
	Protocol uint8      // 6 for TCP, 1 for ICMP
	Src      netip.Addr // source address
	Dst      netip.Addr // destination address
}

// ParseIPv4 parses the IPv4 header at the start of b and returns it with the
// packet's payload. Bytes after the total length (such as padding) are dropped.
func ParseIPv4(b []byte) (IPv4Header, []byte, error) {
	var h IPv4Header

	if len(b) < 20 {
		return h, nil, ErrTruncated
	}

	if b[0]>>4 != 4 {
		return h, nil, ErrNotIPv4
	}

	headerLen := int(b[0]&0x0F) * 4
	if headerLen < 20 {
		return h, nil, ErrBadHeader
	}

	totalLen := int(binary.BigEndian.Uint16(b[2:4]))
	if totalLen < headerLen {
		return h, nil, ErrBadHeader
	}

	if len(b) < totalLen {
		return h, nil, ErrTruncated
	}

	h.ID = binary.BigEndian.Uint16(b[4:6])
	h.TTL = b[8]
	h.Protocol = b[9]
	h.Src = netip.AddrFrom4([4]byte(b[12:16]))
	h.Dst = netip.AddrFrom4([4]byte(b[16:20]))

	return h, b[headerLen:totalLen], nil
}

// Checksum returns the internet checksum of b (RFC 1071), as used in IPv4,
// TCP and ICMP headers.
func Checksum(b []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}

	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8 // an odd last byte is padded with a zero
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16) // fold the carries back in
	}

	return ^uint16(sum)
}

// TCP header flags.
const (
	FlagFIN uint8 = 0x01
	FlagSYN uint8 = 0x02
	FlagRST uint8 = 0x04
	FlagPSH uint8 = 0x08
	FlagACK uint8 = 0x10
)

// TCPHeader holds the TCP header fields dpiprisma inspects.
type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8 // a combination of the Flag constants
	Window  uint16
}

// ParseTCP parses the TCP header at the start of b.
func ParseTCP(b []byte) (TCPHeader, error) {
	var h TCPHeader
	if len(b) < 20 {
		return h, ErrTruncated
	}

	headerLen := int(b[12]>>4) * 4
	if headerLen < 20 || headerLen > len(b) {
		return h, ErrTruncated
	}

	h.SrcPort = binary.BigEndian.Uint16(b[0:2])
	h.DstPort = binary.BigEndian.Uint16(b[2:4])
	h.Seq = binary.BigEndian.Uint32(b[4:8])
	h.Ack = binary.BigEndian.Uint32(b[8:12])
	h.Flags = b[13]
	h.Window = binary.BigEndian.Uint16(b[14:16])

	return h, nil
}

// TCPChecksum returns the TCP checksum of tcp (header plus data, with the
// checksum field zeroed) sent from src to dst. It covers the 12-byte IPv4
// pseudo-header, which is not part of the packet itself.
func TCPChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	buf := make([]byte, 12, 12+len(tcp))

	s, d := src.As4(), dst.As4()
	copy(buf[0:4], s[:])
	copy(buf[4:8], d[:])
	buf[8] = 0
	buf[9] = 6 // protocol: TCP
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(tcp)))

	buf = append(buf, tcp...)
	return Checksum(buf)
}

// MarshalSYN returns a 20-byte TCP SYN header without options, from src to
// dst, with sequence number seq and a valid checksum.
func MarshalSYN(src, dst netip.AddrPort, seq uint32) []byte {
	buf := make([]byte, 20)

	binary.BigEndian.PutUint16(buf[0:2], src.Port())
	binary.BigEndian.PutUint16(buf[2:4], dst.Port())
	binary.BigEndian.PutUint32(buf[4:8], seq)
	// bytes 8-11: ack stays zero in a SYN
	buf[12] = 5 << 4 // header length: 5 words = 20 bytes
	buf[13] = FlagSYN
	binary.BigEndian.PutUint16(buf[14:16], 64240) // a common Linux window, so we do not stand out

	cs := TCPChecksum(src.Addr(), dst.Addr(), buf)
	binary.BigEndian.PutUint16(buf[16:18], cs)
	// bytes 18-19: urgent pointer stays zero

	return buf
}

// TimeExceeded is an ICMP time exceeded message: a router dropped one of our
// packets because its TTL ran out.
type TimeExceeded struct {
	Router      netip.Addr // the hop that dropped the packet; set by the caller
	OrigSrc     netip.Addr // source of the dropped packet
	OrigDst     netip.Addr // destination of the dropped packet
	OrigSrcPort uint16
	OrigDstPort uint16
	OrigSeq     uint32
	At          time.Time // when the message arrived; set by the caller
}

// ParseTimeExceeded parses the ICMP message b (the payload of the outer IPv4
// packet). The quoted packet holds only its IPv4 header and the first 8 bytes
// of TCP, so it is read at fixed offsets instead of with ParseIPv4/ParseTCP.
func ParseTimeExceeded(b []byte) (TimeExceeded, error) {
	var t TimeExceeded

	if len(b) < 8+20+8 {
		return t, ErrTruncated
	}
	if b[0] != 11 {
		return t, ErrNotTimeExceeded
	}

	// The quoted IPv4 header starts after the 8-byte ICMP header.
	if b[8]>>4 != 4 {
		return t, ErrNotIPv4
	}
	hLen := int(b[8]&0x0f) * 4
	if hLen < 20 {
		return t, ErrBadHeader
	}
	t.OrigSrc = netip.AddrFrom4([4]byte(b[8+12 : 8+16]))
	t.OrigDst = netip.AddrFrom4([4]byte(b[8+16 : 8+20]))

	tcpStart := 8 + hLen
	if len(b) < tcpStart+8 {
		return TimeExceeded{}, ErrTruncated
	}
	tcp := b[tcpStart:]
	t.OrigSrcPort = binary.BigEndian.Uint16(tcp[0:2])
	t.OrigDstPort = binary.BigEndian.Uint16(tcp[2:4])
	t.OrigSeq = binary.BigEndian.Uint32(tcp[4:8])

	return t, nil
}
