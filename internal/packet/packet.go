// Package packet parses raw IPv4 and TCP headers and computes the internet
// checksum, for inspecting packets captured from the network.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Errors returned by the parsers.
var (
	ErrTruncated = errors.New("packet: truncated packet")
	ErrNotIPv4   = errors.New("packet: not an IPv4 packet")
	ErrBadHeader = errors.New("packet: invalid header length")
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
