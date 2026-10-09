package packet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

// Captured is one TCP packet seen on a raw socket.
type Captured struct {
	IP  IPv4Header
	TCP TCPHeader
	At  time.Time
}

// CaptureTCP calls handle for every TCP packet that arrives from peer, until
// ctx is cancelled. It reads a raw socket, so it needs root (or CAP_NET_RAW)
// on Linux and does not work on Windows.
func CaptureTCP(ctx context.Context, peer netip.Addr, handle func(Captured)) error {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")

	if err != nil {
		return fmt.Errorf("packet: open raw socket: %w", err)
	}

	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)

	if err != nil {
		return fmt.Errorf("packet: wrap raw socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		rawConn.Close()
	}()

	buf := make([]byte, 65535)

	for {
		h, payload, _, err := rawConn.ReadFrom(buf)

		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("packet: read: %w", err)
		}

		src, ok := netip.AddrFromSlice(h.Src.To4())

		if !ok || src != peer {
			continue
		}

		tcp, err := ParseTCP(payload)

		if err != nil {
			continue
		}

		dst, _ := netip.AddrFromSlice(h.Dst.To4())

		handle(Captured{
			IP: IPv4Header{
				TTL:      uint8(h.TTL),
				ID:       uint16(h.ID),
				Protocol: uint8(h.Protocol),
				Src:      src,
				Dst:      dst,
			},
			TCP: tcp,
			At:  time.Now(),
		})
	}

}

// FlagNames writes TCP flags as "SYN|ACK"-style text, or "-" if none is set.
func FlagNames(f uint8) string {
	var parts []string

	if f&FlagFIN != 0 {
		parts = append(parts, "FIN")
	}
	if f&FlagSYN != 0 {
		parts = append(parts, "SYN")
	}
	if f&FlagRST != 0 {
		parts = append(parts, "RST")
	}
	if f&FlagPSH != 0 {
		parts = append(parts, "PSH")
	}
	if f&FlagACK != 0 {
		parts = append(parts, "ACK")
	}

	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "|")
}
