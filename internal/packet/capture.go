package packet

import (
	"context"
	"fmt"
	"math/rand/v2"
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

// SendSYN sends one TCP SYN to dst with the given IP TTL and returns the
// source address and port it used, so the caller can match replies. Start
// capturing before calling it, or the reply may be missed. It writes a raw
// socket, so it needs root (or CAP_NET_RAW) on Linux.
func SendSYN(dst netip.AddrPort, ttl uint8) (netip.AddrPort, error) {
	// A UDP "dial" sends nothing; it only asks the kernel which local
	// address routes to dst.
	udp, err := net.Dial("udp", dst.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("packet: discover source: %w", err)
	}
	local := udp.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	udp.Close()

	port := uint16(33000 + rand.IntN(60000-33000)) // not crypto: only avoids collisions
	src := netip.AddrPortFrom(local, port)
	tcp := MarshalSYN(src, dst, rand.Uint32())

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("packet: open raw socket: %w", err)
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn) // sets IP_HDRINCL: we write the IP header
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("packet: wrap raw socket: %w", err)
	}

	h := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(tcp),
		TTL:      int(ttl),
		Protocol: 6,
		Src:      src.Addr().AsSlice(),
		Dst:      dst.Addr().AsSlice(),
		// ID and Checksum are left zero; the kernel fills them in.
	}
	if err := rawConn.WriteTo(h, tcp, nil); err != nil {
		return netip.AddrPort{}, fmt.Errorf("packet: send syn: %w", err)
	}

	return src, nil
}

// CaptureTimeExceeded calls handle for every ICMP time exceeded message that
// arrives, until ctx is cancelled. It does not filter by peer: the message
// comes from a router on the path, and OrigDstPort/OrigSeq tell which probe
// it belongs to. It needs root (or CAP_NET_RAW) on Linux.
func CaptureTimeExceeded(ctx context.Context, handle func(TimeExceeded)) error {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("packet: open raw socket: %w", err)
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		return fmt.Errorf("packet: wrap raw socket: %w", err)
	}

	// Close the socket when ctx is cancelled; done stops this goroutine if we
	// return for another reason, so it never leaks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rawConn.Close()
		case <-done:
		}
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

		te, err := ParseTimeExceeded(payload)
		if err != nil {
			continue // ping replies, unreachable messages, ... land here too
		}

		te.Router, _ = netip.AddrFromSlice(h.Src.To4()) // the router is the outer header's source
		te.At = time.Now()
		handle(te)
	}
}
