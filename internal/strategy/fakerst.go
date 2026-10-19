package strategy

import (
	"fmt"
	"net"

	"github.com/mehmetalitilgen/dpiprisma/internal/packet"
)

// defaultRSTTTL is the TTL of the registered fakerst's spoofed RST: high
// enough to reach the DPI, low enough to die before the server.
const defaultRSTTTL = 6

// fakerst sends a spoofed RST with a low TTL after the real ClientHello, so an
// on-path middlebox believes the connection closed and stops tracking it while
// the server, which never sees the RST, keeps it open. It needs root on Linux.
type fakerst struct {
	ttl int // TTL of the spoofed RST
}

// NewFakeRST returns a fakerst strategy that sends its RST with the given IP
// TTL, normally one dpiprisma locate reported as reaching the DPI but not the
// server. An out-of-range TTL falls back to the default.
func NewFakeRST(ttl int) Strategy {
	if ttl <= 0 || ttl > 255 {
		ttl = defaultRSTTTL
	}
	return fakerst{ttl: ttl}
}

// Name returns "fakerst".
func (fakerst) Name() string {
	return "fakerst"
}

// Apply writes the real payload, then sends a spoofed RST at the next sequence
// number with a low TTL over a raw socket. It needs a Linux TCP socket and root.
func (f fakerst) Apply(conn net.Conn, payload []byte) error {
	seq, ack, err := packet.ConnSeq(conn)
	if err != nil {
		return fmt.Errorf("strategy: fakerst read seq: %w", err)
	}

	local, remote, err := tcpEndpoints(conn)
	if err != nil {
		return fmt.Errorf("strategy: fakerst endpoints: %w", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("strategy: fakerst write real: %w", err)
	}

	rstSeq := seq + uint32(len(payload))
	segment := packet.MarshalRST(local, remote, rstSeq, ack)

	ttl := f.ttl
	if ttl < 1 || ttl > 255 {
		ttl = defaultRSTTTL
	}
	if err := packet.SendRawTCP(local, remote, uint8(ttl), segment); err != nil {
		return fmt.Errorf("strategy: fakerst send rst: %w", err)
	}

	return nil
}

func init() { Register(fakerst{ttl: defaultRSTTTL}) }
