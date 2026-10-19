package strategy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mehmetalitilgen/dpiprisma/internal/packet"
	"github.com/mehmetalitilgen/dpiprisma/internal/tlsx"
)

const (
	defaultFakeTTL = 6
	fakeSNI        = "example.com"
)

// fakech sends a harmless decoy ClientHello with a low TTL before the real
// one, so a middlebox that inspects only the first ClientHello sees the
// decoy's SNI while the server, which never gets the decoy, sees the real
// one. It is zapret's "fake" desync and needs root on Linux.
type fakech struct {
	ttl int // TTL of the decoy
}

// NewFakeCH returns a fakech strategy that sends its decoy with the given IP
// TTL, normally one dpiprisma locate reported as reaching the DPI but not the
// server. An out-of-range TTL falls back to the default.
func NewFakeCH(ttl int) Strategy {
	if ttl <= 0 || ttl > 255 {
		ttl = defaultFakeTTL
	}
	return fakech{ttl: ttl}
}

// Name returns "fakech".
func (fakech) Name() string {
	return "fakech"
}

// Apply reads the connection's sequence numbers, sends a decoy ClientHello at
// the same sequence with a low TTL over a raw socket, then writes the real
// payload normally. It needs a Linux TCP socket and root.
func (f fakech) Apply(conn net.Conn, payload []byte) error {
	// 1. Mevcut seq/ack numaralarını oku (Windows'ta ErrNoRepair ile burada biter)
	seq, ack, err := packet.ConnSeq(conn)
	if err != nil {
		return fmt.Errorf("strategy: fakech read seq: %w", err)
	}

	decoy, err := tlsx.BuildClientHello(tlsx.HelloOptions{SNI: fakeSNI})
	if err != nil {
		return fmt.Errorf("strategy: fakech build decoy: %w", err)
	}

	local, remote, err := tcpEndpoints(conn)
	if err != nil {
		return fmt.Errorf("strategy: fakech endpoints: %w", err)
	}

	// 4. Yem için TCP segmentini hazırla
	segment := packet.MarshalData(local, remote, seq, ack, decoy)

	// 5. Düşük TTL ile ham soketten gönder
	ttl := f.ttl
	if ttl < 1 || ttl > 255 {
		ttl = defaultFakeTTL
	}
	if err := packet.SendRawTCP(local, remote, uint8(ttl), segment); err != nil {
		return fmt.Errorf("strategy: fakech send decoy: %w", err)
	}

	// 6. Asıl ClientHello'yu normal bağlantıdan gönder
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("strategy: fakech write real: %w", err)
	}

	// 7.
	return nil
}

func tcpEndpoints(conn net.Conn) (local, remote netip.AddrPort, err error) {
	la, ok1 := conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return local, remote, errors.New("not a TCP connection")
	}
	local = netip.AddrPortFrom(la.AddrPort().Addr().Unmap(), la.AddrPort().Port())
	remote = netip.AddrPortFrom(ra.AddrPort().Addr().Unmap(), ra.AddrPort().Port())
	return local, remote, nil
}

func init() { Register(fakech{ttl: defaultFakeTTL}) }
