package strategy

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	// defaultDisorderAt is where the registered disorder strategy cuts the
	// payload: after its first byte.
	defaultDisorderAt = 1
	// disorderTTL is the TTL of the first part: with 1 the first router drops
	// it, so it cannot reach the server on any path.
	disorderTTL = 1
	// disorderSettle is how long to wait after the first write before the
	// TTL is restored, so the packet has left the host with the low TTL.
	disorderSettle = 20 * time.Millisecond
)

// disorder makes the second part of the payload reach the server before the
// first: the first is sent with a TTL too low to arrive and the kernel
// retransmits it later.
type disorder struct {
	at  int // length of the first part
	ttl int // TTL of the first part
}

// Name returns "disorder".
func (disorder) Name() string {
	return "disorder"
}

// Apply writes payload[:at] with a low TTL, restores the TTL and writes
// payload[at:]. The first part is lost on the way and arrives after the
// second, when the kernel retransmits it. conn must be a real socket.
func (d disorder) Apply(conn net.Conn, payload []byte) error {
	if d.at < 1 || d.at >= len(payload) {
		return fmt.Errorf("%w: at %d of %d bytes", ErrSplitPoint, d.at, len(payload))
	}

	ip := ipv4.NewConn(conn)

	orig, err := ip.TTL()
	if err != nil {
		return fmt.Errorf("strategy: disorder read ttl: %w", err)
	}

	if err := ip.SetTTL(d.ttl); err != nil {
		return fmt.Errorf("strategy: disorder set ttl: %w", err)
	}

	if _, err := conn.Write(payload[:d.at]); err != nil {
		return fmt.Errorf("strategy: disorder write first part: %w", err)
	}

	time.Sleep(disorderSettle)

	if err := ip.SetTTL(orig); err != nil {
		return fmt.Errorf("strategy: disorder restore ttl: %w", err)
	}

	if _, err := conn.Write(payload[d.at:]); err != nil {
		return fmt.Errorf("strategy: disorder write second part: %w", err)
	}
	return nil
}

func init() { Register(disorder{at: defaultDisorderAt, ttl: disorderTTL}) }
