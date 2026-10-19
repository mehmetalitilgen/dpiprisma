package strategy

import (
	"errors"
	"fmt"
	"net"
)

// defaultSplitAt is where the registered split strategy cuts the payload:
// after its first byte.
const defaultSplitAt = 1

// ErrSplitPoint is returned by split.Apply when the split point leaves one
// of the two parts empty.
var ErrSplitPoint = errors.New("strategy: split point outside the payload")

// split sends the payload in two writes, cut after the first at bytes, so a
// middlebox that does not reassemble TCP never sees the whole ClientHello in
// one segment.
type split struct {
	at int
}

// Name returns "split".
func (split) Name() string {
	return "split"
}

// Apply writes payload[:at] and then payload[at:] to conn as two writes, with
// Nagle's algorithm off so each write leaves as its own segment.
func (s split) Apply(conn net.Conn, payload []byte) error {
	if s.at < 1 || s.at >= len(payload) {
		return fmt.Errorf("%w: at %d of %d bytes", ErrSplitPoint, s.at, len(payload))
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			return fmt.Errorf("strategy: split set nodelay: %w", err)
		}
	}

	if _, err := conn.Write(payload[:s.at]); err != nil {
		return fmt.Errorf("strategy: split write first part: %w", err)
	}
	if _, err := conn.Write(payload[s.at:]); err != nil {
		return fmt.Errorf("strategy: split write second part: %w", err)
	}
	return nil
}

func init() { Register(split{at: defaultSplitAt}) }
