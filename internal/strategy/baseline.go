package strategy

import (
	"fmt"
	"net"
)

// baseline sends the payload in one write, unchanged. It is the control
// every other strategy is compared with.
type baseline struct{}

func init() { Register(baseline{}) }

// Name returns "baseline".
func (baseline) Name() string {
	return "baseline"
}

// Apply writes payload to conn in a single write.
func (baseline) Apply(conn net.Conn, payload []byte) error {
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("strategy: baseline write: %w", err)
	}
	return nil
}
