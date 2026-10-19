// Package strategy defines the ways a ClientHello can be sent over a TCP
// connection, and a registry to find them by name.
package strategy

import "net"

// Strategy is one way of sending a payload, normally a ClientHello, over a
// connection.
type Strategy interface {
	// Name returns the strategy's short name, e.g. "split". It is the
	// registry key and the name shown in reports.
	Name() string

	// Apply writes payload to conn the way the strategy prescribes.
	Apply(conn net.Conn, payload []byte) error
}
