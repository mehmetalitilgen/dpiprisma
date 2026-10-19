//go:build !linux

package packet

import (
	"errors"
	"net"
)

// ErrNoRepair is returned by ConnSeq on platforms without Linux's TCP_REPAIR.
var ErrNoRepair = errors.New("packet: reading connection sequence numbers needs Linux")

// ConnSeq is not available off Linux.
func ConnSeq(net.Conn) (seq, ack uint32, err error) {
	return 0, 0, ErrNoRepair
}
