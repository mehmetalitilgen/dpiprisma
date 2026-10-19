package packet

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Values for TCP_REPAIR_QUEUE, from the Linux kernel enum; x/sys/unix does not
// export them as constants.
const (
	tcpSendQueue = 2 // the send queue
	tcpRecvQueue = 1 // the receive queue
)

// ConnSeq reads the next send sequence number and the next expected
// (acknowledgment) number of a live TCP connection, using Linux's TCP_REPAIR
// mode. It needs CAP_NET_ADMIN (root). conn must be a *net.TCPConn.
func ConnSeq(conn net.Conn) (seq, ack uint32, err error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, 0, errors.New("packet: ConnSeq: conn is not a syscall.Conn")
	}

	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("packet: ConnSeq: %w", err)
	}

	var opErr error
	err = raw.Control(func(fd uintptr) {
		opErr = readRepairSeq(int(fd), &seq, &ack)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("packet: ConnSeq: %w", err)
	}
	if opErr != nil {
		return 0, 0, opErr
	}

	return seq, ack, nil
}

func readRepairSeq(fd int, seq, ack *uint32) error {
	err := unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	if err != nil {
		return fmt.Errorf("packet: enter repair: %w", err)
	}

	defer unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)

	if err := unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue); err != nil {
		return fmt.Errorf("packet: select send queue: %w", err)
	}

	s, err := unix.GetsockoptInt(fd, unix.SOL_TCP, unix.TCP_QUEUE_SEQ)

	if err != nil {
		return fmt.Errorf("packet: read send seq: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_REPAIR_QUEUE, tcpRecvQueue); err != nil {
		return fmt.Errorf("packet: select recv queue: %w", err)
	}
	a, err := unix.GetsockoptInt(fd, unix.SOL_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		return fmt.Errorf("packet: read recv seq: %w", err)
	}

	*seq = uint32(s)
	*ack = uint32(a)

	return nil
}
