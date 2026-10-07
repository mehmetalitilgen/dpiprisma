package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// TCPOutcome is what happened when dialing a TCP address.
type TCPOutcome int

const (
	TCPUnknown   TCPOutcome = iota // the dial failed for another reason
	TCPConnected                   // the handshake completed (SYN, SYN-ACK)
	TCPRefused                     // the SYN was answered with a RST
	TCPTimeout                     // the SYN got no answer: packets are being dropped
)

// TCPResult is the outcome of one TCP probe.
type TCPResult struct {
	Outcome TCPOutcome    // what happened
	Elapsed time.Duration // how long the dial took
	Err     error         // the dial error, if any
}

// tcpOutcomeNames holds the name of each outcome, in the same order as the constants.
var tcpOutcomeNames = [4]string{"unknown", "connected", "refused", "timeout"}

// String returns the outcome name, e.g. "refused".
func (t TCPOutcome) String() string {
	if t < 0 || int(t) >= len(tcpOutcomeNames) {
		return fmt.Sprintf("TCPOutcome(%d)", int(t))
	}
	return tcpOutcomeNames[t]
}

// ProbeTCP dials addr over TCP within timeout and reports how it went. A
// failed dial is a measurement, not an error, so it is part of the result.
func ProbeTCP(ctx context.Context, addr netip.AddrPort, timeout time.Duration) TCPResult {
	newCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(newCtx, "tcp", addr.String())
	elapsed := time.Since(start)

	if err != nil {
		return TCPResult{
			Outcome: classifyDialError(err),
			Elapsed: elapsed,
			Err:     err,
		}
	}

	defer conn.Close()

	return TCPResult{
		Outcome: TCPConnected,
		Elapsed: elapsed,
		Err:     nil,
	}
}

// wsaeconnrefused is Windows' error code for a refused connection; there,
// errors.Is(err, syscall.ECONNREFUSED) does not match it.
const wsaeconnrefused = 10061

// classifyDialError maps a dial error to a TCPOutcome.
func classifyDialError(err error) TCPOutcome {
	if err == nil {
		return TCPUnknown
	}

	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(wsaeconnrefused)) {
		return TCPRefused
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return TCPTimeout
	}

	return TCPUnknown
}
