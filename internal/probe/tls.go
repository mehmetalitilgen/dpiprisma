package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/tlsx"
)

// TLSOutcome is how a server, or something on the path, answered a ClientHello.
type TLSOutcome int

const (
	TLSUnknown     TLSOutcome = iota // an unexpected answer or error
	TLSDialFailed                    // the TCP connection could not be opened
	TLSServerHello                   // the server answered with a ServerHello
	TLSAlert                         // the server answered with an alert (e.g. unknown SNI)
	TLSReset                         // the connection was reset after the ClientHello
	TLSTimeout                       // no answer arrived in time
	TLSClosed                        // the connection was closed without an answer
)

// tlsOutcomeNames holds the name of each outcome, in the same order as the constants.
var tlsOutcomeNames = [...]string{"unknown", "dial_failed", "server_hello", "alert", "reset", "timeout", "closed"}

// String returns the outcome name, e.g. "server_hello".
func (t TLSOutcome) String() string {
	if t < 0 || int(t) >= len(tlsOutcomeNames) {
		return fmt.Sprintf("TLSOutcome(%d)", int(t))
	}
	return tlsOutcomeNames[t]
}

// Answered reports whether the server itself replied (with a ServerHello or
// an alert). A server that rejects an SNI still answers; a block does not.
func (t TLSOutcome) Answered() bool {
	return t == TLSServerHello || t == TLSAlert
}

// TLSResult is the outcome of one TLS probe.
type TLSResult struct {
	Outcome TLSOutcome    // what came back
	Elapsed time.Duration // time from sending the ClientHello to the answer or error
	Err     error         // the error, if any
}

// wsaeconnreset is Windows' error code for a reset connection; there,
// errors.Is(err, syscall.ECONNRESET) does not match it.
const wsaeconnreset = 10054

// classifyReadError maps an error from writing the ClientHello or reading the
// answer to a TLSOutcome.
func classifyReadError(err error) TLSOutcome {
	if err == nil {
		return TLSUnknown
	}

	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.Errno(wsaeconnreset)) {
		return TLSReset
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return TLSTimeout
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return TLSClosed
	}

	return TLSUnknown
}

// ProbeTLS opens a TCP connection to addr, sends a ClientHello for sni and
// reports what came back within timeout.
func ProbeTLS(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration) TLSResult {
	newCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	clientHello, err := tlsx.BuildClientHello(tlsx.HelloOptions{SNI: sni})
	if err != nil {
		return TLSResult{Outcome: TLSUnknown, Err: err}
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(newCtx, "tcp", addr.String())
	if err != nil {
		return TLSResult{Outcome: TLSDialFailed, Err: err}
	}
	defer conn.Close()

	if endTime, ok := newCtx.Deadline(); ok {
		conn.SetDeadline(endTime)
	}

	start := time.Now()
	if _, err := conn.Write(clientHello); err != nil {
		return TLSResult{Outcome: classifyReadError(err), Elapsed: time.Since(start), Err: err}
	}

	buf := make([]byte, 6) // record header (5) + handshake type (1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return TLSResult{Outcome: classifyReadError(err), Elapsed: time.Since(start), Err: err}
	}
	elapsed := time.Since(start)

	switch {
	case buf[0] == 0x16 && buf[5] == 0x02:
		return TLSResult{Outcome: TLSServerHello, Elapsed: elapsed}
	case buf[0] == 0x15:
		return TLSResult{Outcome: TLSAlert, Elapsed: elapsed}
	default:
		return TLSResult{Outcome: TLSUnknown, Elapsed: elapsed}
	}
}

// controlSNI is the harmless name sent as the control in CompareSNI.
const controlSNI = "example.com"

// SNIComparison is the result of probing one address with a control SNI and
// a target SNI.
type SNIComparison struct {
	Control TLSResult // the answer to controlSNI
	Target  TLSResult // the answer to the probed SNI
	Blocked bool      // the control got an answer but the target did not
}

// CompareSNI sends the control ClientHello first, then one for sni, to the
// same address. Only the SNI differs, so a control that is answered and a
// target that is not points at SNI-based blocking.
func CompareSNI(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration) SNIComparison {
	controlResult := ProbeTLS(ctx, addr, controlSNI, timeout)
	targetResult := ProbeTLS(ctx, addr, sni, timeout)

	return SNIComparison{
		Control: controlResult,
		Target:  targetResult,
		Blocked: controlResult.Outcome.Answered() && !targetResult.Outcome.Answered(),
	}
}
