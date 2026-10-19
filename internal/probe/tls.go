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
	"golang.org/x/net/ipv4"
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
	Outcome TLSOutcome     // what came back
	Elapsed time.Duration  // time from sending the ClientHello to the answer or error
	Connect time.Duration  // time the TCP handshake took; about one round trip to the server
	Local   netip.AddrPort // local address of the connection, to match captured packets; zero if the dial failed
	Err     error          // the error, if any
}

// EarlyReset reports whether the connection was reset in less than half the
// handshake time. A reset from the server takes at least one round trip, so
// one that comes sooner was injected by a device on the path.
func (r TLSResult) EarlyReset() bool {
	if r.Outcome != TLSReset {
		return false
	}
	if r.Connect == 0 {
		return false // the handshake was never timed
	}
	if r.Elapsed*2 < r.Connect {
		return true
	}
	return false
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
	return ProbeTLSTTL(ctx, addr, sni, timeout, 0)
}

// ProbeTLSTTL is ProbeTLS with the IP TTL set to ttl after the TCP handshake,
// so the ClientHello and every later packet carry it but the handshake does
// not. A ttl of 0 keeps the system default. It needs no root.
func ProbeTLSTTL(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration, ttl uint8) TLSResult {
	return probeWith(ctx, addr, sni, timeout, ttl, func(conn net.Conn, hello []byte) error {
		_, err := conn.Write(hello)
		return err
	})
}

// probeWith is the shared core of every TLS probe: it opens a TCP connection
// to addr, sets ttl on it if nonzero, hands the connection and the freshly
// built ClientHello to send, then reads and classifies the answer within
// timeout. send does the writing, so the caller decides how the ClientHello
// leaves the host; everything around it — dialing, timing, TTL, reading and
// classification — stays the same for every strategy.
func probeWith(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration, ttl uint8, send func(conn net.Conn, hello []byte) error) TLSResult {
	newCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	clientHello, err := tlsx.BuildClientHello(tlsx.HelloOptions{SNI: sni})
	if err != nil {
		return TLSResult{Outcome: TLSUnknown, Err: err}
	}

	dialer := &net.Dialer{}
	dialStart := time.Now()
	conn, err := dialer.DialContext(newCtx, "tcp", addr.String())
	if err != nil {
		return TLSResult{Outcome: TLSDialFailed, Err: err}
	}
	defer conn.Close()

	// Every later return carries the handshake time and the local address.
	res := TLSResult{Connect: time.Since(dialStart)}
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		res.Local = tcpAddr.AddrPort()
	}

	if ttl > 0 {
		if err := ipv4.NewConn(conn).SetTTL(int(ttl)); err != nil {
			res.Outcome, res.Err = TLSUnknown, fmt.Errorf("probe: set TTL: %w", err)
			return res
		}
	}

	if endTime, ok := newCtx.Deadline(); ok {
		conn.SetDeadline(endTime)
	}

	start := time.Now()
	if err := send(conn, clientHello); err != nil {
		res.Outcome, res.Elapsed, res.Err = classifyReadError(err), time.Since(start), err
		return res
	}

	buf := make([]byte, 6) // record header (5) + handshake type (1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		res.Outcome, res.Elapsed, res.Err = classifyReadError(err), time.Since(start), err
		return res
	}
	res.Elapsed = time.Since(start)

	switch {
	case buf[0] == 0x16 && buf[5] == 0x02:
		res.Outcome = TLSServerHello
	case buf[0] == 0x15:
		res.Outcome = TLSAlert
	default:
		res.Outcome = TLSUnknown
	}
	return res
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

// ProbeWith runs the same connect, read and classify flow as ProbeTLS but
// lets send do the writing, so a strategy can shape how the ClientHello leaves
// the host (splitting it, reordering segments, sending a decoy first) while
// the probe still reports what came back. The TTL is left at the system
// default; a strategy that needs a low TTL sets it on the packets it builds.
func ProbeWith(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration, send func(conn net.Conn, hello []byte) error) TLSResult {
	return probeWith(ctx, addr, sni, timeout, 0, send)
}
