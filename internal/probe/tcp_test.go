package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestTCPOutcomeString(t *testing.T) {
	tests := []struct {
		o    TCPOutcome
		want string
	}{
		{TCPUnknown, "unknown"},
		{TCPConnected, "connected"},
		{TCPRefused, "refused"},
		{TCPTimeout, "timeout"},
		{TCPOutcome(9), "TCPOutcome(9)"},
		{TCPOutcome(-1), "TCPOutcome(-1)"},
	}
	for _, tt := range tests {
		if got := tt.o.String(); got != tt.want {
			t.Errorf("TCPOutcome(%d).String() = %q; want %q", int(tt.o), got, tt.want)
		}
	}
}

// timeoutError is a net.Error that reports a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want TCPOutcome
	}{
		{"nil", nil, TCPUnknown},
		{"unix refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, TCPRefused},
		{"windows refused", &net.OpError{Op: "dial", Err: syscall.Errno(10061)}, TCPRefused},
		{"timeout", &net.OpError{Op: "dial", Err: timeoutError{}}, TCPTimeout},
		{"other", errors.New("no route to host"), TCPUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDialError(tt.err); got != tt.want {
				t.Errorf("classifyDialError(%v) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestProbeTCPConnected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	got := ProbeTCP(context.Background(), netip.MustParseAddrPort(ln.Addr().String()), 2*time.Second)
	if got.Outcome != TCPConnected || got.Err != nil {
		t.Errorf("ProbeTCP = %+v; want connected without error", got)
	}
}

func TestProbeTCPRefused(t *testing.T) {
	// Open and immediately close a listener to get a port nobody listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()

	got := ProbeTCP(context.Background(), addr, 2*time.Second)
	if got.Outcome != TCPRefused || got.Err == nil {
		t.Errorf("ProbeTCP = %+v; want refused with an error", got)
	}
}

func TestProbeTCPTimeout(t *testing.T) {
	// 10.255.255.1 is not routed anywhere; a 1 ns budget makes the dial time out
	// immediately instead of waiting on the network.
	got := ProbeTCP(context.Background(), netip.MustParseAddrPort("10.255.255.1:443"), time.Nanosecond)
	if got.Outcome != TCPTimeout {
		t.Errorf("ProbeTCP = %+v; want timeout", got)
	}
}
