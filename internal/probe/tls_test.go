package probe

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/tlsx"
)

func TestTLSOutcomeString(t *testing.T) {
	tests := []struct {
		o    TLSOutcome
		want string
	}{
		{TLSUnknown, "unknown"},
		{TLSDialFailed, "dial_failed"},
		{TLSServerHello, "server_hello"},
		{TLSAlert, "alert"},
		{TLSReset, "reset"},
		{TLSTimeout, "timeout"},
		{TLSClosed, "closed"},
		{TLSOutcome(42), "TLSOutcome(42)"},
	}
	for _, tt := range tests {
		if got := tt.o.String(); got != tt.want {
			t.Errorf("TLSOutcome(%d).String() = %q; want %q", int(tt.o), got, tt.want)
		}
	}
}

func TestTLSOutcomeAnswered(t *testing.T) {
	answered := map[TLSOutcome]bool{TLSServerHello: true, TLSAlert: true}
	for o := TLSUnknown; o <= TLSClosed; o++ {
		if got := o.Answered(); got != answered[o] {
			t.Errorf("%v.Answered() = %v; want %v", o, got, answered[o])
		}
	}
}

func TestClassifyReadError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want TLSOutcome
	}{
		{"nil", nil, TLSUnknown},
		{"unix reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, TLSReset},
		{"windows reset", &net.OpError{Op: "read", Err: syscall.Errno(10054)}, TLSReset},
		{"timeout", &net.OpError{Op: "read", Err: timeoutError{}}, TLSTimeout},
		{"eof", io.EOF, TLSClosed},
		{"unexpected eof", io.ErrUnexpectedEOF, TLSClosed},
		{"other", errors.New("something else"), TLSUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyReadError(tt.err); got != tt.want {
				t.Errorf("classifyReadError(%v) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

// fakeServerHello is the start of a ServerHello record: enough for ProbeTLS.
var fakeServerHello = []byte{0x16, 0x03, 0x03, 0x00, 0x7a, 0x02}

// tcpServer starts a listener on localhost and runs handle for every
// connection after reading the client's first record.
func tcpServer(t *testing.T, handle func(c *net.TCPConn, firstRecord []byte)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				handle(c.(*net.TCPConn), buf[:n])
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func reset(c *net.TCPConn) { c.SetLinger(0) } // the deferred Close then sends a RST

func TestProbeTLS(t *testing.T) {
	realTLS := httptest.NewUnstartedServer(http.NotFoundHandler())
	realTLS.Config.ErrorLog = log.New(io.Discard, "", 0)
	realTLS.StartTLS()
	t.Cleanup(realTLS.Close)

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := netip.MustParseAddrPort(closedLn.Addr().String())
	closedLn.Close()

	tests := []struct {
		name    string
		addr    netip.AddrPort
		timeout time.Duration
		want    TLSOutcome
	}{
		{"real TLS server", netip.MustParseAddrPort(realTLS.Listener.Addr().String()), 2 * time.Second, TLSServerHello},
		{"alert", tcpServer(t, func(c *net.TCPConn, _ []byte) { c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) }), 2 * time.Second, TLSAlert},
		{"reset", tcpServer(t, func(c *net.TCPConn, _ []byte) { reset(c) }), 2 * time.Second, TLSReset},
		{"silent", tcpServer(t, func(c *net.TCPConn, _ []byte) { time.Sleep(time.Second) }), 200 * time.Millisecond, TLSTimeout},
		{"closed", tcpServer(t, func(c *net.TCPConn, _ []byte) {}), 2 * time.Second, TLSClosed},
		{"garbage", tcpServer(t, func(c *net.TCPConn, _ []byte) { c.Write([]byte("HTTP/1.")) }), 2 * time.Second, TLSUnknown},
		{"nobody listening", closedAddr, 2 * time.Second, TLSDialFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProbeTLS(context.Background(), tt.addr, "example.com", tt.timeout)
			if got.Outcome != tt.want {
				t.Errorf("ProbeTLS = %v (err %v); want %v", got.Outcome, got.Err, tt.want)
			}
		})
	}
}

func TestProbeTLSEmptySNI(t *testing.T) {
	got := ProbeTLS(context.Background(), netip.MustParseAddrPort("127.0.0.1:1"), "", time.Second)
	if got.Outcome != TLSUnknown || !errors.Is(got.Err, tlsx.ErrEmptySNI) {
		t.Errorf("ProbeTLS with empty SNI = %+v; want unknown with ErrEmptySNI", got)
	}
}

// TestProbeTLSElapsed checks that Elapsed measures the wait for the answer.
func TestProbeTLSElapsed(t *testing.T) {
	const delay = 50 * time.Millisecond
	addr := tcpServer(t, func(c *net.TCPConn, _ []byte) {
		time.Sleep(delay)
		c.Write(fakeServerHello)
	})
	got := ProbeTLS(context.Background(), addr, "example.com", 2*time.Second)
	if got.Outcome != TLSServerHello {
		t.Fatalf("ProbeTLS = %v; want server_hello", got.Outcome)
	}
	if got.Elapsed < delay || got.Elapsed > time.Second {
		t.Errorf("Elapsed = %v; want between %v and 1s", got.Elapsed, delay)
	}
}

// sniFilter acts like a DPI box: it resets connections whose ClientHello
// carries blockedSNI, rejects unknownSNI with an alert, and answers
// everything else with a ServerHello.
func sniFilter(t *testing.T, blockedSNI, unknownSNI string) netip.AddrPort {
	return tcpServer(t, func(c *net.TCPConn, first []byte) {
		switch sni, _ := tlsx.ParseSNI(first); sni {
		case blockedSNI:
			reset(c)
		case unknownSNI:
			c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28})
		default:
			c.Write(fakeServerHello)
		}
	})
}

func TestCompareSNI(t *testing.T) {
	addr := sniFilter(t, "blocked.example", "other.example")

	tests := []struct {
		sni         string
		wantTarget  TLSOutcome
		wantBlocked bool
	}{
		{"example.com", TLSServerHello, false},
		{"other.example", TLSAlert, false}, // the server refused it: not a block
		{"blocked.example", TLSReset, true},
	}
	for _, tt := range tests {
		t.Run(tt.sni, func(t *testing.T) {
			got := CompareSNI(context.Background(), addr, tt.sni, 2*time.Second)
			if got.Control.Outcome != TLSServerHello {
				t.Fatalf("Control = %v; want server_hello", got.Control.Outcome)
			}
			if got.Target.Outcome != tt.wantTarget || got.Blocked != tt.wantBlocked {
				t.Errorf("Target = %v, Blocked = %v; want %v, %v", got.Target.Outcome, got.Blocked, tt.wantTarget, tt.wantBlocked)
			}
		})
	}
}
