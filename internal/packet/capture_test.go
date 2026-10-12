package packet

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestFlagNames(t *testing.T) {
	tests := []struct {
		f    uint8
		want string
	}{
		{0, "-"},
		{FlagSYN, "SYN"},
		{FlagSYN | FlagACK, "SYN|ACK"},
		{FlagRST, "RST"},
		{FlagRST | FlagACK, "RST|ACK"},
		{FlagPSH | FlagACK, "PSH|ACK"},
		{FlagFIN | FlagSYN | FlagRST | FlagPSH | FlagACK, "FIN|SYN|RST|PSH|ACK"},
	}
	for _, tt := range tests {
		if got := FlagNames(tt.f); got != tt.want {
			t.Errorf("FlagNames(%#02x) = %q; want %q", tt.f, got, tt.want)
		}
	}
}

// TestCaptureTCPLoopback needs root on Linux: it captures the SYN-ACK of a
// connection to a local listener. Run it with:
//
//	go test -c -o packet.test ./internal/packet && sudo ./packet.test -test.run Capture -test.v
func TestCaptureTCPLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (raw sockets)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make(chan Captured, 16)
	errc := make(chan error, 1)
	go func() {
		errc <- CaptureTCP(ctx, netip.MustParseAddr("127.0.0.1"), func(c Captured) {
			select {
			case got <- c:
			default:
			}
		})
	}()
	time.Sleep(200 * time.Millisecond) // let the raw socket open

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	for {
		select {
		case c := <-got:
			if c.TCP.SrcPort == port && c.TCP.Flags == FlagSYN|FlagACK {
				if c.IP.TTL == 0 {
					t.Errorf("SYN-ACK has TTL 0")
				}
				cancel()
				if err := <-errc; err != nil {
					t.Errorf("CaptureTCP returned %v after cancel; want nil", err)
				}
				return
			}
		case err := <-errc:
			t.Fatalf("CaptureTCP stopped early: %v", err)
		case <-ctx.Done():
			t.Fatal("no SYN-ACK captured within 3s")
		}
	}
}

// TestSendSYNLoopback needs root on Linux: it sends a SYN built by SendSYN to
// a local listener and expects the kernel to answer with a SYN-ACK, which it
// only does if the IPv4 header and the TCP checksum are valid. Run it with the
// same command as TestCaptureTCPLoopback.
func TestSendSYNLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (raw sockets)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dst := netip.MustParseAddrPort(ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make(chan Captured, 16)
	errc := make(chan error, 1)
	go func() {
		errc <- CaptureTCP(ctx, dst.Addr(), func(c Captured) {
			select {
			case got <- c:
			default:
			}
		})
	}()
	time.Sleep(200 * time.Millisecond) // let the raw socket open

	src, err := SendSYN(dst, 64)
	if err != nil {
		t.Fatal(err)
	}
	if src.Addr() != dst.Addr() {
		t.Errorf("SendSYN source = %v; want %v (the loopback route)", src.Addr(), dst.Addr())
	}

	for {
		select {
		case c := <-got:
			// Our own SYN comes from 127.0.0.1 too; wait for the answer to it.
			if c.TCP.SrcPort == dst.Port() && c.TCP.DstPort == src.Port() {
				if c.TCP.Flags != FlagSYN|FlagACK {
					t.Errorf("reply flags = %s; want SYN|ACK", FlagNames(c.TCP.Flags))
				}
				return
			}
		case err := <-errc:
			t.Fatalf("CaptureTCP stopped early: %v", err)
		case <-ctx.Done():
			t.Fatal("no SYN-ACK within 3s: the kernel dropped our SYN")
		}
	}
}

// TestCaptureTimeExceededCancel needs root on Linux: CaptureTimeExceeded must
// return nil, not an error, when its context is cancelled.
func TestCaptureTimeExceededCancel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (raw sockets)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- CaptureTimeExceeded(ctx, func(TimeExceeded) {}) }()
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("CaptureTimeExceeded returned %v after cancel; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CaptureTimeExceeded did not return after cancel")
	}
}
