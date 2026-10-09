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
