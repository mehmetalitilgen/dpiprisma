package strategy

import (
	"net"
	"slices"
	"testing"
)

func TestFakeCHRegistered(t *testing.T) {
	s, err := Get("fakech")
	if err != nil {
		t.Fatalf("Get(fakech) error = %v", err)
	}
	if s.Name() != "fakech" {
		t.Errorf("Name() = %q; want fakech", s.Name())
	}
	for _, want := range []string{"baseline", "disorder", "fakech", "split"} {
		if !slices.Contains(Names(), want) {
			t.Errorf("Names() = %q; missing %q", Names(), want)
		}
	}
}

// An out-of-range TTL must fall back to the default rather than produce a
// broken IP packet.
func TestNewFakeCHClampsTTL(t *testing.T) {
	for _, ttl := range []int{0, -1, 256, 9999} {
		if got := NewFakeCH(ttl).(fakech).ttl; got != defaultFakeTTL {
			t.Errorf("NewFakeCH(%d).ttl = %d; want default %d", ttl, got, defaultFakeTTL)
		}
	}
	if got := NewFakeCH(5).(fakech).ttl; got != 5 {
		t.Errorf("NewFakeCH(5).ttl = %d; want 5", got)
	}
}

// Apply must fail before sending anything when it cannot read the sequence
// numbers: a net.Pipe is not a syscall.Conn on Linux, and off Linux ConnSeq is
// unavailable. Either way nothing should reach the wire.
func TestFakeCHApplyNoSeq(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- fakech{ttl: 5}.Apply(client, []byte("x")) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Apply succeeded on a net.Pipe; want an error")
		}
	case <-readOrTimeout(t, server):
		t.Fatal("Apply wrote to the connection before failing to read the sequence")
	}
}

// readOrTimeout returns a channel that fires if the server side receives any
// byte within a short window. If Apply fails early (the intended path), nothing
// arrives and the channel never fires.
func readOrTimeout(t *testing.T, c net.Conn) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			close(ch)
		}
	}()
	return ch
}
