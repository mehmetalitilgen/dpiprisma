package strategy

import (
	"net"
	"slices"
	"testing"
)

func TestFakeRSTRegistered(t *testing.T) {
	s, err := Get("fakerst")
	if err != nil {
		t.Fatalf("Get(fakerst) error = %v", err)
	}
	if s.Name() != "fakerst" {
		t.Errorf("Name() = %q; want fakerst", s.Name())
	}
	for _, want := range []string{"baseline", "disorder", "fakech", "fakerst", "split"} {
		if !slices.Contains(Names(), want) {
			t.Errorf("Names() = %q; missing %q", Names(), want)
		}
	}
}

// NewFakeRST must return a fakerst, not some other strategy, and clamp the TTL.
func TestNewFakeRST(t *testing.T) {
	s := NewFakeRST(5)
	if s.Name() != "fakerst" {
		t.Fatalf("NewFakeRST(5).Name() = %q; want fakerst", s.Name())
	}
	fr, ok := s.(fakerst)
	if !ok {
		t.Fatalf("NewFakeRST returned %T; want fakerst", s)
	}
	if fr.ttl != 5 {
		t.Errorf("ttl = %d; want 5", fr.ttl)
	}
	for _, ttl := range []int{0, -1, 256} {
		if got := NewFakeRST(ttl).(fakerst).ttl; got != defaultRSTTTL {
			t.Errorf("NewFakeRST(%d).ttl = %d; want default %d", ttl, got, defaultRSTTTL)
		}
	}
}

// With no readable sequence (net.Pipe is not a syscall.Conn on Linux, and
// ConnSeq is unavailable off Linux) Apply must fail before writing anything.
func TestFakeRSTApplyNoSeq(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- fakerst{ttl: 5}.Apply(client, []byte("x")) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Apply succeeded on a net.Pipe; want an error")
		}
	case <-readOrTimeout(t, server):
		t.Fatal("Apply wrote before failing to read the sequence")
	}
}
