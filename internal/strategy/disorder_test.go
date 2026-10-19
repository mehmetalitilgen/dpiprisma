package strategy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/ipv4"
)

func TestDisorderRegistered(t *testing.T) {
	s, err := Get("disorder")
	if err != nil {
		t.Fatalf("Get(disorder) error = %v", err)
	}
	if s.Name() != "disorder" {
		t.Errorf("Name() = %q; want disorder", s.Name())
	}
	want := []string{"baseline", "disorder", "split"}
	got := Names()
	for _, name := range want {
		if !slices.Contains(got, name) {
			t.Errorf("Names() = %q; missing %q", got, name)
		}
	}
}

// tcpPair returns both ends of a real TCP connection on loopback.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("Accept failed")
	}
	return client, server
}

// On loopback no router drops the first part, so the data arrives whole and
// in order; the test also checks the TTL is back to what it was.
func TestDisorderApplyOverTCP(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	before, err := ipv4.NewConn(client).TTL()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("a pretend ClientHello")
	if err := (disorder{at: 4, ttl: 1}).Apply(client, payload); err != nil {
		t.Fatalf("Apply error = %v", err)
	}

	after, err := ipv4.NewConn(client).TTL()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("TTL after Apply = %d; want the original %d", after, before)
	}
	client.Close()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("server got %q; want %q", got, payload)
	}
}

func TestDisorderBadPoint(t *testing.T) {
	payload := []byte("0123456789")
	for _, at := range []int{-1, 0, 10, 11} {
		client, server := tcpPair(t)
		err := disorder{at: at, ttl: 1}.Apply(client, payload)
		if !errors.Is(err, ErrSplitPoint) {
			t.Errorf("at=%d: error = %v; want ErrSplitPoint", at, err)
		}
		client.Close()
		got, _ := io.ReadAll(server)
		if len(got) != 0 {
			t.Errorf("at=%d: server got %q; nothing should be written", at, got)
		}
		server.Close()
	}
}

// net.Pipe has no socket, so the TTL cannot be read: Apply must fail before
// anything is written.
func TestDisorderNoSocket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	err := disorder{at: 1, ttl: 1}.Apply(client, []byte("abc"))
	if err == nil {
		t.Fatal("Apply on a net.Pipe succeeded; want an error")
	}
}
