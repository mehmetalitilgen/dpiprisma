package strategy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// The registry must know baseline without anyone listing it: its own init
// registers it. This is the "a new strategy is a new file" rule.
func TestBaselineRegistered(t *testing.T) {
	s, err := Get("baseline")
	if err != nil {
		t.Fatalf("Get(baseline) error = %v", err)
	}
	if s.Name() != "baseline" {
		t.Errorf("Name() = %q; want baseline", s.Name())
	}
}

func TestBaselineApply(t *testing.T) {
	client, server := net.Pipe() // an in-memory connection pair
	defer server.Close()

	payload := []byte("\x16\x03\x01 a ClientHello")
	errc := make(chan error, 1)
	go func() {
		errc <- baseline{}.Apply(client, payload)
		client.Close()
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("server got %q; want %q", got, payload)
	}
}

func TestBaselineApplyError(t *testing.T) {
	client, server := net.Pipe()
	server.Close() // nobody reads: the write fails
	defer client.Close()

	err := baseline{}.Apply(client, []byte("x"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Apply error = %v; want it to wrap io.ErrClosedPipe", err)
	}
}
