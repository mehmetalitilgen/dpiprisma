package strategy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
)

func TestSplitRegistered(t *testing.T) {
	s, err := Get("split")
	if err != nil {
		t.Fatalf("Get(split) error = %v", err)
	}
	if s.Name() != "split" {
		t.Errorf("Name() = %q; want split", s.Name())
	}
	names := Names()
	for _, want := range []string{"baseline", "split"} {
		if !slices.Contains(names, want) {
			t.Errorf("Names() = %q; missing %q", names, want)
		}
	}
}

// readSizes returns the size of every Read the server side needs to drain
// the connection. net.Pipe hands over one Write per Read, so the sizes are
// the sizes of the writes.
func readSizes(t *testing.T, s split, payload []byte) (sizes []int, got []byte, err error) {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()

	errc := make(chan error, 1)
	go func() {
		errc <- s.Apply(client, payload)
		client.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, rerr := server.Read(buf)
		if n > 0 {
			sizes = append(sizes, n)
			got = append(got, buf[:n]...)
		}
		if rerr != nil {
			if rerr != io.EOF {
				t.Fatalf("Read error = %v", rerr)
			}
			break
		}
	}
	return sizes, got, <-errc
}

func TestSplitApply(t *testing.T) {
	payload := []byte("0123456789")
	tests := []struct {
		at   int
		want []int
	}{
		{1, []int{1, 9}},
		{3, []int{3, 7}},
		{9, []int{9, 1}},
	}
	for _, tt := range tests {
		sizes, got, err := readSizes(t, split{at: tt.at}, payload)
		if err != nil {
			t.Errorf("at=%d: Apply error = %v", tt.at, err)
			continue
		}
		if !slices.Equal(sizes, tt.want) {
			t.Errorf("at=%d: reads = %v; want %v", tt.at, sizes, tt.want)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("at=%d: server got %q; want %q", tt.at, got, payload)
		}
	}
}

func TestSplitBadPoint(t *testing.T) {
	payload := []byte("0123456789")
	for _, at := range []int{-1, 0, 10, 11} {
		sizes, _, err := readSizes(t, split{at: at}, payload)
		if !errors.Is(err, ErrSplitPoint) {
			t.Errorf("at=%d: error = %v; want ErrSplitPoint", at, err)
		}
		if len(sizes) != 0 {
			t.Errorf("at=%d: %d reads; nothing should be written", at, len(sizes))
		}
	}

	if _, _, err := readSizes(t, split{at: 1}, nil); !errors.Is(err, ErrSplitPoint) {
		t.Errorf("empty payload: error = %v; want ErrSplitPoint", err)
	}
}

func TestSplitWriteError(t *testing.T) {
	client, server := net.Pipe()
	server.Close() // nobody reads: the first write fails
	defer client.Close()

	err := split{at: 1}.Apply(client, []byte("abc"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Apply error = %v; want it to wrap io.ErrClosedPipe", err)
	}
}

// A real TCP connection takes the SetNoDelay path; the data must still
// arrive whole and in order.
func TestSplitOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		data []byte
		err  error
	}
	resc := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resc <- result{nil, err}
			return
		}
		defer c.Close()
		data, err := io.ReadAll(c)
		resc <- result{data, err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("a pretend ClientHello")
	if err := (split{at: 4}).Apply(conn, payload); err != nil {
		t.Fatalf("Apply error = %v", err)
	}
	conn.Close()

	r := <-resc
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !bytes.Equal(r.data, payload) {
		t.Errorf("server got %q; want %q", r.data, payload)
	}
}
