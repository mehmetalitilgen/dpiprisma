package runner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/strategy"
)

func TestPercentile(t *testing.T) {
	ms := func(xs ...int) []time.Duration {
		out := make([]time.Duration, len(xs))
		for i, x := range xs {
			out[i] = time.Duration(x) * time.Millisecond
		}
		return out
	}
	tests := []struct {
		name            string
		in              []time.Duration
		wantP50, want95 time.Duration
	}{
		{"empty", nil, 0, 0},
		{"one", ms(5), 5 * time.Millisecond, 5 * time.Millisecond},
		{"four", ms(1, 2, 3, 4), 2 * time.Millisecond, 4 * time.Millisecond},
		{"ten shuffled", ms(7, 2, 10, 4, 1, 9, 3, 8, 5, 6), 5 * time.Millisecond, 10 * time.Millisecond},
	}
	for _, tt := range tests {
		in := slices.Clone(tt.in)
		if got := percentile(in, 50); got != tt.wantP50 {
			t.Errorf("%s: p50 = %v; want %v", tt.name, got, tt.wantP50)
		}
		if got := percentile(in, 95); got != tt.want95 {
			t.Errorf("%s: p95 = %v; want %v", tt.name, got, tt.want95)
		}
		if !slices.Equal(in, tt.in) {
			t.Errorf("%s: percentile mutated its input: %v", tt.name, in)
		}
	}
}

func TestSuccessRate(t *testing.T) {
	if got := (Result{}).SuccessRate(); got != 0 {
		t.Errorf("empty SuccessRate = %v; want 0", got)
	}
	if got := (Result{Runs: 10, Successes: 7}).SuccessRate(); got != 0.7 {
		t.Errorf("SuccessRate = %v; want 0.7", got)
	}
}

func TestRunValidation(t *testing.T) {
	base, _ := strategy.Get("baseline")
	strategies := []strategy.Strategy{base}
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	good := Options{Timeout: time.Second, RatePerSec: 0}

	cases := []struct {
		name       string
		strategies []strategy.Strategy
		runs       int
		opt        Options
	}{
		{"runs<1", strategies, 0, good},
		{"no strategies", nil, 3, good},
		{"timeout<=0", strategies, 3, Options{Timeout: 0}},
		{"rate<0", strategies, 3, Options{Timeout: time.Second, RatePerSec: -1}},
	}
	for _, c := range cases {
		if _, err := Run(context.Background(), addr, "example.com", c.strategies, c.runs, c.opt); err == nil {
			t.Errorf("%s: Run error = nil; want an error", c.name)
		}
	}
}

// fakeServer accepts TCP connections and answers each with a ServerHello-looking
// record, so a probe classifies it as TLSServerHello.
func fakeServer(t *testing.T) netip.AddrPort {
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.Read(buf) // drain the ClientHello
				c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x3a, 0x02})
			}(c)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestRunAgainstFakeServer(t *testing.T) {
	base, _ := strategy.Get("baseline")
	addr := fakeServer(t)

	results, err := Run(context.Background(), addr, "example.com",
		[]strategy.Strategy{base}, 5, Options{Timeout: 2 * time.Second, RatePerSec: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d; want 1", len(results))
	}
	r := results[0]
	if r.Name != "baseline" || r.Runs != 5 || r.Successes != 5 {
		t.Errorf("result = %+v; want baseline, 5 runs, 5 successes", r)
	}
	if r.SuccessRate() != 1 || len(r.Latencies) != 5 {
		t.Errorf("rate = %v, latencies = %d; want 1.0 and 5", r.SuccessRate(), len(r.Latencies))
	}
}

func TestRunClosedPortFails(t *testing.T) {
	base, _ := strategy.Get("baseline")
	// Reserve a port, then close it so the dial is refused.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()

	results, err := Run(context.Background(), addr, "example.com",
		[]strategy.Strategy{base}, 3, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Successes != 0 {
		t.Errorf("successes = %d; want 0 on a closed port", results[0].Successes)
	}
}

func TestRunCancelled(t *testing.T) {
	base, _ := strategy.Get("baseline")
	addr := fakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := Run(ctx, addr, "example.com", []strategy.Strategy{base}, 5, Options{Timeout: time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run error = %v; want context.Canceled", err)
	}
}
