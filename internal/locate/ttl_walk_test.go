package locate

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
)

// fakeProber answers from a table instead of the network: hops[ttl] is the
// answer for that TTL (a missing entry is a silent hop) and errs[ttl] its error.
type fakeProber struct {
	hops  map[int]Hop
	errs  map[int]error
	calls []int // TTLs probed, in order

	// onProbe, if set, runs at the start of every Probe call.
	onProbe func(ttl int)
}

func (f *fakeProber) Probe(ctx context.Context, ttl int) (Hop, error) {
	f.calls = append(f.calls, ttl)
	if f.onProbe != nil {
		f.onProbe(ttl)
	}
	return f.hops[ttl], f.errs[ttl]
}

func answer(addr string) Hop { return Hop{Router: netip.MustParseAddr(addr)} }

func target(addr string) Hop {
	h := answer(addr)
	h.Reached = true
	return h
}

// summary writes hops as "1:192.168.1.1 2:* 3:1.1.1.1!" ("!" marks Reached),
// so a failing test shows the whole walk at a glance.
func summary(hops []Hop) string {
	s := ""
	for i, h := range hops {
		if i > 0 {
			s += " "
		}
		switch {
		case h.Silent():
			s += strconv.Itoa(h.TTL) + ":*"
		case h.Reached:
			s += strconv.Itoa(h.TTL) + ":" + h.Router.String() + "!"
		default:
			s += strconv.Itoa(h.TTL) + ":" + h.Router.String()
		}
	}
	return s
}

func TestHopSilent(t *testing.T) {
	if !(Hop{}).Silent() {
		t.Error("zero Hop is not Silent")
	}
	if answer("192.168.1.1").Silent() {
		t.Error("Hop with a Router is Silent")
	}
}

func TestWalk(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		hops      map[int]Hop
		errs      map[int]error
		opt       WalkOptions
		want      string
		wantErr   error
		wantCalls int
	}{
		{
			name: "stops at the target",
			hops: map[int]Hop{1: answer("192.168.1.1"), 3: answer("172.25.35.154"),
				4: target("1.1.1.1"), 5: answer("9.9.9.9")},
			want:      "1:192.168.1.1 2:* 3:172.25.35.154 4:1.1.1.1!",
			wantCalls: 4,
		},
		{
			name:      "stops after MaxSilent quiet hops in a row",
			hops:      map[int]Hop{1: answer("192.168.1.1")},
			opt:       WalkOptions{MaxSilent: 3},
			want:      "1:192.168.1.1 2:* 3:* 4:*",
			wantCalls: 4,
		},
		{
			name:      "MaxSilent defaults to 5",
			want:      "1:* 2:* 3:* 4:* 5:*",
			wantCalls: 5,
		},
		{
			name: "an answer resets the silence count",
			hops: map[int]Hop{3: answer("10.0.0.3"), 6: target("1.1.1.1")},
			opt:  WalkOptions{MaxSilent: 3},
			// two silent, an answer, two silent, the target: never 3 in a row
			want:      "1:* 2:* 3:10.0.0.3 4:* 5:* 6:1.1.1.1!",
			wantCalls: 6,
		},
		{
			name:      "MaxTTL limits the walk",
			hops:      everyTTL(answer("10.0.0.1")),
			opt:       WalkOptions{MaxTTL: 3},
			want:      "1:10.0.0.1 2:10.0.0.1 3:10.0.0.1",
			wantCalls: 3,
		},
		{
			name:    "a probe error returns the hops so far",
			hops:    map[int]Hop{1: answer("192.168.1.1")},
			errs:    map[int]error{2: boom},
			want:    "1:192.168.1.1",
			wantErr: boom,
			// the failed probe was sent, but it is not a hop
			wantCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeProber{hops: tt.hops, errs: tt.errs}
			hops, err := Walk(context.Background(), f, tt.opt)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Walk error = %v; want %v", err, tt.wantErr)
			}
			if got := summary(hops); got != tt.want {
				t.Errorf("Walk hops = %s\n                 want %s", got, tt.want)
			}
			if len(f.calls) != tt.wantCalls {
				t.Errorf("Walk sent %d probes %v; want %d", len(f.calls), f.calls, tt.wantCalls)
			}
		})
	}
}

func everyTTL(h Hop) map[int]Hop {
	m := make(map[int]Hop)
	for ttl := 1; ttl <= 255; ttl++ {
		m[ttl] = h
	}
	return m
}

func TestWalkMaxTTLDefaultsTo30(t *testing.T) {
	f := &fakeProber{hops: everyTTL(answer("10.0.0.1"))}
	hops, err := Walk(context.Background(), f, WalkOptions{})
	if err != nil || len(hops) != 30 {
		t.Errorf("Walk = %d hops, %v; want 30, nil", len(hops), err)
	}
}

func TestWalkBadTTL(t *testing.T) {
	for _, max := range []int{-1, 256} {
		f := &fakeProber{}
		hops, err := Walk(context.Background(), f, WalkOptions{MaxTTL: max})
		if !errors.Is(err, ErrBadTTL) || hops != nil || len(f.calls) != 0 {
			t.Errorf("MaxTTL %d: Walk = %v, %v, %d probes; want nil, ErrBadTTL, 0",
				max, hops, err, len(f.calls))
		}
	}
	f := &fakeProber{hops: everyTTL(answer("10.0.0.1"))}
	if hops, err := Walk(context.Background(), f, WalkOptions{MaxTTL: 255}); err != nil || len(hops) != 255 {
		t.Errorf("MaxTTL 255: Walk = %d hops, %v; want 255, nil", len(hops), err)
	}
}

// The TTL in a Hop comes from Walk, not from the prober.
func TestWalkSetsTTL(t *testing.T) {
	wrong := answer("10.0.0.1")
	wrong.TTL = 99
	f := &fakeProber{hops: map[int]Hop{1: wrong, 2: target("1.1.1.1")}}
	hops, _ := Walk(context.Background(), f, WalkOptions{})
	if len(hops) != 2 || hops[0].TTL != 1 || hops[1].TTL != 2 {
		t.Errorf("Walk hops = %s; want TTLs 1 and 2", summary(hops))
	}
}

func TestWalkCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeProber{}
	hops, err := Walk(ctx, f, WalkOptions{})
	if !errors.Is(err, context.Canceled) || len(hops) != 0 || len(f.calls) != 0 {
		t.Errorf("Walk = %d hops, %v, %d probes; want 0, context.Canceled, 0",
			len(hops), err, len(f.calls))
	}
}

// Ctrl+C during the pause between probes must end the walk at once.
func TestWalkCancelledDuringGap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeProber{hops: everyTTL(answer("10.0.0.1"))}
	f.onProbe = func(ttl int) {
		if ttl == 1 {
			time.AfterFunc(50*time.Millisecond, cancel) // fires while Walk waits for TTL 2
		}
	}
	start := time.Now()
	hops, err := Walk(ctx, f, WalkOptions{Gap: 10 * time.Second})
	if time.Since(start) > 5*time.Second {
		t.Fatal("Walk kept sleeping after cancel")
	}
	if !errors.Is(err, context.Canceled) || summary(hops) != "1:10.0.0.1" || len(f.calls) != 1 {
		t.Errorf("Walk = %s, %v, %d probes; want 1:10.0.0.1, context.Canceled, 1",
			summary(hops), err, len(f.calls))
	}
}

// A probe that was cut short by Ctrl+C has no answer, but that does not make
// the hop silent: the walk must stop without adding it.
func TestWalkCancelledDuringProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeProber{hops: map[int]Hop{1: answer("192.168.1.1")}}
	f.onProbe = func(ttl int) {
		if ttl == 2 {
			cancel() // TCPProber returns an empty Hop and no error here
		}
	}
	hops, err := Walk(ctx, f, WalkOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Walk error = %v; want context.Canceled", err)
	}
	if got := summary(hops); got != "1:192.168.1.1" {
		t.Errorf("Walk hops = %s; want 1:192.168.1.1 (no fake silent hop for TTL 2)", got)
	}
}

// TestTCPProberLoopback needs root on Linux: a probe to a local listener
// reaches it in one hop. Run it with:
//
//	go test -c -o locate.test ./internal/locate && sudo ./locate.test -test.v
func TestTCPProberLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (raw sockets)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dst := netip.MustParseAddrPort(ln.Addr().String())

	hops, err := Walk(context.Background(), TCPProber{Dst: dst}, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "1:127.0.0.1!"
	if got := summary(hops); got != want {
		t.Errorf("Walk hops = %s; want %s", got, want)
	}
	if hops[0].RTT <= 0 {
		t.Errorf("RTT = %v; want > 0", hops[0].RTT)
	}
}

// TestTCPProberClosedPort needs root on Linux: a closed port answers with a
// RST, which still means the target was reached.
func TestTCPProberClosedPort(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (raw sockets)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close() // nobody listens on dst any more

	hop, err := TCPProber{Dst: dst}.Probe(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if !hop.Reached {
		t.Errorf("Probe = %+v; want Reached (RST from a closed port)", hop)
	}
}

// fakeHelloProber answers from a table instead of the network: results[ttl]
// is the answer for that TTL; a missing entry is a timeout.
type fakeHelloProber struct {
	results map[int]probe.TLSResult
	calls   []int // TTLs probed, in order

	// onProbe, if set, runs at the start of every ProbeHello call.
	onProbe func(ttl int)
}

func (f *fakeHelloProber) ProbeHello(ctx context.Context, ttl int) probe.TLSResult {
	f.calls = append(f.calls, ttl)
	if f.onProbe != nil {
		f.onProbe(ttl)
	}
	if r, ok := f.results[ttl]; ok {
		return r
	}
	return probe.TLSResult{Outcome: probe.TLSTimeout}
}

func outcome(o probe.TLSOutcome) probe.TLSResult { return probe.TLSResult{Outcome: o} }

// outcomes writes the outcomes as "timeout timeout reset", so a failing test
// shows the whole search at a glance.
func outcomes(list []probe.TLSOutcome) string {
	s := ""
	for i, o := range list {
		if i > 0 {
			s += " "
		}
		s += o.String()
	}
	return s
}

func TestFindDPI(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		results   map[int]probe.TLSResult
		opt       FindOptions
		wantTTL   int
		want      string
		wantErr   error
		wantCalls int
	}{
		{
			name:      "reset at TTL 4",
			results:   map[int]probe.TLSResult{4: outcome(probe.TLSReset)},
			wantTTL:   4,
			want:      "timeout timeout timeout reset",
			wantCalls: 4,
		},
		{
			name:      "server answers at TTL 3",
			results:   map[int]probe.TLSResult{3: outcome(probe.TLSServerHello)},
			want:      "timeout timeout server_hello",
			wantCalls: 3,
		},
		{
			name:      "server alert stops too",
			results:   map[int]probe.TLSResult{2: outcome(probe.TLSAlert)},
			want:      "timeout alert",
			wantCalls: 2,
		},
		{
			name:      "silent up to MaxTTL",
			opt:       FindOptions{MaxTTL: 5},
			want:      "timeout timeout timeout timeout timeout",
			wantCalls: 5,
		},
		{
			name:      "dial fails",
			results:   map[int]probe.TLSResult{2: {Outcome: probe.TLSDialFailed, Err: boom}},
			want:      "timeout dial_failed",
			wantErr:   boom,
			wantCalls: 2,
		},
		{
			name:      "reset at TTL 1",
			results:   map[int]probe.TLSResult{1: outcome(probe.TLSReset)},
			wantTTL:   1,
			want:      "reset",
			wantCalls: 1,
		},
		{
			name: "closed and unknown do not stop",
			results: map[int]probe.TLSResult{
				2: outcome(probe.TLSClosed),
				3: outcome(probe.TLSUnknown),
				4: outcome(probe.TLSReset),
			},
			wantTTL:   4,
			want:      "timeout closed unknown reset",
			wantCalls: 4,
		},
		{
			name:      "unknown with an error stops",
			results:   map[int]probe.TLSResult{2: {Outcome: probe.TLSUnknown, Err: boom}},
			want:      "timeout unknown",
			wantErr:   boom,
			wantCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeHelloProber{results: tt.results}
			res, err := FindDPI(context.Background(), f, tt.opt)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("FindDPI error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("FindDPI error = %v; want it to wrap %v", err, tt.wantErr)
			}
			if res.TTL != tt.wantTTL || res.Found() != (tt.wantTTL > 0) {
				t.Errorf("TTL = %d, Found = %v; want %d, %v", res.TTL, res.Found(), tt.wantTTL, tt.wantTTL > 0)
			}
			if got := outcomes(res.Outcomes); got != tt.want {
				t.Errorf("Outcomes = %q; want %q", got, tt.want)
			}
			if len(f.calls) != tt.wantCalls {
				t.Errorf("probed TTLs %v; want %d probes", f.calls, tt.wantCalls)
			}
		})
	}
}

func TestFindDPIMaxTTLDefaultsTo30(t *testing.T) {
	f := &fakeHelloProber{}
	res, err := FindDPI(context.Background(), f, FindOptions{})
	if err != nil || len(res.Outcomes) != 30 || len(f.calls) != 30 {
		t.Errorf("FindDPI = %d outcomes, %d probes, %v; want 30, 30, nil", len(res.Outcomes), len(f.calls), err)
	}
}

func TestFindDPIBadTTL(t *testing.T) {
	for _, maxTTL := range []int{-1, 256, 300} {
		f := &fakeHelloProber{}
		_, err := FindDPI(context.Background(), f, FindOptions{MaxTTL: maxTTL})
		if !errors.Is(err, ErrBadTTL) || len(f.calls) != 0 {
			t.Errorf("MaxTTL %d: err = %v, %d probes; want ErrBadTTL, 0", maxTTL, err, len(f.calls))
		}
	}
}

func TestFindDPICancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeHelloProber{}
	res, err := FindDPI(ctx, f, FindOptions{})
	if !errors.Is(err, context.Canceled) || len(res.Outcomes) != 0 || len(f.calls) != 0 {
		t.Errorf("FindDPI = %d outcomes, %v, %d probes; want 0, context.Canceled, 0",
			len(res.Outcomes), err, len(f.calls))
	}
}

func TestFindDPICancelledDuringGap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeHelloProber{}
	f.onProbe = func(ttl int) {
		if ttl == 1 {
			time.AfterFunc(50*time.Millisecond, cancel) // fires while FindDPI waits for TTL 2
		}
	}
	start := time.Now()
	res, err := FindDPI(ctx, f, FindOptions{Gap: 10 * time.Second})
	if time.Since(start) > 5*time.Second {
		t.Fatal("FindDPI kept sleeping after cancel")
	}
	if !errors.Is(err, context.Canceled) || outcomes(res.Outcomes) != "timeout" || len(f.calls) != 1 {
		t.Errorf("FindDPI = %q, %v, %d probes; want %q, context.Canceled, 1",
			outcomes(res.Outcomes), err, len(f.calls), "timeout")
	}
}

// A probe cut short by Ctrl+C looks like a timeout, but it was never
// measured: FindDPI must stop without recording it.
func TestFindDPICancelledDuringProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeHelloProber{}
	f.onProbe = func(ttl int) {
		if ttl == 2 {
			cancel()
		}
	}
	res, err := FindDPI(ctx, f, FindOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("FindDPI error = %v; want context.Canceled", err)
	}
	if got := outcomes(res.Outcomes); got != "timeout" {
		t.Errorf("Outcomes = %q; want %q (no outcome for the cancelled TTL 2)", got, "timeout")
	}
}

func TestTLSHelloProberBadTTL(t *testing.T) {
	// Nobody listens on port 1: if ProbeHello went to the network, it would
	// come back as dial_failed instead.
	p := TLSHelloProber{Dst: netip.MustParseAddrPort("127.0.0.1:1"), SNI: "example.com"}
	for _, ttl := range []int{-1, 0, 256, 300} {
		r := p.ProbeHello(context.Background(), ttl)
		if r.Outcome != probe.TLSUnknown || !errors.Is(r.Err, ErrBadTTL) {
			t.Errorf("ProbeHello(ttl %d) = %v, %v; want unknown, ErrBadTTL", ttl, r.Outcome, r.Err)
		}
	}
}

// localTLS starts a local TLS server and returns its address.
func localTLS(t *testing.T) netip.AddrPort {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

// On loopback nothing decrements the TTL, so even TTL 1 reaches the server.
// The zero Timeout must mean 3 seconds, enough to connect and get an answer.
func TestTLSHelloProberLoopback(t *testing.T) {
	p := TLSHelloProber{Dst: localTLS(t), SNI: "example.com"}
	for _, ttl := range []int{1, 64, 255} {
		r := p.ProbeHello(context.Background(), ttl)
		if r.Outcome != probe.TLSServerHello {
			t.Errorf("ProbeHello(ttl %d) = %v (err %v); want server_hello", ttl, r.Outcome, r.Err)
		}
	}
}

// resetServer resets every connection as soon as the ClientHello arrives,
// like a DPI box next door.
func resetServer(t *testing.T) netip.AddrPort {
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
				c.Read(make([]byte, 1024))
				c.(*net.TCPConn).SetLinger(0) // the deferred Close then sends a RST
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// TestFindDPILoopback runs the real prober end to end, without root.
func TestFindDPILoopback(t *testing.T) {
	tests := []struct {
		name    string
		dst     netip.AddrPort
		wantTTL int
		want    string
	}{
		{"server answers", localTLS(t), 0, "server_hello"},
		{"reset next door", resetServer(t), 1, "reset"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := TLSHelloProber{Dst: tt.dst, SNI: "example.com"}
			res, err := FindDPI(context.Background(), p, FindOptions{})
			if err != nil {
				t.Fatalf("FindDPI error = %v", err)
			}
			if res.TTL != tt.wantTTL || outcomes(res.Outcomes) != tt.want {
				t.Errorf("FindDPI = TTL %d, %q; want TTL %d, %q", res.TTL, outcomes(res.Outcomes), tt.wantTTL, tt.want)
			}
		})
	}
}
