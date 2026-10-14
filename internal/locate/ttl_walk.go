// Package locate finds where on the network path something happens, by
// sending probes with increasing IP TTLs.
package locate

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/packet"
	"golang.org/x/sync/errgroup"
)

// ErrBadTTL is returned by Walk when WalkOptions.MaxTTL is outside 0..255.
var ErrBadTTL = errors.New("locate: MaxTTL must be between 0 and 255")

// Hop is the result of a single probe: one row in the path table.
type Hop struct {
	TTL     int           // IP TTL the probe was sent with
	Router  netip.Addr    // address of the device that answered; zero if no answer
	RTT     time.Duration // time between sending the probe and receiving the answer
	Reached bool          // true if the answer came from the target itself
}

// Silent reports whether no answer was received for this hop.
func (h Hop) Silent() bool {
	return !h.Router.IsValid()
}

// Prober sends one probe with the given TTL and waits for its answer.
type Prober interface {
	Probe(ctx context.Context, ttl int) (Hop, error)
}

// WalkOptions controls how Walk probes the path.
type WalkOptions struct {
	MaxTTL    int           // highest TTL to try; 0 means 30
	MaxSilent int           // stop after this many silent hops in a row; 0 means 5
	Gap       time.Duration // pause between probes; 0 means no pause
}

// Walk probes with TTL 1, 2, 3, ... until the target answers, the path goes
// silent, or MaxTTL is reached. On error or cancellation it returns the hops
// collected so far together with the error.
func Walk(ctx context.Context, p Prober, opt WalkOptions) ([]Hop, error) {
	if opt.MaxTTL < 0 || opt.MaxTTL > 255 {
		return nil, ErrBadTTL
	}

	if opt.MaxTTL == 0 {
		opt.MaxTTL = 30
	}
	if opt.MaxSilent == 0 {
		opt.MaxSilent = 5
	}

	hops := []Hop{}
	silent := 0 // consecutive hops with no answer

	for ttl := 1; ttl <= opt.MaxTTL; ttl++ {
		if ttl > 1 && opt.Gap > 0 {
			t := time.NewTimer(opt.Gap)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return hops, ctx.Err()
			}
		}

		if ctx.Err() != nil {
			return hops, ctx.Err()
		}

		hop, err := p.Probe(ctx, ttl)
		if err != nil {
			return hops, err
		}
		// A probe cut short by cancellation comes back as a silent hop with no
		// error; it was never measured, so do not record it.
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}

		hop.TTL = ttl
		hops = append(hops, hop)

		if hop.Reached {
			break // reached the target
		}

		if hop.Silent() {
			silent++
			if silent >= opt.MaxSilent {
				break // the path went quiet; no point going further
			}
		} else {
			silent = 0 // count in a row, not in total
		}
	}

	return hops, nil
}

// TCPProber probes with TCP SYNs, like traceroute -T. A router on the way
// answers with ICMP time exceeded; the target answers with a SYN-ACK, or a
// RST if the port is closed. It uses raw sockets, so it needs root (or
// CAP_NET_RAW) on Linux.
type TCPProber struct {
	Dst     netip.AddrPort // target, for example 1.1.1.1:443
	Timeout time.Duration  // how long to wait for an answer; 0 means 2s
}

// Probe sends one SYN with the given TTL and waits for its answer. No answer
// within the timeout gives a silent Hop and no error.
func (p TCPProber) Probe(ctx context.Context, ttl int) (Hop, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	icmpChannel := make(chan packet.TimeExceeded, 32)
	tcpChannel := make(chan packet.Captured, 32)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return packet.CaptureTimeExceeded(gctx, func(te packet.TimeExceeded) {
			select {
			case icmpChannel <- te:
			default:
			}
		})
	})
	g.Go(func() error {
		return packet.CaptureTCP(gctx, p.Dst.Addr(), func(c packet.Captured) {
			select {
			case tcpChannel <- c:
			default:
			}
		})
	})

	// Give the raw sockets time to open; the captures do not report when they
	// are ready. Stop waiting early if a capture has already failed.
	select {
	case <-time.After(100 * time.Millisecond):
	case <-gctx.Done():
	}

	sent := time.Now()
	src, err := packet.SendSYN(p.Dst, uint8(ttl))
	if err != nil {
		cancel()
		_ = g.Wait() // only to stop the captures; the send error matters more
		return Hop{}, err
	}

	var hop Hop
loop:
	for {
		select {
		case te := <-icmpChannel:
			if te.OrigProtocol == 6 &&
				te.OrigSrcPort == src.Port() &&
				te.OrigDst == p.Dst.Addr() {
				hop = Hop{Router: te.Router, RTT: te.At.Sub(sent)}
				break loop
			}

		case c := <-tcpChannel:
			if c.TCP.SrcPort == p.Dst.Port() &&
				c.TCP.DstPort == src.Port() {
				hop = Hop{Router: c.IP.Src, RTT: c.At.Sub(sent), Reached: true}
				break loop
			}

		case <-gctx.Done():
			break loop
		}
	}

	cancel()
	if err := g.Wait(); err != nil {
		return Hop{}, err
	}
	return hop, nil
}
