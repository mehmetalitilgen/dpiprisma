package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/packet"
	"golang.org/x/sync/errgroup"
)

// RSTVerdict is the conclusion about whether a RST came from the server.
type RSTVerdict int

const (
	RSTUnknown    RSTVerdict = iota // no decision was made
	RSTConsistent                   // the RST looks like it came from the same host as the SYN-ACK
	RSTSuspicious                   // the TTL matches but the IP-ID is odd; weak evidence
	RSTForged                       // the TTL differs from the SYN-ACK's; strong evidence of injection
)

// rstVerdictNames holds the name of each verdict, in the same order as the constants.
var rstVerdictNames = [...]string{"unknown", "consistent", "suspicious", "forged"}

// String returns the verdict's name, e.g. "forged".
func (v RSTVerdict) String() string {
	if v < 0 || int(v) >= len(rstVerdictNames) {
		return fmt.Sprintf("RSTVerdict(%d)", int(v))
	}

	return rstVerdictNames[v]
}

// Errors returned by AnalyzeRST and ObserveRST.
var (
	ErrNotSynAck = errors.New("probe: not a SYN-ACK packet")
	ErrNotRST    = errors.New("probe: not a RST packet")
	ErrNoSynAck  = errors.New("probe: no SYN-ACK captured")
	ErrNoRST     = errors.New("probe: no RST captured")
)

const (
	ttlTolerance = 1    // largest TTL difference still treated as normal path jitter
	idWindow     = 1000 // largest forward IP-ID gap from SYN-ACK to RST treated as normal
)

// RSTAnalysis is the result of comparing a RST with the SYN-ACK of the same
// connection, with the evidence behind the verdict.
type RSTAnalysis struct {
	Verdict    RSTVerdict
	SynAckTTL  uint8    // TTL of the SYN-ACK
	RSTTTL     uint8    // TTL of the RST
	TTLDelta   int      // RSTTTL minus SynAckTTL; signed
	SynAckHops int      // hops estimated from the SYN-ACK's TTL
	RSTHops    int      // hops estimated from the RST's TTL
	SynAckID   uint16   // IP-ID of the SYN-ACK
	RSTID      uint16   // IP-ID of the RST
	Reasons    []string // one sentence per anomaly found; empty if none
}

// EstimateHops guesses how many hops a packet travelled from its remaining
// TTL, assuming the sender started at 64, 128 or 255. It is a guess: a sender
// may use another initial TTL.
func EstimateHops(ttl uint8) int {
	var start int

	if ttl <= 64 {
		start = 64
	} else if ttl <= 128 {
		start = 128
	} else {
		start = 255
	}

	return start - int(ttl)
}

// synAckMask holds the flags that must both be set in a SYN-ACK.
const synAckMask = packet.FlagSYN | packet.FlagACK

// abs returns the absolute value of x.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// AnalyzeRST compares a RST with the SYN-ACK of the same connection. A TTL
// that differs by more than one points to a RST injected by a device on the
// path; an odd IP-ID alone is only suspicious. It returns ErrNotSynAck or
// ErrNotRST if a packet does not carry the expected flags.
func AnalyzeRST(synAck, rst packet.Captured) (RSTAnalysis, error) {
	if synAck.TCP.Flags&synAckMask != synAckMask {
		return RSTAnalysis{}, ErrNotSynAck
	}

	if rst.TCP.Flags&packet.FlagRST == 0 {
		return RSTAnalysis{}, ErrNotRST
	}

	a := RSTAnalysis{
		SynAckTTL:  synAck.IP.TTL,
		RSTTTL:     rst.IP.TTL,
		TTLDelta:   int(rst.IP.TTL) - int(synAck.IP.TTL),
		SynAckHops: EstimateHops(synAck.IP.TTL),
		RSTHops:    EstimateHops(rst.IP.TTL),
		SynAckID:   synAck.IP.ID,
		RSTID:      rst.IP.ID,
	}

	var ttlAnomaly bool
	if abs(a.TTLDelta) > ttlTolerance {
		ttlAnomaly = true
		a.Reasons = append(a.Reasons, fmt.Sprintf(
			"RST TTL %d differs from SYN-ACK TTL %d", a.RSTTTL, a.SynAckTTL))
	}

	var idAnomaly bool
	s := synAck.IP.ID
	r := rst.IP.ID

	switch {
	case s == 0 && r == 0:

	case s == 0 || r == 0:
		idAnomaly = true
	default:
		d := r - s
		if d > idWindow {
			idAnomaly = true
		}
	}

	if idAnomaly {
		a.Reasons = append(a.Reasons, fmt.Sprintf(
			"RST IP-ID %d does not follow SYN-ACK IP-ID %d", a.RSTID, a.SynAckID))
	}

	if ttlAnomaly {
		a.Verdict = RSTForged
	} else if idAnomaly {
		a.Verdict = RSTSuspicious
	} else {
		a.Verdict = RSTConsistent
	}

	return a, nil
}

// ObserveRST makes a TLS attempt to addr with sni while capturing the packets
// the server sends, then runs AnalyzeRST on the SYN-ACK and the first RST of
// that very connection; packets of other connections to the same server (a
// browser tab, say) are ignored by their port. It returns ErrNoSynAck if the
// connection never opened and ErrNoRST if it was not reset. It reads a raw
// socket, so it needs root (or CAP_NET_RAW) on Linux.
func ObserveRST(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration) (RSTAnalysis, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	paketler := make(chan packet.Captured, 64)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return packet.CaptureTCP(gctx, addr.Addr(), func(c packet.Captured) {
			select {
			case paketler <- c:
			default:
			}
		})
	})

	sleepCtx(gctx, 100*time.Millisecond)

	attempt := ProbeTLS(gctx, addr, sni, timeout)

	sleepCtx(gctx, 100*time.Millisecond)
	cancel()
	if err := g.Wait(); err != nil {
		return RSTAnalysis{}, err
	}
	close(paketler)

	// Only packets of our own connection count: from the server's port to
	// the local port the dial used. A failed dial leaves Local zero, so
	// nothing matches and ErrNoSynAck follows.
	localPort := attempt.Local.Port()

	var synAck, rst packet.Captured
	var gotSynAck, gotRST bool

	for c := range paketler {
		if c.TCP.SrcPort != addr.Port() || c.TCP.DstPort != localPort {
			continue
		}
		if !gotSynAck {
			if c.TCP.Flags&synAckMask == synAckMask {
				synAck = c
				gotSynAck = true
			}
			continue
		}
		if !gotRST && c.TCP.Flags&packet.FlagRST != 0 {
			rst = c
			gotRST = true
		}
	}

	if !gotSynAck {
		return RSTAnalysis{}, ErrNoSynAck
	}
	if !gotRST {
		return RSTAnalysis{}, ErrNoRST
	}

	return AnalyzeRST(synAck, rst)
}

// sleepCtx waits for d, but returns early if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
