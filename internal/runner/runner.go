// Package runner tries strategies against a target, repeating each one and
// measuring its success rate and latency.
package runner

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
	"github.com/mehmetalitilgen/dpiprisma/internal/strategy"
)

// Options configures how Run executes strategies.
type Options struct {
	Timeout    time.Duration // probe timeout for each run
	RatePerSec float64       // max connections per second; <= 0 means unlimited
}

// Result summarizes all runs of a single strategy.
type Result struct {
	Name      string          // strategy name (s.Name())
	Runs      int             // number of times the strategy was tried
	Successes int             // number of runs that received a ServerHello
	Latencies []time.Duration // Elapsed of successful runs only
}

// SuccessRate returns the fraction of runs that succeeded, or 0 if there were no runs.
func (r Result) SuccessRate() float64 {
	if r.Runs == 0 {
		return 0
	}
	return float64(r.Successes) / float64(r.Runs)
}

// P50 returns the median latency of successful runs.
func (r Result) P50() time.Duration { return percentile(r.Latencies, 50) }

// P95 returns the 95th percentile latency of successful runs.
func (r Result) P95() time.Duration { return percentile(r.Latencies, 95) }

// Run tries each strategy runs times against addr and returns one Result per strategy.
// Connections are opened sequentially; if opt.RatePerSec > 0, connection starts are
// spaced roughly 1/RatePerSec apart. If ctx is cancelled, Run returns the results of
// the strategies completed so far together with ctx.Err().
func Run(ctx context.Context, addr netip.AddrPort, sni string, strategies []strategy.Strategy, runs int, opt Options) ([]Result, error) {
	// 1. Validate (before touching the network).
	if runs < 1 {
		return nil, errors.New("runner: runs must be >= 1")
	}
	if len(strategies) == 0 {
		return nil, errors.New("runner: no strategies")
	}
	if opt.Timeout <= 0 {
		return nil, errors.New("runner: timeout must be > 0")
	}
	if opt.RatePerSec < 0 {
		return nil, errors.New("runner: rate must be >= 0")
	}

	// 2. Rate limit ticker; nil channel means unlimited.
	var tick <-chan time.Time
	if opt.RatePerSec > 0 {
		interval := time.Duration(float64(time.Second) / opt.RatePerSec)
		if interval > 0 { // extremely high rates round down to 0, which NewTicker rejects
			t := time.NewTicker(interval)
			defer t.Stop()
			tick = t.C
		}
	}

	// 3–4. Try every strategy runs times.
	results := make([]Result, 0, len(strategies))
	for _, s := range strategies {
		res := Result{Name: s.Name(), Runs: runs}

		for i := 0; i < runs; i++ {
			if err := ctx.Err(); err != nil {
				return results, err
			}
			if tick != nil {
				select {
				case <-tick:
				case <-ctx.Done():
					return results, ctx.Err()
				}
			}

			r := probeOnce(ctx, addr, sni, opt.Timeout, s)
			if r.Outcome == probe.TLSServerHello {
				res.Successes++
				res.Latencies = append(res.Latencies, r.Elapsed)
			}
		}

		results = append(results, res)
	}

	// 5.
	return results, nil
}

// percentile returns the q-th percentile of values using the nearest-rank method.
// It returns 0 for an empty slice and does not modify values.
func percentile(values []time.Duration, q int) time.Duration {
	n := len(values)
	if n == 0 {
		return 0
	}

	sorted := slices.Clone(values)
	slices.Sort(sorted)

	rank := int(math.Ceil(float64(q) / 100 * float64(n)))
	rank = max(rank, 1)

	idx := min(max(rank-1, 0), n-1)
	return sorted[idx]
}

// probeOnce performs a single TLS probe against addr with strategy s applied.
func probeOnce(ctx context.Context, addr netip.AddrPort, sni string, timeout time.Duration, s strategy.Strategy) probe.TLSResult {
	return probe.ProbeWith(ctx, addr, sni, timeout, s.Apply)
}
