package locate

import (
	"context"
	"errors"
	"slices"
)

// ErrBadRuns is returned by Locate when runs is less than 1.
var ErrBadRuns = errors.New("locate: runs must be at least 1")

// Majority returns the most common value in values and how many times it
// occurs. A tie goes to the smaller value, so the same input always gives the
// same answer. An empty slice gives 0, 0.
func Majority(values []int) (value, votes int) {
	counts := make(map[int]int)
	for _, v := range values {
		counts[v]++
	}

	best, bestN := 0, 0
	// Map order is random; the tie rule keeps the result stable.
	for v, n := range counts {
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}

	return best, bestN
}

// Report holds the raw results of the repeated searches in Locate; its
// methods derive the verdicts from them.
type Report struct {
	DPITTLs    []int // TTL of the first reset in each run; 0 if a run saw none
	ServerTTLs []int // TTL at which the server answered the control name; runs without an answer are left out
}

// DPI returns the TTL most runs agreed on for the first reset, and how many
// runs agreed.
func (r Report) DPI() (ttl, votes int) {
	return Majority(r.DPITTLs)
}

// ServerRange returns the shortest and longest distance at which the server
// answered, or ok false if it never did. Paths of different lengths make
// this a range rather than one number.
func (r Report) ServerRange() (lo, hi int, ok bool) {
	if len(r.ServerTTLs) == 0 {
		return 0, 0, false
	}
	return slices.Min(r.ServerTTLs), slices.Max(r.ServerTTLs), true
}

// FakeTTLRange returns the TTLs a decoy packet can use: high enough to reach
// the device that resets the connection, too low to reach the server on its
// shortest path. ok is false if there is no such TTL.
func (r Report) FakeTTLRange() (lo, hi int, ok bool) {
	dpi, _ := r.DPI()
	sLo, _, sOK := r.ServerRange()
	if dpi == 0 || !sOK || sLo <= dpi {
		return 0, 0, false
	}
	return dpi, sLo - 1, true
}

// Locate runs FindDPI runs times with target, which sends the blocked name,
// and each time with control, which sends a harmless name to the same
// address to measure how far away the server is. On error it returns the
// runs collected so far with the error.
func Locate(ctx context.Context, target, control HelloProber, runs int, opt FindOptions) (Report, error) {
	if runs < 1 {
		return Report{}, ErrBadRuns
	}

	var rep Report
	for i := 1; i <= runs; i++ {
		t, err := FindDPI(ctx, target, opt)
		if err != nil {
			return rep, err
		}
		rep.DPITTLs = append(rep.DPITTLs, t.TTL)

		c, err := FindDPI(ctx, control, opt)
		if err != nil {
			return rep, err
		}
		// The search stops at the TTL the server answered, so that TTL is
		// the number of outcomes.
		if len(c.Outcomes) != 0 && c.Outcomes[len(c.Outcomes)-1].Answered() {
			rep.ServerTTLs = append(rep.ServerTTLs, len(c.Outcomes))
		}
	}

	return rep, nil
}
