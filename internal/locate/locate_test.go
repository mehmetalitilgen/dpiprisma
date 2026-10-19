package locate

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
)

func TestMajority(t *testing.T) {
	tests := []struct {
		values    []int
		wantValue int
		wantVotes int
	}{
		{[]int{3, 3, 3}, 3, 3},
		{[]int{3, 4, 3}, 3, 2},
		{[]int{4, 3}, 3, 1}, // a tie goes to the smaller value
		{[]int{0, 0, 3}, 0, 2},
		{[]int{0, 3}, 0, 1},
		{[]int{7, 6, 7, 6, 6}, 6, 3},
		{nil, 0, 0},
	}
	for _, tt := range tests {
		// Map iteration order is random, so ask many times: the answer must
		// never change.
		for range 50 {
			v, n := Majority(tt.values)
			if v != tt.wantValue || n != tt.wantVotes {
				t.Fatalf("Majority(%v) = %d, %d; want %d, %d", tt.values, v, n, tt.wantValue, tt.wantVotes)
			}
		}
	}
}

func TestReport(t *testing.T) {
	tests := []struct {
		name       string
		rep        Report
		dpi, votes int
		sLo, sHi   int
		sOK        bool
		fLo, fHi   int
		fOK        bool
	}{
		{"server range", Report{[]int{3, 3, 3}, []int{6, 7, 6}}, 3, 3, 6, 7, true, 3, 5, true},
		{"far server", Report{[]int{3, 3, 3}, []int{12, 12, 12}}, 3, 3, 12, 12, true, 3, 11, true},
		{"no reset", Report{[]int{0, 0, 0}, []int{6}}, 0, 3, 6, 6, true, 0, 0, false},
		{"server never answered", Report{[]int{3, 3, 3}, nil}, 3, 3, 0, 0, false, 0, 0, false},
		{"no room", Report{[]int{3, 3, 3}, []int{3}}, 3, 3, 3, 3, true, 0, 0, false},
		{"room for one", Report{[]int{3, 3, 3}, []int{4}}, 3, 3, 4, 4, true, 3, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if dpi, votes := tt.rep.DPI(); dpi != tt.dpi || votes != tt.votes {
				t.Errorf("DPI() = %d, %d; want %d, %d", dpi, votes, tt.dpi, tt.votes)
			}
			if lo, hi, ok := tt.rep.ServerRange(); lo != tt.sLo || hi != tt.sHi || ok != tt.sOK {
				t.Errorf("ServerRange() = %d, %d, %v; want %d, %d, %v", lo, hi, ok, tt.sLo, tt.sHi, tt.sOK)
			}
			if lo, hi, ok := tt.rep.FakeTTLRange(); lo != tt.fLo || hi != tt.fHi || ok != tt.fOK {
				t.Errorf("FakeTTLRange() = %d, %d, %v; want %d, %d, %v", lo, hi, ok, tt.fLo, tt.fHi, tt.fOK)
			}
		})
	}
}

var errTooManyRuns = errors.New("test: prober used for more runs than scripted")

// scriptedProber plays one script per FindDPI run: scripts[i][ttl] is the
// answer in run i (a missing TTL is a timeout). A new run starts whenever TTL
// 1 is probed. Using it for more runs than scripted fails the probe, so a
// Locate that loops too often stops instead of hanging the test.
type scriptedProber struct {
	scripts []map[int]probe.TLSResult
	run     int // runs started so far
}

func (s *scriptedProber) ProbeHello(ctx context.Context, ttl int) probe.TLSResult {
	if ttl == 1 {
		s.run++
	}
	if s.run > len(s.scripts) {
		return probe.TLSResult{Outcome: probe.TLSDialFailed, Err: errTooManyRuns}
	}
	if r, ok := s.scripts[s.run-1][ttl]; ok {
		return r
	}
	return probe.TLSResult{Outcome: probe.TLSTimeout}
}

// at returns a one-entry script: answer o at ttl, time out before it.
func at(ttl int, o probe.TLSOutcome) map[int]probe.TLSResult {
	return map[int]probe.TLSResult{ttl: {Outcome: o}}
}

func TestLocate(t *testing.T) {
	boom := errors.New("boom")
	reset3 := at(3, probe.TLSReset)
	tests := []struct {
		name            string
		target, control []map[int]probe.TLSResult
		runs            int
		opt             FindOptions
		wantDPI         []int
		wantServer      []int
		wantErr         error
		wantControlRuns int
	}{
		{
			name:            "three runs",
			target:          []map[int]probe.TLSResult{reset3, reset3, reset3},
			control:         []map[int]probe.TLSResult{at(6, probe.TLSServerHello), at(7, probe.TLSServerHello), at(6, probe.TLSServerHello)},
			runs:            3,
			wantDPI:         []int{3, 3, 3},
			wantServer:      []int{6, 7, 6},
			wantControlRuns: 3,
		},
		{
			name:            "alert counts as an answer",
			target:          []map[int]probe.TLSResult{reset3, at(4, probe.TLSReset), reset3},
			control:         []map[int]probe.TLSResult{at(12, probe.TLSAlert), at(12, probe.TLSAlert), at(12, probe.TLSAlert)},
			runs:            3,
			wantDPI:         []int{3, 4, 3},
			wantServer:      []int{12, 12, 12},
			wantControlRuns: 3,
		},
		{
			name:            "control name is reset too",
			target:          []map[int]probe.TLSResult{reset3, reset3},
			control:         []map[int]probe.TLSResult{at(2, probe.TLSReset), at(2, probe.TLSReset)},
			runs:            2,
			wantDPI:         []int{3, 3},
			wantControlRuns: 2,
		},
		{
			name:            "server silent up to MaxTTL",
			target:          []map[int]probe.TLSResult{reset3},
			control:         []map[int]probe.TLSResult{{}},
			runs:            1,
			opt:             FindOptions{MaxTTL: 5},
			wantDPI:         []int{3},
			wantControlRuns: 1,
		},
		{
			name:            "target cannot connect",
			target:          []map[int]probe.TLSResult{{2: {Outcome: probe.TLSDialFailed, Err: boom}}},
			control:         []map[int]probe.TLSResult{{}},
			runs:            3,
			wantErr:         boom,
			wantControlRuns: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &scriptedProber{scripts: tt.target}
			control := &scriptedProber{scripts: tt.control}
			rep, err := Locate(context.Background(), target, control, tt.runs, tt.opt)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("Locate error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Locate error = %v; want it to wrap %v", err, tt.wantErr)
			}
			if !slices.Equal(rep.DPITTLs, tt.wantDPI) {
				t.Errorf("DPITTLs = %v; want %v", rep.DPITTLs, tt.wantDPI)
			}
			if !slices.Equal(rep.ServerTTLs, tt.wantServer) {
				t.Errorf("ServerTTLs = %v; want %v", rep.ServerTTLs, tt.wantServer)
			}
			if control.run != tt.wantControlRuns {
				t.Errorf("control searched %d times; want %d", control.run, tt.wantControlRuns)
			}
		})
	}
}

func TestLocateBadRuns(t *testing.T) {
	for _, runs := range []int{0, -1} {
		target := &scriptedProber{}
		_, err := Locate(context.Background(), target, &scriptedProber{}, runs, FindOptions{})
		if !errors.Is(err, ErrBadRuns) || target.run != 0 {
			t.Errorf("runs %d: err = %v, %d searches; want ErrBadRuns, 0", runs, err, target.run)
		}
	}
}
