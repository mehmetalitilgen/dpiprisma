package model

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// LocateResult is what "dpiprisma locate" found for one domain, reduced to
// the numbers a report needs. Zero means "not found" for every hop count.
type LocateResult struct {
	Domain     string `json:"domain"`                 // the located domain
	Blocked    bool   `json:"blocked"`                // the first, full-TTL ClientHello was reset
	Runs       int    `json:"runs,omitempty"`         // how many TTL walks ran
	DPIHops    int    `json:"dpi_hops,omitempty"`     // distance to the device that resets the connection
	DPIVotes   int    `json:"dpi_votes,omitempty"`    // how many runs agreed on DPIHops
	ServerMin  int    `json:"server_min,omitempty"`   // shortest distance at which the server answered
	ServerMax  int    `json:"server_max,omitempty"`   // longest distance at which the server answered
	FakeTTLMin int    `json:"fake_ttl_min,omitempty"` // lowest TTL a decoy packet can use
	FakeTTLMax int    `json:"fake_ttl_max,omitempty"` // highest TTL a decoy packet can use
}

// StrategyResult is how one strategy, with one set of parameters, did
// against one domain over repeated runs. "dpiprisma matrix --json" writes a
// list of these and "dpiprisma report" reads them. Params carries what the
// strategy's name does not, so the report can turn it into commands.
type StrategyResult struct {
	Domain    string         `json:"domain"`           // the domain the ClientHellos named
	Strategy  string         `json:"strategy"`         // registry name, e.g. "split"
	Params    map[string]int `json:"params,omitempty"` // e.g. {"at": 1} or {"ttl": 5}; nil for none
	Runs      int            `json:"runs"`             // connections tried
	Successes int            `json:"successes"`        // connections that got a ServerHello
	P50       time.Duration  `json:"p50_ns"`           // median time to the ServerHello, over successes
	P95       time.Duration  `json:"p95_ns"`           // 95th percentile of the same
}

// SuccessRate returns Successes/Runs, or 0 when nothing was attempted.
func (r StrategyResult) SuccessRate() float64 {
	if r.Runs <= 0 {
		return 0
	}
	return float64(r.Successes) / float64(r.Runs)
}

// Label names the strategy with its parameters, sorted by key, e.g.
// "split at=1" or "baseline". Reports use it as a column name.
func (r StrategyResult) Label() string {
	keys := make([]string, 0, len(r.Params))
	for k := range r.Params {
		keys = append(keys, k)
	}
	slices.Sort(keys) // map order is random; the label must not be

	var b strings.Builder
	b.WriteString(r.Strategy)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%d", k, r.Params[k])
	}
	return b.String()
}
