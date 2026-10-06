// Package model defines the result types shared by probes, the CLI and reports.
package model

import (
	"fmt"
	"time"
)

// Verdict is the outcome of probing a domain.
type Verdict int

const (
	VerdictUnknown      Verdict = iota // could not decide
	VerdictAccessible                  // the domain is reachable
	VerdictDNSPoisoning                // DNS returns a wrong address
	VerdictIPBlackhole                 // packets to the IP are dropped
	VerdictSNIBlocking                 // the connection is cut when the SNI is seen
)

// verdictNames holds the name of each verdict, in the same order as the constants.
var verdictNames = [...]string{"unknown", "accessible", "dns_poisoning", "ip_blackhole", "sni_blocking"}

// String returns the verdict's name, e.g. "sni_blocking".
func (v Verdict) String() string {
	if v < 0 || int(v) >= len(verdictNames) {
		return fmt.Sprintf("Verdict(%d)", int(v)) // out of range: never panic
	}
	return verdictNames[v]
}

// MarshalText writes the verdict's name; encoding/json uses it automatically.
func (v Verdict) MarshalText() ([]byte, error) {
	if v < 0 || int(v) >= len(verdictNames) {
		return nil, fmt.Errorf("model: invalid verdict %d", int(v))
	}
	return []byte(verdictNames[v]), nil
}

// UnmarshalText parses a verdict name written by MarshalText.
func (v *Verdict) UnmarshalText(text []byte) error {
	for i, name := range verdictNames {
		if name == string(text) {
			*v = Verdict(i)
			return nil
		}
	}
	return fmt.Errorf("model: unknown verdict %q", text)
}

// ProbeResult is the outcome of probing one domain.
type ProbeResult struct {
	Domain    string    `json:"domain"`           // the probed domain
	Verdict   Verdict   `json:"verdict"`          // what we concluded
	Reason    string    `json:"reason,omitempty"` // short explanation; left out of JSON when empty
	CheckedAt time.Time `json:"checked_at"`       // when the probe ran
}
