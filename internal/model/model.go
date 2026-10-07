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

// Evidence is what the DNS, TCP and TLS probes found for one domain, reduced
// to plain facts so that this package does not depend on the probe package.
type Evidence struct {
	DNSBogus           bool // the system DNS returned a private, loopback or unspecified address
	DNSNXDomain        bool // the system DNS said the domain does not exist, but DoH resolved it
	DNSMismatch        bool // the system and DoH answers share no address
	TCPConnected       bool // a TCP connection to the real address succeeded
	TCPTimeout         bool // the TCP connection to the real address timed out
	TLSControlAnswered bool // the server answered the control SNI
	TLSTargetAnswered  bool // the server answered the target SNI
}

// Classify turns the evidence into a verdict and a short reason. The rules are
// checked in order and the first match wins: DNS, then TCP, then TLS.
func Classify(e Evidence) (Verdict, string) {
	if e.DNSBogus {
		return VerdictDNSPoisoning, "system DNS returned a bogus address"
	}

	if e.DNSNXDomain {
		return VerdictDNSPoisoning, "system DNS says the domain does not exist"
	}

	if !e.TCPConnected && e.TCPTimeout {
		return VerdictIPBlackhole, "TCP connection to the real address timed out"
	}

	if !e.TCPConnected {
		return VerdictUnknown, "TCP connection to the real address failed"
	}

	if e.TLSControlAnswered && !e.TLSTargetAnswered {
		return VerdictSNIBlocking, "the server answers other names but not this one"
	}

	if e.TLSTargetAnswered {
		if e.DNSMismatch {
			return VerdictAccessible, "TLS handshake succeeded; DNS answers differ (CDN?)"
		}
		return VerdictAccessible, "TLS handshake succeeded"
	}

	return VerdictUnknown, "no TLS answer for either name"
}
