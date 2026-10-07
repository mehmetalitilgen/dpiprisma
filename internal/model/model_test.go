package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictUnknown, "unknown"},
		{VerdictSNIBlocking, "sni_blocking"},
		{Verdict(99), "Verdict(99)"},
		{VerdictAccessible, "accessible"},
		{VerdictDNSPoisoning, "dns_poisoning"},
		{VerdictIPBlackhole, "ip_blackhole"},
		{Verdict(-1), "Verdict(-1)"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("Verdict(%d).String() = %q; want %q", int(tt.v), got, tt.want)
		}
	}
}

func TestVerdictTextRoundTrip(t *testing.T) {
	all := []Verdict{VerdictUnknown, VerdictAccessible, VerdictDNSPoisoning, VerdictIPBlackhole, VerdictSNIBlocking}
	for _, v := range all {
		text, err := v.MarshalText()
		if err != nil {
			t.Fatalf("%v.MarshalText() error = %v", v, err)
		}

		var back Verdict
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q) error = %v", text, err)
		}
		if back != v {
			t.Errorf("round trip of %v gave %v", v, back)
		}
	}
}

func TestVerdictTextErrors(t *testing.T) {
	if _, err := Verdict(99).MarshalText(); err == nil {
		t.Error("Verdict(99).MarshalText() error = nil; want an error")
	}

	var v Verdict
	if err := v.UnmarshalText([]byte("blocked")); err == nil {
		t.Error(`UnmarshalText("blocked") error = nil; want an error`)
	}
}

func TestProbeResultJSON(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) // fixed time, so the expected JSON never changes

	tests := []struct {
		name string
		r    ProbeResult
		want string
	}{
		{
			name: "with reason",
			r:    ProbeResult{Domain: "x.com", Verdict: VerdictSNIBlocking, Reason: "RST after ClientHello", CheckedAt: at},
			want: `{"domain":"x.com","verdict":"sni_blocking","reason":"RST after ClientHello","checked_at":"2026-10-06T12:00:00Z"}`,
		},
		{
			name: "without reason",
			r:    ProbeResult{Domain: "example.org", Verdict: VerdictAccessible, CheckedAt: at},
			want: `{"domain":"example.org","verdict":"accessible","checked_at":"2026-10-06T12:00:00Z"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.r)
			if err != nil {
				t.Fatalf("json.Marshal error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal = %s\nwant           %s", got, tt.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	// reachable is the evidence for a site that works end to end.
	reachable := Evidence{TCPConnected: true, TLSControlAnswered: true, TLSTargetAnswered: true}

	tests := []struct {
		name       string
		e          Evidence
		want       Verdict
		wantReason string
	}{
		{"accessible", reachable, VerdictAccessible, "TLS handshake succeeded"},
		{"accessible with DNS mismatch",
			Evidence{DNSMismatch: true, TCPConnected: true, TLSControlAnswered: true, TLSTargetAnswered: true},
			VerdictAccessible, "TLS handshake succeeded; DNS answers differ (CDN?)"},
		{"bogus DNS wins over a working site",
			Evidence{DNSBogus: true, TCPConnected: true, TLSControlAnswered: true, TLSTargetAnswered: true},
			VerdictDNSPoisoning, "system DNS returned a bogus address"},
		{"NXDOMAIN", Evidence{DNSNXDomain: true, TCPConnected: true, TLSTargetAnswered: true},
			VerdictDNSPoisoning, "system DNS says the domain does not exist"},
		{"bogus is checked before NXDOMAIN", Evidence{DNSBogus: true, DNSNXDomain: true},
			VerdictDNSPoisoning, "system DNS returned a bogus address"},
		{"TCP timeout", Evidence{TCPTimeout: true}, VerdictIPBlackhole, "TCP connection to the real address timed out"},
		{"TCP refused", Evidence{}, VerdictUnknown, "TCP connection to the real address failed"},
		{"TCP failure wins over TLS", Evidence{TCPTimeout: true, TLSControlAnswered: true}, VerdictIPBlackhole,
			"TCP connection to the real address timed out"},
		{"SNI blocking", Evidence{TCPConnected: true, TLSControlAnswered: true}, VerdictSNIBlocking,
			"the server answers other names but not this one"},
		{"SNI blocking despite DNS mismatch", Evidence{DNSMismatch: true, TCPConnected: true, TLSControlAnswered: true},
			VerdictSNIBlocking, "the server answers other names but not this one"},
		{"target answered without control", Evidence{TCPConnected: true, TLSTargetAnswered: true},
			VerdictAccessible, "TLS handshake succeeded"},
		{"no TLS answer at all", Evidence{TCPConnected: true}, VerdictUnknown, "no TLS answer for either name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := Classify(tt.e)
			if got != tt.want || reason != tt.wantReason {
				t.Errorf("Classify(%+v) = (%v, %q); want (%v, %q)", tt.e, got, reason, tt.want, tt.wantReason)
			}
		})
	}
}
