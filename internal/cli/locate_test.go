package cli

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/locate"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
)

func TestPrintLocate(t *testing.T) {
	addr := netip.MustParseAddrPort("66.254.114.41:443")
	tests := []struct {
		name  string
		first probe.TLSResult
		rep   locate.Report
		want  string
	}{
		{
			name:  "injected reset",
			first: probe.TLSResult{Outcome: probe.TLSReset, Elapsed: 4400 * time.Microsecond, Connect: 53800 * time.Microsecond},
			rep:   locate.Report{DPITTLs: []int{3, 3, 3}, ServerTTLs: []int{6, 7, 6}},
			want: `target    pornhub.com (66.254.114.41:443)
reset     4.4 ms after the ClientHello, handshake 53.8 ms: injected (faster than the server could answer)
dpi       about 3 hops away (3 of 3 runs agree)
server    6-7 hops away
fake-ttl  3-5
`,
		},
		{
			name:  "not reset",
			first: probe.TLSResult{Outcome: probe.TLSServerHello, Elapsed: 50 * time.Millisecond, Connect: 50 * time.Millisecond},
			want: `target    pornhub.com (66.254.114.41:443)
reset     none (server_hello): this name is not blocked by a reset
`,
		},
		{
			name:  "nothing found",
			first: probe.TLSResult{Outcome: probe.TLSReset, Elapsed: 60 * time.Millisecond, Connect: 54 * time.Millisecond},
			rep:   locate.Report{DPITTLs: []int{0, 0, 3}},
			want: `target    pornhub.com (66.254.114.41:443)
reset     60.0 ms after the ClientHello, handshake 54.0 ms: no timing anomaly
dpi       no reset at any TTL (2 of 3 runs agree)
server    the control name was never answered
fake-ttl  none found
`,
		},
		{
			name:  "single values",
			first: probe.TLSResult{Outcome: probe.TLSReset, Elapsed: 4 * time.Millisecond, Connect: 50 * time.Millisecond},
			rep:   locate.Report{DPITTLs: []int{3}, ServerTTLs: []int{4}},
			want: `target    pornhub.com (66.254.114.41:443)
reset     4.0 ms after the ClientHello, handshake 50.0 ms: injected (faster than the server could answer)
dpi       about 3 hops away (1 of 1 runs agree)
server    4 hops away
fake-ttl  3
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printLocate(&out, "pornhub.com", addr, tt.first, tt.rep)
			if got := out.String(); got != tt.want {
				t.Errorf("printLocate wrote:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestLocateCmd(t *testing.T) {
	out, err := run(t, "locate", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--runs", "--timeout", "--max-ttl", "--gap", "--control", "--doh"} {
		if !strings.Contains(out, flag) {
			t.Errorf("locate --help does not mention %s:\n%s", flag, out)
		}
	}

	if _, err := run(t, "locate"); err == nil {
		t.Error("locate without a domain: want an error")
	}
	if _, err := run(t, "locate", "a.example", "b.example"); err == nil {
		t.Error("locate with two domains: want an error")
	}
}

// TestLocateFlagValidation checks that bad flag values fail before any
// network step; none of these cases may need the internet.
func TestLocateFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string // text the error must contain
	}{
		{"zero runs", []string{"locate", "--runs", "0", "a.example"}, "--runs"},
		{"zero max-ttl", []string{"locate", "--max-ttl", "0", "a.example"}, "--max-ttl"},
		{"max-ttl above 255", []string{"locate", "--max-ttl", "256", "a.example"}, "--max-ttl"},
		{"zero timeout", []string{"locate", "--timeout", "0", "a.example"}, "--timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v; want one mentioning %s", err, tt.want)
			}
		})
	}
}
