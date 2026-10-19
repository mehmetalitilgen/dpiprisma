package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
	"github.com/mehmetalitilgen/dpiprisma/internal/tlsx"
)

// staticResolver answers every lookup with addrs, or fails with err.
type staticResolver struct {
	addrs []string
	err   error
}

func (s staticResolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.err != nil {
		return nil, s.err
	}
	var out []netip.Addr
	for _, a := range s.addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

// fakeTLSServer listens on 127.0.0.1. It resets connections whose ClientHello
// carries blockedSNI and answers everything else with the start of a
// ServerHello. It returns the port.
func fakeTLSServer(t *testing.T, blockedSNI string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if sni, _ := tlsx.ParseSNI(buf[:n]); sni == blockedSNI {
					c.(*net.TCPConn).SetLinger(0) // Close now sends a RST
					return
				}
				c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x7a, 0x02})
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()).Port()
}

// fakeVerifier answers every certificate check with outcome and records the
// addresses it was asked about.
type fakeVerifier struct {
	outcome probe.CertOutcome
	asked   []netip.AddrPort
}

func (f *fakeVerifier) Verify(ctx context.Context, addr netip.AddrPort, serverName string, timeout time.Duration) probe.CertResult {
	f.asked = append(f.asked, addr)
	return probe.CertResult{Outcome: f.outcome}
}

func TestScanDomain(t *testing.T) {
	port := fakeTLSServer(t, "blocked.example")
	local := staticResolver{addrs: []string{"127.0.0.1"}} // DoH: the real address is our fake server
	public := staticResolver{addrs: []string{"93.184.215.14"}}
	publicAddr := netip.AddrPortFrom(netip.MustParseAddr("93.184.215.14"), port)

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := netip.MustParseAddrPort(closedLn.Addr().String()).Port()
	closedLn.Close()

	tests := []struct {
		name        string
		domain      string
		system      probe.Resolver
		trusted     probe.Resolver
		cert        probe.CertOutcome // what the system address's certificate check finds
		port        uint16
		wantVerdict model.Verdict
		wantReason  string
		wantAsked   []netip.AddrPort // addresses the certificate check must have been run on
	}{
		{"accessible", "open.example", public, local, probe.CertValid, port,
			model.VerdictAccessible, "TLS handshake succeeded; DNS answers differ (CDN?)", []netip.AddrPort{publicAddr}},
		{"redirect to a block page", "open.example", public, local, probe.CertInvalid, port,
			model.VerdictDNSPoisoning, "system DNS points to a host without a certificate for this domain", []netip.AddrPort{publicAddr}},
		{"redirect that cannot be checked", "open.example", public, local, probe.CertUnknown, port,
			model.VerdictAccessible, "TLS handshake succeeded; DNS answers differ (CDN?)", []netip.AddrPort{publicAddr}},
		{"SNI blocking", "blocked.example", public, local, probe.CertValid, port,
			model.VerdictSNIBlocking, "the server answers other names but not this one", []netip.AddrPort{publicAddr}},
		{"bogus system DNS", "open.example", staticResolver{addrs: []string{"127.0.0.1"}}, local, probe.CertInvalid, port,
			model.VerdictDNSPoisoning, "system DNS returned a bogus address", nil},
		{"system NXDOMAIN", "open.example", staticResolver{err: probe.ErrNXDomain}, local, probe.CertInvalid, port,
			model.VerdictDNSPoisoning, "system DNS says the domain does not exist", nil},
		{"TCP refused", "open.example", public, local, probe.CertValid, closedPort,
			model.VerdictUnknown, "TCP connection to the real address failed", []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("93.184.215.14"), closedPort)}},
		{"DoH failure", "open.example", public, staticResolver{err: errors.New("doh down")}, probe.CertValid, port,
			model.VerdictUnknown, "DNS lookup failed: doh down", nil},
		{"DoH empty", "open.example", public, staticResolver{}, probe.CertValid, port,
			model.VerdictUnknown, "DoH returned no address", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := &fakeVerifier{outcome: tt.cert}
			s := scanner{system: tt.system, trusted: tt.trusted, verify: verify, port: tt.port, timeout: 2 * time.Second}
			got := s.scanDomain(context.Background(), tt.domain)
			if got.Domain != tt.domain || got.Verdict != tt.wantVerdict || got.Reason != tt.wantReason {
				t.Errorf("scanDomain = %+v; want verdict %v, reason %q", got, tt.wantVerdict, tt.wantReason)
			}
			if got.CheckedAt.IsZero() {
				t.Error("CheckedAt is not set")
			}
			if !slices.Equal(verify.asked, tt.wantAsked) {
				t.Errorf("certificate check ran on %v; want %v", verify.asked, tt.wantAsked)
			}
		})
	}
}

func TestScanFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string // text the error must contain
	}{
		{"parallel 0 would deadlock", []string{"scan", "--parallel", "0", "a.example"}, "--parallel"},
		{"negative parallel", []string{"scan", "--parallel", "-1", "a.example"}, "--parallel"},
		{"zero timeout", []string{"scan", "--timeout", "0", "a.example"}, "--timeout"},
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

func TestPrintTable(t *testing.T) {
	results := []model.ProbeResult{
		{Domain: "example.com", Verdict: model.VerdictAccessible, Reason: "TLS handshake succeeded"},
		{Domain: "x.com", Verdict: model.VerdictSNIBlocking, Reason: "the server answers other names but not this one"},
	}
	var out bytes.Buffer
	if err := printTable(&out, results); err != nil {
		t.Fatal(err)
	}
	want := "DOMAIN       VERDICT       REASON\n" +
		"example.com  accessible    TLS handshake succeeded\n" +
		"x.com        sni_blocking  the server answers other names but not this one\n"
	if out.String() != want {
		t.Errorf("printTable wrote\n%s\nwant\n%s", out.String(), want)
	}
}

func TestScanNeedsADomain(t *testing.T) {
	if _, err := run(t, "scan"); err == nil {
		t.Error("scan without domains: error = nil; want an error")
	}
}

func TestIntegrationScanJSON(t *testing.T) {
	if os.Getenv("DPIPRISMA_INTEGRATION") == "" {
		t.Skip("set DPIPRISMA_INTEGRATION=1 to run tests that need the internet")
	}
	out, err := run(t, "scan", "--json", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var results []model.ProbeResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if len(results) != 1 || results[0].Verdict != model.VerdictAccessible {
		t.Errorf("results = %+v; want example.com accessible", results)
	}
	if strings.Contains(out, "level=") {
		t.Error("log lines leaked into the JSON output")
	}
}
