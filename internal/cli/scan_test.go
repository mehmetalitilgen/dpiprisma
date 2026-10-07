package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
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

func TestScanDomain(t *testing.T) {
	port := fakeTLSServer(t, "blocked.example")
	local := staticResolver{addrs: []string{"127.0.0.1"}} // DoH: the real address is our fake server
	public := staticResolver{addrs: []string{"93.184.215.14"}}

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
		port        uint16
		wantVerdict model.Verdict
		wantReason  string
	}{
		{"accessible", "open.example", public, local, port,
			model.VerdictAccessible, "TLS handshake succeeded; DNS answers differ (CDN?)"},
		{"SNI blocking", "blocked.example", public, local, port,
			model.VerdictSNIBlocking, "the server answers other names but not this one"},
		{"bogus system DNS", "open.example", staticResolver{addrs: []string{"127.0.0.1"}}, local, port,
			model.VerdictDNSPoisoning, "system DNS returned a bogus address"},
		{"system NXDOMAIN", "open.example", staticResolver{err: probe.ErrNXDomain}, local, port,
			model.VerdictDNSPoisoning, "system DNS says the domain does not exist"},
		{"TCP refused", "open.example", public, local, closedPort,
			model.VerdictUnknown, "TCP connection to the real address failed"},
		{"DoH failure", "open.example", public, staticResolver{err: errors.New("doh down")}, port,
			model.VerdictUnknown, "DNS lookup failed: doh down"},
		{"DoH empty", "open.example", public, staticResolver{}, port,
			model.VerdictUnknown, "DoH returned no address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanDomain(context.Background(), tt.domain, tt.system, tt.trusted, tt.port, 2*time.Second)
			if got.Domain != tt.domain || got.Verdict != tt.wantVerdict || got.Reason != tt.wantReason {
				t.Errorf("scanDomain = %+v; want verdict %v, reason %q", got, tt.wantVerdict, tt.wantReason)
			}
			if got.CheckedAt.IsZero() {
				t.Error("CheckedAt is not set")
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
