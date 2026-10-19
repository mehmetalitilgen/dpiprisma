package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"text/tabwriter"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// certVerifier is the part of probe.CertVerifier that scanDomain uses; tests
// replace it so that no real handshake is needed.
type certVerifier interface {
	Verify(ctx context.Context, addr netip.AddrPort, serverName string, timeout time.Duration) probe.CertResult
}

// scanner holds what scanDomain needs besides the domain itself.
type scanner struct {
	system  probe.Resolver // the operating system's resolver, which the ISP usually controls
	trusted probe.Resolver // a resolver the ISP cannot tamper with (DoH)
	verify  certVerifier   // checks the certificate of the address the system DNS gave
	port    uint16         // 443 outside of tests
	timeout time.Duration  // time limit for each network step
}

// scanDomain runs the DNS, TCP and TLS probes for domain and classifies the
// result. TCP and TLS go to the first address from the trusted resolver, since
// the system answer may be poisoned.
func (s scanner) scanDomain(ctx context.Context, domain string) model.ProbeResult {
	probeResult := model.ProbeResult{
		Domain:    domain,
		CheckedAt: time.Now().UTC(),
	}

	dnsCmp, err := probe.CompareDNS(ctx, s.system, s.trusted, domain)
	if err != nil {
		probeResult.Reason = fmt.Sprintf("DNS lookup failed: %v", err)
		return probeResult
	}

	if len(dnsCmp.Trusted) == 0 {
		probeResult.Reason = "DoH returned no address"
		return probeResult
	}

	slog.Debug("dns", "domain", domain, "system", dnsCmp.System, "trusted", dnsCmp.Trusted)

	evidence := model.Evidence{
		DNSBogus:    dnsCmp.Bogus,
		DNSNXDomain: dnsCmp.NXDomain,
		DNSMismatch: dnsCmp.Mismatch,
	}

	// A system answer that differs from DoH is either a CDN node or an ISP
	// block page. Only the real site can present a certificate for the domain.
	if dnsCmp.Mismatch && !dnsCmp.Bogus && len(dnsCmp.System) > 0 {
		systemAddr := netip.AddrPortFrom(dnsCmp.System[0], s.port)
		cert := s.verify.Verify(ctx, systemAddr, domain, s.timeout)
		slog.Debug("cert", "domain", domain, "addr", systemAddr, "outcome", cert.Outcome, "err", cert.Err)
		evidence.DNSRedirectBadCert = cert.Outcome == probe.CertInvalid
	}

	addr := netip.AddrPortFrom(dnsCmp.Trusted[0], s.port)

	tcp := probe.ProbeTCP(ctx, addr, s.timeout)
	slog.Debug("tcp", "domain", domain, "addr", addr, "outcome", tcp.Outcome, "elapsed", tcp.Elapsed)
	evidence.TCPConnected = tcp.Outcome == probe.TCPConnected
	evidence.TCPTimeout = tcp.Outcome == probe.TCPTimeout

	if tcp.Outcome == probe.TCPConnected {
		cmpSNI := probe.CompareSNI(ctx, addr, domain, s.timeout)
		slog.Debug("tls", "domain", domain, "control", cmpSNI.Control.Outcome, "target", cmpSNI.Target.Outcome)
		evidence.TLSControlAnswered = cmpSNI.Control.Outcome.Answered()
		evidence.TLSTargetAnswered = cmpSNI.Target.Outcome.Answered()
	}

	verdict, reason := model.Classify(evidence)

	probeResult.Verdict = verdict
	probeResult.Reason = reason

	return probeResult
}

// printTable writes results as an aligned DOMAIN / VERDICT / REASON table.
func printTable(w io.Writer, results []model.ProbeResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tVERDICT\tREASON")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Domain, r.Verdict, r.Reason)
	}
	return tw.Flush() // without Flush nothing reaches w
}

// newScanCmd builds "dpiprisma scan".
func newScanCmd() *cobra.Command {
	var (
		jsonOut  bool // set by --json
		timeout  time.Duration
		parallel int
		dohURL   string
	)

	cmd := &cobra.Command{
		Use:   "scan DOMAIN...",
		Short: "Probe domains and report how each one is blocked",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// errgroup treats a limit of 0 as "never start a goroutine", which
			// would deadlock below, so reject it up front.
			if parallel < 1 {
				return fmt.Errorf("--parallel must be at least 1, got %d", parallel)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, got %v", timeout)
			}

			s := scanner{
				system: &probe.SystemResolver{},
				trusted: &probe.DoHResolver{
					URL:    dohURL,
					Client: &http.Client{Timeout: timeout},
				},
				verify:  probe.CertVerifier{},
				port:    443,
				timeout: timeout,
			}

			results := make([]model.ProbeResult, len(args))
			var g errgroup.Group
			g.SetLimit(parallel)
			for i, domain := range args {
				g.Go(func() error {
					// Each goroutine writes only its own cell, so no lock is needed.
					results[i] = s.scanDomain(cmd.Context(), domain)
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(results)
			}
			return printTable(cmd.OutOrStdout(), results)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "write JSON instead of a table")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "time limit for each network step")
	cmd.Flags().IntVar(&parallel, "parallel", 4, "how many domains to scan at the same time")
	cmd.Flags().StringVar(&dohURL, "doh", "https://cloudflare-dns.com/dns-query", "trusted DNS-over-HTTPS server")
	return cmd
}
