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

// scanDomain runs the DNS, TCP and TLS probes for domain and classifies the
// result. TCP and TLS go to the first address from the trusted resolver, since
// the system answer may be poisoned. port is 443 outside of tests.
func scanDomain(ctx context.Context, domain string, system, trusted probe.Resolver, port uint16, timeout time.Duration) model.ProbeResult {
	probeResult := model.ProbeResult{
		Domain:    domain,
		CheckedAt: time.Now().UTC(),
	}

	dnsCmp, err := probe.CompareDNS(ctx, system, trusted, domain)

	if err != nil {
		probeResult.Reason = fmt.Sprintf("DNS lookup failed: %v", err)
		return probeResult
	}

	if len(dnsCmp.Trusted) == 0 {
		probeResult.Reason = "DoH returned no address"
		return probeResult
	}

	slog.Debug("dns", "domain", domain, "system", dnsCmp.System, "trusted", dnsCmp.Trusted)

	firstIP := dnsCmp.Trusted[0]

	addr := netip.AddrPortFrom(firstIP, port)

	tcp := probe.ProbeTCP(ctx, addr, timeout)
	slog.Debug("tcp", "domain", domain, "addr", addr, "outcome", tcp.Outcome, "elapsed", tcp.Elapsed)

	evidence := model.Evidence{
		DNSBogus:     dnsCmp.Bogus,
		DNSNXDomain:  len(dnsCmp.System) == 0, // system DNS gave nothing, DoH did (checked above)
		DNSMismatch:  dnsCmp.Mismatch,
		TCPConnected: tcp.Outcome == probe.TCPConnected,
		TCPTimeout:   tcp.Outcome == probe.TCPTimeout,
	}

	if tcp.Outcome == probe.TCPConnected {
		cmpSNI := probe.CompareSNI(ctx, addr, domain, timeout)
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
			system := &probe.SystemResolver{}
			trusted := &probe.DoHResolver{
				URL:    dohURL,
				Client: &http.Client{Timeout: timeout},
			}

			results := make([]model.ProbeResult, len(args))
			var g errgroup.Group
			g.SetLimit(parallel)
			for i, domain := range args {
				g.Go(func() error {
					// Each goroutine writes only its own cell, so no lock is needed.
					results[i] = scanDomain(cmd.Context(), domain, system, trusted, 443, timeout)
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
