package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/locate"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
	"github.com/spf13/cobra"
)

// printLocate writes the locate report for domain at addr: how the first,
// full-TTL attempt was reset and, if it was, what the TTL walks found.
func printLocate(w io.Writer, domain string, addr netip.AddrPort, first probe.TLSResult, rep locate.Report) {
	line := func(label, text string) {
		fmt.Fprintf(w, "%-10s%s\n", label, text)
	}

	line("target", fmt.Sprintf("%s (%v)", domain, addr))

	if first.Outcome != probe.TLSReset {
		line("reset", fmt.Sprintf("none (%v): this name is not blocked by a reset", first.Outcome))
		return
	}
	timing := "no timing anomaly"
	if first.EarlyReset() {
		timing = "injected (faster than the server could answer)"
	}
	line("reset", fmt.Sprintf("%.1f ms after the ClientHello, handshake %.1f ms: %s",
		ms(first.Elapsed), ms(first.Connect), timing))

	ttl, votes := rep.DPI()
	if ttl > 0 {
		line("dpi", fmt.Sprintf("about %d hops away (%d of %d runs agree)", ttl, votes, len(rep.DPITTLs)))
	} else {
		line("dpi", fmt.Sprintf("no reset at any TTL (%d of %d runs agree)", votes, len(rep.DPITTLs)))
	}

	if lo, hi, ok := rep.ServerRange(); ok {
		line("server", span(lo, hi)+" hops away")
	} else {
		line("server", "the control name was never answered")
	}

	if lo, hi, ok := rep.FakeTTLRange(); ok {
		line("fake-ttl", span(lo, hi))
	} else {
		line("fake-ttl", "none found")
	}
}

// span writes lo..hi as "3" when both are equal, otherwise as "3-5".
func span(lo, hi int) string {
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// ms converts d to milliseconds with sub-millisecond precision, e.g. 4.4.
func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// newLocateCmd builds "dpiprisma locate".
func newLocateCmd() *cobra.Command {
	var (
		runs    int
		timeout time.Duration
		maxTTL  int
		gap     time.Duration
		control string
		doh     string
	)

	cmd := &cobra.Command{
		Use:   "locate DOMAIN",
		Short: "Find how many hops away the device that blocks a domain sits",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			ctx := cmd.Context()

			// Check the flags before touching the network, so a bad value
			// fails at once instead of after the first probe.
			if runs < 1 {
				return fmt.Errorf("--runs must be at least 1, got %d", runs)
			}
			if maxTTL < 1 || maxTTL > 255 {
				return fmt.Errorf("--max-ttl must be between 1 and 255, got %d", maxTTL)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, got %v", timeout)
			}

			trusted := probe.DoHResolver{
				URL:    doh,
				Client: &http.Client{Timeout: timeout},
			}
			ips, err := trusted.LookupA(ctx, domain)
			if err != nil {
				return fmt.Errorf("resolve %s: %w", domain, err)
			}
			if len(ips) == 0 {
				return fmt.Errorf("resolve %s: no address", domain)
			}
			addr := netip.AddrPortFrom(ips[0], 443)

			first := probe.ProbeTLS(ctx, addr, domain, timeout)
			if first.Outcome != probe.TLSReset {
				printLocate(cmd.OutOrStdout(), domain, addr, first, locate.Report{})
				return nil
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "probing %s %d times; this can take a minute or two\n", domain, runs)

			target := locate.TLSHelloProber{Dst: addr, SNI: domain, Timeout: timeout}
			ctrl := locate.TLSHelloProber{Dst: addr, SNI: control, Timeout: timeout}

			rep, err := locate.Locate(ctx, target, ctrl, runs, locate.FindOptions{MaxTTL: maxTTL, Gap: gap})
			if err != nil {
				return err
			}
			printLocate(cmd.OutOrStdout(), domain, addr, first, rep)
			return nil
		},
	}

	cmd.Flags().IntVar(&runs, "runs", 3, "how many times to repeat the search")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "time limit for each probe")
	cmd.Flags().IntVar(&maxTTL, "max-ttl", 30, "highest TTL to try")
	cmd.Flags().DurationVar(&gap, "gap", 100*time.Millisecond, "pause between probes")
	cmd.Flags().StringVar(&control, "control", "example.com", "harmless name sent to measure the server's distance")
	cmd.Flags().StringVar(&doh, "doh", "https://cloudflare-dns.com/dns-query", "trusted DNS-over-HTTPS server")
	return cmd
}
