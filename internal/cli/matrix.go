package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"text/tabwriter"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
	"github.com/mehmetalitilgen/dpiprisma/internal/runner"
	"github.com/mehmetalitilgen/dpiprisma/internal/strategy"
	"github.com/spf13/cobra"
)

// plan is one strategy together with the parameters that built it. The
// strategy's Name carries no parameters, so the matrix command remembers them
// here and copies them into each StrategyResult for the report.
type plan struct {
	strat  strategy.Strategy
	params map[string]int // nil for a strategy with no parameters, e.g. baseline
}

// buildPlans returns the strategies the matrix tries, in a stable order:
// baseline, split, disorder, then a fakech and a fakerst for each TTL in
// fakeTTLs. split and disorder have no exported constructor, so their
// registered defaults are used and recorded as {"at": 1}.
func buildPlans(fakeTTLs []int) ([]plan, error) {
	plans := make([]plan, 0, 3+2*len(fakeTTLs))

	for _, name := range []string{"baseline", "split", "disorder"} {
		s, err := strategy.Get(name)
		if err != nil {
			return nil, fmt.Errorf("matrix: %w", err)
		}
		var params map[string]int
		if name != "baseline" {
			params = map[string]int{"at": 1}
		}
		plans = append(plans, plan{strat: s, params: params})
	}

	for _, ttl := range fakeTTLs {
		plans = append(plans,
			plan{strat: strategy.NewFakeCH(ttl), params: map[string]int{"ttl": ttl}},
			plan{strat: strategy.NewFakeRST(ttl), params: map[string]int{"ttl": ttl}},
		)
	}

	return plans, nil
}

// strategies pulls the strategy values out of plans, in order, for runner.Run.
func strategies(plans []plan) []strategy.Strategy {
	out := make([]strategy.Strategy, len(plans))
	for i, p := range plans {
		out[i] = p.strat
	}
	return out
}

// toResults zips the runner's results back with the plans that produced them
// (runner.Run keeps the input order) and fills in the domain and parameters
// the report needs.
func toResults(domain string, plans []plan, results []runner.Result) []model.StrategyResult {
	out := make([]model.StrategyResult, len(results))
	for i, r := range results {
		out[i] = model.StrategyResult{
			Domain:    domain,
			Strategy:  r.Name,
			Params:    plans[i].params,
			Runs:      r.Runs,
			Successes: r.Successes,
			P50:       r.P50(),
			P95:       r.P95(),
		}
	}
	return out
}

// printMatrix writes the results as an aligned text table.
func printMatrix(w io.Writer, results []model.StrategyResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "strategy\truns\tok\trate\tp50\tp95")
	for _, r := range results {
		p50, p95 := "-", "-"
		if r.Successes > 0 {
			p50 = r.P50.Round(time.Millisecond).String()
			p95 = r.P95.Round(time.Millisecond).String()
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.0f%%\t%s\t%s\n",
			r.Label(), r.Runs, r.Successes, r.SuccessRate()*100, p50, p95)
	}
	tw.Flush()
}

// newMatrixCmd builds "dpiprisma matrix".
func newMatrixCmd() *cobra.Command {
	var (
		runs     int
		rate     float64
		timeout  time.Duration
		fakeTTLs []int
		doh      string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "matrix DOMAIN",
		Short: "Try every bypass strategy against a domain and score them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			ctx := cmd.Context()

			// Check the flags before touching the network, so a bad value
			// fails at once instead of after the first connection.
			if runs < 1 {
				return fmt.Errorf("--runs must be at least 1, got %d", runs)
			}
			if rate < 0 {
				return fmt.Errorf("--rate must not be negative, got %v", rate)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, got %v", timeout)
			}
			for _, ttl := range fakeTTLs {
				if ttl < 1 || ttl > 255 {
					return fmt.Errorf("--fake-ttl values must be between 1 and 255, got %d", ttl)
				}
			}

			plans, err := buildPlans(fakeTTLs)
			if err != nil {
				return err
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

			fmt.Fprintf(cmd.ErrOrStderr(), "trying %d strategies against %s %d times each\n",
				len(plans), domain, runs)

			results, err := runner.Run(ctx, addr, domain, strategies(plans), runs,
				runner.Options{Timeout: timeout, RatePerSec: rate})
			if err != nil {
				return err
			}

			out := toResults(domain, plans, results)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			printMatrix(cmd.OutOrStdout(), out)
			return nil
		},
	}

	cmd.Flags().IntVar(&runs, "runs", 10, "how many times to try each strategy")
	cmd.Flags().Float64Var(&rate, "rate", 5, "most connections to open per second")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "time limit for each connection")
	cmd.Flags().IntSliceVar(&fakeTTLs, "fake-ttl", []int{6}, "TTLs to try for the fakech and fakerst strategies")
	cmd.Flags().StringVar(&doh, "doh", "https://cloudflare-dns.com/dns-query", "trusted DNS-over-HTTPS server")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "write JSON for \"dpiprisma report\" instead of a table")
	return cmd
}
