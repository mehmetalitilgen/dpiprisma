// Package report turns saved scan, locate and matrix results into Markdown
// and HTML reports, with ready-to-use commands for circumvention tools.
package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
)

// Results is everything a report shows. Any part may be empty; the report
// leaves out the sections it has no data for.
type Results struct {
	Generated time.Time              // when the report was made; zero leaves it out
	Version   string                 // dpiprisma version that made the report
	Scan      []model.ProbeResult    // from "dpiprisma scan --json"
	Locate    []model.LocateResult   // from "dpiprisma locate --json"
	Matrix    []model.StrategyResult // from "dpiprisma matrix --json"
}

// grid is the strategy matrix laid out as a table: one row per domain, one
// column per strategy label.
type grid struct {
	Columns []string  // strategy labels, baseline first
	Rows    []gridRow // domains in the order they first appear
}

// gridRow is one domain's line of the matrix.
type gridRow struct {
	Domain string
	Cells  []*model.StrategyResult // one per column; nil where nothing was measured
}

// buildGrid lays results out as a grid. If the same domain and label appear
// twice, the first one wins.
func buildGrid(results []model.StrategyResult) grid {
	sorted := slices.Clone(results)
	slices.SortStableFunc(sorted, compareStrategies)

	var g grid
	column := make(map[string]int) // label -> column index
	for _, r := range sorted {
		label := r.Label()
		if _, ok := column[label]; !ok {
			column[label] = len(g.Columns)
			g.Columns = append(g.Columns, label)
		}
	}

	row := make(map[string]int) // domain -> row index
	for i := range results {
		r := &results[i]
		ri, ok := row[r.Domain]
		if !ok {
			ri = len(g.Rows)
			row[r.Domain] = ri
			g.Rows = append(g.Rows, gridRow{Domain: r.Domain, Cells: make([]*model.StrategyResult, len(g.Columns))})
		}
		ci := column[r.Label()]
		if g.Rows[ri].Cells[ci] == nil {
			g.Rows[ri].Cells[ci] = r
		}
	}
	return g
}

// compareStrategies orders results for display: baseline first, then by
// strategy name, then by parameters with numbers compared as numbers, so
// that "at=2" comes before "at=10".
func compareStrategies(a, b model.StrategyResult) int {
	if (a.Strategy == "baseline") != (b.Strategy == "baseline") {
		if a.Strategy == "baseline" {
			return -1
		}
		return 1
	}
	if c := strings.Compare(a.Strategy, b.Strategy); c != 0 {
		return c
	}
	return compareParams(a.Params, b.Params)
}

// compareParams compares two parameter sets key by key in sorted key order.
func compareParams(a, b map[string]int) int {
	ka, kb := sortedKeys(a), sortedKeys(b)
	for i := 0; i < len(ka) && i < len(kb); i++ {
		if c := strings.Compare(ka[i], kb[i]); c != 0 {
			return c
		}
		if c := cmp.Compare(a[ka[i]], b[kb[i]]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ka), len(kb))
}

// sortedKeys returns the keys of m in sorted order.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// percent writes a success rate as a whole percentage, e.g. "90%".
func percent(rate float64) string {
	return fmt.Sprintf("%.0f%%", rate*100)
}

// ms writes d in milliseconds with one decimal, e.g. "42.0 ms".
func ms(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
}

// span writes lo..hi as "3" when both are equal, otherwise as "3-5".
func span(lo, hi int) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// locateSummary returns the reset, DPI, server and fake-TTL columns that
// both report formats show for one located domain.
func locateSummary(l model.LocateResult) (reset, dpi, server, fakeTTL string) {
	if !l.Blocked {
		return "no", "-", "-", "-"
	}
	reset = "yes"

	dpi = "not found"
	if l.DPIHops > 0 {
		dpi = fmt.Sprintf("%d hops (%d of %d runs)", l.DPIHops, l.DPIVotes, l.Runs)
	}

	server = "no answer"
	if l.ServerMin > 0 {
		server = span(l.ServerMin, l.ServerMax) + " hops"
	}

	fakeTTL = "none"
	if l.FakeTTLMin > 0 {
		fakeTTL = span(l.FakeTTLMin, l.FakeTTLMax)
	}
	return reset, dpi, server, fakeTTL
}

// generatedLine returns the "Generated ... by ..." line, or "" when the
// results carry neither a time nor a version.
func generatedLine(r Results) string {
	var parts []string
	if !r.Generated.IsZero() {
		parts = append(parts, "Generated "+r.Generated.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if r.Version != "" {
		parts = append(parts, "by dpiprisma "+r.Version)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + "."
}
