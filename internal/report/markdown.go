package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Markdown writes r as a Markdown report: diagnosis, DPI location, strategy
// matrix and recommended commands, leaving out sections without data.
func Markdown(w io.Writer, r Results) error {
	bw := bufio.NewWriter(w)

	fmt.Fprintln(bw, "# dpiprisma report")
	if line := generatedLine(r); line != "" {
		fmt.Fprintf(bw, "\n%s\n", line)
	}

	if len(r.Scan) > 0 {
		fmt.Fprint(bw, "\n## Diagnosis\n\n")
		fmt.Fprintln(bw, "| Domain | Verdict | Reason |")
		fmt.Fprintln(bw, "|---|---|---|")
		for _, s := range r.Scan {
			fmt.Fprintf(bw, "| %s | %s | %s |\n", cell(s.Domain), s.Verdict, cell(s.Reason))
		}
	}

	if len(r.Locate) > 0 {
		fmt.Fprint(bw, "\n## DPI location\n\n")
		fmt.Fprintln(bw, "| Domain | Reset | DPI | Server | Fake TTL |")
		fmt.Fprintln(bw, "|---|---|---|---|---|")
		for _, l := range r.Locate {
			reset, dpi, server, fakeTTL := locateSummary(l)
			fmt.Fprintf(bw, "| %s | %s | %s | %s | %s |\n", cell(l.Domain), reset, dpi, server, fakeTTL)
		}
	}

	if len(r.Matrix) > 0 {
		writeMatrix(bw, buildGrid(r.Matrix))
	}

	if advice := Recommend(r); len(advice) > 0 {
		writeAdvice(bw, advice)
	}

	return bw.Flush()
}

// writeMatrix writes the strategy matrix with one column per strategy.
func writeMatrix(w io.Writer, g grid) {
	fmt.Fprint(w, "\n## Strategy matrix\n\n")
	fmt.Fprintln(w, "Share of connections that got a ServerHello; median latency in parentheses.")
	fmt.Fprintln(w)

	fmt.Fprint(w, "| Domain |")
	for _, c := range g.Columns {
		fmt.Fprintf(w, " %s |", cell(c))
	}
	fmt.Fprint(w, "\n|---|")
	fmt.Fprint(w, strings.Repeat("---|", len(g.Columns)))
	fmt.Fprintln(w)

	for _, row := range g.Rows {
		fmt.Fprintf(w, "| %s |", cell(row.Domain))
		for _, r := range row.Cells {
			switch {
			case r == nil:
				fmt.Fprint(w, " - |")
			case r.Successes == 0:
				fmt.Fprintf(w, " %s |", percent(r.SuccessRate()))
			default:
				fmt.Fprintf(w, " %s (%s) |", percent(r.SuccessRate()), ms(r.P50))
			}
		}
		fmt.Fprintln(w)
	}
}

// writeAdvice writes the recommended commands, one subsection per domain.
func writeAdvice(w io.Writer, advice []Advice) {
	fmt.Fprint(w, "\n## Recommended commands\n")
	for _, a := range advice {
		fmt.Fprintf(w, "\n### %s\n\n%s\n", a.Domain, a.Note)
		if len(a.Commands) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Tool | Command | Based on |")
		fmt.Fprintln(w, "|---|---|---|")
		for _, c := range a.Commands {
			fmt.Fprintf(w, "| %s | `%s` | %s |\n", c.Tool, c.Line, cell(c.Basis))
		}
	}
}

// cell escapes s for a Markdown table cell: a "|" would end the cell and a
// newline the row.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}
