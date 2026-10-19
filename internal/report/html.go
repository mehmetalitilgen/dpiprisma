package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed report.html.tmpl
var htmlSource string

// htmlTemplate is parsed once; a broken template is a programming error
// caught by the tests, so Must is fine here.
var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

// heatSteps is the number of color steps in the heat map; a cell's step is
// its success rate cut into this many equal bands.
const heatSteps = 5

// htmlPage is what the template sees. Everything is already formatted, so
// the template only lays it out.
type htmlPage struct {
	Generated string
	Scan      []htmlScanRow
	Locate    []htmlLocateRow
	Matrix    *htmlMatrix // nil without matrix results
	Advice    []Advice
	ToolsNote string
}

type htmlScanRow struct {
	Domain, Verdict, Reason string
}

type htmlLocateRow struct {
	Domain, Reset, DPI, Server, FakeTTL string
}

type htmlMatrix struct {
	Columns []string
	Rows    []htmlMatrixRow
}

type htmlMatrixRow struct {
	Domain string
	Cells  []htmlCell
}

// htmlCell is one heat map cell.
type htmlCell struct {
	Text  string // the success rate, e.g. "90%", or "-" when not measured
	Step  int    // color step, 0 to heatSteps-1; -1 when not measured
	Title string // tooltip with the raw numbers
}

// HTML writes r as a single self-contained HTML page with the strategy
// matrix drawn as a heat map. It needs no network to view.
func HTML(w io.Writer, r Results) error {
	page := htmlPage{
		Generated: generatedLine(r),
		Advice:    Recommend(r),
		ToolsNote: ToolsNote,
	}
	for _, s := range r.Scan {
		page.Scan = append(page.Scan, htmlScanRow{s.Domain, s.Verdict.String(), s.Reason})
	}
	for _, l := range r.Locate {
		reset, dpi, server, fakeTTL := locateSummary(l)
		page.Locate = append(page.Locate, htmlLocateRow{l.Domain, reset, dpi, server, fakeTTL})
	}
	if len(r.Matrix) > 0 {
		page.Matrix = heatMap(buildGrid(r.Matrix))
	}
	return htmlTemplate.Execute(w, page)
}

// heatMap formats g for the template.
func heatMap(g grid) *htmlMatrix {
	m := &htmlMatrix{Columns: g.Columns}
	for _, row := range g.Rows {
		hr := htmlMatrixRow{Domain: row.Domain}
		for i, r := range row.Cells {
			if r == nil {
				hr.Cells = append(hr.Cells, htmlCell{Text: "-", Step: -1, Title: g.Columns[i] + ": not measured"})
				continue
			}
			title := fmt.Sprintf("%s: %d of %d succeeded", g.Columns[i], r.Successes, r.Runs)
			if r.Successes > 0 {
				title += fmt.Sprintf(", median %s, p95 %s", ms(r.P50), ms(r.P95))
			}
			hr.Cells = append(hr.Cells, htmlCell{Text: percent(r.SuccessRate()), Step: heatStep(r.SuccessRate()), Title: title})
		}
		m.Rows = append(m.Rows, hr)
	}
	return m
}

// heatStep maps a success rate to a color step: [0, 0.2) is 0, ...,
// [0.8, 1] is heatSteps-1.
func heatStep(rate float64) int {
	step := int(rate * heatSteps)
	return max(0, min(step, heatSteps-1))
}
