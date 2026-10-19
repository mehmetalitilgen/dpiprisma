package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
)

// update rewrites the golden files: go test ./internal/report -update
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// sample is a small but complete set of results: one domain blocked by SNI
// and tested by the matrix, one only located, one poisoned, one fine.
func sample() Results {
	at := time.Date(2026, 10, 19, 12, 30, 0, 0, time.UTC)
	return Results{
		Generated: at,
		Version:   "v1.0.0",
		Scan: []model.ProbeResult{
			{Domain: "blocked.example", Verdict: model.VerdictSNIBlocking, Reason: "the server answers other names but not this one", CheckedAt: at},
			{Domain: "poisoned.example", Verdict: model.VerdictDNSPoisoning, Reason: "system DNS returned a bogus address", CheckedAt: at},
			{Domain: "example.com", Verdict: model.VerdictAccessible, Reason: "TLS handshake succeeded", CheckedAt: at},
		},
		Locate: []model.LocateResult{
			{Domain: "blocked.example", Blocked: true, Runs: 3, DPIHops: 3, DPIVotes: 3, ServerMin: 6, ServerMax: 7, FakeTTLMin: 3, FakeTTLMax: 5},
			{Domain: "located.example", Blocked: true, Runs: 3, DPIHops: 4, DPIVotes: 2, ServerMin: 9, ServerMax: 9, FakeTTLMin: 4, FakeTTLMax: 8},
		},
		Matrix: []model.StrategyResult{
			{Domain: "blocked.example", Strategy: "split", Params: map[string]int{"at": 10}, Runs: 10, Successes: 6, P50: 51 * time.Millisecond, P95: 90 * time.Millisecond},
			{Domain: "blocked.example", Strategy: "split", Params: map[string]int{"at": 2}, Runs: 10, Successes: 9, P50: 48 * time.Millisecond, P95: 70 * time.Millisecond},
			{Domain: "blocked.example", Strategy: "baseline", Runs: 10, Successes: 0},
			{Domain: "blocked.example", Strategy: "fakech", Params: map[string]int{"ttl": 4}, Runs: 10, Successes: 10, P50: 44500 * time.Microsecond, P95: 60 * time.Millisecond},
			{Domain: "blocked.example", Strategy: "fakerst", Params: map[string]int{"ttl": 4}, Runs: 10, Successes: 2, P50: 47 * time.Millisecond, P95: 47 * time.Millisecond},
			{Domain: "example.com", Strategy: "baseline", Runs: 10, Successes: 10, P50: 30 * time.Millisecond, P95: 35 * time.Millisecond},
		},
	}
}

// golden compares got with testdata/name, or rewrites the file with -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	// Git may check the golden file and the embedded template out with CRLF
	// line endings on Windows; compare lines, not line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the output; run with -update and review the diff\n--- got ---\n%s", path, got)
	}
}

func TestMarkdownGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.md", buf.Bytes())
}

func TestHTMLGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.html", buf.Bytes())
}

func TestMarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, Results{}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "# dpiprisma report\n"; got != want {
		t.Errorf("Markdown(empty) = %q; want %q", got, want)
	}
}

func TestHTMLEscapes(t *testing.T) {
	r := Results{Scan: []model.ProbeResult{{Domain: "<script>alert(1)</script>", Reason: `"quoted" & <b>`}}}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("<script>alert")) || bytes.Contains(buf.Bytes(), []byte("<b>")) {
		t.Errorf("HTML did not escape untrusted text:\n%s", buf.String())
	}
}

func TestMarkdownCellEscapes(t *testing.T) {
	if got, want := cell("a|b\nc"), `a\|b c`; got != want {
		t.Errorf("cell() = %q; want %q", got, want)
	}
}

func TestBuildGrid(t *testing.T) {
	g := buildGrid(sample().Matrix)

	wantCols := []string{"baseline", "fakech ttl=4", "fakerst ttl=4", "split at=2", "split at=10"}
	if !reflect.DeepEqual(g.Columns, wantCols) {
		t.Errorf("Columns = %q; want %q", g.Columns, wantCols)
	}
	if len(g.Rows) != 2 || g.Rows[0].Domain != "blocked.example" || g.Rows[1].Domain != "example.com" {
		t.Fatalf("Rows = %+v; want blocked.example then example.com", g.Rows)
	}
	if r := g.Rows[0].Cells[3]; r == nil || r.Successes != 9 {
		t.Errorf("blocked.example / split at=2 = %+v; want the 9/10 result", r)
	}
	for i, c := range g.Rows[1].Cells[1:] {
		if c != nil {
			t.Errorf("example.com column %d = %+v; want nil (not measured)", i+1, c)
		}
	}
}

func TestHeatStep(t *testing.T) {
	tests := []struct {
		rate float64
		want int
	}{
		{0, 0}, {0.19, 0}, {0.2, 1}, {0.5, 2}, {0.79, 3}, {0.8, 4}, {1, 4},
	}
	for _, tt := range tests {
		if got := heatStep(tt.rate); got != tt.want {
			t.Errorf("heatStep(%v) = %d; want %d", tt.rate, got, tt.want)
		}
	}
}
