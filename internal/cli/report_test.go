package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mehmetalitilgen/dpiprisma/internal/locate"
	"github.com/mehmetalitilgen/dpiprisma/internal/model"
	"github.com/mehmetalitilgen/dpiprisma/internal/probe"
)

// writeFile writes content to name in a fresh temporary directory and
// returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	scanJSON = `[
  {"domain": "blocked.example", "verdict": "sni_blocking", "reason": "the server answers other names but not this one", "checked_at": "2026-10-19T12:00:00Z"}
]`
	locateJSON = `{"domain": "blocked.example", "blocked": true, "runs": 3, "dpi_hops": 3, "dpi_votes": 3,
  "server_min": 6, "server_max": 7, "fake_ttl_min": 3, "fake_ttl_max": 5}`
	matrixJSON = `[
  {"domain": "blocked.example", "strategy": "baseline", "attempts": 10, "successes": 0, "p50_ns": 0, "p95_ns": 0},
  {"domain": "blocked.example", "strategy": "split", "params": {"at": 1}, "attempts": 10, "successes": 9, "p50_ns": 42000000, "p95_ns": 60000000}
]`
)

func TestReadResults(t *testing.T) {
	list, err := readResults[model.ProbeResult](writeFile(t, "scan.json", scanJSON))
	if err != nil || len(list) != 1 || list[0].Verdict != model.VerdictSNIBlocking {
		t.Errorf("list file: %+v, %v", list, err)
	}

	one, err := readResults[model.LocateResult](writeFile(t, "locate.json", "\n  "+locateJSON))
	if err != nil || len(one) != 1 || one[0].FakeTTLMax != 5 {
		t.Errorf("single object: %+v, %v", one, err)
	}

	if _, err := readResults[model.ProbeResult](writeFile(t, "bad.json", `[{"verdict": "nonsense"}]`)); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("bad verdict: error = %v; want one naming the file", err)
	}
	if _, err := readResults[model.ProbeResult](filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: want an error")
	}
}

func TestToUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"plain", []byte(`{"a":"ş"}`), `{"a":"ş"}`},
		{"utf-8 with mark", append([]byte{0xEF, 0xBB, 0xBF}, `[1]`...), `[1]`},
		// What Windows PowerShell 5.1 writes for: echo '[1]' > f.json
		{"utf-16 little endian", []byte{0xFF, 0xFE, '[', 0, '1', 0, ']', 0, '\r', 0, '\n', 0}, "[1]\r\n"},
		{"utf-16 big endian", []byte{0xFE, 0xFF, 0, '[', 0x01, 0x5F, 0, ']'}, "[ş]"},
	}
	for _, tt := range tests {
		if got := string(toUTF8(tt.in)); got != tt.want {
			t.Errorf("%s: toUTF8() = %q; want %q", tt.name, got, tt.want)
		}
	}
}

func TestReportFormat(t *testing.T) {
	tests := []struct {
		format, output, want string
		wantErr              bool
	}{
		{"", "", "md", false},
		{"", "out.md", "md", false},
		{"", "out.HTML", "html", false},
		{"", "out.htm", "html", false},
		{"md", "out.html", "md", false}, // the flag wins over the extension
		{"html", "", "html", false},
		{"pdf", "", "", true},
	}
	for _, tt := range tests {
		got, err := reportFormat(tt.format, tt.output)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("reportFormat(%q, %q) = %q, %v; want %q, error %v", tt.format, tt.output, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestReportCmd(t *testing.T) {
	scan := writeFile(t, "scan.json", scanJSON)
	loc := writeFile(t, "locate.json", locateJSON)
	matrix := writeFile(t, "matrix.json", matrixJSON)

	out, err := run(t, "report", "--scan", scan, "--locate", loc, "--matrix", matrix)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# dpiprisma report",
		"by dpiprisma 1.2.3.",
		"| blocked.example | sni_blocking |",
		"| blocked.example | yes | 3 hops (3 of 3 runs) | 6-7 hops | 3-5 |",
		"| blocked.example | 0% | 90% (42.0 ms) |",
		"`ciadpi --split 1`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report output does not contain %q:\n%s", want, out)
		}
	}

	html := filepath.Join(t.TempDir(), "report.html")
	if out, err := run(t, "report", "--scan", scan, "-o", html); err != nil || out != "" {
		t.Fatalf("report -o: output %q, error %v", out, err)
	}
	data, err := os.ReadFile(html)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!doctype html>") {
		t.Errorf("report.html does not start with a doctype:\n%.200s", data)
	}
}

func TestReportCmdErrors(t *testing.T) {
	bad := writeFile(t, "bad.json", "not json")
	tests := []struct {
		name string
		args []string
		want string // text the error must contain
	}{
		{"no input", []string{"report"}, "at least one"},
		{"bad format", []string{"report", "--scan", bad, "--format", "pdf"}, "--format"},
		{"bad file", []string{"report", "--scan", bad}, "bad.json"},
		{"stray argument", []string{"report", "extra"}, "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v; want one mentioning %q", err, tt.want)
			}
		})
	}
}

func TestLocateResult(t *testing.T) {
	reset := probe.TLSResult{Outcome: probe.TLSReset}
	tests := []struct {
		name  string
		first probe.TLSResult
		rep   locate.Report
		want  model.LocateResult
	}{
		{
			name:  "not blocked",
			first: probe.TLSResult{Outcome: probe.TLSServerHello},
			rep:   locate.Report{DPITTLs: []int{3}}, // ignored
			want:  model.LocateResult{Domain: "d.example"},
		},
		{
			name:  "found",
			first: reset,
			rep:   locate.Report{DPITTLs: []int{3, 3, 4}, ServerTTLs: []int{6, 7, 6}},
			want: model.LocateResult{Domain: "d.example", Blocked: true, Runs: 3, DPIHops: 3, DPIVotes: 2,
				ServerMin: 6, ServerMax: 7, FakeTTLMin: 3, FakeTTLMax: 5},
		},
		{
			name:  "no reset at any TTL",
			first: reset,
			rep:   locate.Report{DPITTLs: []int{0, 0}},
			want:  model.LocateResult{Domain: "d.example", Blocked: true, Runs: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := locateResult("d.example", tt.first, tt.rep); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("locateResult() = %+v; want %+v", got, tt.want)
			}
		})
	}
}
