package report

import (
	"reflect"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
)

func TestRecommend(t *testing.T) {
	got := Recommend(sample())
	want := []Advice{
		{
			Domain: "blocked.example",
			Note:   "Best: fakech ttl=4.",
			Commands: []Command{
				{Tool: "gecit", Line: "sudo gecit run --fake-ttl 4", Basis: "fakech ttl=4: 10/10, median 44.5 ms"},
				{Tool: "zapret", Line: "nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=4", Basis: "fakech ttl=4: 10/10, median 44.5 ms"},
				{Tool: "GoodbyeDPI", Line: "goodbyedpi.exe --set-ttl 4", Basis: "fakech ttl=4: 10/10, median 44.5 ms"},
				{Tool: "byedpi", Line: "ciadpi --fake -1 --ttl 4", Basis: "fakech ttl=4: 10/10, median 44.5 ms"},
			},
		},
		{Domain: "poisoned.example", Note: "DNS poisoning: use an encrypted resolver (DoH or DoT); gecit has one built in."},
		{Domain: "example.com", Note: "Not blocked: a plain ClientHello succeeded 10 of 10 times."},
		{
			Domain: "located.example",
			Note:   `Not tested by the matrix; run "dpiprisma matrix" to confirm.`,
			Commands: []Command{
				{Tool: "gecit", Line: "sudo gecit run --fake-ttl 4", Basis: "fake-ttl 4-8 from locate; not tested"},
				{Tool: "zapret", Line: "nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=4", Basis: "fake-ttl 4-8 from locate; not tested"},
				{Tool: "GoodbyeDPI", Line: "goodbyedpi.exe --set-ttl 4", Basis: "fake-ttl 4-8 from locate; not tested"},
				{Tool: "byedpi", Line: "ciadpi --fake -1 --ttl 4", Basis: "fake-ttl 4-8 from locate; not tested"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Recommend() =\n%+v\nwant\n%+v", got, want)
	}
}

// matrixOnly wraps strategy results for one domain into Results.
func matrixOnly(rs ...model.StrategyResult) Results {
	for i := range rs {
		rs[i].Domain = "d.example"
	}
	return Results{Matrix: rs}
}

func TestRecommendPicksPerTool(t *testing.T) {
	// fakech is best overall, but only split is something every tool except
	// gecit can do; disorder ties split on rate and loses on latency.
	r := matrixOnly(
		model.StrategyResult{Strategy: "baseline", Runs: 10},
		model.StrategyResult{Strategy: "split", Params: map[string]int{"at": 1}, Runs: 10, Successes: 9, P50: 40 * time.Millisecond},
		model.StrategyResult{Strategy: "disorder", Params: map[string]int{"at": 1, "ttl": 1}, Runs: 10, Successes: 9, P50: 60 * time.Millisecond},
		model.StrategyResult{Strategy: "fakerst", Params: map[string]int{"ttl": 3}, Runs: 10, Successes: 10, P50: 50 * time.Millisecond},
	)
	a := Recommend(r)[0]

	if a.Note != "Best: fakerst ttl=3." {
		t.Errorf("Note = %q", a.Note)
	}
	want := map[string]string{
		"zapret":     "nfqws --qnum=200 --dpi-desync=rst --dpi-desync-ttl=3",
		"GoodbyeDPI": "goodbyedpi.exe -e 1 --native-frag",
		"byedpi":     "ciadpi --split 1",
	}
	got := make(map[string]string)
	for _, c := range a.Commands {
		got[c.Tool] = c.Line
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commands = %v; want %v", got, want)
	}
}

func TestRecommendNothingWorks(t *testing.T) {
	a := Recommend(matrixOnly(
		model.StrategyResult{Strategy: "baseline", Runs: 10},
		model.StrategyResult{Strategy: "split", Params: map[string]int{"at": 1}, Runs: 10, Successes: 7},
	))[0]
	if a.Note != "No strategy succeeded at least 80% of the time." || len(a.Commands) != 0 {
		t.Errorf("advice = %+v", a)
	}
}

func TestRecommendMissingParam(t *testing.T) {
	// Without "ttl" no command can be written, even though fakech worked.
	a := Recommend(matrixOnly(
		model.StrategyResult{Strategy: "fakech", Runs: 10, Successes: 10},
	))[0]
	if a.Note != "fakech works, but none of the tools offers it." || len(a.Commands) != 0 {
		t.Errorf("advice = %+v", a)
	}
}

func TestRecommendBlackholeAndUnknown(t *testing.T) {
	got := Recommend(Results{Scan: []model.ProbeResult{
		{Domain: "hole.example", Verdict: model.VerdictIPBlackhole},
		{Domain: "odd.example", Verdict: model.VerdictUnknown},
	}})
	want := []Advice{
		{Domain: "hole.example", Note: "IP blackhole: packets to the address are dropped; only a VPN or proxy helps."},
		{Domain: "odd.example", Note: "No data to base a command on."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Recommend() = %+v; want %+v", got, want)
	}
}

func TestRecommendLocateNotBlocked(t *testing.T) {
	got := Recommend(Results{Locate: []model.LocateResult{{Domain: "fine.example"}}})
	if len(got) != 1 || got[0].Note != "Not blocked; nothing to do." {
		t.Errorf("Recommend() = %+v", got)
	}
}

func TestCommandFor(t *testing.T) {
	tests := []struct {
		tool, strategy string
		params         map[string]int
		want           string // "" means no command
	}{
		{"gecit", "fakech", map[string]int{"ttl": 5}, "sudo gecit run --fake-ttl 5"},
		{"gecit", "split", map[string]int{"at": 1}, ""},
		{"zapret", "split", map[string]int{"at": 2}, "nfqws --qnum=200 --dpi-desync=multisplit --dpi-desync-split-pos=2"},
		{"zapret", "disorder", map[string]int{"at": 1, "ttl": 1}, "nfqws --qnum=200 --dpi-desync=multidisorder --dpi-desync-split-pos=1"},
		{"zapret", "fakech", map[string]int{"ttl": 5}, "nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=5"},
		{"zapret", "fakerst", map[string]int{"ttl": 5}, "nfqws --qnum=200 --dpi-desync=rst --dpi-desync-ttl=5"},
		{"GoodbyeDPI", "split", map[string]int{"at": 2}, "goodbyedpi.exe -e 2 --native-frag"},
		{"GoodbyeDPI", "disorder", map[string]int{"at": 2}, "goodbyedpi.exe -e 2 --reverse-frag"},
		{"GoodbyeDPI", "fakech", map[string]int{"ttl": 5}, "goodbyedpi.exe --set-ttl 5"},
		{"GoodbyeDPI", "fakerst", map[string]int{"ttl": 5}, ""},
		{"byedpi", "split", map[string]int{"at": 2}, "ciadpi --split 2"},
		{"byedpi", "disorder", map[string]int{"at": 2}, "ciadpi --disorder 2"},
		{"byedpi", "fakech", map[string]int{"ttl": 5}, "ciadpi --fake -1 --ttl 5"},
		{"byedpi", "fakech", nil, ""},
		{"zapret", "baseline", nil, ""},
	}
	for _, tt := range tests {
		line, ok := commandFor(tt.tool, model.StrategyResult{Strategy: tt.strategy, Params: tt.params})
		if line != tt.want || ok != (tt.want != "") {
			t.Errorf("commandFor(%s, %s %v) = %q, %v; want %q", tt.tool, tt.strategy, tt.params, line, ok, tt.want)
		}
	}
}
