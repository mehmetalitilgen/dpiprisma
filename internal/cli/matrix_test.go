package cli

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
	"github.com/mehmetalitilgen/dpiprisma/internal/runner"
)

func TestBuildPlans(t *testing.T) {
	plans, err := buildPlans([]int{4, 9})
	if err != nil {
		t.Fatal(err)
	}

	type want struct {
		name   string
		params map[string]int
	}
	wants := []want{
		{"baseline", nil},
		{"split", map[string]int{"at": 1}},
		{"disorder", map[string]int{"at": 1}},
		{"fakech", map[string]int{"ttl": 4}},
		{"fakerst", map[string]int{"ttl": 4}},
		{"fakech", map[string]int{"ttl": 9}},
		{"fakerst", map[string]int{"ttl": 9}},
	}
	if len(plans) != len(wants) {
		t.Fatalf("len(plans) = %d; want %d", len(plans), len(wants))
	}
	for i, w := range wants {
		if got := plans[i].strat.Name(); got != w.name {
			t.Errorf("plan[%d].Name = %q; want %q", i, got, w.name)
		}
		if got := plans[i].params; !sameParams(got, w.params) {
			t.Errorf("plan[%d].params = %v; want %v", i, got, w.params)
		}
	}
}

func sameParams(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestToResults(t *testing.T) {
	plans, err := buildPlans([]int{6})
	if err != nil {
		t.Fatal(err)
	}
	// One runner.Result per plan, in the same order.
	results := make([]runner.Result, len(plans))
	for i, p := range plans {
		results[i] = runner.Result{
			Name:      p.strat.Name(),
			Runs:      10,
			Successes: i, // arbitrary but distinct
			Latencies: []time.Duration{time.Duration(i+1) * time.Millisecond},
		}
	}

	out := toResults("pornhub.com", plans, results)
	if len(out) != len(plans) {
		t.Fatalf("len(out) = %d; want %d", len(out), len(plans))
	}
	for i := range out {
		if out[i].Domain != "pornhub.com" {
			t.Errorf("out[%d].Domain = %q; want pornhub.com", i, out[i].Domain)
		}
		if out[i].Strategy != plans[i].strat.Name() {
			t.Errorf("out[%d].Strategy = %q; want %q", i, out[i].Strategy, plans[i].strat.Name())
		}
		if !sameParams(out[i].Params, plans[i].params) {
			t.Errorf("out[%d].Params = %v; want %v", i, out[i].Params, plans[i].params)
		}
		if out[i].Runs != 10 || out[i].Successes != i {
			t.Errorf("out[%d] runs/successes = %d/%d; want 10/%d", i, out[i].Runs, out[i].Successes, i)
		}
	}
}

// The JSON must carry exactly the fields the report reads.
func TestToResultsJSONContract(t *testing.T) {
	plans, _ := buildPlans([]int{6})
	results := make([]runner.Result, len(plans))
	for i, p := range plans {
		results[i] = runner.Result{Name: p.strat.Name(), Runs: 3, Successes: 2,
			Latencies: []time.Duration{40 * time.Millisecond, 60 * time.Millisecond}}
	}
	out := toResults("example.com", plans, results)

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip into the very type the report uses.
	var back []model.StrategyResult
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("report cannot read matrix JSON: %v", err)
	}
	if len(back) != len(out) || back[0].Domain != "example.com" {
		t.Fatalf("round-trip lost data: %+v", back)
	}

	// baseline has no params and must omit the field; fakech must keep its ttl.
	var raw []map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	if _, ok := raw[0]["params"]; ok {
		t.Error("baseline emitted a params field; want it omitted")
	}
	for i, p := range plans {
		if p.strat.Name() == "fakech" {
			if _, ok := raw[i]["params"]; !ok {
				t.Error("fakech omitted its params")
			}
		}
	}
	for _, key := range []string{"domain", "strategy", "runs", "successes", "p50_ns", "p95_ns"} {
		if _, ok := raw[0][key]; !ok {
			t.Errorf("JSON missing contract field %q", key)
		}
	}
}

func TestPrintMatrix(t *testing.T) {
	results := []model.StrategyResult{
		{Domain: "d", Strategy: "baseline", Runs: 10, Successes: 0},
		{Domain: "d", Strategy: "split", Params: map[string]int{"at": 1}, Runs: 10, Successes: 9,
			P50: 41 * time.Millisecond, P95: 58 * time.Millisecond},
	}
	var buf bytes.Buffer
	printMatrix(&buf, results)
	out := buf.String()

	if !bytes.Contains(buf.Bytes(), []byte("baseline")) || !bytes.Contains(buf.Bytes(), []byte("split at=1")) {
		t.Errorf("table missing a strategy label:\n%s", out)
	}
	// A strategy with no successes shows "-" for latency, not 0s.
	if !bytes.Contains(buf.Bytes(), []byte("0%")) {
		t.Errorf("table missing the 0%% row:\n%s", out)
	}
}
