package model

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestStrategyResultSuccessRate(t *testing.T) {
	tests := []struct {
		attempts, successes int
		want                float64
	}{
		{10, 10, 1},
		{10, 7, 0.7},
		{4, 0, 0},
		{0, 0, 0}, // nothing attempted: no division by zero
	}
	for _, tt := range tests {
		r := StrategyResult{Attempts: tt.attempts, Successes: tt.successes}
		if got := r.SuccessRate(); got != tt.want {
			t.Errorf("%d/%d: SuccessRate() = %v; want %v", tt.successes, tt.attempts, got, tt.want)
		}
	}
}

func TestStrategyResultLabel(t *testing.T) {
	tests := []struct {
		r    StrategyResult
		want string
	}{
		{StrategyResult{Strategy: "baseline"}, "baseline"},
		{StrategyResult{Strategy: "split", Params: map[string]int{"at": 1}}, "split at=1"},
		{StrategyResult{Strategy: "disorder", Params: map[string]int{"ttl": 1, "at": 2}}, "disorder at=2 ttl=1"},
	}
	for _, tt := range tests {
		if got := tt.r.Label(); got != tt.want {
			t.Errorf("Label() = %q; want %q", got, tt.want)
		}
	}
}

func TestStrategyResultJSON(t *testing.T) {
	in := StrategyResult{
		Domain:    "blocked.example",
		Strategy:  "fakech",
		Params:    map[string]int{"ttl": 5},
		Attempts:  10,
		Successes: 9,
		P50:       42 * time.Millisecond,
		P95:       80 * time.Millisecond,
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"domain":"blocked.example","strategy":"fakech","params":{"ttl":5},"attempts":10,"successes":9,"p50_ns":42000000,"p95_ns":80000000}`
	if string(data) != want {
		t.Errorf("json = %s\nwant   %s", data, want)
	}

	var back StrategyResult
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Errorf("round trip = %+v; want %+v", back, in)
	}
}

func TestLocateResultJSON(t *testing.T) {
	data, err := json.Marshal(LocateResult{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// An unblocked domain has no hop counts, so they stay out of the JSON.
	if want := `{"domain":"example.com","blocked":false}`; string(data) != want {
		t.Errorf("json = %s; want %s", data, want)
	}
}
