package report

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/mehmetalitilgen/dpiprisma/internal/model"
)

// WorkingRate is the success rate at which a strategy counts as working.
// Below it the strategy fails often enough to be worse than no advice.
const WorkingRate = 0.8

// Tools are the circumvention tools Recommend writes commands for, in the
// order the report lists them.
var Tools = []string{"gecit", "zapret", "GoodbyeDPI", "byedpi"}

// ToolsNote is printed above the commands: they are starting points, and
// some tools need more setup than one line.
const ToolsNote = "These are starting points. gecit and zapret run on Linux (zapret's nfqws also " +
	"needs a firewall rule that sends traffic to queue 200), GoodbyeDPI on Windows, " +
	"byedpi anywhere as a local SOCKS proxy."

// Advice is what the report recommends for one domain.
type Advice struct {
	Domain   string
	Note     string    // one line on the situation, e.g. why there is no command
	Commands []Command // at most one per tool, in the order of Tools
}

// Command is one ready-to-use command line.
type Command struct {
	Tool  string // one of Tools
	Line  string // the command to run
	Basis string // what the command is based on, e.g. "fakech ttl=5: 10/10, median 42.0 ms"
}

// Recommend turns results into advice for every domain they mention, in the
// order scan, locate, matrix first mention them.
//
// For each tool it picks the working strategy (success rate at least
// WorkingRate) that the tool can express, preferring the highest success
// rate and then the lowest median latency. A domain the matrix never tested
// but locate found a decoy TTL for gets untested fake-packet commands built
// from that TTL.
func Recommend(r Results) []Advice {
	var order []string
	seen := make(map[string]bool)
	add := func(domain string) {
		if !seen[domain] {
			seen[domain] = true
			order = append(order, domain)
		}
	}
	verdicts := make(map[string]model.Verdict)
	for _, s := range r.Scan {
		add(s.Domain)
		verdicts[s.Domain] = s.Verdict
	}
	located := make(map[string]model.LocateResult)
	for _, l := range r.Locate {
		add(l.Domain)
		located[l.Domain] = l
	}
	matrix := make(map[string][]model.StrategyResult)
	for _, m := range r.Matrix {
		add(m.Domain)
		matrix[m.Domain] = append(matrix[m.Domain], m)
	}

	advice := make([]Advice, 0, len(order))
	for _, domain := range order {
		advice = append(advice, adviseDomain(domain, verdicts[domain], located[domain], matrix[domain]))
	}
	return advice
}

// adviseDomain builds the advice for one domain from whatever is known
// about it. verdict is VerdictUnknown and loc is zero when they are missing.
func adviseDomain(domain string, verdict model.Verdict, loc model.LocateResult, tested []model.StrategyResult) Advice {
	a := Advice{Domain: domain}

	// TLS tricks only hide the SNI; they cannot fix a lying resolver or a
	// dropped IP, so say what can.
	switch verdict {
	case model.VerdictDNSPoisoning:
		a.Note = "DNS poisoning: use an encrypted resolver (DoH or DoT); gecit has one built in."
		return a
	case model.VerdictIPBlackhole:
		a.Note = "IP blackhole: packets to the address are dropped; only a VPN or proxy helps."
		return a
	}

	if len(tested) > 0 {
		return adviseFromMatrix(a, tested)
	}

	if loc.Blocked && loc.FakeTTLMin > 0 {
		basis := fmt.Sprintf("fake-ttl %s from locate; not tested", span(loc.FakeTTLMin, loc.FakeTTLMax))
		fake := model.StrategyResult{Strategy: "fakech", Params: map[string]int{"ttl": loc.FakeTTLMin}}
		for _, tool := range Tools {
			if line, ok := commandFor(tool, fake); ok {
				a.Commands = append(a.Commands, Command{Tool: tool, Line: line, Basis: basis})
			}
		}
		a.Note = "Not tested by the matrix; run \"dpiprisma matrix\" to confirm."
		return a
	}

	switch {
	case verdict == model.VerdictAccessible, loc.Domain != "" && !loc.Blocked:
		a.Note = "Not blocked; nothing to do."
	default:
		a.Note = "No data to base a command on."
	}
	return a
}

// adviseFromMatrix fills a from the strategies tested against its domain.
func adviseFromMatrix(a Advice, tested []model.StrategyResult) Advice {
	for _, r := range tested {
		if r.Strategy == "baseline" && r.SuccessRate() >= WorkingRate {
			a.Note = fmt.Sprintf("Not blocked: a plain ClientHello succeeded %d of %d times.", r.Successes, r.Runs)
			return a
		}
	}

	working := make([]model.StrategyResult, 0, len(tested))
	for _, r := range tested {
		if r.Strategy != "baseline" && r.SuccessRate() >= WorkingRate {
			working = append(working, r)
		}
	}
	slices.SortStableFunc(working, func(x, y model.StrategyResult) int {
		if c := cmp.Compare(y.SuccessRate(), x.SuccessRate()); c != 0 {
			return c // higher rate first
		}
		if c := cmp.Compare(x.P50, y.P50); c != 0 {
			return c // then faster first
		}
		return compareStrategies(x, y)
	})

	for _, tool := range Tools {
		for _, r := range working {
			if line, ok := commandFor(tool, r); ok {
				basis := fmt.Sprintf("%s: %d/%d, median %s", r.Label(), r.Successes, r.Runs, ms(r.P50))
				a.Commands = append(a.Commands, Command{Tool: tool, Line: line, Basis: basis})
				break
			}
		}
	}

	switch {
	case len(working) == 0:
		a.Note = fmt.Sprintf("No strategy succeeded at least %s of the time.", percent(WorkingRate))
	case len(a.Commands) == 0:
		a.Note = fmt.Sprintf("%s works, but none of the tools offers it.", working[0].Label())
	default:
		a.Note = fmt.Sprintf("Best: %s.", working[0].Label())
	}
	return a
}

// commandFor writes the command that makes tool do what result's strategy
// did, or ok false if the tool has no such technique or result lacks the
// parameter the command needs.
func commandFor(tool string, result model.StrategyResult) (line string, ok bool) {
	at, hasAt := result.Params["at"]
	ttl, hasTTL := result.Params["ttl"]

	switch tool + "/" + result.Strategy {
	case "gecit/fakech":
		if hasTTL {
			return fmt.Sprintf("sudo gecit run --fake-ttl %d", ttl), true
		}

	case "zapret/split":
		if hasAt {
			return fmt.Sprintf("nfqws --qnum=200 --dpi-desync=multisplit --dpi-desync-split-pos=%d", at), true
		}
	case "zapret/disorder":
		if hasAt {
			return fmt.Sprintf("nfqws --qnum=200 --dpi-desync=multidisorder --dpi-desync-split-pos=%d", at), true
		}
	case "zapret/fakech":
		if hasTTL {
			return fmt.Sprintf("nfqws --qnum=200 --dpi-desync=fake --dpi-desync-ttl=%d", ttl), true
		}
	case "zapret/fakerst":
		if hasTTL {
			return fmt.Sprintf("nfqws --qnum=200 --dpi-desync=rst --dpi-desync-ttl=%d", ttl), true
		}

	case "GoodbyeDPI/split":
		if hasAt {
			return fmt.Sprintf("goodbyedpi.exe -e %d --native-frag", at), true
		}
	case "GoodbyeDPI/disorder":
		if hasAt {
			return fmt.Sprintf("goodbyedpi.exe -e %d --reverse-frag", at), true
		}
	case "GoodbyeDPI/fakech":
		if hasTTL {
			return fmt.Sprintf("goodbyedpi.exe --set-ttl %d", ttl), true
		}

	case "byedpi/split":
		if hasAt {
			return fmt.Sprintf("ciadpi --split %d", at), true
		}
	case "byedpi/disorder":
		if hasAt {
			return fmt.Sprintf("ciadpi --disorder %d", at), true
		}
	case "byedpi/fakech":
		if hasTTL {
			return fmt.Sprintf("ciadpi --fake -1 --ttl %d", ttl), true
		}
	}
	return "", false
}
