// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package routing

import (
	"sort"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// workedEngine builds the doc's worked-config engine: three signal leaves, a
// fleet ruleset, and a composed prod-policy ruleset.
func workedEngine(t *testing.T) *Engine {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	rulesets := map[string]Ruleset{
		"fleet": {
			Rules: []Rule{
				{Match: Match{Event: StringOrList{"oom"}}, To: StringOrList{"signal-ops"}},
				{Match: Match{Event: StringOrList{"die", "health_status"}, Labels: map[string]string{"env": "prod"}}, To: StringOrList{"prod-policy"}},
				{Match: Match{Severity: StringOrList{"critical"}}, To: StringOrList{"signal-ops", "signal-oncall"}},
				{Match: Match{Time: "22:00-07:00"}, To: StringOrList{"signal"}, RepeatAfter: 30 * time.Minute},
				{Match: Match{State: StringOrList{"resolved"}}, To: StringOrList{"signal"}},
			},
			Default: "signal",
		},
		"prod-policy": {
			Rules: []Rule{
				{Match: Match{Source: "ingest", Event: StringOrList{"vikunja"}}, To: StringOrList{"signal-oncall"}},
			},
			Default: "signal-ops",
		},
	}
	return New(rulesets, []string{"signal", "signal-ops", "signal-oncall"}, loc)
}

func leafNames(d Decision) []string {
	out := make([]string, 0, len(d.Leaves))
	for n := range d.Leaves {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// noon and lateNight are stable times for the time dimension in America/New_York.
func atClock(t *testing.T, hhmm string) time.Time {
	t.Helper()
	loc, _ := time.LoadLocation("America/New_York")
	parsed, err := time.ParseInLocation("15:04", hhmm, loc)
	if err != nil {
		t.Fatal(err)
	}
	return time.Date(2026, 3, 15, parsed.Hour(), parsed.Minute(), 0, 0, loc)
}

// TestResolveEveryDimension is a table-driven proof that each match dimension
// selects the expected destination (C7, C8).
func TestResolveEveryDimension(t *testing.T) {
	eng := workedEngine(t)
	cases := []struct {
		name string
		in   Input
		want []string
	}{
		{"event scalar", Input{Channel: "fleet", Event: "oom", Source: "watch", Time: atClock(t, "12:00")}, []string{"signal-ops"}},
		{"labels AND event list -> composed default", Input{Channel: "fleet", Event: "die", Source: "watch", Labels: map[string]string{"env": "prod"}, Time: atClock(t, "12:00")}, []string{"signal-ops"}},
		{"composed ruleset inner rule (entry names the ruleset)", Input{Channel: "prod-policy", Event: "vikunja", Source: "ingest", Time: atClock(t, "12:00")}, []string{"signal-oncall"}},
		{"severity fan-out", Input{Channel: "fleet", Severity: "critical", Source: "watch", Time: atClock(t, "12:00")}, []string{"signal-oncall", "signal-ops"}},
		{"time of day (late night)", Input{Channel: "fleet", Event: "die", Source: "watch", Time: atClock(t, "23:00")}, []string{"signal"}},
		{"state resolved", Input{Channel: "fleet", Event: "die", Source: "watch", State: "resolved", Time: atClock(t, "12:00")}, []string{"signal"}},
		{"no match -> default", Input{Channel: "fleet", Event: "die", Source: "watch", Time: atClock(t, "12:00")}, []string{"signal"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := leafNames(eng.Resolve(tc.in, "signal"))
			if !eq(got, tc.want) {
				t.Fatalf("leaves = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFirstMatchWins proves the first matching rule decides and no later rule is
// considered (C7): an event that is both oom and critical routes only to the oom
// rule's destination.
func TestFirstMatchWins(t *testing.T) {
	eng := workedEngine(t)
	got := leafNames(eng.Resolve(Input{Channel: "fleet", Event: "oom", Severity: "critical", Source: "watch", Time: atClock(t, "12:00")}, "signal"))
	if !eq(got, []string{"signal-ops"}) {
		t.Fatalf("first-match-wins: leaves = %v, want [signal-ops]", got)
	}
}

// TestFanOutDedupsOverlap proves overlapping branches resolve each distinct leaf
// exactly once (C9).
func TestFanOutDedupsOverlap(t *testing.T) {
	loc := time.UTC
	rulesets := map[string]Ruleset{
		"top": {
			Rules: []Rule{
				// Fan out to a leaf AND a ruleset whose default is the same leaf.
				{Match: Match{}, To: StringOrList{"a", "sub"}},
			},
			Default: "a",
		},
		"sub": {Default: "a"},
	}
	eng := New(rulesets, []string{"a", "b"}, loc)
	dec := eng.Resolve(Input{Channel: "top"}, "a")
	if got := leafNames(dec); !eq(got, []string{"a"}) {
		t.Fatalf("overlapping branches should dedup to one leaf, got %v", got)
	}
}

// TestRepeatAfterMaxAlongPath proves a leaf carries the max repeat_after over
// the matched rules on the path that reached it (C15 seam).
func TestRepeatAfterMaxAlongPath(t *testing.T) {
	eng := workedEngine(t)
	dec := eng.Resolve(Input{Channel: "fleet", Event: "die", Source: "watch", Time: atClock(t, "23:00")}, "signal")
	if got := dec.Leaves["signal"]; got != 30*time.Minute {
		t.Fatalf("late-night leaf repeat_after = %v, want 30m", got)
	}
}

// TestRuntimeUnknownEntryUsesFleetDefault proves a channel naming nothing in
// either map resolves to the fleet default and signals it (C11).
func TestRuntimeUnknownEntryUsesFleetDefault(t *testing.T) {
	eng := workedEngine(t)
	dec := eng.Resolve(Input{Channel: "typo-not-real", Event: "oom", Source: "watch", Time: atClock(t, "12:00")}, "fleet")
	if !dec.UsedFleetDefault {
		t.Fatal("an unknown entry name must flag UsedFleetDefault")
	}
	if got := leafNames(dec); !eq(got, []string{"signal-ops"}) {
		t.Fatalf("unknown entry should route through the fleet default, got %v", got)
	}
}

// TestEntryLeafDeliversDirect proves an entry that is itself a leaf delivers
// there with no rules (C7/C2 leaf-only path).
func TestEntryLeafDeliversDirect(t *testing.T) {
	eng := workedEngine(t)
	dec := eng.Resolve(Input{Channel: "signal-ops", Event: "die", Source: "watch"}, "signal")
	if got := leafNames(dec); !eq(got, []string{"signal-ops"}) {
		t.Fatalf("a leaf entry should deliver directly, got %v", got)
	}
}

// --- Level-1 invariant tests over the matcher input space --------------------

// TestMatchLabelsInvariants covers the label semantics exhaustively (C8): an
// absent key never matches, an exact value matches, a mismatched value fails,
// and an empty-string wanted value matches a present empty value only.
func TestMatchLabelsInvariants(t *testing.T) {
	cases := []struct {
		name string
		want map[string]string
		have map[string]string
		ok   bool
	}{
		{"empty want is wildcard", nil, map[string]string{"a": "b"}, true},
		{"exact match", map[string]string{"env": "prod"}, map[string]string{"env": "prod"}, true},
		{"absent key non-match", map[string]string{"env": "prod"}, map[string]string{"other": "x"}, false},
		{"value mismatch", map[string]string{"env": "prod"}, map[string]string{"env": "dev"}, false},
		{"empty-string wanted matches present empty", map[string]string{"env": ""}, map[string]string{"env": ""}, true},
		{"empty-string wanted non-match on absent", map[string]string{"env": ""}, map[string]string{"x": "y"}, false},
		{"all ANDed, one fails", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1", "b": "3"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchLabels(tc.want, tc.have); got != tc.ok {
				t.Fatalf("matchLabels(%v,%v) = %v, want %v", tc.want, tc.have, got, tc.ok)
			}
		})
	}
}

// TestTimeWindowInvariants proves the window semantics: start inclusive, end
// exclusive, and midnight wrap, over the full day boundary (C8).
func TestTimeWindowInvariants(t *testing.T) {
	loc := time.UTC
	at := func(hhmm string) time.Time {
		p, _ := time.ParseInLocation("15:04", hhmm, loc)
		return time.Date(2026, 1, 1, p.Hour(), p.Minute(), 0, 0, loc)
	}
	// Non-wrap window 09:00-17:00.
	day, err := parseTimeWindow("09:00-17:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		hhmm string
		in   bool
	}{
		{"08:59", false}, {"09:00", true}, {"12:00", true}, {"16:59", true}, {"17:00", false}, {"23:00", false},
	} {
		if got := day.contains(at(tc.hhmm)); got != tc.in {
			t.Errorf("09:00-17:00 contains %s = %v, want %v", tc.hhmm, got, tc.in)
		}
	}
	// Wrap window 22:00-07:00.
	night, err := parseTimeWindow("22:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	if !night.wrap {
		t.Fatal("22:00-07:00 should be a wrap window")
	}
	for _, tc := range []struct {
		hhmm string
		in   bool
	}{
		{"22:00", true}, {"23:59", true}, {"00:00", true}, {"06:59", true}, {"07:00", false}, {"12:00", false}, {"21:59", false},
	} {
		if got := night.contains(at(tc.hhmm)); got != tc.in {
			t.Errorf("22:00-07:00 contains %s = %v, want %v", tc.hhmm, got, tc.in)
		}
	}
}

// TestParseTimeWindowErrors proves malformed windows are rejected (C3).
func TestParseTimeWindowErrors(t *testing.T) {
	for _, bad := range []string{"09:00", "9-17", "25:00-09:00", "09:60-10:00", "09:00-09:00", "abc-def"} {
		if _, err := parseTimeWindow(bad); err == nil {
			t.Errorf("parseTimeWindow(%q) should error", bad)
		}
	}
}

// TestStringOrListDecode proves the codec accepts a scalar and a sequence (C1).
func TestStringOrListDecode(t *testing.T) {
	var scalar struct {
		To StringOrList `yaml:"to"`
	}
	if err := yaml.Unmarshal([]byte("to: signal"), &scalar); err != nil {
		t.Fatal(err)
	}
	if len(scalar.To) != 1 || scalar.To[0] != "signal" {
		t.Errorf("scalar decode = %v", scalar.To)
	}
	var list struct {
		To StringOrList `yaml:"to"`
	}
	if err := yaml.Unmarshal([]byte("to: [a, b]"), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.To) != 2 {
		t.Errorf("list decode = %v", list.To)
	}
}

// TestUnknownKeyRejected proves the custom unmarshalers reject a stray key,
// closing the fail-open typo hole (C3).
func TestUnknownKeyRejected(t *testing.T) {
	var m Match
	if err := yaml.Unmarshal([]byte("sevrity: critical"), &m); err == nil {
		t.Fatal("an unknown match key must be rejected")
	}
}

// TestDetectCycle proves cycle detection over the graph, including a default
// self-reference (C5).
func TestDetectCycle(t *testing.T) {
	acyclic := map[string]Ruleset{
		"a": {Rules: []Rule{{Match: Match{}, To: StringOrList{"b"}}}, Default: "leaf"},
		"b": {Default: "leaf"},
	}
	if err := detectCycle(acyclic); err != nil {
		t.Fatalf("acyclic graph should pass, got %v", err)
	}
	cyclic := map[string]Ruleset{
		"a": {Rules: []Rule{{Match: Match{}, To: StringOrList{"b"}}}, Default: "leaf"},
		"b": {Rules: []Rule{{Match: Match{}, To: StringOrList{"a"}}}, Default: "leaf"},
	}
	if err := detectCycle(cyclic); err == nil {
		t.Fatal("a two-node cycle must be detected")
	}
	selfDefault := map[string]Ruleset{"a": {Default: "a"}}
	if err := detectCycle(selfDefault); err == nil {
		t.Fatal("a default self-reference must be detected")
	}
}

// TestUnreachableRules proves the lint finds a rule after a catch-all and a
// duplicate-match rule (C21).
func TestUnreachableRules(t *testing.T) {
	rulesets := map[string]Ruleset{
		"r": {
			Rules: []Rule{
				{Match: Match{Event: StringOrList{"oom"}}, To: StringOrList{"a"}},
				{Match: Match{Event: StringOrList{"oom"}}, To: StringOrList{"b"}}, // duplicate of rule 0
				{Match: Match{}, To: StringOrList{"a"}},                           // catch-all
				{Match: Match{Event: StringOrList{"die"}}, To: StringOrList{"a"}}, // after catch-all
			},
			Default: "a",
		},
	}
	warns := UnreachableRules(rulesets)
	if len(warns) < 2 {
		t.Fatalf("expected a duplicate and an after-catch-all warning, got %v", warns)
	}
}
