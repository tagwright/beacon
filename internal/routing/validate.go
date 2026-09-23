// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package routing

import (
	"fmt"
	"sort"
	"strings"
)

// ValidateRulesets checks the ruleset tree is well-formed and fail-closed:
// every ruleset carries a terminal default, every rule has a non-empty
// destination and a valid time window, every destination names a known leaf or
// ruleset, and no cycle is reachable. validNames is the set of all leaf plus
// ruleset names (uniqueness across the two maps is the caller's check).
func ValidateRulesets(validNames map[string]bool, rulesets map[string]Ruleset) error {
	for name, rs := range rulesets {
		if rs.Default == "" {
			return fmt.Errorf("beacon: ruleset %q has no default terminal, so an event could be un-routed", name)
		}
		if !validNames[rs.Default] {
			return fmt.Errorf("beacon: ruleset %q default %q names no configured channel or ruleset", name, rs.Default)
		}
		for i, r := range rs.Rules {
			if len(r.To) == 0 {
				return fmt.Errorf("beacon: ruleset %q rule %d has an empty to, which is not a drop sink", name, i)
			}
			for _, dst := range r.To {
				if !validNames[dst] {
					return fmt.Errorf("beacon: ruleset %q rule %d routes to %q, which names no configured channel or ruleset", name, i, dst)
				}
			}
			if r.Match.Time != "" {
				if _, err := parseTimeWindow(r.Match.Time); err != nil {
					return fmt.Errorf("beacon: ruleset %q rule %d: %w", name, i, err)
				}
			}
		}
	}
	return detectCycle(rulesets)
}

// detectCycle fails load if any cycle is reachable through a to: or a default:,
// including a default: self-reference. Nodes are rulesets; a leaf is a sink.
func detectCycle(rulesets map[string]Ruleset) error {
	const (
		white = 0 // unvisited
		gray  = 1 // on the current DFS stack
		black = 2 // fully explored
	)
	color := make(map[string]int, len(rulesets))
	var stack []string

	var visit func(name string) error
	visit = func(name string) error {
		rs, ok := rulesets[name]
		if !ok {
			return nil // a leaf, not a cycle node
		}
		color[name] = gray
		stack = append(stack, name)
		edges := rulesetEdges(rs)
		for _, dst := range edges {
			switch color[dst] {
			case gray:
				return fmt.Errorf("beacon: ruleset cycle detected: %s", strings.Join(append(stack, dst), " -> "))
			case white:
				if err := visit(dst); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[name] = black
		return nil
	}

	names := sortedKeys(rulesets)
	for _, name := range names {
		if color[name] == white {
			if err := visit(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// rulesetEdges returns every ruleset-or-leaf destination named by a ruleset,
// one per to: entry and one for the default.
func rulesetEdges(rs Ruleset) []string {
	var edges []string
	for _, r := range rs.Rules {
		edges = append(edges, r.To...)
	}
	edges = append(edges, rs.Default)
	return edges
}

// LintWarning is one advisory finding from lint, non-fatal.
type LintWarning string

// UnreachableRules reports rules that can never fire because first-match-wins
// shadows them: a rule after a catch-all (an empty match), or a rule whose match
// set duplicates an earlier rule in the same ruleset.
func UnreachableRules(rulesets map[string]Ruleset) []LintWarning {
	var out []LintWarning
	for _, name := range sortedKeys(rulesets) {
		rs := rulesets[name]
		seen := map[string]int{}
		sawCatchAll := -1
		for i, r := range rs.Rules {
			if sawCatchAll >= 0 {
				out = append(out, LintWarning(fmt.Sprintf(
					"ruleset %q rule %d is unreachable: rule %d is a catch-all (empty match) that matches everything first",
					name, i, sawCatchAll)))
				continue
			}
			key := matchKey(r.Match)
			if prev, dup := seen[key]; dup {
				out = append(out, LintWarning(fmt.Sprintf(
					"ruleset %q rule %d is unreachable: its match duplicates rule %d", name, i, prev)))
			} else {
				seen[key] = i
			}
			if r.Match.isEmpty() {
				sawCatchAll = i
			}
		}
	}
	return out
}

// UnreferencedRulesets reports rulesets not reachable from any of the given root
// names (the resolvable fleet defaults and any entry a container may name is not
// knowable, so roots are the config-side defaults). This is a lint warning, not
// a load error.
func UnreferencedRulesets(rulesets map[string]Ruleset, roots []string) []LintWarning {
	reachable := map[string]bool{}
	var mark func(name string)
	mark = func(name string) {
		if reachable[name] {
			return
		}
		rs, ok := rulesets[name]
		if !ok {
			return // a leaf
		}
		reachable[name] = true
		for _, dst := range rulesetEdges(rs) {
			mark(dst)
		}
	}
	for _, r := range roots {
		mark(r)
	}
	var out []LintWarning
	for _, name := range sortedKeys(rulesets) {
		if !reachable[name] {
			out = append(out, LintWarning(fmt.Sprintf("ruleset %q is not referenced by any fleet default or composition", name)))
		}
	}
	return out
}

// matchKey renders a match into a canonical, comparable string for duplicate
// detection.
func matchKey(m Match) string {
	var b strings.Builder
	b.WriteString("event=" + strings.Join([]string(m.Event), ",") + ";")
	b.WriteString("source=" + m.Source + ";")
	b.WriteString("severity=" + strings.Join([]string(m.Severity), ",") + ";")
	labelKeys := make([]string, 0, len(m.Labels))
	for k := range m.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		b.WriteString("label:" + k + "=" + m.Labels[k] + ";")
	}
	b.WriteString("time=" + m.Time + ";")
	b.WriteString("state=" + strings.Join([]string(m.State), ",") + ";")
	return b.String()
}

func sortedKeys(m map[string]Ruleset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
