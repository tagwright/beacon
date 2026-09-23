// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package routing

import (
	"time"
)

// Engine evaluates the ruleset tree. It is built once from validated config and
// is safe for concurrent use (it holds only immutable maps).
type Engine struct {
	rulesets map[string]Ruleset
	leaves   map[string]bool
	loc      *time.Location
}

// New builds an Engine from the ruleset map, the set of leaf channel names, and
// the timezone the time dimension is evaluated in. A nil loc uses UTC.
func New(rulesets map[string]Ruleset, leafNames []string, loc *time.Location) *Engine {
	if loc == nil {
		loc = time.UTC
	}
	leaves := make(map[string]bool, len(leafNames))
	for _, n := range leafNames {
		leaves[n] = true
	}
	// Copy the ruleset map so the engine owns immutable state.
	rs := make(map[string]Ruleset, len(rulesets))
	for k, v := range rulesets {
		rs[k] = v
	}
	return &Engine{rulesets: rs, leaves: leaves, loc: loc}
}

// TraceLine is one step of an evaluation, for beacon explain.
type TraceLine struct {
	// Kind is "rule", "default", "leaf", "unknown", or "cycle".
	Kind string
	// Name is the ruleset (for rule/default) or the destination (for leaf).
	Name string
	// RuleIndex is the matched rule's index within the ruleset (Kind=="rule").
	RuleIndex int
	// To is the destination list a rule or default routed to.
	To []string
	// RepeatAfter is the effective per-leaf repeat window (Kind=="leaf").
	RepeatAfter time.Duration
}

// Decision is the result of resolving an alert: the distinct leaf set with each
// leaf's effective repeat_after (the max over every matched rule on every path
// that reached it), a trace for explain, and whether the entry name fell back to
// the fleet default (a runtime unknown name, which the caller logs at Warn).
type Decision struct {
	Leaves           map[string]time.Duration
	Trace            []TraceLine
	UsedFleetDefault bool
}

// Resolve resolves an alert's entry channel through the tree to the leaf set.
// entry is in.Channel; when it is empty, or names nothing in either map, the
// fleetDefault is used (and UsedFleetDefault is set for the unknown-name case).
func (e *Engine) Resolve(in Input, fleetDefault string) Decision {
	d := Decision{Leaves: map[string]time.Duration{}}
	entry := in.Channel
	switch {
	case entry == "":
		entry = fleetDefault
	case e.leaves[entry] || e.hasRuleset(entry):
		// a known leaf or ruleset, use it
	default:
		d.UsedFleetDefault = true
		entry = fleetDefault
	}
	e.descend(entry, 0, in, &d, map[string]bool{})
	return d
}

func (e *Engine) hasRuleset(name string) bool {
	_, ok := e.rulesets[name]
	return ok
}

func (e *Engine) descend(name string, carriedRA time.Duration, in Input, d *Decision, visited map[string]bool) {
	if e.leaves[name] {
		if cur, ok := d.Leaves[name]; !ok || carriedRA > cur {
			d.Leaves[name] = carriedRA
		}
		d.Trace = append(d.Trace, TraceLine{Kind: "leaf", Name: name, RepeatAfter: carriedRA})
		return
	}
	rs, ok := e.rulesets[name]
	if !ok {
		d.Trace = append(d.Trace, TraceLine{Kind: "unknown", Name: name})
		return
	}
	if visited[name] {
		d.Trace = append(d.Trace, TraceLine{Kind: "cycle", Name: name})
		return
	}
	visited[name] = true
	defer delete(visited, name)

	for idx, r := range rs.Rules {
		if e.matches(r.Match, in) {
			ra := carriedRA
			if r.RepeatAfter > ra {
				ra = r.RepeatAfter
			}
			d.Trace = append(d.Trace, TraceLine{Kind: "rule", Name: name, RuleIndex: idx, To: []string(r.To)})
			for _, t := range r.To {
				e.descend(t, ra, in, d, visited)
			}
			return
		}
	}
	// No rule matched: the mandatory terminal default (carries no repeat_after).
	d.Trace = append(d.Trace, TraceLine{Kind: "default", Name: name, To: []string{rs.Default}})
	e.descend(rs.Default, carriedRA, in, d, visited)
}

// Rulesets returns the engine's ruleset map, for lint and explain rendering.
func (e *Engine) Rulesets() map[string]Ruleset { return e.rulesets }

// IsLeaf reports whether name is a configured leaf channel.
func (e *Engine) IsLeaf(name string) bool { return e.leaves[name] }
