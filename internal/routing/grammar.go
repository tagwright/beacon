// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package routing is beacon's ruleset engine. It sits between an alert and
// delivery: a container names a channel, and routing resolves that name through
// a tree of rulesets to the set of leaf delivery targets, first-match-wins per
// ruleset, ANDing a rule's match dimensions, before anything is delivered.
//
// Fleet-wide policy lives in a default ruleset and a container names a channel
// only to override, so routing is fleet-by-default and per-container by
// exception. The grammar (StringOrList, Ruleset, Rule, Match) is the loaded
// config shape; the Engine evaluates it. Validation (cycle detection, reference
// resolution, the mandatory terminal, the required fleet default) is fail-closed
// at load, extending config.validate.
package routing

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// StringOrList decodes a YAML scalar or a YAML sequence into a string slice, so
// a rule can write either `to: signal` or `to: [signal, signal-oncall]` and an
// `event`, `severity`, or `state` can be a scalar or a list. yaml.v3 will not
// decode a scalar into a []string on its own, so this custom type is required or
// the worked config will not parse.
type StringOrList []string

// UnmarshalYAML accepts a scalar (one element) or a sequence (many). A null or
// empty node decodes to a nil slice.
func (s *StringOrList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			*s = nil
			return nil
		}
		var one string
		if err := value.Decode(&one); err != nil {
			return err
		}
		*s = StringOrList{one}
		return nil
	case yaml.SequenceNode:
		var many []string
		if err := value.Decode(&many); err != nil {
			return err
		}
		*s = StringOrList(many)
		return nil
	default:
		return fmt.Errorf("beacon: expected a string or a list of strings, got yaml kind %d", value.Kind)
	}
}

// Ruleset is a named node in the routing tree: an ordered list of rules and a
// mandatory terminal default. A destination (a rule `to:` or the `default:`)
// names a leaf channel or another ruleset.
type Ruleset struct {
	// Rules are evaluated in order, first match wins. May be empty or absent
	// (a default-only ruleset is legal).
	Rules []Rule `yaml:"rules"`
	// Default is the mandatory terminal destination used when no rule matched.
	// A ruleset without a default fails load.
	Default string `yaml:"default"`
}

// rulesetKeys is the closed set of keys a ruleset mapping may carry.
var rulesetKeys = map[string]bool{"rules": true, "default": true}

// UnmarshalYAML decodes a ruleset and rejects any unknown key, closing the
// fail-open hole where a typo silently changes meaning.
func (rs *Ruleset) UnmarshalYAML(value *yaml.Node) error {
	if err := rejectUnknownKeys(value, rulesetKeys, "ruleset"); err != nil {
		return err
	}
	type raw Ruleset
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}
	*rs = Ruleset(r)
	return nil
}

// Rule is one routing decision: a match, a non-empty destination, and an
// optional per-rule repeat-suppression window.
type Rule struct {
	// Match is the ANDed set of conditions. An empty or absent match matches
	// everything (a catch-all).
	Match Match `yaml:"match"`
	// To is the destination, a leaf or ruleset name, or a list for fan-out.
	// An empty To is a load error; there is no drop sink.
	To StringOrList `yaml:"to"`
	// RepeatAfter is the per-rule repeat-suppression window applied to every
	// leaf reached through this rule. Zero falls back to the dedup window.
	RepeatAfter time.Duration `yaml:"repeat_after"`
}

var ruleKeys = map[string]bool{"match": true, "to": true, "repeat_after": true}

// UnmarshalYAML decodes a rule and rejects unknown keys.
func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	if err := rejectUnknownKeys(value, ruleKeys, "rule"); err != nil {
		return err
	}
	type raw Rule
	var rr raw
	if err := value.Decode(&rr); err != nil {
		return err
	}
	*r = Rule(rr)
	return nil
}

// Match is the ANDed set of conditions a rule tests against an alert. Every
// dimension present must match; a dimension absent is a wildcard.
type Match struct {
	// Event matches the alert's event type (die, oom, health_status, restart)
	// or an ingest source name (gatus, vikunja, native). A list is an OR.
	Event StringOrList `yaml:"event"`
	// Source matches watch or ingest.
	Source string `yaml:"source"`
	// Severity matches the container beacon.severity, exact and case-sensitive.
	// A list is an OR.
	Severity StringOrList `yaml:"severity"`
	// Labels matches raw container labels, all ANDed, exact and case-sensitive.
	// An absent key is a non-match; an empty-string value matches a present key
	// with an empty value.
	Labels map[string]string `yaml:"labels"`
	// Time matches HH:MM-HH:MM (24h, start inclusive, end exclusive) in the
	// configured timezone. start>end wraps midnight; start==end is a load error.
	Time string `yaml:"time"`
	// State matches the resolution state (firing or resolved). A list is an OR.
	State StringOrList `yaml:"state"`
}

var matchKeys = map[string]bool{
	"event": true, "source": true, "severity": true,
	"labels": true, "time": true, "state": true,
}

// UnmarshalYAML decodes a match and rejects unknown keys, so a typo like
// `sevrity:` fails load rather than silently becoming a match-everything rule.
func (m *Match) UnmarshalYAML(value *yaml.Node) error {
	if err := rejectUnknownKeys(value, matchKeys, "match"); err != nil {
		return err
	}
	type raw Match
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}
	*m = Match(r)
	return nil
}

// isEmpty reports whether a match has no conditions, i.e. it is a catch-all.
func (m Match) isEmpty() bool {
	return len(m.Event) == 0 && m.Source == "" && len(m.Severity) == 0 &&
		len(m.Labels) == 0 && m.Time == "" && len(m.State) == 0
}

// rejectUnknownKeys errors if a mapping node carries a key outside allowed. A
// non-mapping node is left for the normal decoder to report.
func rejectUnknownKeys(value *yaml.Node, allowed map[string]bool, where string) error {
	if value.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if !allowed[key] {
			return fmt.Errorf("beacon: unknown key %q under %s", key, where)
		}
	}
	return nil
}
