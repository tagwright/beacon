// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package discovery

import "testing"

// TestParseEnableAndChannel is a Level 1 pure-core check of the label grammar.
func TestParseEnableAndChannel(t *testing.T) {
	spec, err := Parse(map[string]string{
		"beacon.enable":  "true",
		"beacon.channel": "ops",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !spec.Enabled {
		t.Error("expected Enabled")
	}
	if spec.Channel != "ops" {
		t.Errorf("Channel = %q, want ops", spec.Channel)
	}
}

// TestAliasDisagreementErrors guards the primary/alias reconciliation.
func TestAliasDisagreementErrors(t *testing.T) {
	_, err := Parse(map[string]string{
		"beacon.channel":          "ops",
		"tagwright.notify.channel": "pager",
	})
	if err == nil {
		t.Fatal("expected an error when primary and alias disagree")
	}
}

// TestEventsDefaultMinusExclude checks the effective event set.
func TestEventsDefaultMinusExclude(t *testing.T) {
	spec := Spec{Exclude: []string{"restart"}}
	for _, e := range spec.Events() {
		if e == "restart" {
			t.Fatal("restart should be excluded from the default set")
		}
	}
	if !spec.Wants("die") {
		t.Error("die should remain in the default set")
	}
}

// TestSeverityParsesWithAlias proves beacon.severity parses as a separate match
// attribute, honoring the tagwright.notify.severity alias (C16).
func TestSeverityParsesWithAlias(t *testing.T) {
	primary, err := Parse(map[string]string{"beacon.enable": "true", "beacon.severity": "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if primary.Severity != "critical" {
		t.Errorf("beacon.severity = %q, want critical", primary.Severity)
	}
	alias, err := Parse(map[string]string{"beacon.enable": "true", "tagwright.notify.severity": "warning"})
	if err != nil {
		t.Fatal(err)
	}
	if alias.Severity != "warning" {
		t.Errorf("tagwright.notify.severity alias = %q, want warning", alias.Severity)
	}
}

// TestRawLabelsPassthrough proves the raw container labels are carried through
// for routing to match on, verbatim (C16).
func TestRawLabelsPassthrough(t *testing.T) {
	labels := map[string]string{
		"beacon.enable": "true",
		"env":           "prod",
		"team":          "payments",
	}
	spec, err := Parse(labels)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Labels["env"] != "prod" || spec.Labels["team"] != "payments" {
		t.Errorf("raw labels not passed through: %v", spec.Labels)
	}
	// It must be a copy, not the caller's map aliased.
	spec.Labels["env"] = "mutated"
	if labels["env"] != "prod" {
		t.Error("Spec.Labels must be a copy, not an alias of the caller's map")
	}
}
