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
