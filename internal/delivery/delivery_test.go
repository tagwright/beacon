// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package delivery

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/courier"
)

// TestDeliverUnknownLeafErrors proves an unknown leaf is a hard error, never a
// silent fallback to a default channel (C10). The router resolves every name to
// a configured leaf before delivery, so reaching here with an unknown name is a
// real misconfiguration.
func TestDeliverUnknownLeafErrors(t *testing.T) {
	d, err := New(map[string]config.ChannelConfig{
		"ops": {Type: "log"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Deliver(context.Background(), "not-configured", courier.Notification{Title: "x", Level: courier.LevelError})
	if err == nil || !strings.Contains(err.Error(), "no channel") {
		t.Fatalf("Deliver(unknown leaf) must error, got %v", err)
	}
}

// TestDeliverKnownLeaf proves a configured leaf delivers without error.
func TestDeliverKnownLeaf(t *testing.T) {
	d, err := New(map[string]config.ChannelConfig{"ops": {Type: "log"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Deliver(context.Background(), "ops", courier.Notification{Title: "hi", Level: courier.LevelError}); err != nil {
		t.Fatalf("delivering to a known leaf should not error: %v", err)
	}
}

// TestMinLevelSkipsBelowThreshold proves a leaf min_level above the alert Level
// is the sanctioned post-routing drop: courier skips the channel and returns
// nil, so Deliver reports no error and nothing is sent (C17).
func TestMinLevelSkipsBelowThreshold(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d, err := New(map[string]config.ChannelConfig{
		"errors-only": {Type: "log", MinLevel: "error"},
	}, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	// An info alert is below the channel's error floor: skipped, not an error.
	if err := d.Deliver(context.Background(), "errors-only", courier.Notification{Title: "fyi", Level: courier.LevelInfo}); err != nil {
		t.Fatalf("a below-min-level alert should be silently skipped, not error: %v", err)
	}
	// The engine logs the sanctioned drop at Warn so it is observable.
	if !strings.Contains(buf.String(), "min_level") {
		t.Errorf("a routed leaf skipping by level should log at Warn, log = %q", buf.String())
	}
}

// TestParseLevel is a Level-1 check of the level string mapping.
func TestParseLevel(t *testing.T) {
	cases := map[string]courier.Level{
		"":        courier.LevelInfo,
		"info":    courier.LevelInfo,
		"warning": courier.LevelWarning,
		"warn":    courier.LevelWarning,
		"error":   courier.LevelError,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v,%v want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("bogus"); err == nil {
		t.Error("an unknown level must error")
	}
}
