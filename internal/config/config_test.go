// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes a config body to a temp file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "beacon.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// validConfig is a well-formed two-map config used as the base for mutation
// tests. It loads clean.
const validConfig = `
watch:
  enabled: true
  default_channel: fleet
ingest:
  enabled: true
  default_channel: fleet
  auth_mode: none
timezone: America/New_York
spool:
  dir: /tmp/beacon-spool
channels:
  signal:     { type: signal }
  signal-ops: { type: signal }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: signal-ops
      - match: { event: [die, health_status], labels: { env: prod } }
        to: signal
      - match: { severity: critical }
        to: [signal-ops, signal]
      - match: { time: "22:00-07:00" }
        to: signal
        repeat_after: 30m
      - match: { state: resolved }
        to: signal
    default: signal
`

// TestLoadTwoMapValid loads the two-map config and confirms the ruleset tree
// and the shared namespace parse (C1).
func TestLoadTwoMapValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("valid two-map config should load: %v", err)
	}
	if _, ok := cfg.Channels["signal"]; !ok {
		t.Error("channel signal missing")
	}
	rs, ok := cfg.Rulesets["fleet"]
	if !ok {
		t.Fatal("ruleset fleet missing")
	}
	if rs.Default != "signal" {
		t.Errorf("fleet default = %q, want signal", rs.Default)
	}
	if len(rs.Rules) != 5 {
		t.Errorf("fleet rules = %d, want 5", len(rs.Rules))
	}
	// The severity rule fans out to a list, proving StringOrList decoded a seq.
	if got := rs.Rules[2].To; len(got) != 2 {
		t.Errorf("severity rule to = %v, want two leaves", got)
	}
	// The oom rule uses a scalar to, proving StringOrList decoded a scalar.
	if got := rs.Rules[0].To; len(got) != 1 || got[0] != "signal-ops" {
		t.Errorf("oom rule to = %v, want [signal-ops]", got)
	}
}

// TestDuplicateNameAcrossMapsFailsLoad proves a name used by both a channel and
// a ruleset fails load (C1).
func TestDuplicateNameAcrossMapsFailsLoad(t *testing.T) {
	body := `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels:
  signal: { type: signal }
  fleet:  { type: signal }
rulesets:
  fleet:
    default: signal
`
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate name across maps must fail load, got %v", err)
	}
}

// TestBackwardCompatLeafOnly proves an existing Stage-3 leaf-only config (a
// channels table, a top-level default_channel, auth_mode none, no rulesets, no
// history) loads unchanged (C2).
func TestBackwardCompatLeafOnly(t *testing.T) {
	body := `
watch:
  enabled: true
ingest:
  enabled: true
  auth_mode: none
default_channel: ops
spool:
  dir: /tmp/beacon-spool
channels:
  ops: { type: signal }
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Stage-3 leaf-only config should still load: %v", err)
	}
	if cfg.DefaultChannel != "ops" {
		t.Errorf("default_channel = %q, want ops", cfg.DefaultChannel)
	}
	if len(cfg.Rulesets) != 0 {
		t.Errorf("no rulesets expected, got %d", len(cfg.Rulesets))
	}
	if !cfg.NotifyResolved() {
		t.Error("notify_on_resolved should default ON")
	}
	if cfg.WatchDefault() != "ops" || cfg.IngestDefault() != "ops" {
		t.Errorf("both paths should fall back to top-level default_channel, got watch=%q ingest=%q",
			cfg.WatchDefault(), cfg.IngestDefault())
	}
}

// TestFailClosedValidation covers every load-time fail-closed case (C3): an
// unknown key under rulesets, a ruleset with no default, a rule with an empty
// to, an invalid timezone, and a time with start==end.
func TestFailClosedValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown key under match",
			body: `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    rules:
      - match: { sevrity: critical }
        to: signal
    default: signal
`,
			want: "unknown key",
		},
		{
			name: "ruleset with no default",
			body: `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: signal
`,
			want: "no default",
		},
		{
			name: "rule with empty to",
			body: `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: []
    default: signal
`,
			want: "empty to",
		},
		{
			name: "invalid timezone",
			body: `
watch: { enabled: true, default_channel: signal }
timezone: Nowhere/Nothere
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
`,
			want: "timezone",
		},
		{
			name: "time start==end",
			body: `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    rules:
      - match: { time: "09:00-09:00" }
        to: signal
    default: signal
`,
			want: "start==end",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("%s must fail load", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestDanglingReferenceFailsLoad proves every config-side reference to a
// non-existent entry fails load (C4).
func TestDanglingReferenceFailsLoad(t *testing.T) {
	cases := map[string]string{
		"rule to dangling": `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: nope
    default: signal
`,
		"default dangling": `
watch: { enabled: true, default_channel: signal }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  fleet:
    default: nope
`,
		"watch default_channel dangling": `
watch: { enabled: true, default_channel: nope }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatalf("%s must fail load", name)
			}
		})
	}
}

// TestCycleFailsLoad proves a ruleset cycle, including a default self-reference,
// fails load (C5).
func TestCycleFailsLoad(t *testing.T) {
	cases := map[string]string{
		"two-node cycle via to": `
watch: { enabled: true, default_channel: a }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  a:
    rules:
      - match: { event: oom }
        to: b
    default: signal
  b:
    rules:
      - match: { event: die }
        to: a
    default: signal
`,
		"default self-reference": `
watch: { enabled: true, default_channel: a }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
rulesets:
  a:
    default: a
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "cycle") {
				t.Fatalf("%s must fail load with a cycle error, got %v", name, err)
			}
		})
	}
}

// TestFleetDefaultRequiredForEnabledPath proves an enabled ingress path with no
// resolvable fleet default fails load (C6).
func TestFleetDefaultRequiredForEnabledPath(t *testing.T) {
	body := `
watch: { enabled: true }
spool: { dir: /tmp/s }
channels: { signal: { type: signal } }
`
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "fleet default") {
		t.Fatalf("watch enabled with no default must fail load, got %v", err)
	}
}

// TestHistoryDirDefaultsUnderSpool proves the store dir is always well-defined
// (C19 config seam).
func TestHistoryDirDefaultsUnderSpool(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.HistoryDir(), filepath.Join("/tmp/beacon-spool", "history"); got != want {
		t.Errorf("history dir = %q, want %q", got, want)
	}
}
