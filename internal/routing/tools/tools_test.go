// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/history"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "beacon.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const explainCfg = `
watch: { enabled: true, default_channel: fleet }
timezone: UTC
spool: { dir: /tmp/beacon-tools-spool }
channels:
  signal:     { type: log }
  signal-ops: { type: log }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: signal-ops
      - match: { severity: critical }
        to: [signal-ops, signal]
    default: signal
`

// TestExplainFromFlags proves explain traces the branch and prints the final
// leaf set, from flags, without a socket (C20).
func TestExplainFromFlags(t *testing.T) {
	path := writeCfg(t, explainCfg)
	var buf bytes.Buffer
	if err := Explain([]string{"--config", path, "--event", "oom", "--source", "watch"}, &buf, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "rule 0 matched") {
		t.Errorf("explain should show the matched rule, got:\n%s", out)
	}
	if !strings.Contains(out, "leaves: signal-ops") {
		t.Errorf("explain should show the final leaf set, got:\n%s", out)
	}
}

// TestExplainFromStdinJSON proves explain accepts a JSON event on stdin (C20).
func TestExplainFromStdinJSON(t *testing.T) {
	path := writeCfg(t, explainCfg)
	var buf bytes.Buffer
	stdin := bytes.NewReader([]byte(`{"channel":"fleet","severity":"critical","source":"watch"}`))
	if err := Explain([]string{"--config", path}, &buf, stdin); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// The critical rule fans out to both leaves.
	if !strings.Contains(out, "signal-ops") || !strings.Contains(out, "signal") {
		t.Errorf("explain from stdin should fan out to both leaves, got:\n%s", out)
	}
}

// TestLintReportsWarnings proves lint flags an unreachable rule and a
// min_level-above-info leaf reachable from a ruleset (C21).
func TestLintReportsWarnings(t *testing.T) {
	body := `
watch: { enabled: true, default_channel: fleet }
timezone: UTC
spool: { dir: /tmp/beacon-tools-spool }
channels:
  loud:  { type: log }
  quiet: { type: log, min_level: error }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: loud
      - match: { event: oom }
        to: quiet
    default: quiet
`
	path := writeCfg(t, body)
	var buf bytes.Buffer
	if err := Lint([]string{"--config", path}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "unreachable") {
		t.Errorf("lint should flag the duplicate-match unreachable rule, got:\n%s", out)
	}
	if !strings.Contains(out, "min_level above info") {
		t.Errorf("lint should flag the high-min_level leaf, got:\n%s", out)
	}
}

// TestLintErrorsOnMissingDefault proves lint surfaces the fail-closed load error
// for a ruleset with no terminal default (C21/C6).
func TestLintErrorsOnMissingDefault(t *testing.T) {
	body := `
watch: { enabled: true, default_channel: fleet }
spool: { dir: /tmp/s }
channels: { signal: { type: log } }
rulesets:
  fleet:
    rules:
      - match: { event: oom }
        to: signal
`
	path := writeCfg(t, body)
	var buf bytes.Buffer
	if err := Lint([]string{"--config", path}, &buf); err == nil {
		t.Fatal("lint must surface the missing-default load error")
	}
}

// TestReplayEvaluatesAtRecordedTime seeds history at set recorded times and
// proves replay evaluates each event at its RECORDED time against the candidate
// ruleset (C22).
func TestReplayEvaluatesAtRecordedTime(t *testing.T) {
	// Candidate config: a time rule routing late-night to 'night', else 'day'.
	body := `
watch: { enabled: true, default_channel: fleet }
timezone: UTC
spool: { dir: /tmp/beacon-replay-spool }
channels:
  day:   { type: log }
  night: { type: log }
rulesets:
  fleet:
    rules:
      - match: { time: "22:00-07:00" }
        to: night
    default: day
`
	path := writeCfg(t, body)
	histDir := t.TempDir()
	store, err := history.New(histDir, 0, 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	// Two recorded events at different wall-clock times.
	night := time.Date(2026, 3, 15, 23, 0, 0, 0, time.UTC)
	day := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if err := store.Record(history.Record{Time: night, Source: "watch", Event: "die", State: "firing", Channel: "fleet"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(history.Record{Time: day, Source: "watch", Event: "die", State: "firing", Channel: "fleet"}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Replay([]string{"--config", path, "--history", histDir}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// The 23:00 event routes to night, the 12:00 event routes to day, proving
	// evaluation at the recorded time (not now).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var nightLine, dayLine string
	for _, l := range lines {
		if strings.Contains(l, "T23:00:00") {
			nightLine = l
		}
		if strings.Contains(l, "T12:00:00") {
			dayLine = l
		}
	}
	if !strings.Contains(nightLine, "now=night") {
		t.Errorf("the 23:00 event should route to night, got %q", nightLine)
	}
	if !strings.Contains(dayLine, "now=day") {
		t.Errorf("the 12:00 event should route to day, got %q", dayLine)
	}
}

// TestReplayEmptyStoreErrors proves replay errors clearly on an empty store
// rather than routing nothing silently (C19/C22).
func TestReplayEmptyStoreErrors(t *testing.T) {
	path := writeCfg(t, explainCfg)
	var buf bytes.Buffer
	if err := Replay([]string{"--config", path, "--history", t.TempDir()}, &buf); err == nil {
		t.Fatal("replay on an empty store must error")
	}
}

// TestScaffoldLintsClean proves the scaffold emits a parseable template that
// itself loads and lints clean (C23, optional).
func TestScaffoldLintsClean(t *testing.T) {
	var buf bytes.Buffer
	if err := Scaffold(nil, &buf); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scaffold.yml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("scaffold must load as a valid config: %v", err)
	}
	if w := LintWarnings(cfg); len(w) != 0 {
		t.Fatalf("scaffold should lint clean, got warnings: %v", w)
	}
}
