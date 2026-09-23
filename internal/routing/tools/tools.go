// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package tools holds the logic behind beacon's routing subcommands: explain,
// lint, replay, and scaffold. It lives here, not in cmd/beacon, so main stays
// thin and the tools are tested without the daemon socket. Each entry point
// parses its own flags, reads config, and writes to an injected writer, so a
// test drives it end to end in-process.
package tools

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/history"
	"github.com/tagwright/beacon/internal/routing"
)

// engineFromConfig builds a routing engine from a loaded config: the channel
// names are the leaves, the rulesets the tree, and the timezone the clock for
// time matching.
func engineFromConfig(cfg config.Config) (*routing.Engine, error) {
	loc, err := cfg.Location()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Channels))
	for n := range cfg.Channels {
		names = append(names, n)
	}
	return routing.New(cfg.Rulesets, names, loc), nil
}

// eventInput is the JSON shape explain and replay accept for an event.
type eventInput struct {
	Channel  string            `json:"channel"`
	Event    string            `json:"event"`
	Source   string            `json:"source"`
	Severity string            `json:"severity"`
	Labels   map[string]string `json:"labels"`
	State    string            `json:"state"`
	Time     string            `json:"time"`
}

// labelFlag collects repeated --label key=value flags.
type labelFlag map[string]string

func (l labelFlag) String() string { return "" }
func (l labelFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("label must be key=value, got %q", v)
	}
	l[k] = val
	return nil
}

// Explain traces an event through the ruleset tree and prints every branch and
// the final leaf set. The event comes from flags, or from JSON on stdin when a
// body is piped. It runs without the daemon socket.
func Explain(args []string, stdout io.Writer, stdin io.Reader) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stdout)
	configPath := fs.String("config", envOr("BEACON_CONFIG", "/etc/beacon/beacon.yml"), "config file")
	event := fs.String("event", "", "event type or ingest source name")
	source := fs.String("source", "watch", "source: watch or ingest")
	severity := fs.String("severity", "", "beacon.severity value")
	state := fs.String("state", "firing", "firing or resolved")
	channel := fs.String("channel", "", "entry channel name (a beacon.channel), empty for the fleet default")
	at := fs.String("at", "", "evaluate at this time (HH:MM or RFC3339), empty for now")
	labels := labelFlag{}
	fs.Var(labels, "label", "a container label as key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	eng, err := engineFromConfig(cfg)
	if err != nil {
		return err
	}
	loc, _ := cfg.Location()

	in := routing.Input{
		Channel:  *channel,
		Event:    *event,
		Source:   *source,
		Severity: *severity,
		State:    *state,
		Labels:   map[string]string(labels),
		Time:     parseAt(*at, loc),
	}
	// A piped JSON body overrides the flags.
	if body := readPiped(stdin); len(body) > 0 {
		var ei eventInput
		if err := json.Unmarshal(body, &ei); err != nil {
			return fmt.Errorf("beacon explain: stdin json: %w", err)
		}
		in = inputFromJSON(ei, loc)
	}

	fleet := cfg.WatchDefault()
	if in.Source == "ingest" {
		fleet = cfg.IngestDefault()
	}
	dec := eng.Resolve(in, fleet)

	fmt.Fprintf(stdout, "explain: channel=%q event=%q source=%q severity=%q state=%q\n",
		orDefault(in.Channel, "(fleet default)"), in.Event, in.Source, in.Severity, in.State)
	if dec.UsedFleetDefault {
		fmt.Fprintf(stdout, "  note: entry channel %q names nothing, using fleet default %q\n", in.Channel, fleet)
	}
	for _, t := range dec.Trace {
		printTrace(stdout, t)
	}
	fmt.Fprintf(stdout, "leaves: %s\n", strings.Join(leafList(dec), ", "))
	return nil
}

func printTrace(w io.Writer, t routing.TraceLine) {
	switch t.Kind {
	case "rule":
		fmt.Fprintf(w, "  ruleset %q: rule %d matched -> %s\n", t.Name, t.RuleIndex, strings.Join(t.To, ", "))
	case "default":
		fmt.Fprintf(w, "  ruleset %q: no rule matched -> default %s\n", t.Name, strings.Join(t.To, ", "))
	case "leaf":
		if t.RepeatAfter > 0 {
			fmt.Fprintf(w, "  leaf %q (repeat_after %s)\n", t.Name, t.RepeatAfter)
		} else {
			fmt.Fprintf(w, "  leaf %q\n", t.Name)
		}
	case "cycle":
		fmt.Fprintf(w, "  cycle guard hit at ruleset %q\n", t.Name)
	case "unknown":
		fmt.Fprintf(w, "  unknown destination %q\n", t.Name)
	}
}

func leafList(dec routing.Decision) []string {
	out := make([]string, 0, len(dec.Leaves))
	for name := range dec.Leaves {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lint validates the config, renders the resolved tree, and flags unreachable
// rules, unreferenced rulesets, and a min_level-above-info leaf reachable from a
// ruleset. It runs without the socket. It returns an error only when the config
// fails to load (the fail-closed load validation); warnings are printed, not
// fatal.
func Lint(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stdout)
	configPath := fs.String("config", envOr("BEACON_CONFIG", "/etc/beacon/beacon.yml"), "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "config loaded and validated")
	renderTree(stdout, cfg)

	warnings := LintWarnings(cfg)
	if len(warnings) == 0 {
		fmt.Fprintln(stdout, "no lint warnings")
		return nil
	}
	fmt.Fprintf(stdout, "%d lint warning(s):\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(stdout, "  warning: %s\n", w)
	}
	return nil
}

// LintWarnings collects every lint finding for a config: unreachable rules,
// unreferenced rulesets, and leaves whose min_level exceeds info reachable from
// a ruleset (which would silently eat an Info RECOVERED, colliding with
// notify-on-resolved). It is exported so a test asserts each planted defect.
func LintWarnings(cfg config.Config) []string {
	var out []string
	for _, w := range routing.UnreachableRules(cfg.Rulesets) {
		out = append(out, string(w))
	}
	roots := fleetRoots(cfg)
	for _, w := range routing.UnreferencedRulesets(cfg.Rulesets, roots) {
		out = append(out, string(w))
	}
	out = append(out, minLevelWarnings(cfg)...)
	return out
}

// minLevelWarnings warns for any leaf with a min_level above info that is
// reachable from a ruleset, since it silently drops an Info RECOVERED.
func minLevelWarnings(cfg config.Config) []string {
	reachable := reachableLeaves(cfg)
	var out []string
	names := make([]string, 0, len(cfg.Channels))
	for n := range cfg.Channels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if !reachable[name] {
			continue
		}
		lvl, err := delivery.ParseLevel(cfg.Channels[name].MinLevel)
		if err != nil {
			continue
		}
		if lvl > 0 { // above LevelInfo
			out = append(out, fmt.Sprintf("leaf %q has min_level above info (%q), which silently drops an Info RECOVERED",
				name, cfg.Channels[name].MinLevel))
		}
	}
	return out
}

// reachableLeaves returns the set of leaf channels reachable from any fleet
// default through the ruleset tree.
func reachableLeaves(cfg config.Config) map[string]bool {
	leaves := map[string]bool{}
	seen := map[string]bool{}
	var mark func(name string)
	mark = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		rs, ok := cfg.Rulesets[name]
		if !ok {
			// a leaf
			if _, isChannel := cfg.Channels[name]; isChannel {
				leaves[name] = true
			}
			return
		}
		for _, r := range rs.Rules {
			for _, dst := range r.To {
				mark(dst)
			}
		}
		mark(rs.Default)
	}
	for _, root := range fleetRoots(cfg) {
		mark(root)
	}
	return leaves
}

// fleetRoots is the set of resolvable fleet-default entry names.
func fleetRoots(cfg config.Config) []string {
	var roots []string
	if d := cfg.WatchDefault(); d != "" {
		roots = append(roots, d)
	}
	if d := cfg.IngestDefault(); d != "" {
		roots = append(roots, d)
	}
	return roots
}

func renderTree(w io.Writer, cfg config.Config) {
	names := make([]string, 0, len(cfg.Rulesets))
	for n := range cfg.Rulesets {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintln(w, "no rulesets (leaf-only routing)")
		return
	}
	fmt.Fprintln(w, "rulesets:")
	for _, name := range names {
		rs := cfg.Rulesets[name]
		fmt.Fprintf(w, "  %s:\n", name)
		for i, r := range rs.Rules {
			fmt.Fprintf(w, "    rule %d -> %s\n", i, strings.Join([]string(r.To), ", "))
		}
		fmt.Fprintf(w, "    default -> %s\n", rs.Default)
	}
}

// Replay runs the recorded history through a candidate ruleset (an alternate
// --config), evaluating each event at its RECORDED time, and reports what would
// route for each. It reads the store directory from --history or the candidate
// config's history dir.
func Replay(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stdout)
	configPath := fs.String("config", envOr("BEACON_CONFIG", "/etc/beacon/beacon.yml"), "candidate config file")
	historyDir := fs.String("history", "", "history store dir (default: the config's history dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	eng, err := engineFromConfig(cfg)
	if err != nil {
		return err
	}
	loc, _ := cfg.Location()

	dir := *historyDir
	if dir == "" {
		dir = cfg.HistoryDir()
	}
	store, err := history.New(dir, 0, 0, nil)
	if err != nil {
		return err
	}
	records, err := store.All()
	if err != nil {
		return err // clear error when the store is empty
	}

	fmt.Fprintf(stdout, "replaying %d recorded event(s) against %s\n", len(records), *configPath)
	for _, rec := range records {
		in := routing.Input{
			Channel:  rec.Channel,
			Event:    rec.Event,
			Source:   rec.Source,
			Severity: rec.Severity,
			Labels:   rec.Labels,
			State:    rec.State,
			Time:     rec.Time.In(loc), // evaluate at the RECORDED time
		}
		fleet := cfg.WatchDefault()
		if in.Source == "ingest" {
			fleet = cfg.IngestDefault()
		}
		dec := eng.Resolve(in, fleet)
		fmt.Fprintf(stdout, "  %s event=%q state=%q was=%s now=%s\n",
			rec.Time.In(loc).Format(time.RFC3339), rec.Event, rec.State,
			strings.Join(rec.Leaves, ","), strings.Join(leafList(dec), ","))
	}
	return nil
}

// Scaffold emits a commented ruleset template. It is not a generation wizard; it
// is a starting point an operator edits. It lints clean.
func Scaffold(args []string, stdout io.Writer) error {
	fmt.Fprint(stdout, scaffoldTemplate)
	return nil
}

func parseAt(s string, loc *time.Location) time.Time {
	if s == "" {
		return time.Now()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	// HH:MM on a fixed date, so only the time-of-day matters.
	if t, err := time.ParseInLocation("15:04", s, loc); err == nil {
		return time.Date(2000, 1, 1, t.Hour(), t.Minute(), 0, 0, loc)
	}
	return time.Now()
}

func inputFromJSON(ei eventInput, loc *time.Location) routing.Input {
	in := routing.Input{
		Channel:  ei.Channel,
		Event:    ei.Event,
		Source:   ei.Source,
		Severity: ei.Severity,
		Labels:   ei.Labels,
		State:    ei.State,
		Time:     parseAt(ei.Time, loc),
	}
	if in.Source == "" {
		in.Source = "watch"
	}
	if in.State == "" {
		in.State = "firing"
	}
	return in
}

// readPiped reads all of stdin when a body is piped, returning nil for a
// terminal or an empty stream.
func readPiped(stdin io.Reader) []byte {
	if stdin == nil {
		return nil
	}
	if f, ok := stdin.(*os.File); ok {
		info, err := f.Stat()
		if err != nil || (info.Mode()&os.ModeCharDevice) != 0 {
			return nil // a terminal, not a pipe
		}
	}
	r := bufio.NewReader(stdin)
	data, _ := io.ReadAll(r)
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return data
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
