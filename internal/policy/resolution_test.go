// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/history"
	"github.com/tagwright/beacon/internal/routing"
	"github.com/tagwright/courier"
)

// capturingDeliverer records the channel and notification of each delivery.
type capturingDeliverer struct {
	mu   sync.Mutex
	sent []sentPair
}

type sentPair struct {
	channel string
	notif   courier.Notification
}

func (c *capturingDeliverer) Deliver(_ context.Context, channel string, n courier.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, sentPair{channel, n})
	return nil
}

func (c *capturingDeliverer) channels() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.sent))
	for i, s := range c.sent {
		out[i] = s.channel
	}
	return out
}

func (c *capturingDeliverer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

func countChannel(chs []string, want string) int {
	n := 0
	for _, c := range chs {
		if c == want {
			n++
		}
	}
	return n
}

// stateRouter routes state:resolved to a quiet leaf and a critical severity to a
// fan-out with a repeat_after, so tests exercise the router matching on state
// and the per-leaf repeat window.
func stateRouter() *routing.Engine {
	rulesets := map[string]routing.Ruleset{
		"fleet": {
			Rules: []routing.Rule{
				{Match: routing.Match{State: routing.StringOrList{"resolved"}}, To: routing.StringOrList{"quiet"}},
				{Match: routing.Match{Severity: routing.StringOrList{"critical"}}, To: routing.StringOrList{"ops", "oncall"}, RepeatAfter: 15 * time.Minute},
			},
			Default: "ops",
		},
	}
	return routing.New(rulesets, []string{"ops", "oncall", "quiet"}, time.UTC)
}

func resolutionPipeline(d *capturingDeliverer, clk clock.Clock, cfg Config) *Pipeline {
	cfg.WatchDefault = "fleet"
	cfg.MaxAttempts = 1
	return New(d, &fakeSpooler{}, clk, cfg, nil)
}

func stateAlert(container, event string, st alert.State) alert.Alert {
	return alert.Alert{
		Channel:   "fleet",
		Source:    alert.SourceWatch,
		Container: container,
		Event:     event,
		State:     st,
		Notification: courier.Notification{
			Title: event + ": " + container,
			Level: courier.LevelError,
		},
	}
}

// TestRouterMatchesOnState proves the resolution engine sets Alert.State before
// the router, so a state:resolved rule routes a recovery to a different leaf
// (C12).
func TestRouterMatchesOnState(t *testing.T) {
	d := &capturingDeliverer{}
	p := resolutionPipeline(d, clock.Real{}, Config{Router: stateRouter(), DedupWindow: time.Minute, CorrelationWindow: 0})

	if err := p.Process(context.Background(), stateAlert("c1", "die", alert.StateFiring)); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), stateAlert("c1", "die", alert.StateResolved)); err != nil {
		t.Fatal(err)
	}
	chs := d.channels()
	if countChannel(chs, "ops") != 1 {
		t.Errorf("firing should route to ops, channels = %v", chs)
	}
	if countChannel(chs, "quiet") != 1 {
		t.Errorf("a resolved recovery should route to quiet via the state rule, channels = %v", chs)
	}
}

// TestFastRecovery proves a resolve within the dedup window is delivered, not
// digested as a repeat of its firing, and repeated resolves within the window
// dedup among themselves (C13, C15). It routes firing and resolved to the same
// leaf so only the state key differentiates them.
func TestFastRecovery(t *testing.T) {
	d := &capturingDeliverer{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	// No router: the entry channel is the single leaf, so firing and resolved
	// share a leaf and only their state differs in the suppressor key.
	p := resolutionPipeline(d, clk, Config{DedupWindow: 5 * time.Minute, CorrelationWindow: 0})

	base := func(st alert.State) alert.Alert {
		a := stateAlert("c1", "health_status", st)
		a.Channel = "ops"
		return a
	}
	// Firing fires.
	_ = p.Process(context.Background(), base(alert.StateFiring))
	// A resolve one minute later (well inside the 5m window) must still deliver.
	clk.Advance(time.Minute)
	_ = p.Process(context.Background(), base(alert.StateResolved))
	if d.count() != 2 {
		t.Fatalf("a resolve inside the dedup window must be delivered, not digested; delivered %d", d.count())
	}
	// A second resolve inside the window dedups against the first resolve.
	clk.Advance(time.Minute)
	_ = p.Process(context.Background(), base(alert.StateResolved))
	if d.count() != 2 {
		t.Fatalf("two repeated resolves within the window must dedup among themselves; delivered %d", d.count())
	}
}

// TestOrphanResolveNotifies proves a resolve with no prior firing (e.g. after a
// restart) still notifies, and notify_on_resolved defaults ON (C13).
func TestOrphanResolveNotifies(t *testing.T) {
	d := &capturingDeliverer{}
	p := resolutionPipeline(d, clock.Real{}, Config{DedupWindow: time.Minute, CorrelationWindow: 0})
	a := stateAlert("never-fired", "health_status", alert.StateResolved)
	a.Channel = "ops"
	if err := p.Process(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if d.count() != 1 {
		t.Fatalf("an orphan resolve must notify (notify_on_resolved defaults ON); delivered %d", d.count())
	}
}

// TestNotifyOnResolvedOffDrops proves the resolve gate drops a recovery when the
// fleet policy is off (C13 inverse), and that it is dropped after the history
// write.
func TestNotifyOnResolvedOffDrops(t *testing.T) {
	d := &capturingDeliverer{}
	off := false
	rec := &recordingHistory{}
	p := resolutionPipeline(d, clock.Real{}, Config{DedupWindow: time.Minute, CorrelationWindow: 0, NotifyOnResolved: &off, History: rec})
	a := stateAlert("c1", "health_status", alert.StateResolved)
	a.Channel = "ops"
	if err := p.Process(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if d.count() != 0 {
		t.Fatalf("notify_on_resolved off must drop the recovery; delivered %d", d.count())
	}
	if rec.count() != 1 {
		t.Fatalf("the dropped recovery must still be recorded in history first; recorded %d", rec.count())
	}
}

// TestRepeatAfterOverridesDedupWindow proves the effective per-leaf window is
// the max of the container min-interval and every matched rule's repeat_after,
// so a repeat inside the repeat_after but outside the dedup window is suppressed
// (C15).
func TestRepeatAfterOverridesDedupWindow(t *testing.T) {
	d := &capturingDeliverer{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	// Dedup window 5m, but the critical rule carries repeat_after 15m.
	p := resolutionPipeline(d, clk, Config{Router: stateRouter(), DedupWindow: 5 * time.Minute, CorrelationWindow: 0})

	crit := func() alert.Alert {
		a := stateAlert("c1", "die", alert.StateFiring)
		a.Severity = "critical"
		return a
	}
	// First critical fans out to ops and oncall.
	_ = p.Process(context.Background(), crit())
	if d.count() != 2 {
		t.Fatalf("a critical alert should fan out to two leaves; delivered %d", d.count())
	}
	// A repeat at 10m: past the 5m dedup window but inside the 15m repeat_after,
	// so both leaves are suppressed.
	clk.Advance(10 * time.Minute)
	_ = p.Process(context.Background(), crit())
	if d.count() != 2 {
		t.Fatalf("repeat_after 15m must suppress a repeat at 10m even past the 5m dedup window; delivered %d", d.count())
	}
	// A repeat past 15m fires again on both leaves.
	clk.Advance(6 * time.Minute)
	_ = p.Process(context.Background(), crit())
	if d.count() != 4 {
		t.Fatalf("a repeat past repeat_after should fire on both leaves again; delivered %d", d.count())
	}
	// Both leaves were exercised independently.
	chs := d.channels()
	if countChannel(chs, "ops") != 2 || countChannel(chs, "oncall") != 2 {
		t.Fatalf("two fanned leaves must suppress independently and each fire twice; channels = %v", chs)
	}
}

// TestCorrelationOnceBeforeFanOut proves correlation is alert-level, keyed by
// container plus state, evaluated once before fan-out (C15): a second event
// about the same container and state collapses even though it would fan out.
func TestCorrelationOnceBeforeFanOut(t *testing.T) {
	d := &capturingDeliverer{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	p := resolutionPipeline(d, clk, Config{Router: stateRouter(), DedupWindow: 5 * time.Minute, CorrelationWindow: 5 * time.Minute})

	a := stateAlert("c1", "die", alert.StateFiring)
	a.Severity = "critical"
	_ = p.Process(context.Background(), a) // fans out to ops + oncall, records correlation
	if d.count() != 2 {
		t.Fatalf("first critical should fan out to two leaves; delivered %d", d.count())
	}
	// A different event about the same container and state, within the window.
	b := stateAlert("c1", "oom", alert.StateFiring)
	b.Severity = "critical"
	_ = p.Process(context.Background(), b)
	if d.count() != 2 {
		t.Fatalf("a same-incident alert should collapse once before fan-out; delivered %d", d.count())
	}
}

// recordingHistory is a counting fake history.Recorder.
type recordingHistory struct {
	mu sync.Mutex
	n  int
}

func (r *recordingHistory) Record(_ history.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	return nil
}

func (r *recordingHistory) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}
