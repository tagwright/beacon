// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/history"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/routing"
	"github.com/tagwright/beacon/internal/spool"
	"github.com/tagwright/core/runtime"
	"github.com/tagwright/core/runtime/runtimetest"
	"github.com/tagwright/courier"
)

// perLeafDeliverer fails a named set of leaves and counts per-leaf deliveries,
// the fault injection a Level-2 fan-out test needs.
type perLeafDeliverer struct {
	mu     sync.Mutex
	fail   map[string]bool
	counts map[string]int
}

func newPerLeafDeliverer() *perLeafDeliverer {
	return &perLeafDeliverer{fail: map[string]bool{}, counts: map[string]int{}}
}

func (d *perLeafDeliverer) Deliver(_ context.Context, channel string, _ courier.Notification) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail[channel] {
		return errContext("leaf " + channel + " down")
	}
	d.counts[channel]++
	return nil
}

func (d *perLeafDeliverer) setFail(channel string, v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fail[channel] = v
}

func (d *perLeafDeliverer) count(channel string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts[channel]
}

type errContext string

func (e errContext) Error() string { return string(e) }

// fanOutRouter routes the fleet ruleset's catch-all to two leaves.
func fanOutRouter() *routing.Engine {
	rulesets := map[string]routing.Ruleset{
		"fleet": {
			Rules:   []routing.Rule{{Match: routing.Match{}, To: routing.StringOrList{"a", "b"}}},
			Default: "a",
		},
	}
	return routing.New(rulesets, []string{"a", "b"}, time.UTC)
}

func fleetDieEvent() runtime.Event {
	return runtime.Event{
		Type: runtime.EventDie,
		ID:   "c1",
		Name: "web",
		Labels: map[string]string{
			"beacon.enable":  "true",
			"beacon.channel": "fleet",
		},
	}
}

// TestRunFanOutSpoolsOnlyFailedLeaf is the load-bearing Level-2 wiring test
// (S8): a labeled container event routes through a ruleset fanning to two
// leaves, one leaf's delivery fails, and only the failed leaf is spooled and
// replayed while the other is not re-sent. It exercises routing (C7), fan-out
// (C9), the per-leaf spool (C10), and state through the pipeline (C12) end to
// end through the real Run(Deps) seam.
func TestRunFanOutSpoolsOnlyFailedLeaf(t *testing.T) {
	d := newPerLeafDeliverer()
	d.setFail("b", true)
	sp, err := spool.New(t.TempDir(), 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(d, sp, clock.Real{}, policy.Config{
		DedupWindow:       time.Minute,
		CorrelationWindow: time.Minute,
		MaxAttempts:       1,
		Router:            fanOutRouter(),
		WatchDefault:      "fleet",
	}, nil)
	rt := runtimetest.New()

	cfg := config.Config{
		Watch:    config.WatchConfig{Enabled: true, Runtime: "docker", DefaultChannel: "fleet"},
		Spool:    config.SpoolConfig{Dir: t.TempDir(), RetryInterval: 20 * time.Millisecond},
		Dedup:    config.DedupConfig{Window: time.Minute, CorrelationWindow: time.Minute},
		Delivery: config.DeliveryConfig{MaxAttempts: 1},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Deps{Config: cfg, Runtime: rt, Engine: engine, Clock: clock.Real{}}) }()

	rt.Emit(fleetDieEvent())

	// Leaf a delivers; leaf b fails and must spool exactly one unit.
	waitFor(t, "leaf a to deliver", func() bool { return d.count("a") == 1 })
	waitFor(t, "the failed leaf b to spool", func() bool { n, _ := sp.Len(); return n == 1 })

	// Recover b: the replayer drains only the failed leaf; a is not re-sent.
	d.setFail("b", false)
	waitFor(t, "leaf b to replay", func() bool { return d.count("b") == 1 })
	waitFor(t, "the spool to drain", func() bool { n, _ := sp.Len(); return n == 0 })
	if d.count("a") != 1 {
		t.Fatalf("leaf a must not be re-sent on a partial fan-out failure, got %d", d.count("a"))
	}
}

// TestRunWritesHistoryUnconditionally proves the pipeline records every
// processed event into the store, after routing and before the suppression
// gates, so a suppressed repeat is still recorded (C18).
func TestRunWritesHistoryUnconditionally(t *testing.T) {
	d := newPerLeafDeliverer()
	sp, err := spool.New(t.TempDir(), 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := history.New(t.TempDir(), 0, 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(d, sp, clock.Real{}, policy.Config{
		DedupWindow:       time.Minute,
		CorrelationWindow: 0,
		MaxAttempts:       1,
		Router:            fanOutRouter(),
		History:           store,
		WatchDefault:      "fleet",
	}, nil)
	rt := runtimetest.New()

	cfg := config.Config{
		Watch:    config.WatchConfig{Enabled: true, Runtime: "docker", DefaultChannel: "fleet"},
		Spool:    config.SpoolConfig{Dir: t.TempDir(), RetryInterval: time.Minute},
		Dedup:    config.DedupConfig{Window: time.Minute},
		Delivery: config.DeliveryConfig{MaxAttempts: 1},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Deps{Config: cfg, Runtime: rt, Engine: engine, Clock: clock.Real{}}) }()

	// Two identical die events for the same container: the first fires, the
	// second is a suppressed dedup repeat. Both must be recorded.
	rt.Emit(fleetDieEvent())
	rt.Emit(fleetDieEvent())

	waitFor(t, "both events to be recorded (including the suppressed repeat)", func() bool {
		n, _ := store.Len()
		return n == 2
	})
}
